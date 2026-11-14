//! `ssh` and `git` with an SSH key msd holds (L16, SPEC.md).
//!
//! A call that carries [`SSH_VAR`] `=ms://<key>` (msd takes the variable out of the call, so the
//! value never reaches the child's environment) gets an SSH agent msd serves for the run
//! ([`agent`]). The private key stays in msd; the agent signs only logins to host keys pinned in
//! the key's rule (`session-bind@openssh.com`), and ssh is started with options that turn off
//! forwarding, other configs, proxies and the user's own keys ([`args`]). git runs only the
//! subcommands that talk to a remote, with forced settings that start no program, and only in a
//! repository whose own config holds data keys only ([`repo`]).
//!
//! A [`Session`] owns the agent socket and its private directory for one run. msd starts it after
//! policy allowed the run, builds the plan with [`SshGitAdapter`] through
//! [`Runner::plan_with`](crate::Runner::plan_with), and hands it to the run with
//! [`Prepared::hold`](crate::Prepared::hold): it accepts connections only from the run's process
//! group, and when the run ends, however it ends, it stops and its directory is removed.
//!
//! Every sign request goes through [`Audit`] first (msd writes a receipt); when recording fails,
//! nothing is signed.

pub mod agent;
pub mod args;
mod key;
pub mod repo;
mod wire;

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ms_core::{KeyName, Result as CoreResult};
use ms_vault::{Vault, VaultExt};

use crate::error::{RunError, adapter_refuse};
use crate::resolve::Resolver;
use crate::{EffectPreview, EnvValue, ExecPlan, RunAdapter, RunCall, RunGuard};

pub use args::{Tool, tool_of};

/// The variable that selects the SSH agent: `MS_SSH_KEY=ms://<key>`.
pub const SSH_VAR: &str = "MS_SSH_KEY";
/// Largest agent message accepted.
const MAX_AGENT_MESSAGE: usize = 256 * 1024;
/// Most connections one run's sockets accept, in all.
const MAX_CONNECTIONS: usize = 64;

/// One pinned SSH host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPin {
    /// Normalised host name or IP literal.
    pub host: String,
    /// Port.
    pub port: u16,
    /// ed25519 public key.
    pub key: [u8; 32],
}

impl HostPin {
    /// `host`, or `[host]:port` when the port is not 22 (known_hosts form).
    pub fn host_field(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }
}

/// What is being released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// An SSH signature for a login to `host` (the pinned host, or why there is none).
    Sign {
        /// The pinned host the connection is bound to.
        host: String,
    },
}

/// One sign request, for a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The key.
    pub key: KeyName,
    /// What was asked.
    pub action: Action,
    /// `None` when released, else why it was refused.
    pub refused: Option<String>,
}

/// msd's side of a session: receipts and the kill switch.
pub trait Audit: Send + Sync + std::fmt::Debug {
    /// Records the event. An error refuses a release (nothing leaves without a receipt).
    fn record(&self, event: &AuditEvent) -> Result<(), String>;
    /// `ms stop` is in effect or the session was stopped: refuse everything.
    fn stopped(&self) -> bool;
}

/// The SSH side of a session.
#[derive(Debug, Clone)]
pub struct SshSetup {
    /// The key holding the OpenSSH private key.
    pub key: KeyName,
    /// Host keys it may sign logins for.
    pub pins: Vec<HostPin>,
    /// Absolute path of `ssh` (resolved by msd).
    pub ssh: PathBuf,
}

/// Everything a session needs.
#[derive(Debug, Clone)]
pub struct Setup {
    /// The tool the call runs.
    pub tool: Tool,
    /// The SSH agent, if the call carries [`SSH_VAR`].
    pub ssh: Option<SshSetup>,
    /// The run's canonical working directory.
    pub cwd: PathBuf,
    /// Absolute path of `git`, for the repository config check (required when `tool` is git).
    pub git: Option<PathBuf>,
    /// `PATH` and the base environment the child gets (for the config check).
    pub base_env: Vec<(OsString, OsString)>,
}

/// The effect line shown in an approval: where the key can be used in this run.
pub fn effect(ssh: Option<&SshSetup>) -> String {
    let mut parts = Vec::new();
    if let Some(s) = ssh {
        let hosts: Vec<String> = s
            .pins
            .iter()
            .map(|p| format!("{} ({})", p.host_field(), key::fingerprint(&p.key)))
            .collect();
        parts.push(format!(
            "SSH logins with {} to {} only",
            s.key,
            hosts.join(", ")
        ));
    }
    parts.join("; ")
}

/// Shared between a session's sockets and its guard.
#[derive(Debug, Default)]
struct Shared {
    /// The run's process group, once the child started.
    pgid: OnceLock<i32>,
    closed: AtomicBool,
    accepted: AtomicUsize,
    conns: Mutex<Vec<StdStream>>,
}

impl Shared {
    /// A peer may talk to the run's sockets only if it is this user's and in the run's process
    /// group, and the session is still open.
    async fn peer_ok(&self, s: &tokio::net::UnixStream) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        // The child may connect before the runner reports its group (review R5): wait briefly.
        let mut tries = 0;
        let pgid = loop {
            if let Some(&g) = self.pgid.get() {
                break g;
            }
            tries += 1;
            if tries > 50 {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let Ok(cred) = s.peer_cred() else {
            return false;
        };
        if cred.uid() != rustix::process::getuid().as_raw() {
            return false;
        }
        let Some(pid) = cred.pid().and_then(rustix::process::Pid::from_raw) else {
            return false;
        };
        // The run's child leads its own session (security review S1), so the peer must be in
        // that session as well as in its group: a process from elsewhere can't join either.
        rustix::process::getpgid(Some(pid)).is_ok_and(|g| g.as_raw_nonzero().get() == pgid)
            && rustix::process::getsid(Some(pid)).is_ok_and(|s| s.as_raw_nonzero().get() == pgid)
    }

    /// Takes a connection on, or refuses it when too many came or the session closed.
    fn adopt(&self, s: tokio::net::UnixStream) -> Option<StdStream> {
        if self.accepted.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            return None;
        }
        let s = s.into_std().ok()?;
        s.set_nonblocking(false).ok()?;
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        conns.push(s.try_clone().ok()?);
        Some(s)
    }
}

/// One run's sockets and private directory. See the module docs.
#[derive(Debug)]
pub struct Session {
    dir: PathBuf,
    agent: Option<PathBuf>,
    public: Option<PathBuf>,
    known_hosts: Option<PathBuf>,
    setup: Setup,
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Session {
    /// Creates the directory and sockets and starts serving them on the current tokio runtime.
    /// Nothing is accepted until [`RunGuard::started`] names the run's process group.
    pub fn start(
        setup: Setup,
        vault: Arc<dyn Vault>,
        audit: Arc<dyn Audit>,
    ) -> Result<Self, RunError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| RunError::internal("morsec: the SSH agent needs msd's runtime"))?;
        let dir = private_dir()?;
        let mut session = Self {
            dir: dir.clone(),
            agent: None,
            public: None,
            known_hosts: None,
            setup: setup.clone(),
            shared: Arc::new(Shared::default()),
            tasks: Vec::new(),
        };
        let _enter = rt.enter();
        // Before git starts (review R1): the repository's own config may hold only data keys.
        if setup.tool == Tool::Git {
            let git = setup.git.as_deref().ok_or_else(|| {
                RunError::internal("morsec: no git to check the repository's config with")
            })?;
            let raw = repo::read_config(git, &setup.cwd, &git_env(&setup.base_env))
                .map_err(|e| RunError::denied(format!("morsec: {e}")))?;
            if let Some(why) = repo::config_violation(&raw) {
                return Err(RunError::denied(format!("morsec: {why}")));
            }
        }
        if let Some(ssh) = &setup.ssh {
            let public = vault
                .read_with(&ssh.key, |v| {
                    key::PrivateKey::from_openssh(v).map(|k| k.public())
                })
                .map_err(|e| crate::error::from_core(&e))?
                .map_err(|why| RunError::denied(format!("morsec: {}: {why}", ssh.key)))?;
            let pub_file = dir.join("id.pub");
            write_private(&pub_file, key::public_line(&public, "morsec").as_bytes())?;
            let mut hosts = String::new();
            for p in &ssh.pins {
                hosts.push_str(&format!(
                    "{} {}",
                    p.host_field(),
                    key::public_line(&p.key, "").trim_end()
                ));
                hosts.push('\n');
            }
            let kh = dir.join("known_hosts");
            write_private(&kh, hosts.as_bytes())?;
            let sock = dir.join("agent.sock");
            let ctx = Arc::new(agent::AgentCtx {
                key: ssh.key.clone(),
                pins: ssh.pins.clone(),
                vault: vault.clone(),
                audit: audit.clone(),
                signs: AtomicUsize::new(0),
            });
            let listener = listen(&sock)?;
            let shared = session.shared.clone();
            let task = tokio::spawn(serve(listener, shared, move |s| serve_agent(s, &ctx)));
            session.tasks.push(task.abort_handle());
            session.agent = Some(sock);
            session.public = Some(pub_file);
            session.known_hosts = Some(kh);
        }
        Ok(session)
    }

    /// The run's private directory (tests).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        for t in &self.tasks {
            t.abort();
        }
        let conns =
            std::mem::take(&mut *self.shared.conns.lock().unwrap_or_else(|e| e.into_inner()));
        for c in conns {
            hang_up(&c);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl RunGuard for Session {
    fn started(&self, pid: u32) {
        if let Ok(p) = i32::try_from(pid) {
            let _ = self.shared.pgid.set(p);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// The git settings every run of this adapter gets: no system or global config (both are
/// writable by the agent), no prompts, hooks and fsmonitor off (they would run programs inside
/// the run's process group), TLS verification on.
fn git_env(base: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = base.to_vec();
    for (k, v) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ] {
        env.push((k.into(), v.into()));
    }
    env
}

/// A fresh 0700 directory under `$TMPDIR` (per-user on macOS) with a random name.
fn private_dir() -> Result<PathBuf, RunError> {
    use ring::rand::SecureRandom as _;
    let mut r = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut r)
        .map_err(|_| RunError::internal("morsec: no randomness for the SSH agent directory"))?;
    let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let base = std::env::temp_dir();
    let base = std::fs::canonicalize(&base).unwrap_or(base);
    let dir = base.join(format!("ms-ssh-{name}"));
    if !args::plain_path(&dir) || dir.join("agent.sock").as_os_str().len() > 100 {
        return Err(RunError::internal(format!(
            "morsec: the temporary directory {} has characters ssh would expand, or is too long for a socket; start msd with a plain TMPDIR",
            dir.display()
        )));
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| {
            RunError::internal(format!("morsec: could not create {}: {e}", dir.display()))
        })?;
    Ok(dir)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), RunError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_nofollow())
        .open(path)
        .map_err(|e| {
            RunError::internal(format!("morsec: could not write {}: {e}", path.display()))
        })?;
    f.write_all(bytes)
        .map_err(|e| RunError::internal(format!("morsec: could not write {}: {e}", path.display())))
}

fn libc_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

fn listen(path: &Path) -> Result<tokio::net::UnixListener, RunError> {
    let l = tokio::net::UnixListener::bind(path).map_err(|e| {
        RunError::internal(format!("morsec: could not open {}: {e}", path.display()))
    })?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(l)
}

/// Accepts connections from the run's process group and hands each to `handle` on a blocking
/// thread. Aborting the task stops accepting; the session shuts the open connections down.
async fn serve<H>(listener: tokio::net::UnixListener, shared: Arc<Shared>, handle: H)
where
    H: Fn(&StdStream) + Send + Sync + 'static,
{
    let handle = Arc::new(handle);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        // Checked on a task of its own, so a peer that connects before the run's group is
        // known can't hold up the others (review R8).
        let shared = shared.clone();
        let h = handle.clone();
        tokio::spawn(async move {
            if !shared.peer_ok(&stream).await {
                return;
            }
            let Some(std) = shared.adopt(stream) else {
                return;
            };
            tokio::task::spawn_blocking(move || {
                h(&std);
                hang_up(&std);
            });
        });
    }
}

fn serve_agent(mut s: &StdStream, ctx: &agent::AgentCtx) {
    let mut conn = agent::AgentConn::new();
    loop {
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_AGENT_MESSAGE {
            return;
        }
        let mut msg = vec![0u8; n];
        if s.read_exact(&mut msg).is_err() {
            return;
        }
        let reply = conn.handle(ctx, &msg);
        let mut out = Vec::with_capacity(reply.len() + 4);
        wire::put_string(&mut out, &reply);
        if s.write_all(&out).is_err() {
            return;
        }
    }
}

/// Ends a connection for the peer. The session keeps a clone of every connection (to cut them
/// when the run ends), so dropping this one would not send EOF; and `shutdown(Both)` fails on
/// macOS once the peer closed its writing side, so each direction is shut separately.
fn hang_up(s: &StdStream) {
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.shutdown(std::net::Shutdown::Read);
}

/// Builds the exec plan for one call, from a started [`Session`].
#[derive(Debug)]
pub struct SshGitAdapter<'a> {
    resolver: &'a Resolver,
    session: &'a Session,
}

impl<'a> SshGitAdapter<'a> {
    /// An adapter for `session`'s call.
    pub fn new(resolver: &'a Resolver, session: &'a Session) -> Self {
        Self { resolver, session }
    }

    fn forced_ssh(&self) -> Option<Vec<String>> {
        let s = self.session;
        Some(args::forced_ssh_options(
            s.agent.as_deref()?,
            s.public.as_deref()?,
            s.known_hosts.as_deref()?,
        ))
    }
}

impl RunAdapter for SshGitAdapter<'_> {
    fn matches(&self, argv: &[OsString]) -> bool {
        argv.first()
            .and_then(|a| a.to_str())
            .and_then(tool_of)
            .is_some_and(|t| t == self.session.setup.tool)
    }

    fn plan(&self, call: &RunCall, _vault: &dyn Vault) -> CoreResult<ExecPlan> {
        let argv: Vec<&str> = call
            .argv
            .iter()
            .map(|a| a.to_str())
            .collect::<Option<_>>()
            .ok_or_else(|| crate::error::adapter_invalid("an argument is not valid UTF-8"))?;
        let Some((first, rest)) = argv.split_first() else {
            return Err(crate::error::adapter_invalid("the command is empty"));
        };
        if !self.matches(&call.argv) {
            return Err(adapter_refuse(
                "this command is not the ssh or git call morsec prepared",
            ));
        }
        let setup = &self.session.setup;
        let program = self
            .resolver
            .resolve(first)
            .map_err(|e| adapter_refuse(e.message.trim_start_matches("morsec: ")))?;
        let mut env: Vec<(OsString, EnvValue)> = Vec::new();
        let plain = |k: &str, v: &str| (OsString::from(k), EnvValue::Plain(v.into()));
        let args: Vec<OsString> = match setup.tool {
            Tool::Ssh => {
                let forced = self.forced_ssh().ok_or_else(|| {
                    adapter_refuse(format!(
                        "ssh needs {SSH_VAR}=ms://<key> with pinned host keys"
                    ))
                })?;
                forced
                    .into_iter()
                    .map(OsString::from)
                    .chain(rest.iter().map(OsString::from))
                    .collect()
            }
            Tool::Git => {
                for (k, v) in git_env(&[]) {
                    env.push((k, EnvValue::Plain(v)));
                }
                // Programs git would start for the caller: none (review R1).
                for (k, v) in [
                    ("GIT_PAGER", "cat"),
                    ("GIT_EDITOR", "true"),
                    ("GIT_SEQUENCE_EDITOR", "true"),
                    ("GIT_MERGE_AUTOEDIT", "no"),
                ] {
                    env.push(plain(k, v));
                }
                let mut config: Vec<(String, String)> = vec![
                    ("core.hooksPath".into(), "/dev/null".into()),
                    ("core.fsmonitor".into(), "false".into()),
                    ("http.sslVerify".into(), "true".into()),
                    // No submodule recursion: a submodule's own config is never checked.
                    ("submodule.recurse".into(), "false".into()),
                    ("push.recurseSubmodules".into(), "no".into()),
                    ("fetch.recurseSubmodules".into(), "false".into()),
                    ("gpg.program".into(), "false".into()),
                    ("gpg.ssh.program".into(), "false".into()),
                    ("gpg.x509.program".into(), "false".into()),
                    ("diff.external".into(), String::new()),
                ];
                // Only the transports this run needs (review R1): no local paths (a local
                // push runs receive-pack and the remote's hooks inside the run), no `ext::`,
                // no plain git or http. Per-protocol keys are forced too, since a repository's
                // `protocol.<name>.allow` would beat the general `protocol.allow`.
                config.push(("protocol.allow".into(), "never".into()));
                for (proto, on) in [
                    ("file", false),
                    ("ext", false),
                    ("git", false),
                    ("http", false),
                    ("https", false),
                    ("ssh", setup.ssh.is_some()),
                ] {
                    config.push((
                        format!("protocol.{proto}.allow"),
                        if on { "always" } else { "never" }.into(),
                    ));
                }
                if let (Some(forced), Some(ssh)) = (self.forced_ssh(), &setup.ssh) {
                    let cmd: Vec<String> = std::iter::once(ssh.ssh.display().to_string())
                        .chain(forced)
                        .map(|a| args::shell_quote(&a))
                        .collect();
                    env.push(plain("GIT_SSH_COMMAND", &cmd.join(" ")));
                    env.push(plain("GIT_SSH_VARIANT", "ssh"));
                }
                env.push(plain("GIT_CONFIG_COUNT", &config.len().to_string()));
                for (i, (k, v)) in config.iter().enumerate() {
                    env.push(plain(&format!("GIT_CONFIG_KEY_{i}"), k));
                    env.push(plain(&format!("GIT_CONFIG_VALUE_{i}"), v));
                }
                rest.iter().map(OsString::from).collect()
            }
        };
        Ok(ExecPlan {
            program,
            args,
            env,
            cwd: call.cwd.clone(),
        })
    }

    fn preview(&self, _call: &RunCall) -> Option<EffectPreview> {
        let s = &self.session.setup;
        Some(EffectPreview {
            summary: effect(s.ssh.as_ref()),
        })
    }
}

/// Shared test helpers.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use ms_core::{KeyMeta, Mode, SecretBytes, Tier};
    use ms_vault::memory::MemoryVault;

    #[derive(Debug, Default)]
    pub(crate) struct FakeAudit {
        events: Mutex<Vec<AuditEvent>>,
        stopped: AtomicBool,
        fail: AtomicBool,
    }

    impl FakeAudit {
        pub(crate) fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().unwrap().clone()
        }
        pub(crate) fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
        pub(crate) fn fail_writes(&self) {
            self.fail.store(true, Ordering::SeqCst);
        }
        pub(crate) fn allow_writes(&self) {
            self.fail.store(false, Ordering::SeqCst);
        }
    }

    impl Audit for FakeAudit {
        fn record(&self, event: &AuditEvent) -> Result<(), String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("disk full".into());
            }
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
        fn stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }
    }

    pub(crate) fn vault_with(value: &str) -> (Arc<dyn Vault>, KeyName) {
        let v = MemoryVault::new();
        let k = KeyName::new("gh/deploy").unwrap();
        v.put(
            &k,
            SecretBytes::from(value.to_owned()),
            KeyMeta {
                name: k.clone(),
                mode: Mode::Run,
                tier: Tier::Test,
                created_unix_ms: 0,
            },
        )
        .unwrap();
        (Arc::new(v), k)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    fn setup(tool: Tool, seed: [u8; 32]) -> (Setup, Arc<dyn Vault>) {
        let (vault, k) = vault_with(&key::testkey::openssh(&seed));
        let ssh = SshSetup {
            key: k.clone(),
            pins: vec![HostPin {
                host: "127.0.0.1".into(),
                port: 4422,
                key: key::testkey::public_of(&[2; 32]),
            }],
            ssh: "/usr/bin/ssh".into(),
        };
        (
            Setup {
                tool,
                ssh: Some(ssh),
                cwd: std::env::temp_dir(),
                git: Some("/usr/bin/git".into()),
                base_env: vec![],
            },
            vault,
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    // protects=SPEC D3/Verify 2: the session's directory is private (0700, files 0600) and
    // holds only public data (the public key and the pinned host keys); the exec plan's
    // environment holds no part of the private key; the directory is gone once the session is
    // dropped; fails_when=the private key (or its seed, in any encoding) reaches a file or the
    // child's environment, or the directory outlives the run; no_claim=processes outside msd
    // reading msd's memory
    #[test]
    fn private_key_never_written() {
        let rt = rt();
        let _g = rt.enter();
        let seed = [0x5a; 32];
        let (s, vault) = setup(Tool::Git, seed);
        let session = Session::start(s, vault.clone(), Arc::new(FakeAudit::default())).unwrap();
        let dir = session.dir().to_path_buf();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let private_text = key::testkey::openssh(&seed);
        let seed_forms = crate::adapters::ssh_git::tests::encodings(&seed);
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            if m.file_type().is_file() {
                assert_eq!(m.permissions().mode() & 0o777, 0o600, "{p:?}");
                let bytes = std::fs::read(&p).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("PRIVATE KEY"), "{p:?}");
                for f in &seed_forms {
                    assert!(!bytes.windows(f.len()).any(|w| w == &f[..]), "{p:?}");
                }
            }
        }
        let resolver = Resolver::new(
            vec!["/usr/bin".into(), "/bin".into(), "/opt/homebrew/bin".into()],
            vec![],
        );
        let adapter = SshGitAdapter::new(&resolver, &session);
        let call = RunCall {
            argv: vec!["git".into(), "push".into()],
            cwd: std::env::temp_dir(),
            session: ms_core::SessionId {
                agent: ms_core::AgentKind::ClaudeCode,
                pid: 1,
                started_unix_ms: 1,
            },
        };
        let plan = adapter.plan(&call, &*vault).unwrap();
        let mut env_text = Vec::new();
        for (k, v) in &plan.env {
            let EnvValue::Plain(v) = v else {
                panic!("{k:?} holds a secret")
            };
            env_text.extend_from_slice(v.as_encoded_bytes());
        }
        assert!(!String::from_utf8_lossy(&env_text).contains(&private_text[40..80]));
        for f in &seed_forms {
            assert!(!env_text.windows(f.len()).any(|w| w == &f[..]));
        }
        let names: Vec<_> = plan
            .env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for want in [
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "GIT_PAGER",
            "GIT_EDITOR",
        ] {
            assert!(names.iter().any(|n| n == want), "{names:?}");
        }
        // The forced git settings (review R1): only ssh among the transports, no hooks, no
        // fsmonitor, no submodule recursion, no signing program.
        let plain_of = |name: &str| {
            plan.env.iter().find_map(|(k, v)| match v {
                EnvValue::Plain(v) if k == name => Some(v.to_string_lossy().into_owned()),
                _ => None,
            })
        };
        let n: usize = plain_of("GIT_CONFIG_COUNT").unwrap().parse().unwrap();
        let forced: std::collections::BTreeMap<String, String> = (0..n)
            .map(|i| {
                (
                    plain_of(&format!("GIT_CONFIG_KEY_{i}")).unwrap(),
                    plain_of(&format!("GIT_CONFIG_VALUE_{i}")).unwrap(),
                )
            })
            .collect();
        for (k, v) in [
            ("protocol.allow", "never"),
            ("protocol.file.allow", "never"),
            ("protocol.ext.allow", "never"),
            ("protocol.https.allow", "never"),
            ("protocol.ssh.allow", "always"),
            ("core.hooksPath", "/dev/null"),
            ("core.fsmonitor", "false"),
            ("submodule.recurse", "false"),
            ("gpg.program", "false"),
        ] {
            assert_eq!(
                forced.get(k).map(String::as_str),
                Some(v),
                "{k}: {forced:?}"
            );
        }
        assert!(!forced.contains_key("credential.helper"));
        assert!(
            adapter
                .preview(&call)
                .unwrap()
                .summary
                .contains("[127.0.0.1]:4422")
        );
        drop(session);
        assert!(!dir.exists());
    }

    /// The seed in the encodings a leak would likely take.
    pub(crate) fn encodings(seed: &[u8; 32]) -> Vec<Vec<u8>> {
        use base64::Engine as _;
        vec![
            seed.to_vec(),
            seed.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into_bytes(),
            base64::engine::general_purpose::STANDARD
                .encode(seed)
                .into_bytes()[..40]
                .to_vec(),
        ]
    }

    // protects=the sockets refuse every connection until the run's process group is known, and
    // then any process outside that group; fails_when=a process outside the run gets an answer;
    // no_claim=processes inside the group (the run's own git/ssh are allowed by design)
    #[test]
    fn sockets_only_serve_the_run() {
        let rt = rt();
        let (s, vault) = setup(Tool::Ssh, [0x11; 32]);
        let session = {
            let _g = rt.enter();
            Session::start(s, vault, Arc::new(FakeAudit::default())).unwrap()
        };
        let sock = session.agent.clone().unwrap();
        let ask = |sock: &Path| -> Option<Vec<u8>> {
            let mut c = StdStream::connect(sock).ok()?;
            c.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
            c.write_all(&[0, 0, 0, 1, agent::REQUEST_IDENTITIES]).ok()?;
            let mut len = [0u8; 4];
            c.read_exact(&mut len).ok()?;
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).ok()?;
            Some(body)
        };
        // Not started: refused.
        assert!(ask(&sock).is_none());
        // Started with another group (this test runs in its own group, not that one): refused.
        session.started(1);
        assert!(ask(&sock).is_none());
        // A session for this process's own group: answered only if this process also leads
        // that session (the peer check wants both, security review S1). A test harness is
        // usually not a session leader, so this is mostly the refusal; the answered path runs
        // with real run children in the sshd test.
        let (s2, vault2) = setup(Tool::Ssh, [0x11; 32]);
        let mine = {
            let _g = rt.enter();
            Session::start(s2, vault2, Arc::new(FakeAudit::default())).unwrap()
        };
        let pgid = rustix::process::getpgid(None)
            .unwrap()
            .as_raw_nonzero()
            .get();
        let leads = rustix::process::getsid(None)
            .unwrap()
            .as_raw_nonzero()
            .get()
            == pgid;
        mine.started(u32::try_from(pgid).unwrap());
        match ask(mine.agent.as_deref().unwrap()) {
            Some(body) => {
                assert!(leads, "answered a peer outside the run's session");
                assert_eq!(body[0], agent::IDENTITIES_ANSWER);
            }
            None => assert!(!leads, "refused a peer in the run's group and session"),
        }
        let dir = mine.dir().to_path_buf();
        drop(mine);
        assert!(!dir.exists());
        drop(rt);
    }
}
