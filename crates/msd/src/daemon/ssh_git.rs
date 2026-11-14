//! L16 in msd: `ssh` / `git` runs with `MS_SSH_KEY` or `MS_GIT_CREDENTIAL` (SPEC.md).
//!
//! [`Daemon::ssh_git_call`] takes those variables out of a checked call (so the value never goes
//! into the child's environment, though it is still redacted from the output) and checks the call against the effective rules: the tool, the
//! pinned host keys or HTTPS hosts, and the caller's arguments. [`Daemon::plan_ssh_git`] starts
//! the run's [`Session`] (agent and credential sockets), builds the plan with the session's
//! adapter, and ties the session to the run. Each signature and credential becomes a receipt
//! through [`RunAudit`] before anything is released.

use std::path::PathBuf;
use std::sync::{Arc, Weak};

use ms_core::{KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, SecretRef, SessionId};
use ms_receipts::ReceiptDetail;
use ms_rules::{NormalHost, Rules};
use ms_run::adapters::ssh_git::{
    self, Action, Audit, AuditEvent, CRED_VAR, CredSetup, HELPER_NAME, HostPin, SSH_VAR, Session,
    Setup, SshGitAdapter, SshSetup, Tool,
};
use ms_run::{Prepared, RunCall, RunError, RunInput, Runner};

use super::{Daemon, TOUCH_ID_METHOD, now_ms};

/// The ssh/git side of one call, decided before approvals.
#[derive(Debug)]
pub(super) struct SshGitCall {
    tool: Tool,
    ssh: Option<SshSetup>,
    cred: Option<CredSetup>,
}

impl SshGitCall {
    /// The effect line for an approval.
    pub(super) fn effect(&self) -> String {
        ssh_git::effect(self.ssh.as_ref(), self.cred.as_ref())
    }
}

/// What a receipt for one signature or credential carries from its run.
#[derive(Debug, Clone)]
pub(super) struct RunContext {
    pub(super) session: SessionId,
    pub(super) target: String,
    pub(super) argv_hash: [u8; 32],
    pub(super) rule_version: u64,
    /// Approval ids per key (production keys).
    pub(super) approvals: Vec<(KeyName, Option<String>)>,
}

/// Writes receipts for a run's signatures and credentials, and answers `ms stop`.
#[derive(Debug)]
struct RunAudit {
    daemon: Weak<Daemon>,
    run: RunContext,
}

/// Longest reason kept in a receipt target.
const REASON_MAX: usize = 160;

impl Audit for RunAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), String> {
        let d = self
            .daemon
            .upgrade()
            .ok_or_else(|| "msd is shutting down".to_owned())?;
        let (what, host) = match &event.action {
            Action::Sign { host } => ("ssh-sign", host),
            Action::Credential { host } => ("git-credential", host),
        };
        let approval_id = self
            .run
            .approvals
            .iter()
            .find(|(k, _)| *k == event.key)
            .and_then(|(_, a)| a.clone());
        let (result, target) = match &event.refused {
            None => (
                if approval_id.is_some() {
                    ReceiptResult::Approved
                } else {
                    ReceiptResult::Allowed
                },
                format!("{what} {host} for: {}", self.run.target),
            ),
            Some(why) => {
                let reason = if d.is_stopped() || d.session_stopped(&self.run.session) {
                    Reason::Stopped
                } else {
                    Reason::HostNotAllowed
                };
                let why: String = why.chars().take(REASON_MAX).collect();
                (
                    ReceiptResult::Blocked(reason),
                    format!("{what} {host} refused ({why}) for: {}", self.run.target),
                )
            }
        };
        let method = approval_id.as_ref().map(|_| TOUCH_ID_METHOD.to_owned());
        d.receipts
            .append_detailed(
                ReceiptEvent {
                    time_unix_ms: now_ms(),
                    session: self.run.session.clone(),
                    key: event.key.clone(),
                    mode: Mode::Run,
                    target,
                    argv_hash: Some(self.run.argv_hash),
                    rule_version: self.run.rule_version,
                    approval_id,
                    result,
                },
                ReceiptDetail {
                    approval_method: method,
                    ..ReceiptDetail::default()
                },
            )
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn stopped(&self) -> bool {
        self.daemon
            .upgrade()
            .is_none_or(|d| d.is_stopped() || d.session_stopped(&self.run.session))
    }
}

/// `ms-git-credential` next to msd (or one directory up, for test binaries in `deps/`).
fn helper_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [dir.join(HELPER_NAME), dir.parent()?.join(HELPER_NAME)]
        .into_iter()
        .find(|p| p.is_file())
}

impl Daemon {
    /// Takes `MS_SSH_KEY` / `MS_GIT_CREDENTIAL` out of `input` and checks the call against
    /// `rules` (the effective rules for its directory). `Ok(None)`: neither is set, an ordinary
    /// run. `Err((key, message))`: refused.
    pub(super) fn ssh_git_call(
        &self,
        runner: &Runner,
        input: &mut RunInput,
        rules: &Rules,
    ) -> Result<Option<SshGitCall>, (KeyName, String)> {
        let mut ssh_key = None;
        let mut cred_key = None;
        let mut kept = Vec::new();
        for (name, value) in std::mem::take(&mut input.env) {
            let slot = match name.as_str() {
                SSH_VAR => &mut ssh_key,
                CRED_VAR => &mut cred_key,
                _ => {
                    kept.push((name, value));
                    continue;
                }
            };
            // The env policy before this already required exactly `ms://<run key>`.
            if let Ok(r) = SecretRef::parse(&value) {
                *slot = Some(r.name().clone());
            }
        }
        // `env_keys` keeps the taken keys: the runner then reads their values only to redact
        // them from the output (a `git` subcommand that prints a credential shows a label).
        input.env = kept;
        let Some(first) = ssh_key.clone().or_else(|| cred_key.clone()) else {
            return Ok(None);
        };
        let refuse = |k: &KeyName, m: String| Err((k.clone(), m));
        let Some(tool) = ssh_git::tool_of(&input.argv[0]) else {
            return refuse(
                &first,
                format!(
                    "morsec: {SSH_VAR} and {CRED_VAR} work only with ssh and git, not {}",
                    printable(&input.argv[0])
                ),
            );
        };
        let ssh = match &ssh_key {
            None => None,
            Some(k) => {
                let pins: Vec<HostPin> = rules
                    .keys
                    .get(k)
                    .map(|r| {
                        r.ssh_host_keys
                            .iter()
                            .map(|p| HostPin {
                                host: p.host.clone(),
                                port: p.port,
                                key: p.key,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if pins.is_empty() {
                    return refuse(
                        k,
                        format!(
                            "morsec: {k} has no pinned SSH host keys, so it can't sign any login. Pin the server's key from your own terminal: ms rules {k} --add-ssh-host-key \"$(ssh-keyscan -t ed25519 HOST)\""
                        ),
                    );
                }
                let ssh = runner
                    .resolver()
                    .resolve("ssh")
                    .map_err(|e| (k.clone(), e.message))?;
                Some(SshSetup {
                    key: k.clone(),
                    pins,
                    ssh,
                })
            }
        };
        let cred = match &cred_key {
            None => None,
            Some(k) => {
                let hosts = rules
                    .keys
                    .get(k)
                    .map(|r| r.hosts.clone())
                    .unwrap_or_default();
                if hosts.is_empty() {
                    return refuse(
                        k,
                        format!(
                            "morsec: {k} has no hosts, so git gets no credential anywhere. Bind the git host from your own terminal: ms rules {k} --add-host github.com"
                        ),
                    );
                }
                if tool != Tool::Git {
                    return refuse(k, format!("morsec: {CRED_VAR} works only with git"));
                }
                let Some(helper) = helper_path() else {
                    return refuse(
                        k,
                        format!(
                            "morsec: {HELPER_NAME} was not found next to msd, so git can't get the credential. Reinstall morsec"
                        ),
                    );
                };
                let helper = runner
                    .resolver()
                    .resolve(&helper.to_string_lossy())
                    .map_err(|e| (k.clone(), e.message))?;
                let shown = hosts.iter().map(ToString::to_string).collect();
                let allowed = hosts.clone();
                Some(CredSetup {
                    key: k.clone(),
                    host_allowed: Arc::new(move |h: &str| {
                        NormalHost::parse(h).is_some_and(|n| allowed.iter().any(|p| p.matches(&n)))
                    }),
                    hosts_shown: shown,
                    helper,
                })
            }
        };
        if tool == Tool::Ssh && ssh.is_none() {
            return refuse(&first, format!("morsec: ssh needs {SSH_VAR}=ms://<key>"));
        }
        let pins = ssh.as_ref().map(|s| s.pins.clone()).unwrap_or_default();
        ssh_git::args::check(tool, &input.argv[1..], &pins).map_err(|e| (first, e.message))?;
        Ok(Some(SshGitCall { tool, ssh, cred }))
    }

    /// Starts the run's session and builds its plan; the session lives as long as the run.
    pub(super) fn plan_ssh_git(
        &self,
        runner: &Runner,
        sg: SshGitCall,
        input: &RunInput,
        call: &RunCall,
        run_keys: &std::collections::BTreeSet<KeyName>,
        run: RunContext,
    ) -> Result<Prepared, RunError> {
        let git = if sg.tool == Tool::Git {
            Some(runner.resolver().resolve("git")?)
        } else {
            None
        };
        let base_env = vec![
            ("PATH".into(), runner.resolver().path_var()),
            (
                "HOME".into(),
                std::env::var_os("HOME").unwrap_or_else(|| "/".into()),
            ),
        ];
        let setup = Setup {
            tool: sg.tool,
            ssh: sg.ssh,
            cred: sg.cred,
            cwd: call.cwd.clone(),
            git,
            base_env,
        };
        let audit = Arc::new(RunAudit {
            daemon: self.me.clone(),
            run,
        });
        let session = Session::start(setup, self.vault.clone(), audit)?;
        let adapter = SshGitAdapter::new(runner.resolver(), &session);
        let mut prepared = runner.plan_with(&adapter, input, call, run_keys, &*self.vault)?;
        prepared.hold(Box::new(session));
        Ok(prepared)
    }
}

fn printable(s: &str) -> String {
    s.chars().take(80).flat_map(char::escape_default).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::daemon::Identify;
    use crate::paths::Paths;
    use ms_approve::HumanApprover;
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{AgentKind, KeyMeta, SecretBytes, Tier};
    use ms_ipc::{ApprovalScope, ErrorCode, PeerInfo, RequestBody, ResponseBody, RunEnv};
    use ms_session::Caller;
    use ms_vault::memory::MemoryVault;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;

    const PERSON_PID: i32 = 7101;

    fn peer() -> PeerInfo {
        PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(42),
            accepted_unix_ms: 1,
        }
    }

    fn person() -> PeerInfo {
        PeerInfo {
            pid: Some(PERSON_PID),
            ..peer()
        }
    }

    /// Approves the next pending approval as the person in `ms approve`.
    fn approve_next(d: &Arc<Daemon>) -> std::thread::JoinHandle<()> {
        let d = d.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let ResponseBody::Approval { pending: Some(p) } =
                    d.handle(&person(), RequestBody::ApprovalPending, None)
                {
                    let r = d.handle(
                        &person(),
                        RequestBody::ApprovalDecide {
                            id: p.id,
                            approve: true,
                            scope: Some(ApprovalScope::Once),
                        },
                        None,
                    );
                    assert!(matches!(r, ResponseBody::Ok { .. }), "{r:?}");
                    return;
                }
                assert!(std::time::Instant::now() < deadline, "no approval asked");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    }

    /// A daemon whose caller is an agent session once `keys` (name, value, tier, rule body) are
    /// stored and their rules saved (rules loosening approved as the person would).
    fn daemon(dir: &Path, keys: &[(&str, &str, Tier, String)]) -> Arc<Daemon> {
        let who: Arc<Mutex<Option<Caller>>> = Arc::new(Mutex::new(Some(Caller::Unattributed {
            pid: 43,
            started_unix_ms: 1,
        })));
        let w = who.clone();
        let identify: Identify = Arc::new(move |p: &PeerInfo| match p.pid {
            Some(PERSON_PID) => Some(Caller::Unattributed {
                pid: 99,
                started_unix_ms: 1,
            }),
            _ => w.lock().unwrap().clone(),
        });
        let approvals =
            Arc::new(HumanApprover::new(Arc::new(FakeAuthenticator::approve())).unwrap());
        approvals.set_cooldown(std::time::Duration::ZERO);
        let d = Daemon::open(
            Backend::Memory(Arc::new(MemoryVault::new())),
            Paths::under(dir.join("state")),
            0,
            approvals,
            identify,
        )
        .unwrap();
        for (name, value, tier, body) in keys {
            let k = KeyName::new(name).unwrap();
            let put = d.handle(
                &peer(),
                RequestBody::PutKey {
                    name: k.clone(),
                    meta: KeyMeta {
                        name: k.clone(),
                        mode: Mode::Run,
                        tier: *tier,
                        created_unix_ms: 1,
                    },
                },
                Some(SecretBytes::new(value.as_bytes().to_vec())),
            );
            assert!(matches!(put, ResponseBody::Ok { .. }), "{put:?}");
            let tier_s = if *tier == Tier::Test {
                "test"
            } else {
                "production"
            };
            let rule = format!(
                "version = 1\n[keys.\"{name}\"]\nmode = \"run\"\ntier = \"{tier_s}\"\n{body}\n"
            );
            let decider = approve_next(&d);
            let saved = d.handle(
                &peer(),
                RequestBody::RulesProposeLoosen {
                    key: k,
                    rule: Some(rule),
                    at_terminal: false,
                },
                None,
            );
            decider.join().unwrap();
            assert!(matches!(saved, ResponseBody::Ok { .. }), "{saved:?}");
        }
        *who.lock().unwrap() = Some(Caller::Agent(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
            started_unix_ms: 1,
        }));
        d
    }

    fn run(d: &Arc<Daemon>, cwd: &Path, argv: &[&str], env: &[(&str, &str)]) -> ResponseBody {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let d = d.clone();
        let cwd = cwd.to_path_buf();
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let env: Vec<RunEnv> = env
            .iter()
            .map(|(n, v)| RunEnv {
                name: n.to_string(),
                value: v.to_string(),
            })
            .collect();
        rt.block_on(async move {
            tokio::task::spawn_blocking(move || {
                d.handle(&peer(), RequestBody::Run { argv, cwd, env }, None)
            })
            .await
            .unwrap()
        })
    }

    fn receipts(dir: &Path) -> String {
        std::fs::read_dir(dir.join("state/receipts"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect()
    }

    fn sh(cmd: &mut Command) -> String {
        let out = cmd
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// A throwaway sshd on 127.0.0.1 as this user, with its own host key and one authorized
    /// throwaway client key. Never reads or writes `~/.ssh`.
    struct Sshd {
        child: Child,
        port: u16,
        host_pub: String,
    }

    impl Drop for Sshd {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn keygen(path: &Path) {
        sh(Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "throwaway", "-f"])
            .arg(path));
    }

    fn start_sshd(dir: &Path, authorized: &Path) -> Sshd {
        keygen(&dir.join("host"));
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cfg = dir.join("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile none\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nLogLevel VERBOSE\n",
                dir.join("host").display(),
                authorized.display()
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.join("sshd.log")).unwrap();
        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(std::time::Instant::now() < deadline, "sshd did not start");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let host_pub = std::fs::read_to_string(dir.join("host.pub")).unwrap();
        Sshd {
            child,
            port,
            host_pub: host_pub
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    // protects=SPEC Verify 2 and 3 end to end through msd: `git push` over ssh to a bound remote
    // (a throwaway sshd and bare repository) works with MS_SSH_KEY, the signature is recorded as
    // a receipt, the private key is on no disk the run touched and in no output; the same push
    // with a key whose rule pins another host key fails; MS_SSH_KEY with another tool or git
    // global options is refused and recorded; fails_when=the push fails through the agent, lands
    // without a pinned host key, or the key shows up in a file, an output or a receipt;
    // no_claim=GitHub or any real host, HTTPS pushes
    #[test]
    #[allow(clippy::print_stderr)] // says why it was skipped
    fn git_push_through_the_agent() {
        if !Path::new("/usr/sbin/sshd").exists() || !Path::new("/usr/bin/ssh-keygen").exists() {
            eprintln!("SKIPPED git_push_through_the_agent: no /usr/sbin/sshd or ssh-keygen here");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let keys = t.join("keys");
        std::fs::create_dir(&keys).unwrap();
        keygen(&keys.join("client"));
        let sshd = start_sshd(&keys, &keys.join("client.pub"));
        let private = std::fs::read_to_string(keys.join("client")).unwrap();
        // The vault is now the only place the key lives.
        std::fs::remove_file(keys.join("client")).unwrap();
        let key_body: String = private
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>();
        // Every OpenSSH key starts with the same header; the private part is near the end.
        let secret_part = key_body[key_body.len() - 120..key_body.len() - 40].to_owned();

        let remote = t.join("remote.git");
        sh(Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&remote));
        let proj = t.join("proj");
        std::fs::create_dir(&proj).unwrap();
        sh(Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .current_dir(&proj));
        std::fs::write(proj.join("f.txt"), "hello\n").unwrap();
        sh(Command::new("git")
            .args(["add", "f.txt"])
            .current_dir(&proj));
        sh(Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "commit",
                "-q",
                "-m",
                "x",
            ])
            .current_dir(&proj));
        let user = sh(Command::new("/usr/bin/id").arg("-un")).trim().to_owned();
        let url = format!("ssh://{user}@127.0.0.1:{}{}", sshd.port, remote.display());
        sh(Command::new("git")
            .args(["remote", "add", "origin", &url])
            .current_dir(&proj));
        let head = sh(Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&proj));

        let pin = format!("[127.0.0.1]:{} {}", sshd.port, sshd.host_pub);
        let other_pin = "[127.0.0.1]:1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPtd2fa6erUsRui9x7T64boFCGFRwuEig/mwpm4LdTO7";
        let body = |pin: &str| {
            format!(
                "commands = [[\"git\", \"push\", \"origin\", \"main\"], [\"env\"], [\"git\", \"-c\", \"a=b\", \"push\"]]\nenv = [\"MS_SSH_KEY\"]\nroots = [\"{}\"]\nssh_host_keys = [\"{pin}\"]",
                proj.display()
            )
        };
        let d = daemon(
            &t,
            &[
                ("gh/deploy", &private, Tier::Test, body(&pin)),
                ("gh/other", &private, Tier::Test, body(other_pin)),
            ],
        );
        let before: Vec<_> = tmp_ssh_dirs();

        // A key whose rule pins another host key: ssh refuses the server, nothing lands.
        let r = run(
            &d,
            &proj,
            &["git", "push", "origin", "main"],
            &[("MS_SSH_KEY", "ms://gh/other")],
        );
        let ResponseBody::RunResult { code, .. } = &r else {
            panic!("{r:?}")
        };
        assert_ne!(*code, Some(0), "{r:?}");
        assert!(
            sh(Command::new("git")
                .arg("--git-dir")
                .arg(&remote)
                .args(["branch", "--list"]))
            .trim()
            .is_empty()
        );

        // The bound remote: the push lands.
        let r = run(
            &d,
            &proj,
            &["git", "push", "origin", "main"],
            &[("MS_SSH_KEY", "ms://gh/deploy")],
        );
        let ResponseBody::RunResult {
            code,
            stdout,
            stderr,
            ..
        } = &r
        else {
            panic!("{r:?}")
        };
        let out = String::from_utf8(ms_ipc::b64_decode(stdout).unwrap()).unwrap()
            + &String::from_utf8(ms_ipc::b64_decode(stderr).unwrap()).unwrap();
        assert_eq!(*code, Some(0), "{out}");
        let landed = sh(Command::new("git")
            .arg("--git-dir")
            .arg(&remote)
            .args(["rev-parse", "main"]));
        assert_eq!(landed, head);
        assert!(!out.contains(&secret_part));

        // Refused before anything runs, and recorded.
        for (argv, _) in [
            (&["env"][..], "only with ssh and git"),
            (
                &["git", "-c", "a=b", "push"],
                "options before the subcommand",
            ),
        ] {
            let r = run(&d, &proj, argv, &[("MS_SSH_KEY", "ms://gh/deploy")]);
            assert!(
                matches!(
                    &r,
                    ResponseBody::Error {
                        code: ErrorCode::Denied,
                        ..
                    }
                ),
                "{argv:?}: {r:?}"
            );
        }

        let rec = receipts(&t);
        let signed = format!(
            "ssh-sign [127.0.0.1]:{} for: git push origin main",
            sshd.port
        );
        assert!(rec.contains(&signed), "{rec}");
        assert!(rec.contains("\"target\":\"env [env MS_SSH_KEY]\""), "{rec}");
        assert_eq!(rec.matches("command_not_allowed").count(), 2, "{rec}");
        // The push with the other key never got as far as a signature (ssh refused the host).
        assert_eq!(rec.matches("ssh-sign").count(), 1, "{rec}");
        // The key is in no file under the test's directories, msd's state, or a run directory
        // left in $TMPDIR (all are removed after the run).
        assert_eq!(tmp_ssh_dirs(), before);
        let mut stack = vec![t.clone()];
        while let Some(p) = stack.pop() {
            let m = std::fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                for e in std::fs::read_dir(&p).unwrap() {
                    stack.push(e.unwrap().path());
                }
            } else if m.is_file() {
                let bytes = std::fs::read(&p).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains(&secret_part), "the key is in {p:?}");
            }
        }
    }

    fn tmp_ssh_dirs() -> Vec<PathBuf> {
        let base = std::env::temp_dir();
        let base = std::fs::canonicalize(&base).unwrap_or(base);
        let mut v: Vec<PathBuf> = std::fs::read_dir(base)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("ms-ssh-"))
            })
            .collect();
        v.sort();
        v
    }

    // protects=SPEC D1/D2: MS_SSH_KEY on a key without pinned host keys, MS_GIT_CREDENTIAL on a
    // key without hosts, and MS_GIT_CREDENTIAL with ssh are refused with a receipt; the variable
    // never reaches the child; fails_when=any of these runs; no_claim=-
    #[test]
    fn needs_pins_and_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let proj = t.join("proj");
        std::fs::create_dir(&proj).unwrap();
        let body = format!(
            "commands = [[\"git\", \"push\"], [\"ssh\", \"h\"]]\nenv = [\"MS_SSH_KEY\", \"MS_GIT_CREDENTIAL\"]\nroots = [\"{}\"]",
            proj.display()
        );
        let d = daemon(&t, &[("gh/bare", "x", Tier::Test, body)]);
        for (argv, var) in [
            (&["git", "push"][..], "MS_SSH_KEY"),
            (&["git", "push"], "MS_GIT_CREDENTIAL"),
            (&["ssh", "h"], "MS_GIT_CREDENTIAL"),
        ] {
            let r = run(&d, &proj, argv, &[(var, "ms://gh/bare")]);
            assert!(
                matches!(
                    &r,
                    ResponseBody::Error {
                        code: ErrorCode::Denied,
                        ..
                    }
                ),
                "{argv:?} {var}: {r:?}"
            );
        }
        let rec = receipts(&t);
        assert_eq!(rec.matches("blocked").count(), 3, "{rec}");
    }
}
