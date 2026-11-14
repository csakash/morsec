//! The git credential side (SPEC D7): msd answers `ms-git-credential get` for the run.
//!
//! git runs the helper with its request (`protocol=…`, `host=…`, …); the helper forwards it to
//! the run's credential socket and prints the answer. msd answers only for `https` and a host
//! (no port) the key's rule binds, at most [`MAX_ANSWERS`] times per run, and only while the
//! repository's own git config adds no credential helper, proxy, TLS setting or include (those
//! could hand the token to another program or host). Anything else gets an empty answer.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ms_core::KeyName;
use ms_vault::{Vault, VaultExt};
use zeroize::Zeroizing;

use super::{Action, Audit, AuditEvent};

/// Most credential answers in one run.
pub const MAX_ANSWERS: usize = 4;
/// Largest request or answer, bytes.
pub const MAX_MESSAGE: usize = 8 * 1024;
/// Longest the repository config check may take.
const CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Most config output read.
const MAX_CONFIG_OUTPUT: u64 = 1024 * 1024;
/// Longest username echoed back (so the answer never outgrows its buffer, review R6).
const MAX_USERNAME: usize = 256;
/// The username when the request names none (GitHub's for tokens; most hosts accept any).
pub const DEFAULT_USERNAME: &str = "x-access-token";

/// Decides whether an HTTPS host (no port) is bound to the key.
pub type HostCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What every credential request of one run shares.
pub(crate) struct CredCtx {
    pub(crate) key: KeyName,
    pub(crate) host_allowed: HostCheck,
    pub(crate) vault: Arc<dyn Vault>,
    pub(crate) audit: Arc<dyn Audit>,
    /// The git used for the config check, its working directory and environment.
    pub(crate) git: PathBuf,
    pub(crate) cwd: PathBuf,
    pub(crate) env: Vec<(OsString, OsString)>,
    /// The config as checked before the child started ([`read_config`]).
    pub(crate) snapshot: Vec<u8>,
    pub(crate) answers: AtomicUsize,
}

impl std::fmt::Debug for CredCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredCtx")
            .field("key", &self.key)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// Answers one request. The answer (possibly empty) holds the value, so it is wiped on drop.
pub(crate) fn answer(ctx: &CredCtx, request: &[u8]) -> Zeroizing<Vec<u8>> {
    let empty = Zeroizing::new(Vec::new());
    let req = parse(request);
    let host = req
        .get("host")
        .map(|h| h.chars().take(255).flat_map(char::escape_default).collect())
        .unwrap_or_else(|| "no host".to_owned());
    let protocol = req.get("protocol").cloned().unwrap_or_default();
    let n = ctx.answers.fetch_add(1, Ordering::SeqCst) + 1;
    if n > MAX_ANSWERS + 1 {
        return empty;
    }
    let refuse = |why: &str| {
        let event = AuditEvent {
            key: ctx.key.clone(),
            action: Action::Credential {
                host: format!("{protocol}://{host}"),
            },
            refused: Some(why.to_owned()),
        };
        if let Err(e) = ctx.audit.record(&event) {
            tracing::error!(error = %e, "could not record a refused git credential");
        }
        Zeroizing::new(Vec::new())
    };
    if n > MAX_ANSWERS {
        return refuse("more than 4 credential requests in one run");
    }
    if ctx.audit.stopped() {
        return refuse("morsec is stopped (ms stop) or this agent session was stopped");
    }
    if protocol != "https" {
        return refuse("morsec gives git credentials only over https");
    }
    let Some(h) = req.get("host") else {
        return refuse("the request names no host");
    };
    if h.contains(':') || !(ctx.host_allowed)(h) {
        return refuse(
            "the host is not bound to the key (ms rules <key> --add-host HOST); ports other than 443 are never bound",
        );
    }
    if let Some(problem) = config_problem(ctx) {
        return refuse(&problem);
    }
    let user = req
        .get("username")
        .filter(|u| !u.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_USERNAME.to_owned());
    if user.len() > MAX_USERNAME || user.contains(['\r', '\0']) {
        return refuse("the username in the request is too long or holds control characters");
    }
    let event = AuditEvent {
        key: ctx.key.clone(),
        action: Action::Credential {
            host: format!("https://{host}"),
        },
        refused: None,
    };
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_MESSAGE));
    let read = ctx.vault.read_with(&ctx.key, |v| {
        if v.is_empty()
            || v.len() > MAX_MESSAGE / 2
            || v.iter().any(|b| *b == b'\n' || *b == 0 || *b == b'\r')
        {
            return false;
        }
        out.extend_from_slice(b"username=");
        out.extend_from_slice(user.as_bytes());
        out.extend_from_slice(b"\npassword=");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\n");
        true
    });
    match read {
        Ok(true) => {}
        Ok(false) => {
            return refuse(
                "the key's value can't be a git password (empty, too long, or holds a line break)",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "could not read the git credential");
            return refuse("the key could not be read from the vault");
        }
    }
    // Recorded before it leaves msd; no receipt, no credential.
    if let Err(e) = ctx.audit.record(&event) {
        tracing::error!(error = %e, "could not record a git credential, so it was refused");
        return empty;
    }
    out
}

/// git's `key=value` lines. Later values win, like git; unknown keys are ignored.
fn parse(request: &[u8]) -> std::collections::BTreeMap<String, String> {
    let text = String::from_utf8_lossy(&request[..request.len().min(MAX_MESSAGE)]);
    text.lines()
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Config keys a repository's own files (`local`, `worktree`) may set while a credential is
/// handed out. Everything else refuses it (review R1): the repository's config is writable by the
/// agent, and git keys that run programs (`remote.*.receivepack`, `alias.*`, `protocol.*`,
/// `remote.*.vcs`, filters, `core.*` commands), send traffic elsewhere (`http.*`, proxies,
/// `url.*`), add helpers (`credential.*`) or pull in other files (`include*`, `submodule.*`) are
/// too many to list one by one, so this is an allowlist of plain bookkeeping keys.
pub(crate) fn allowed_repo_key(scope: &str, name: &str) -> bool {
    if scope != "local" && scope != "worktree" {
        return true;
    }
    let n = name.to_ascii_lowercase();
    const PLAIN: &[&str] = &[
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.symlinks",
        "core.autocrlf",
        "core.eol",
        "user.name",
        "user.email",
        "pull.rebase",
        "pull.ff",
        "push.default",
        "push.autosetupremote",
        "fetch.prune",
        "init.defaultbranch",
        "extensions.objectformat",
        "extensions.worktreeconfig",
    ];
    if PLAIN.contains(&n.as_str()) {
        return true;
    }
    // remote.<name>.<key> and branch.<name>.<key>: the name may hold dots, the key is last.
    let last = n.rsplit('.').next().unwrap_or("");
    (n.starts_with("remote.")
        && ["url", "pushurl", "fetch", "tagopt", "prune", "mirror"].contains(&last))
        || (n.starts_with("branch.") && ["remote", "merge", "rebase", "pushremote"].contains(&last))
}

/// The repository's effective git config, as `git config --list --show-scope --includes -z`
/// prints it, run in `cwd` with the run's git environment (no system or global config). A
/// failure or a timeout (an include pointing at a FIFO) is an error: callers fail closed.
pub(crate) fn read_config(
    git: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
) -> Result<Vec<u8>, String> {
    const CANT: &str = "the repository's git config could not be checked";
    let mut child = Command::new(git)
        .args(["config", "--list", "--show-scope", "--includes", "-z"])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CANT.to_owned())?;
    // Read on a thread so a hung git can't block msd.
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut raw = Vec::new();
        if let Some(out) = stdout {
            let _ = out.take(MAX_CONFIG_OUTPUT).read_to_end(&mut raw);
        }
        raw
    });
    let deadline = Instant::now() + CONFIG_CHECK_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let raw = reader.join().unwrap_or_default();
    if status.is_some_and(|s| s.success()) {
        Ok(raw)
    } else {
        Err(CANT.to_owned())
    }
}

/// Why `raw` (from [`read_config`]) is unsafe for a run with a morsec key, if it is: any key in
/// the repository's own files outside [`allowed_repo_key`].
pub(crate) fn config_violation(raw: &[u8]) -> Option<String> {
    let mut fields = raw.split(|b| *b == 0);
    let mut bad = Vec::new();
    while let (Some(scope), Some(entry)) = (fields.next(), fields.next()) {
        let scope = String::from_utf8_lossy(scope);
        let name_bytes = entry.split(|b| *b == b'\n').next().unwrap_or_default();
        let name = String::from_utf8_lossy(name_bytes);
        if !allowed_repo_key(&scope, &name) && bad.len() < 3 {
            bad.push(
                name.chars()
                    .take(80)
                    .flat_map(char::escape_default)
                    .collect::<String>(),
            );
        }
    }
    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "the repository's git config sets {} (with a morsec key a repository may set only plain keys such as remote.<name>.url and branch.<name>.merge: others can run programs or send a credential elsewhere); remove them from .git/config",
            bad.join(", ")
        ))
    }
}

/// The check at credential time: the config must be the one checked before git started
/// (review R1: a program could change it in between), and still allowed.
fn config_problem(ctx: &CredCtx) -> Option<String> {
    let raw = match read_config(&ctx.git, &ctx.cwd, &ctx.env) {
        Ok(r) => r,
        Err(e) => return Some(e),
    };
    if raw != ctx.snapshot {
        return Some(
            "the repository's git config changed while the command ran, so morsec gives no credential".into(),
        );
    }
    config_violation(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::ssh_git::tests_support::{FakeAudit, vault_with};

    fn env() -> Vec<(OsString, OsString)> {
        vec![
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ]
    }

    fn ctx(cwd: PathBuf) -> (CredCtx, Arc<FakeAudit>) {
        let snapshot = read_config(Path::new("/usr/bin/git"), &cwd, &env()).unwrap();
        let audit = Arc::new(FakeAudit::default());
        let (vault, key) = vault_with("ghp_CREDCANARY_1234");
        (
            CredCtx {
                key,
                host_allowed: Arc::new(|h| h == "git.example.com"),
                vault,
                audit: audit.clone(),
                git: PathBuf::from("/usr/bin/git"),
                cwd,
                snapshot,
                env: env(),
                answers: AtomicUsize::new(0),
            },
            audit,
        )
    }

    fn ask(c: &CredCtx, req: &str) -> String {
        String::from_utf8(answer(c, req.as_bytes()).to_vec()).unwrap()
    }

    // protects=SPEC D7 / Verify 4: the token is given only for https and a bound host without a
    // port, never for http, another host, a port, a lookalike, or a repository config that adds
    // a helper, a proxy, TLS settings or an include; at most 4 answers per run; each request is
    // recorded; fails_when=the value leaves in any of those cases; no_claim=git's own use of the
    // helper (tests/ssh_git.rs)
    #[test]
    #[allow(clippy::print_stderr)] // says why it was skipped
    fn answers_only_bound_https_hosts() {
        if !std::path::Path::new("/usr/bin/git").exists() {
            eprintln!("skipped: /usr/bin/git is not installed");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        let ok = Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(&repo)
            .status()
            .unwrap();
        assert!(ok.success());
        let (c, audit) = ctx(repo.clone());
        let good = "protocol=https\nhost=git.example.com\n\n";
        assert_eq!(
            ask(&c, good),
            "username=x-access-token\npassword=ghp_CREDCANARY_1234\n"
        );
        assert_eq!(
            ask(&c, "protocol=https\nhost=git.example.com\nusername=me\n"),
            "username=me\npassword=ghp_CREDCANARY_1234\n"
        );
        assert_eq!(audit.events().len(), 2);
        // Each refusal is recorded (a fresh run each, as the cap counts refusals too).
        for bad in [
            "protocol=http\nhost=git.example.com\n",
            "protocol=https\nhost=evil.example.com\n",
            "protocol=https\nhost=git.example.com:8443\n",
            "protocol=https\nhost=git.example.com.evil.com\n",
            "protocol=https\n",
        ] {
            let (c, audit) = ctx(repo.clone());
            assert_eq!(ask(&c, bad), "", "{bad}");
            let e = audit.events();
            assert!(e.len() == 1 && e[0].refused.is_some(), "{e:?}");
        }

        // A repository that adds a proxy, a helper, an include or an alias: refused, whether
        // the key was there before the run started or added while it ran (review R1).
        let git = |a: &[&str]| {
            let ok = Command::new("/usr/bin/git")
                .args(a)
                .current_dir(&repo)
                .status()
                .unwrap();
            assert!(ok.success(), "{a:?}");
        };
        for (k, v) in [
            ("http.https://git.example.com/.proxy", "http://127.0.0.1:9"),
            ("credential.helper", "!cat"),
            ("include.path", "/tmp/x"),
            ("remote.origin.proxy", "http://127.0.0.1:9"),
            ("alias.x", "!sh -c true"),
        ] {
            git(&["config", "--local", k, v]);
            let (c, audit) = ctx(repo.clone());
            assert_eq!(ask(&c, good), "", "{k}");
            let why = audit.events()[0].refused.clone().unwrap();
            assert!(why.contains("sets"), "{why}");
            git(&["config", "--local", "--unset-all", k]);
        }
        // Even a plain key changed after the run started refuses: the config is not the one
        // that was checked.
        let (c, audit) = ctx(repo.clone());
        git(&["config", "--local", "user.name", "x"]);
        assert_eq!(ask(&c, good), "");
        assert!(
            audit.events()[0]
                .refused
                .as_deref()
                .unwrap()
                .contains("changed")
        );
        git(&["config", "--local", "--unset", "user.name"]);

        // The cap: 4 answers, then one receipt for the limit, then silence.
        let (c, audit) = ctx(repo);
        let answered = (0..8).filter(|_| !ask(&c, good).is_empty()).count();
        assert_eq!(answered, MAX_ANSWERS);
        assert_eq!(audit.events().len(), MAX_ANSWERS + 1);
    }

    // protects=review R1: with a credential, the repository's own config may hold only plain
    // bookkeeping keys; keys that run programs (receivepack, uploadpack, vcs, alias, protocol,
    // filters), route traffic (http, proxy, url) or add helpers and files are refused; morsec's
    // own command-line keys and the default config git init writes pass; fails_when=one of
    // those passes or a plain repository is refused; no_claim=-
    #[test]
    fn repo_config_allowlist() {
        for ok in [
            "core.repositoryformatversion",
            "core.bare",
            "remote.origin.url",
            "remote.my.fork.fetch",
            "branch.main.merge",
            "user.email",
        ] {
            assert!(allowed_repo_key("local", ok), "{ok}");
        }
        for bad in [
            "http.sslVerify",
            "Credential.https://x.helper",
            "includeIf.gitdir:/x.path",
            "remote.origin.proxy",
            "remote.origin.receivepack",
            "remote.origin.uploadpack",
            "remote.origin.vcs",
            "protocol.ext.allow",
            "alias.c",
            "url.https://x.insteadof",
            "submodule.a.url",
            "filter.lfs.clean",
            "core.sshcommand",
            "core.askpass",
        ] {
            assert!(!allowed_repo_key("worktree", bad), "{bad}");
        }
        assert!(allowed_repo_key("command", "credential.helper"));
    }
}
