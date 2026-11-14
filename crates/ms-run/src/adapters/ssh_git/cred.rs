//! The git credential side (SPEC D7): msd answers `ms-git-credential get` for the run.
//!
//! git runs the helper with its request (`protocol=…`, `host=…`, …); the helper forwards it to
//! the run's credential socket and prints the answer. msd answers only for `https` and a host
//! (no port) the key's rule binds, at most [`MAX_ANSWERS`] times per run, and only while the
//! repository's own git config adds no credential helper, proxy, TLS setting or include (those
//! could hand the token to another program or host). Anything else gets an empty answer.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::PathBuf;
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

/// Config keys in the repository's own files (`local`, `worktree`) that could send the token to
/// another program or host. The forced settings the run passes win over the plain ones, but not
/// over URL-scoped (`http.<url>.*`, `credential.<url>.*`) or multi-valued ones, so any of these
/// refuses the credential.
pub(crate) fn risky_key(scope: &str, name: &str) -> bool {
    if scope != "local" && scope != "worktree" {
        return false;
    }
    let n = name.to_ascii_lowercase();
    n.starts_with("http.")
        || n.starts_with("credential.")
        || n.starts_with("include.")
        || n.starts_with("includeif.")
        || (n.starts_with("remote.") && (n.ends_with(".proxy") || n.ends_with(".proxyauthmethod")))
}

/// Why the repository's config makes the credential unsafe to hand out, if it does. Runs
/// `git config --list --show-scope --name-only --includes` in the run's directory with the run's
/// git environment (no system or global config); a failure or timeout refuses (fail closed).
fn config_problem(ctx: &CredCtx) -> Option<String> {
    let child = Command::new(&ctx.git)
        .args([
            "config",
            "--list",
            "--show-scope",
            "--name-only",
            "--includes",
        ])
        .env_clear()
        .envs(ctx.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&ctx.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return Some("the repository's git config could not be checked".into()),
    };
    // Read on a thread so a hung git (an include pointing at a FIFO) can't block msd.
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(out) = stdout {
            let _ = out.take(MAX_CONFIG_OUTPUT).read_to_string(&mut text);
        }
        text
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
    let text = reader.join().unwrap_or_default();
    if !status.is_some_and(|s| s.success()) {
        return Some("the repository's git config could not be checked".into());
    }
    let bad: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .filter(|(scope, name)| risky_key(scope, name))
        .map(|(_, name)| name)
        .take(3)
        .collect();
    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "the repository's git config sets {} (credential helpers, proxies, TLS settings and includes could send the token elsewhere); remove them from .git/config",
            bad.iter()
                .map(|n| n
                    .chars()
                    .take(80)
                    .flat_map(char::escape_default)
                    .collect::<String>())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::ssh_git::tests_support::{FakeAudit, vault_with};

    fn ctx(cwd: PathBuf) -> (CredCtx, Arc<FakeAudit>) {
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
                env: vec![
                    ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                    ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
                ],
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

        // A repository that adds a proxy or a credential helper: refused.
        for (k, v) in [
            ("http.https://git.example.com/.proxy", "http://127.0.0.1:9"),
            ("credential.helper", "!cat"),
            ("include.path", "/tmp/x"),
            ("remote.origin.proxy", "http://127.0.0.1:9"),
        ] {
            let (c, _) = ctx(repo.clone());
            let set = Command::new("/usr/bin/git")
                .args(["config", "--local", k, v])
                .current_dir(&repo)
                .status()
                .unwrap();
            assert!(set.success());
            let a = ask(&c, good);
            assert_eq!(a, "", "{k}");
            let unset = Command::new("/usr/bin/git")
                .args(["config", "--local", "--unset-all", k])
                .current_dir(&repo)
                .status()
                .unwrap();
            assert!(unset.success());
        }

        // The cap: 4 answers, then one receipt for the limit, then silence.
        let (c, audit) = ctx(repo);
        let answered = (0..8).filter(|_| !ask(&c, good).is_empty()).count();
        assert_eq!(answered, MAX_ANSWERS);
        assert_eq!(audit.events().len(), MAX_ANSWERS + 1);
    }

    // protects=only the repository's own files are checked, by scope; fails_when=a risky local
    // key passes or a command-line (morsec's own) key is refused; no_claim=-
    #[test]
    fn risky_keys() {
        assert!(risky_key("local", "http.sslVerify"));
        assert!(risky_key("worktree", "Credential.https://x.helper"));
        assert!(risky_key("local", "includeIf.gitdir:/x.path"));
        assert!(risky_key("local", "remote.origin.proxy"));
        assert!(!risky_key("local", "remote.origin.url"));
        assert!(!risky_key("command", "credential.helper"));
        assert!(!risky_key("local", "core.hookspath"));
    }
}
