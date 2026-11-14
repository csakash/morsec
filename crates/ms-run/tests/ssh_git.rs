//! The git credential helper end to end (L16 SPEC Verify 4): real git, the real
//! `ms-git-credential` binary and a run session, as msd wires them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_core::{AgentKind, KeyMeta, KeyName, Mode, SecretBytes, SessionId, Tier};
use ms_run::adapters::ssh_git::{
    Audit, AuditEvent, CRED_VAR, CredSetup, Session, Setup, SshGitAdapter, Tool,
};
use ms_run::resolve::Resolver;
use ms_run::{RunCall, RunInput, Runner, RunnerConfig};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

const TOKEN: &str = "ghp_HELPERCANARY_5f2a9c";
const GIT: &str = "/usr/bin/git";

#[derive(Debug, Default)]
struct Log(Mutex<Vec<AuditEvent>>);

impl Audit for Log {
    fn record(&self, e: &AuditEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(e.clone());
        Ok(())
    }
    fn stopped(&self) -> bool {
        false
    }
}

fn vault(k: &KeyName) -> Arc<dyn Vault> {
    let v = MemoryVault::new();
    v.put(
        k,
        SecretBytes::from(TOKEN.to_owned()),
        KeyMeta {
            name: k.clone(),
            mode: Mode::Run,
            tier: Tier::Test,
            created_unix_ms: 0,
        },
    )
    .unwrap();
    Arc::new(v)
}

/// Runs `git credential fill` in `repo` with `request` on stdin, through a session; returns the
/// exit code, the (redacted) stdout and the audit log.
fn fill(repo: &Path, request: &str) -> (Option<i32>, String, Vec<AuditEvent>) {
    run_git(repo, &["credential", "fill"], request)
}

/// Runs `git <args>` in `repo` through a session with the credential helper, as msd would.
fn run_git(repo: &Path, args: &[&str], request: &str) -> (Option<i32>, String, Vec<AuditEvent>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let k = KeyName::new("gh/token").unwrap();
    let v = vault(&k);
    let log = Arc::new(Log::default());
    let resolver = Resolver::new(vec!["/usr/bin".into(), "/bin".into()], vec![]);
    let runner = Runner::new(RunnerConfig {
        resolver: resolver.clone(),
        base_env: vec![("HOME".into(), "/nonexistent-home".into())],
        max_runtime: Duration::from_secs(30),
    });
    let setup = Setup {
        tool: Tool::Git,
        ssh: None,
        cred: Some(CredSetup {
            key: k.clone(),
            host_allowed: Arc::new(|h| h == "git.example.com"),
            hosts_shown: vec!["git.example.com".into()],
            helper: PathBuf::from(env!("CARGO_BIN_EXE_ms-git-credential")),
        }),
        cwd: repo.to_path_buf(),
        git: Some(GIT.into()),
        base_env: vec![("PATH".into(), resolver.path_var())],
    };
    // As msd does: the variable is taken out of the call, the key stays for redaction.
    let mut input = RunInput::new(
        std::iter::once("git")
            .chain(args.iter().copied())
            .map(String::from)
            .collect(),
        repo.to_path_buf(),
        vec![(CRED_VAR.into(), "ms://gh/token".into())],
    )
    .unwrap();
    input.env.clear();
    let call = RunCall {
        argv: input.argv.iter().map(Into::into).collect(),
        cwd: repo.to_path_buf(),
        session: SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 1,
            started_unix_ms: 1,
        },
    };
    let keys = BTreeSet::from([k]);
    let (code, out) = rt.block_on(async {
        let session = match Session::start(setup, v.clone(), log.clone()) {
            Ok(s) => s,
            // Refused before git starts: no exit code, the message as output.
            Err(e) => return (None, e.message),
        };
        let adapter = SshGitAdapter::new(&resolver, &session);
        let mut prepared = runner
            .plan_with(&adapter, &input, &call, &keys, &*v)
            .unwrap();
        prepared.hold(Box::new(session));
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
        in_tx
            .send(ms_ipc::StdinEvent::Data(request.as_bytes().to_vec()))
            .await
            .unwrap();
        drop(in_tx);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(16);
        let run = runner.execute(
            prepared,
            ms_run::ExecIo {
                stdin: in_rx,
                output: out_tx,
            },
        );
        let collect = async {
            // stdout, then stderr after a marker line.
            let (mut o, mut e) = (Vec::new(), Vec::new());
            while let Some((s, b)) = out_rx.recv().await {
                if s == ms_ipc::OutStream::Stdout {
                    o.extend(b);
                } else {
                    e.extend(b);
                }
            }
            o.extend_from_slice(b"\n--- stderr\n");
            o.extend(e);
            o
        };
        let (exit, o) = tokio::join!(run, collect);
        (exit.unwrap().code, String::from_utf8(o).unwrap())
    });
    let events = log.0.lock().unwrap().clone();
    (code, out, events)
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new(GIT)
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(ok.success(), "{args:?}");
}

// protects=SPEC D7 / Verify 4 with real git and the real helper: git gets the token for the
// bound HTTPS host (the output shows only the redaction label), and nothing for another host or
// http; a credential helper the repository adds itself never runs (morsec resets the list), and
// a repository proxy refuses the credential; every request is recorded; fails_when=the token
// reaches git for an unbound host, appears in output, or a repository helper sees it;
// no_claim=git push over HTTPS to a real server (not verified, see PROOF.md)
#[test]
#[allow(clippy::print_stderr)] // says why it was skipped
fn helper_gives_the_token_only_to_bound_hosts() {
    if !Path::new(GIT).exists() {
        eprintln!("SKIPPED: {GIT} is not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let repo = std::fs::canonicalize(d.path()).unwrap().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);

    let (code, out, events) = fill(&repo, "protocol=https\nhost=git.example.com\n\n");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("username=x-access-token"), "{out}");
    assert!(out.contains("password=[redacted ms://gh/token]"), "{out}");
    assert!(!out.contains(TOKEN));
    assert_eq!(events.len(), 1);
    assert!(events[0].refused.is_none());

    for req in [
        "protocol=https\nhost=evil.example.com\n\n",
        "protocol=http\nhost=git.example.com\n\n",
        "protocol=https\nhost=git.example.com:8443\n\n",
    ] {
        let (code, out, events) = fill(&repo, req);
        assert_ne!(code, Some(0), "{req}: {out}");
        assert!(!out.contains("password"), "{req}: {out}");
        assert!(events.iter().all(|e| e.refused.is_some()), "{events:?}");
        assert!(!events.is_empty());
    }

    // A helper the repository adds would get the token on `store`; it never runs.
    let marker = d.path().join("helper-ran");
    git(
        &repo,
        &[
            "config",
            "--local",
            "credential.helper",
            &format!("!touch {}; true", marker.display()),
        ],
    );
    let (code, out, events) = fill(&repo, "protocol=https\nhost=git.example.com\n\n");
    assert!(!marker.exists());
    // The repository helper refuses the run before git starts (review R1).
    assert_eq!(code, None, "{out}");
    assert!(out.contains("credential.helper"), "{out}");
    assert!(events.is_empty());
    git(
        &repo,
        &["config", "--local", "--unset-all", "credential.helper"],
    );

    git(
        &repo,
        &["config", "--local", "http.proxy", "http://127.0.0.1:9"],
    );
    let (code, out, _) = fill(&repo, "protocol=https\nhost=git.example.com\n\n");
    assert_ne!(code, Some(0), "{out}");
    assert!(!out.contains("password"));
}

// protects=review R1: a repository can't make the run's git start a program that asks the
// helper for the token: a local remote with `remote.origin.receivepack` (a shell that calls the
// helper and saves its answer) is refused by the forced protocol policy, an `ext::` remote too,
// and a credential request while such keys are in the repository's config is refused;
// fails_when=the marker or the token file appears; no_claim=programs in the trusted path the
// agent could replace (resolver checks)
#[test]
fn repository_config_cant_start_a_token_reader() {
    if !Path::new(GIT).exists() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let top = std::fs::canonicalize(d.path()).unwrap();
    let repo = top.join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("f"), "x").unwrap();
    git(&repo, &["add", "f"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@x.invalid",
            "commit",
            "-qm",
            "x",
        ],
    );
    let leak = top.join("leak");
    let helper = env!("CARGO_BIN_EXE_ms-git-credential");
    let reader = format!(
        "sh -c 'printf \"protocol=https\\nhost=git.example.com\\n\\n\" | {helper} get > {}; exit 1'",
        leak.display()
    );
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            &top.join("bare.git").display().to_string(),
        ],
    );
    git(
        &repo,
        &["config", "--local", "remote.origin.receivepack", &reader],
    );
    git(
        &repo,
        &["config", "--local", "protocol.file.allow", "always"],
    );
    let (code, out, _) = run_git(&repo, &["push", "origin", "main"], "");
    assert_eq!(code, None, "{out}");
    assert!(out.contains("remote.origin.receivepack"), "{out}");
    assert!(!leak.exists());
    // The config check alone would catch the keys above; with only a remote URL (an allowed
    // key) left, the forced protocol policy is what stops an `ext::` remote.
    git(
        &repo,
        &["config", "--local", "--unset", "remote.origin.receivepack"],
    );
    git(
        &repo,
        &["config", "--local", "--unset", "protocol.file.allow"],
    );
    let script = top.join("reader.sh");
    std::fs::write(
        &script,
        format!(
            "printf 'protocol=https\\nhost=git.example.com\\n\\n' | {helper} get > {}\nexit 1\n",
            leak.display()
        ),
    )
    .unwrap();
    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            &format!("ext::sh {}", script.display()),
        ],
    );
    let (code, out, _) = run_git(&repo, &["push", "origin", "main"], "");
    assert_ne!(code, Some(0), "{out}");
    assert!(
        !leak.exists() || std::fs::read_to_string(&leak).unwrap().is_empty(),
        "{out}"
    );
    assert!(!out.contains(TOKEN));
}
