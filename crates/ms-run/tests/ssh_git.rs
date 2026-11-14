//! The git side of the SSH adapter against real git (L16 SPEC D6, review R12): a repository
//! whose config would make the run start a program is refused before git starts, and a remote
//! that would run a command (`ext::`) is stopped by the forced transport policy.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ms_core::{AgentKind, KeyMeta, KeyName, Mode, SecretBytes, SessionId, Tier};
use ms_run::adapters::ssh_git::{
    Audit, AuditEvent, HostPin, SSH_VAR, Session, Setup, SshGitAdapter, SshSetup, Tool,
};
use ms_run::resolve::Resolver;
use ms_run::{RunCall, RunInput, Runner, RunnerConfig};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

const GIT: &str = "/usr/bin/git";
const KEYGEN: &str = "/usr/bin/ssh-keygen";

#[derive(Debug)]
struct NoAudit;

impl Audit for NoAudit {
    fn record(&self, _e: &AuditEvent) -> Result<(), String> {
        Ok(())
    }
    fn stopped(&self) -> bool {
        false
    }
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new(GIT)
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(ok.success(), "{args:?}");
}

/// Runs `git <args>` in `repo` through a session, as msd wires it. `Err` is a refusal before
/// git started; `Ok` is the exit code and output.
fn run_git(repo: &Path, key_text: &str, args: &[&str]) -> Result<(Option<i32>, String), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let k = KeyName::new("gh/deploy").unwrap();
    let v = MemoryVault::new();
    v.put(
        &k,
        SecretBytes::from(key_text.to_owned()),
        KeyMeta {
            name: k.clone(),
            mode: Mode::Run,
            tier: Tier::Test,
            created_unix_ms: 0,
        },
    )
    .unwrap();
    let v: Arc<dyn Vault> = Arc::new(v);
    let resolver = Resolver::new(vec!["/usr/bin".into(), "/bin".into()], vec![]);
    let runner = Runner::new(RunnerConfig {
        resolver: resolver.clone(),
        base_env: vec![("HOME".into(), "/nonexistent-home".into())],
        max_runtime: Duration::from_secs(30),
    });
    let setup = Setup {
        tool: Tool::Git,
        ssh: Some(SshSetup {
            key: k.clone(),
            pins: vec![HostPin {
                host: "127.0.0.1".into(),
                port: 1,
                key: [7; 32],
            }],
            ssh: "/usr/bin/ssh".into(),
        }),
        cwd: repo.to_path_buf(),
        git: Some(GIT.into()),
        base_env: vec![("PATH".into(), resolver.path_var())],
    };
    let mut input = RunInput::new(
        std::iter::once("git")
            .chain(args.iter().copied())
            .map(String::from)
            .collect(),
        repo.to_path_buf(),
        vec![(SSH_VAR.into(), "ms://gh/deploy".into())],
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
    rt.block_on(async {
        let session = Session::start(setup, v.clone(), Arc::new(NoAudit)).map_err(|e| e.message)?;
        let adapter = SshGitAdapter::new(&resolver, &session);
        let mut prepared = runner
            .plan_with(&adapter, &input, &call, &keys, &*v)
            .map_err(|e| e.message)?;
        prepared.hold(Box::new(session));
        let (exit, out, err, _) = runner.execute_buffered(prepared, 64 * 1024).await.unwrap();
        Ok((
            exit.code,
            String::from_utf8_lossy(&out).into_owned() + &String::from_utf8_lossy(&err),
        ))
    })
}

// protects=SPEC D6 / review R12 with real git: a repository whose own config sets a
// program-running key (`remote.origin.receivepack` writing a marker) is refused before git
// starts, naming the key; with only a remote URL (an allowed key) left, an `ext::` remote that
// would run a command is refused by the forced transport policy; fails_when=either marker
// appears or the run starts; no_claim=programs git starts for allowed subcommands from the
// trusted path (ARI42 residual)
#[test]
#[allow(clippy::print_stderr)] // says why it was skipped
fn repository_cant_make_the_run_start_a_program() {
    if !Path::new(GIT).exists() || !Path::new(KEYGEN).exists() {
        eprintln!("SKIPPED: {GIT} or {KEYGEN} is not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let top = std::fs::canonicalize(d.path()).unwrap();
    let ok = Command::new(KEYGEN)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "throwaway", "-f"])
        .arg(top.join("id"))
        .status()
        .unwrap();
    assert!(ok.success());
    let key_text = std::fs::read_to_string(top.join("id")).unwrap();
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
    let marker = top.join("marker");
    let script = top.join("run.sh");
    std::fs::write(&script, format!("touch {}\nexit 1\n", marker.display())).unwrap();

    // A clean repository starts.
    git(
        &repo,
        &["remote", "add", "origin", "ssh://127.0.0.1:1/x.git"],
    );
    assert!(run_git(&repo, &key_text, &["ls-remote", "origin"]).is_ok());

    git(
        &repo,
        &[
            "config",
            "--local",
            "remote.origin.receivepack",
            &format!("sh {}", script.display()),
        ],
    );
    let refused = run_git(&repo, &key_text, &["push", "origin", "main"]).unwrap_err();
    assert!(refused.contains("remote.origin.receivepack"), "{refused}");
    assert!(!marker.exists());
    git(
        &repo,
        &["config", "--local", "--unset", "remote.origin.receivepack"],
    );

    git(
        &repo,
        &[
            "remote",
            "set-url",
            "origin",
            &format!("ext::sh {}", script.display()),
        ],
    );
    let (code, out) = run_git(&repo, &key_text, &["push", "origin", "main"]).unwrap();
    assert_ne!(code, Some(0), "{out}");
    assert!(!marker.exists(), "{out}");
    assert!(out.contains("transport 'ext' not allowed"), "{out}");
}
