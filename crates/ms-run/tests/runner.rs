//! The runner against real processes: argv never meets a shell, the child's environment is
//! minimal, values are redacted, stdin flows, exit codes pass through, and the process group dies
//! with the run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use ms_core::{AgentKind, KeyMeta, KeyName, Mode, SecretBytes, SessionId, Tier};
use ms_ipc::{OutStream, StdinEvent};
use ms_run::resolve::Resolver;
use ms_run::{ExecIo, Exit, RunErrorKind, RunInput, Runner, RunnerConfig};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;
use tokio::sync::mpsc;

const CANARY: &str = "sk_live_RUNNER_canary/7c+e=21";

fn key(s: &str) -> KeyName {
    KeyName::new(s).unwrap()
}

fn vault() -> MemoryVault {
    let v = MemoryVault::new();
    let k = key("svc/prod");
    v.put(
        &k,
        SecretBytes::from(CANARY.to_owned()),
        KeyMeta {
            name: k.clone(),
            mode: Mode::Run,
            tier: Tier::Test,
            created_unix_ms: 0,
        },
    )
    .unwrap();
    v
}

fn runner(max: Duration) -> Runner {
    Runner::new(RunnerConfig {
        resolver: Resolver::new(vec!["/usr/bin".into(), "/bin".into()], vec![]),
        base_env: vec![("HOME".into(), "/nonexistent-home".into())],
        max_runtime: max,
    })
}

fn session() -> SessionId {
    SessionId {
        agent: AgentKind::ClaudeCode,
        pid: 1,
        started_unix_ms: 1,
    }
}

fn input(argv: &[&str], env: &[(&str, &str)], cwd: &Path) -> RunInput {
    RunInput::new(
        argv.iter().map(|s| s.to_string()).collect(),
        cwd.to_path_buf(),
        env.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
    .unwrap()
}

/// Plans and runs `argv`, feeding `stdin`; returns (exit, stdout, stderr).
async fn run(
    r: &Runner,
    argv: &[&str],
    env: &[(&str, &str)],
    stdin: &[u8],
) -> (Exit, Vec<u8>, Vec<u8>) {
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let inp = input(argv, env, &cwd);
    let call = Runner::call(&inp, cwd, session());
    let keys: BTreeSet<_> = [key("svc/prod")].into();
    let prepared = r.plan(&inp, &call, &keys, &vault()).unwrap();
    let (in_tx, in_rx) = mpsc::channel(4);
    let (out_tx, mut out_rx) = mpsc::channel(64);
    if !stdin.is_empty() {
        in_tx.send(StdinEvent::Data(stdin.to_vec())).await.unwrap();
    }
    in_tx.send(StdinEvent::End).await.unwrap();
    let collect = async move {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        while let Some((s, b)) = out_rx.recv().await {
            if s == OutStream::Stdout {
                o.extend(b);
            } else {
                e.extend(b);
            }
        }
        (o, e)
    };
    let exec = r.execute(
        prepared,
        ExecIo {
            stdin: in_rx,
            output: out_tx,
        },
    );
    let (exit, (o, e)) = tokio::join!(exec, collect);
    (exit.unwrap(), o, e)
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

// protects=OUT-1: shell metacharacters in arguments reach the program as literal single
// arguments; nothing is interpreted by a shell (no command substitution, no chaining, no file
// created); fails_when=any payload is split, expanded or executed; no_claim=programs that are
// themselves shells and are allowlisted with `-c` (the user's rule)
#[tokio::test]
async fn injection_payloads_never_reach_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("pwned");
    let m = marker.display().to_string();
    let payloads = [
        format!("; touch {m}"),
        format!("$(touch {m})"),
        format!("`touch {m}`"),
        format!("&& touch {m}"),
        format!("| touch {m}"),
        format!("x\ntouch {m}"),
        "$HOME ${PATH} *".to_owned(),
        "'\"\\".to_owned(),
    ];
    let mut argv = vec!["printf", "[%s]\\n"];
    argv.extend(payloads.iter().map(String::as_str));
    let (exit, out, _) = run(&runner(Duration::from_secs(20)), &argv, &[], b"").await;
    assert_eq!(exit.code, Some(0));
    let want: String = payloads.iter().map(|p| format!("[{p}]\n")).collect();
    assert_eq!(String::from_utf8(out).unwrap(), want);
    assert!(!marker.exists(), "a payload was executed");
}

// protects=the "agent runs env" test: the child's environment is exactly PATH (trusted path),
// the base set and the forwarded variable; nothing from the caller (this test process's CARGO_*
// and other variables) leaks in; the value appears in env output only redacted, in every
// encoding; fails_when=an extra variable or the value appears; no_claim=msd's own environment
// (the e2e test runs through a real msd)
#[tokio::test]
async fn agent_runs_env() {
    let r = runner(Duration::from_secs(20));
    let (exit, out, _) = run(&r, &["env"], &[("SVC_TOKEN", "Bearer ms://svc/prod")], b"").await;
    assert_eq!(exit.code, Some(0));
    let text = String::from_utf8(out).unwrap();
    let mut names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, _)| k)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["HOME", "PATH", "SVC_TOKEN"], "{text}");
    assert!(
        text.contains("SVC_TOKEN=Bearer [redacted ms://svc/prod]"),
        "{text}"
    );
    assert!(text.contains("PATH=/usr/bin:/bin"), "{text}");
    assert!(!text.contains(CANARY));
    assert!(!text.contains("CARGO"), "caller env leaked: {text}");

    // Encodings of the value in output are redacted too.
    let b64 = base64::engine::general_purpose::STANDARD.encode(CANARY);
    let (_, out, _) = run(
        &r,
        &["base64"],
        &[("T", "ms://svc/prod")],
        CANARY.as_bytes(),
    )
    .await;
    let out_s = String::from_utf8_lossy(&out);
    assert!(!out_s.contains(b64.trim_end_matches('=')), "{out_s}");
    let (_, out, _) = run(
        &r,
        &["xxd", "-p"],
        &[("T", "ms://svc/prod")],
        CANARY.as_bytes(),
    )
    .await;
    assert!(!contains(&out, hex::encode(CANARY).as_bytes()));
}

// protects=stdin is forwarded to the child and a value echoed back through stdin/stderr is
// redacted; fails_when=input is lost or the value appears on either stream; no_claim=-
#[tokio::test]
async fn stdin_and_stderr() {
    let r = runner(Duration::from_secs(20));
    let data = format!("line one\nvalue {CANARY} here\n");
    let (exit, out, _) = run(&r, &["cat"], &[("T", "ms://svc/prod")], data.as_bytes()).await;
    assert_eq!(exit.code, Some(0));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "line one\nvalue [redacted ms://svc/prod] here\n"
    );
    let (_, out, err) = run(
        &r,
        &["sh", "-c", "printf '%s' \"$T\" >&2; echo ok"],
        &[("T", "ms://svc/prod")],
        b"",
    )
    .await;
    assert_eq!(out, b"ok\n");
    assert_eq!(err, b"[redacted ms://svc/prod]");
}

// protects=exit codes and signals pass through unchanged; fails_when=a code is lost or remapped;
// no_claim=-
#[tokio::test]
async fn exit_codes_pass_through() {
    let r = runner(Duration::from_secs(20));
    let (exit, _, _) = run(&r, &["sh", "-c", "exit 7"], &[], b"").await;
    assert_eq!(
        exit,
        Exit {
            code: Some(7),
            signal: None
        }
    );
    let (exit, _, _) = run(&r, &["sh", "-c", "kill -TERM $$"], &[], b"").await;
    assert_eq!(
        exit,
        Exit {
            code: None,
            signal: Some(15)
        }
    );
    assert_eq!(exit.shell_code(), 143);
}

fn alive(pid: i32) -> bool {
    rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid).unwrap()).is_ok()
}

/// Starts `sh -c 'sleep 60 & echo $!; wait'`: the run (not yet polled), its output, and the
/// stdin sender (kept open so stdin never ends).
#[allow(clippy::type_complexity)]
fn start_with_background(
    r: &Runner,
) -> (
    impl std::future::Future<Output = Result<Exit, ms_run::RunError>> + '_,
    mpsc::Receiver<(OutStream, Vec<u8>)>,
    mpsc::Sender<StdinEvent>,
) {
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let inp = input(&["sh", "-c", "sleep 60 & echo $!; wait"], &[], &cwd);
    let call = Runner::call(&inp, cwd, session());
    let prepared = r.plan(&inp, &call, &BTreeSet::new(), &vault()).unwrap();
    let (in_tx, in_rx) = mpsc::channel(1);
    let (out_tx, out_rx) = mpsc::channel(8);
    let fut = r.execute(
        prepared,
        ExecIo {
            stdin: in_rx,
            output: out_tx,
        },
    );
    (fut, out_rx, in_tx)
}

// protects=cancelling a run (the client went away: the future is dropped) kills the child and
// everything it started; fails_when=a background process survives; no_claim=processes that
// leave the group with setsid (same-user; OUT-4 residual until L23)
#[tokio::test]
async fn cancel_kills_the_group() {
    let r = runner(Duration::from_secs(60));
    let (fut, mut out_rx, _stdin) = start_with_background(&r);
    let mut fut = Box::pin(fut);
    let pid = tokio::select! {
        msg = out_rx.recv() => {
            let (_, b) = msg.unwrap();
            String::from_utf8(b).unwrap().trim().parse::<i32>().unwrap()
        }
        _ = &mut fut => panic!("finished early"),
    };
    assert!(alive(pid));
    drop(fut);
    for _ in 0..50 {
        if !alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("background process {pid} survived the cancelled run");
}

// protects=a run past its time limit is killed with its group and reports SIGKILL plus a note;
// fails_when=it runs on or the group survives; no_claim=-
#[tokio::test]
async fn time_limit() {
    let r = runner(Duration::from_millis(500));
    let (fut, mut out_rx, _stdin) = start_with_background(&r);
    let collect = async {
        let mut all = Vec::new();
        while let Some((_, b)) = out_rx.recv().await {
            all.extend(b);
        }
        all
    };
    let (exit, all) = tokio::join!(fut, collect);
    assert_eq!(exit.unwrap().signal, Some(9));
    let text = String::from_utf8(all).unwrap();
    let pid: i32 = text.lines().next().unwrap().trim().parse().unwrap();
    assert!(text.contains("run-mode time limit"), "{text}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!alive(pid));
}

// protects=the generic adapter refuses a ref in an argument (argv is world-readable via ps), a
// relative program, and a program outside the trusted path; fails_when=any plans;
// no_claim=adapters with their own channel (L15, L16)
#[tokio::test]
async fn generic_refusals() {
    let r = runner(Duration::from_secs(5));
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let keys: BTreeSet<_> = [key("svc/prod")].into();
    let try_plan = |argv: &[&str]| {
        let inp = RunInput::new(
            argv.iter().map(|s| s.to_string()).collect(),
            cwd.clone(),
            vec![],
        );
        inp.and_then(|inp| {
            let call = Runner::call(&inp, cwd.clone(), session());
            r.plan(&inp, &call, &keys, &vault()).map(|_| ())
        })
    };
    let e = try_plan(&["curl", "-H", "Authorization: Bearer ms://svc/prod"]).unwrap_err();
    assert_eq!(e.kind, RunErrorKind::Denied);
    assert!(e.message.contains("environment variable"), "{e}");
    assert!(try_plan(&["./x.sh"]).is_err());
    let e = try_plan(&["definitely-not-a-tool-xyz"]).unwrap_err();
    assert_eq!(e.kind, RunErrorKind::Denied);
    // An absolute program is still checked (exists, not writable by others).
    assert!(try_plan(&["/nonexistent/bin/x"]).is_err());
    assert!(try_plan(&["/usr/bin/true"]).is_ok());
}

// protects=a run-mode ref is replaced only for keys policy allowed; a ref to another key stays
// literal (fails closed at the tool); the plan's Debug never shows the value; fails_when=an
// un-allowed key is resolved or the value prints; no_claim=-
#[tokio::test]
async fn only_allowed_keys_resolve() {
    let r = runner(Duration::from_secs(5));
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let inp = input(
        &["env"],
        &[("T", "ms://svc/prod"), ("S", "ms://stripe/test")],
        &cwd,
    );
    let call = Runner::call(&inp, cwd.clone(), session());
    let p = r.plan(&inp, &call, &BTreeSet::new(), &vault()).unwrap();
    assert!(!format!("{p:?}").contains(CANARY));
    let (_, out, _) = run(&r, &["env"], &[("S", "ms://stripe/test")], b"").await;
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("S=ms://stripe/test")
    );
    let p = r
        .plan(&inp, &call, &[key("svc/prod")].into(), &vault())
        .unwrap();
    assert!(!format!("{p:?}").contains(CANARY));
    assert_eq!(p.program(), PathBuf::from("/usr/bin/env"));
}

// protects=R3: a descendant that leaves the process group (setsid) and keeps the output pipes
// open doesn't hold the run past a short grace, and the command's own exit code comes back;
// fails_when=the run waits for the time limit or reports a signal; no_claim=killing that
// descendant (it left the group: OUT-4 residual until L23)
#[tokio::test]
async fn escaped_descendant_does_not_stall() {
    if !std::path::Path::new("/usr/bin/perl").exists() {
        return;
    }
    let r = runner(Duration::from_secs(60));
    let started = std::time::Instant::now();
    let (exit, _, _) = run(
        &r,
        &[
            "perl",
            "-e",
            "use POSIX; if (fork()==0) { POSIX::setsid(); sleep 20; exit 0 } exit 3",
        ],
        &[],
        b"",
    )
    .await;
    assert_eq!(
        exit,
        Exit {
            code: Some(3),
            signal: None
        }
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

// protects=R3 round 2: a slow client (output not read for longer than the exit grace) still gets
// every byte after the command exited; fails_when=output is cut or the note appears;
// no_claim=-
#[tokio::test]
async fn slow_reader_gets_all_output() {
    let r = runner(Duration::from_secs(60));
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let inp = input(
        &["sh", "-c", "head -c 50000 /dev/zero | tr '\\0' x; exit 4"],
        &[],
        &cwd,
    );
    let call = Runner::call(&inp, cwd, session());
    let prepared = r.plan(&inp, &call, &BTreeSet::new(), &vault()).unwrap();
    let (_in_tx, in_rx) = mpsc::channel(1);
    let (out_tx, mut out_rx) = mpsc::channel::<(OutStream, Vec<u8>)>(1);
    let collect = async move {
        tokio::time::sleep(ms_run::runner::EXIT_GRACE + Duration::from_secs(1)).await;
        let (mut o, mut e) = (0usize, Vec::new());
        while let Some((s, b)) = out_rx.recv().await {
            if s == OutStream::Stdout {
                o += b.iter().filter(|c| **c == b'x').count();
            } else {
                e.extend(b);
            }
        }
        (o, e)
    };
    let exec = r.execute(
        prepared,
        ExecIo {
            stdin: in_rx,
            output: out_tx,
        },
    );
    let (exit, (o, e)) = tokio::join!(exec, collect);
    assert_eq!(exit.unwrap().code, Some(4));
    assert_eq!(o, 50_000);
    assert!(!String::from_utf8_lossy(&e).contains("output cut"));
}
