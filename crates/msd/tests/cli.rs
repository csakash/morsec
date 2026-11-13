//! End-to-end tests of the two binaries. They live in the msd package because only here is
//! `CARGO_BIN_EXE_msd` available; `ms` is its sibling in the same target directory.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn msd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_msd"))
}

/// `cargo test` does not relink other packages' binaries, so `ms` must come from a prior
/// `cargo build --workspace` (scripts/check.sh does this first). A stale `ms` fails these tests
/// rather than passing them.
fn ms() -> PathBuf {
    let p = msd().with_file_name("ms");
    assert!(
        p.exists(),
        "{} not built; run cargo build --workspace first (scripts/check.sh does)",
        p.display()
    );
    p
}

/// `ms` reached through a symlink called `mors`, like the installed alias.
fn mors(dir: &Path) -> PathBuf {
    let link = dir.join("mors");
    std::os::unix::fs::symlink(ms(), &link).unwrap();
    link
}

fn tmpdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mscli")
        .tempdir_in("/tmp")
        .unwrap()
}

/// Stops msd with SIGTERM so it removes its own socket; SIGKILL only if it doesn't exit in 5s.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until the daemon accepts connections; a socket file alone may be stale.
fn wait_ready(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "msd is not accepting on {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts an ephemeral msd (memory vault) with its socket at `socket`, its state next to it, and
/// the proxy on `proxy_port`.
fn start_msd_on(socket: &Path, proxy_port: u16) -> Daemon {
    let state = socket.parent().unwrap().join("state");
    let child = Command::new(msd())
        .args(["--foreground", "--vault", "memory", "--socket"])
        .arg(socket)
        .arg("--state-dir")
        .arg(&state)
        .args(["--proxy-port", &proxy_port.to_string()])
        .env("MORSEC_LOG", "warn")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon(child);
    wait_ready(socket);
    d
}

fn start_msd(socket: &Path) -> Daemon {
    start_msd_on(socket, free_port())
}

fn run(bin: &Path, args: &[&str], socket: &Path) -> (i32, String, String) {
    let out = Command::new(bin)
        .args(args)
        .env("MORSEC_SOCKET", socket)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

// protects=`ms --version` and `mors --version` print the same "morsec <ver> (<sha>)" line;
// fails_when=either name misbehaves or the format changes; no_claim=the installed symlink (L10)
#[test]
fn version_under_both_names() {
    let d = tmpdir();
    let sock = d.path().join("none.sock");
    let (code, out, _) = run(&ms(), &["--version"], &sock);
    assert_eq!(code, 0);
    let re_ok = out.starts_with("morsec 0.0.0 (") && out.trim_end().ends_with(')');
    assert!(re_ok, "{out:?}");
    let (code2, out2, _) = run(&mors(d.path()), &["-V"], &sock);
    assert_eq!((code2, out2), (0, out));
}

// protects=every PRD command not built yet exits 69 and names its loop, under the invoked name;
// fails_when=a stub exits 0, prints to stdout, or names the wrong binary/loop; no_claim=behaviour
// once the owning loop lands
#[test]
fn stubs_exit_69_and_name_their_loop() {
    let d = tmpdir();
    let sock = d.path().join("none.sock");
    let table = [
        ("run", "L12 run-core"),
        ("doctor", "L17 doctor"),
        ("mcp", "L14 mcp-server"),
        ("scan", "L09 e2e-canary"),
    ];
    let alias = mors(d.path());
    for (cmd, loop_id) in table {
        for (bin, name) in [(ms(), "ms"), (alias.clone(), "mors")] {
            let (code, out, err) = run(&bin, &[cmd, "--some-flag", ".env"], &sock);
            assert_eq!(code, 69, "{name} {cmd}: {err}");
            assert!(out.is_empty(), "{name} {cmd} printed to stdout: {out}");
            let want =
                format!("morsec: '{name} {cmd}' is not built yet (planned in loop {loop_id}).\n");
            assert_eq!(err, want);
        }
    }
}

// protects=`ms status` reports the running daemon over IPC (on, protected-key count) and exits 0;
// with no daemon it fails closed with the ms start hint and exits 1; fails_when=status claims "on"
// without a daemon or fails with one running; no_claim=launchd or the production socket path
#[test]
fn status_with_and_without_daemon() {
    let d = tmpdir();
    let sock = d.path().join("run/msd.sock");

    let (code, out, err) = run(&ms(), &["status"], &sock);
    assert_eq!(code, 1, "{out}{err}");
    assert!(out.is_empty());
    assert!(
        err.contains("daemon not running") && err.contains("ms start"),
        "{err}"
    );

    let daemon = start_msd(&sock);
    let (code, out, err) = run(&ms(), &["status"], &sock);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "morsec on · 0 secrets protected\n");
    let (code, out, _) = run(&mors(d.path()), &["status"], &sock);
    assert_eq!(
        (code, out.as_str()),
        (0, "morsec on · 0 secrets protected\n")
    );
    drop(daemon);
}

// protects=--port picks the per-port dev socket even when MORSEC_SOCKET is exported, so parallel
// loops never share one socket; fails_when=msd binds $MORSEC_SOCKET instead; no_claim=the
// --socket flag (it always wins, by construction)
#[test]
fn port_beats_exported_socket() {
    let d = tmpdir();
    let exported = d.path().join("exported.sock");
    // A port unlikely to be used by another test run at the same time.
    let port = 40000 + (std::process::id() % 20000) as u16;
    let dev_dir = std::env::temp_dir().join(format!("morsec-dev-{port}"));
    let expected = dev_dir.join("msd.sock");
    // A socket left by an earlier killed run would make the wait below pass too early.
    let _ = std::fs::remove_dir_all(&dev_dir);
    let child = Command::new(msd())
        .args([
            "--foreground",
            "--vault",
            "memory",
            "--port",
            &port.to_string(),
        ])
        .env("MORSEC_SOCKET", &exported)
        .env("MORSEC_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let daemon = Daemon(child);
    wait_ready(&expected);
    assert!(!exported.exists(), "msd bound the exported socket");
    let (code, out, err) = run(&ms(), &["status"], &expected);
    assert_eq!(
        (code, out.as_str()),
        (0, "morsec on · 0 secrets protected\n"),
        "{err}"
    );
    // SIGTERM: msd removes its socket on a clean shutdown.
    drop(daemon);
    assert!(!expected.exists(), "socket left after SIGTERM");
    let _ = std::fs::remove_dir_all(&dev_dir);
}

// protects=msd refuses to start without --foreground (launchd runs it in the foreground; there
// is no self-daemonizing mode); fails_when=it starts or exits 0; no_claim=service management
#[test]
fn msd_requires_foreground() {
    let st = Command::new(msd()).stderr(Stdio::null()).status().unwrap();
    assert_eq!(st.code(), Some(64));
}

const CANARY: &str = "sk_test_MSDCLI_CANARY_7c2f41";

fn run_stdin(
    bin: &Path,
    args: &[&str],
    socket: &Path,
    cwd: &Path,
    stdin: &[u8],
) -> (i32, String, String) {
    use std::io::Write;
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("MORSEC_SOCKET", socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn receipts_text(socket: &Path) -> String {
    let dir = socket.parent().unwrap().join("state/receipts");
    let mut s = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
    }
    s
}

// protects=L04's gap is closed: `ms add` and `ms import` store end to end through a running msd
// (Ok/Keys replies), `ms rules` then shows the keys as verified by msd, `ms status` counts them,
// and no value reaches stdout, stderr, the rewritten .env or the receipts; fails_when=either
// command fails against a real daemon or a value leaks; no_claim=the keychain backend (manual QA)
#[test]
fn add_and_import_store_through_msd() {
    let d = tmpdir();
    let sock = d.path().join("run/msd.sock");
    let _daemon = start_msd(&sock);
    let (code, out, err) = run_stdin(
        &ms(),
        &["add", "openai/test", "--stdin", "--tier", "test"],
        &sock,
        d.path(),
        CANARY.as_bytes(),
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("ms://openai/test"), "{out}");
    let env = d.path().join(".env");
    std::fs::write(
        &env,
        format!("STRIPE_SECRET_KEY={CANARY}_stripe\nPORT=3000\n"),
    )
    .unwrap();
    let (code, out, err) = run_stdin(&ms(), &["import", ".env", "--yes"], &sock, d.path(), b"");
    assert_eq!(code, 0, "{out}{err}");
    let rewritten = std::fs::read_to_string(&env).unwrap();
    assert!(rewritten.contains("ms://stripe/test"), "{rewritten}");
    assert!(!rewritten.contains(CANARY));
    let (code, out, err) = run(&ms(), &["rules"], &sock);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("verified by msd"), "{out}");
    assert!(
        out.contains("openai/test") && out.contains("stripe/test"),
        "{out}"
    );
    assert!(out.contains("nothing allowed"), "{out}");
    let (code, out, _) = run(&ms(), &["status"], &sock);
    assert_eq!(
        (code, out.as_str()),
        (0, "morsec on · 2 secrets protected\n")
    );
    for text in [&out, &err, &receipts_text(&sock)] {
        assert!(!text.contains(CANARY), "value leaked: {text}");
    }
}
