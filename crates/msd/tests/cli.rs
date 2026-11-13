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

fn start_msd(socket: &Path) -> Daemon {
    let child = Command::new(msd())
        .args(["--foreground", "--socket"])
        .arg(socket)
        .env("MORSEC_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon(child);
    wait_ready(socket);
    d
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
        ("init", "L07 daemon"),
        ("add", "L04 import-env"),
        ("import", "L04 import-env"),
        ("connect", "L08 connect-claude"),
        ("disconnect", "L08 connect-claude"),
        ("run", "L12 run-core"),
        ("rules", "L03 rules-policy"),
        ("log", "L02 receipts"),
        ("stop", "L07 daemon"),
        ("start", "L07 daemon"),
        ("doctor", "L17 doctor"),
        ("mcp", "L14 mcp-server"),
        ("scan", "L09 e2e-canary"),
        ("stats", "L02 receipts"),
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

// protects=`ms status` reports the running daemon over IPC and exits 0; with no daemon it fails
// closed with the ms start hint and exits 1; fails_when=status claims "on" without a daemon or
// fails with one running; no_claim=launchd or the production socket path (L07)
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
    assert_eq!(out, "morsec on · daemon 0.0.0\n");
    let (code, out, _) = run(&mors(d.path()), &["status"], &sock);
    assert_eq!((code, out.as_str()), (0, "morsec on · daemon 0.0.0\n"));
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
        .args(["--foreground", "--port", &port.to_string()])
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
        (0, "morsec on · daemon 0.0.0\n"),
        "{err}"
    );
    // SIGTERM: msd removes its socket on a clean shutdown.
    drop(daemon);
    assert!(!expected.exists(), "socket left after SIGTERM");
    let _ = std::fs::remove_dir(&dev_dir);
}

// protects=msd refuses to start without --foreground (no silent background mode before L07);
// fails_when=it starts or exits 0; no_claim=service management
#[test]
fn msd_requires_foreground() {
    let st = Command::new(msd()).stderr(Stdio::null()).status().unwrap();
    assert_eq!(st.code(), Some(64));
}
