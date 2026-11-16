//! T-03: `ms` checks that the process serving the socket is msd before it sends anything.
//!
//! - An impostor listening on the socket path gets no bytes at all, and `ms` and `ms doctor`
//!   say why.
//! - The dev opt-out is the only way past on an unsigned build, and it is loud.
//! - The live signature check (audit token → SecCode → requirement) accepts the real msd and
//!   refuses an impostor and the Developer ID requirement (a cargo-built msd is not a release).
//!
//! Temp HOME and memory vault only: nothing touches the real ~/.claude, ~/.codex, ~/.ssh or the
//! login keychain.

use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ms_ipc::peer_verify::{DEV_OPT_OUT_ENV, MSD_IDENTIFIER, developer_id_requirement, verify_peer};

const CANARY: &str = "sk_live_CANARYpeer7f3a9c1e5b2d8046";

fn msd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_msd"))
}

/// `ms` from the same target directory (built by `cargo build --workspace`, as in tests/cli.rs).
fn ms() -> PathBuf {
    let p = msd().with_file_name("ms");
    assert!(
        p.exists(),
        "{} not built; run cargo build --workspace",
        p.display()
    );
    p
}

fn tmpdir() -> tempfile::TempDir {
    // Under /tmp: Unix socket paths are limited to ~104 bytes on macOS.
    tempfile::Builder::new()
        .prefix("mspv")
        .tempdir_in("/tmp")
        .unwrap()
}

fn private_dir(p: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
}

/// A same-user process listening where msd should be. Reports how many bytes each client sent.
struct Impostor {
    socket: PathBuf,
    got: mpsc::Receiver<usize>,
}

fn impostor(dir: &Path) -> Impostor {
    let run = dir.join("run");
    private_dir(&run);
    let socket = run.join("msd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (tx, got) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { return };
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf);
            if tx.send(buf.len()).is_err() {
                return;
            }
        }
    });
    Impostor { socket, got }
}

impl Impostor {
    /// Bytes from every connection made so far (each one ends when the client closes it).
    fn total_received(&self) -> usize {
        let mut total = 0;
        while let Ok(n) = self.got.recv_timeout(Duration::from_millis(500)) {
            total += n;
        }
        total
    }
}

/// Runs `bin args` against `socket` with a temp HOME, feeding `stdin`. `opt_out` sets or removes
/// the dev opt-out (cargo's `[env]` sets it for every test by default).
fn run(
    args: &[&str],
    socket: &Path,
    home: &Path,
    stdin: &[u8],
    opt_out: bool,
) -> (i32, String, String) {
    use std::io::Write;
    let mut cmd = Command::new(ms());
    cmd.args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("MORSEC_SOCKET", socket)
        .env_remove("CODEX_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if opt_out {
        cmd.env(DEV_OPT_OUT_ENV, "1");
    } else {
        cmd.env_remove(DEV_OPT_OUT_ENV);
    }
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

// protects=T-03 an impostor on the socket path receives nothing from `ms add` (not even a
// request frame), and ms says it is not a verified msd and points at ms doctor; ms doctor
// reports the same failure instead of "not running"; fails_when=any byte reaches the impostor,
// ms exits 0, or the message is the generic daemon-down one; no_claim=a signed release (the
// impostor would then fail the Developer ID requirement instead of the dev-build refusal; the
// live check is real_msd_passes_the_signature_check)
#[test]
fn impostor_gets_nothing_and_a_clear_error() {
    let d = tmpdir();
    let home = d.path().join("home");
    private_dir(&home);
    let imp = impostor(d.path());
    let (code, out, err) = run(
        &["add", "--stdin", "stripe/test"],
        &imp.socket,
        &home,
        CANARY.as_bytes(),
        false,
    );
    assert_ne!(code, 0, "{out}{err}");
    assert!(
        err.contains("not a verified msd")
            && err.contains("Nothing was sent")
            && err.contains("ms doctor"),
        "{err}"
    );
    assert!(!err.contains("Start it with: ms start"), "{err}");
    assert!(!out.contains("CANARY") && !err.contains("CANARY"));
    let (_, out, err) = run(&["doctor"], &imp.socket, &home, b"", false);
    assert!(out.contains("msd identity not verified"), "{out}{err}");
    assert!(!out.contains("msd not running"), "{out}");
    assert_eq!(imp.total_received(), 0, "the impostor received bytes");
}

// protects=T-03 on an unsigned build the only way past the check is the explicit opt-out, and it
// announces itself on stderr; fails_when=the opt-out is silent; no_claim=signed releases (they
// ignore the variable: peer_verify::tests::release_signature_ignores_the_dev_opt_out)
#[test]
fn dev_opt_out_is_explicit_and_loud() {
    let d = tmpdir();
    let home = d.path().join("home");
    private_dir(&home);
    let imp = impostor(d.path());
    let (_, _, err) = run(&["status"], &imp.socket, &home, b"", true);
    assert!(
        err.contains("DEV BUILD") && err.contains(DEV_OPT_OUT_ENV),
        "{err}"
    );
    assert!(
        imp.total_received() > 0,
        "the opt-out did not reach the server"
    );
}

/// Stops msd with SIGTERM on drop (it removes its socket), SIGKILL after 5 s.
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

fn start_msd(dir: &Path) -> (Daemon, PathBuf) {
    let run = dir.join("msd");
    private_dir(&run);
    let socket = run.join("msd.sock");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(msd())
        .args(["--foreground", "--vault", "memory", "--socket"])
        .arg(&socket)
        .arg("--state-dir")
        .arg(run.join("state"))
        .args(["--proxy-port", &port.to_string()])
        .env("HOME", dir)
        .env("MORSEC_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "msd is not accepting");
        std::thread::sleep(Duration::from_millis(20));
    }
    (daemon, socket)
}

/// The code-directory hash of the msd binary on disk, from codesign.
fn msd_cdhash() -> String {
    let out = Command::new("/usr/bin/codesign")
        .args(["-d", "-vvv"])
        .arg(msd())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .find_map(|l| l.strip_prefix("CDHash="))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("no CDHash for msd: {text}"))
}

// protects=T-03 the live check (peer audit token from the connected socket, looked up through
// the kernel and checked against a code requirement) accepts the real msd, refuses a same-user
// impostor on the same requirement, and refuses a cargo-built msd under the Developer ID
// requirement (it is not a release); fails_when=the check passes for the impostor or fails for
// msd; no_claim=a Developer ID-signed msd (needs the release identity; manual in PROOF.md)
#[test]
fn real_msd_passes_the_signature_check() {
    let d = tmpdir();
    let (_daemon, socket) = start_msd(d.path());
    let pin = format!("cdhash H\"{}\"", msd_cdhash());

    let to_msd = UnixStream::connect(&socket).unwrap();
    verify_peer(&to_msd, &pin).expect("the real msd must pass");
    let release = developer_id_requirement(MSD_IDENTIFIER, "ABCDE12345").unwrap();
    let err = verify_peer(&to_msd, &release).unwrap_err();
    assert!(!err.is_empty());

    let imp = impostor(d.path());
    let to_imp = UnixStream::connect(&imp.socket).unwrap();
    let err = verify_peer(&to_imp, &pin).expect_err("an impostor must fail");
    assert!(!err.is_empty());
}
