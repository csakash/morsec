//! `ms import` and `ms add` end to end, under both names, against no daemon and a stub daemon.
//!
//! IPC v1 has no success reply for `ListKeys`/`PutKey` yet (L07), so every path that would
//! store must fail closed here: the file stays byte-identical and no value is printed. The
//! storing path itself is proven in `ms-import` against the in-memory vault.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use ms_core::SecretBytes;
use ms_ipc::server::{Handler, PeerInfo, SameUid, Server};
use ms_ipc::{ErrorCode, RequestBody, ResponseBody};

const CANARY: &str = "sk_live_CANARY4b1d9e7a2c5f8e0d3b6a";

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

fn tmpdir() -> tempfile::TempDir {
    // Under /tmp: Unix socket paths are limited to ~104 bytes on macOS.
    tempfile::Builder::new()
        .prefix("msimp")
        .tempdir_in("/tmp")
        .unwrap()
}

fn perms(p: &Path) -> fs::Permissions {
    fs::metadata(p).unwrap().permissions()
}

fn mors(dir: &Path) -> PathBuf {
    let link = dir.join("mors");
    std::os::unix::fs::symlink(ms(), &link).unwrap();
    link
}

fn env_file(dir: &Path) -> (PathBuf, String) {
    let text = format!(
        "# app\nSTRIPE_SECRET_KEY={CANARY}\nPORT=3000\nSESSION_SECRET='CANARYsess42'\n\
         DATABASE_URL=postgres://app:CANARYpw@db.prod.example.com/app\n"
    );
    let p = dir.join(".env");
    fs::write(&p, &text).unwrap();
    (p, text)
}

fn run(bin: &Path, args: &[&str], sock: &Path, stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(bin)
        .args(args)
        .env("MORSEC_SOCKET", sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().unwrap();
    (
        status.code().unwrap_or(-1),
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

fn no_canary(out: &str, err: &str) {
    assert!(
        !out.contains("CANARY") && !err.contains("CANARY"),
        "{out}\n{err}"
    );
}

// protects=--dry-run shows the review table with masked values only, under ms and mors, and
// changes nothing; fails_when=a value is printed, the file changes, or the names differ in
// behaviour; no_claim=terminal rendering of the table
#[test]
fn dry_run_masks_and_changes_nothing() {
    let d = tmpdir();
    let (p, text) = env_file(d.path());
    let sock = d.path().join("none.sock");
    let alias = mors(d.path());
    let mut outs = Vec::new();
    for bin in [ms(), alias] {
        let (code, out, err) = run(
            &bin,
            &["import", "--dry-run", p.to_str().unwrap()],
            &sock,
            b"",
        );
        assert_eq!(code, 0, "{err}");
        no_canary(&out, &err);
        for want in [
            "STRIPE_SECRET_KEY",
            "stripe/production",
            "sk_live_… (34 bytes)",
            "api.stripe.com",
            "env/session-secret",
            "none yet (ms rules)",
            "pg/production",
            "postgres://…",
            "keep: not a secret",
            "Dry run: 3 key(s)",
        ] {
            assert!(out.contains(want), "missing {want:?} in\n{out}");
        }
        assert!(err.contains("could not read the vault's keys"), "{err}");
        assert_eq!(fs::read_to_string(&p).unwrap(), text);
        outs.push(out);
    }
    assert_eq!(outs[0], outs[1], "ms and mors differ");
}

// protects=without a terminal and without --yes the import refuses (exit 2) before contacting
// anything; fails_when=it proceeds or changes the file; no_claim=the interactive prompt itself
#[test]
fn refuses_without_tty_or_yes() {
    let d = tmpdir();
    let (p, text) = env_file(d.path());
    let (code, out, err) = run(
        &ms(),
        &["import", p.to_str().unwrap()],
        &d.path().join("s"),
        b"y\n",
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--dry-run") && err.contains("--yes"), "{err}");
    no_canary(&out, &err);
    assert_eq!(fs::read_to_string(&p).unwrap(), text);
}

// protects=--yes with no daemon fails loudly and leaves the file byte-identical;
// fails_when=it exits 0, rewrites, or falls back to anything; no_claim=a working daemon (L07)
#[test]
fn no_daemon_fails_closed() {
    let d = tmpdir();
    let (p, text) = env_file(d.path());
    let (code, out, err) = run(
        &ms(),
        &["import", "--yes", p.to_str().unwrap()],
        &d.path().join("none.sock"),
        b"",
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("daemon not running"), "{err}");
    assert!(err.contains("was not changed"), "{err}");
    no_canary(&out, &err);
    assert_eq!(fs::read_to_string(&p).unwrap(), text);
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
}

/// A daemon that answers every request with a `not_implemented` error whose text tries to
/// rewrite the terminal, and records whether a key value ever arrived.
struct Stub {
    got_value: std::sync::atomic::AtomicBool,
}

impl Handler for Stub {
    async fn handle(
        &self,
        _peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        if value.is_some() {
            self.got_value
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        ResponseBody::error(
            ErrorCode::NotImplemented,
            format!(
                "morsec: '{}' is not built yet\u{1b}[2J\r\nfake line",
                request.owner_loop()
            ),
        )
    }
}

// protects=a daemon that can't list keys stops import and add before any value is sent, and its
// message reaches the terminal without control characters; fails_when=a value is sent, the file
// changes, or escape bytes are printed; no_claim=behaviour once msd implements the replies
#[test]
fn stub_daemon_fails_closed_and_is_terminal_safe() {
    let d = tmpdir();
    let (p, text) = env_file(d.path());
    fs::set_permissions(d.path(), {
        let mut p = perms(d.path());
        std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o700);
        p
    })
    .unwrap();
    let sock = d.path().join("d.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stub = Arc::new(Stub {
        got_value: false.into(),
    });
    let server = rt.block_on(async { Server::bind(&sock) }).unwrap();
    let uid = server.owner_uid();
    rt.spawn(server.serve(
        stub.clone(),
        Arc::new(SameUid { uid }),
        std::future::pending(),
    ));

    let (code, out, err) = run(&ms(), &["import", "--yes", p.to_str().unwrap()], &sock, b"");
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("L07 daemon") && err.contains("is not built yet"),
        "{err}"
    );
    assert!(!err.contains('\u{1b}') && !err.contains('\r'), "{err:?}");
    no_canary(&out, &err);
    assert_eq!(fs::read_to_string(&p).unwrap(), text);

    let (code, out, err) = run(
        &ms(),
        &["add", "--stdin", "stripe/test"],
        &sock,
        CANARY.as_bytes(),
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("L07 daemon"), "{err}");
    no_canary(&out, &err);
    assert!(!stub.got_value.load(std::sync::atomic::Ordering::SeqCst));
}

// protects=ms add refuses a non-terminal stdin without --stdin, an empty value, a bad name, and
// fails closed with no daemon, never echoing the value; fails_when=any of these exits 0 or
// prints the value; no_claim=hidden terminal input (manual QA)
#[test]
fn add_refusals() {
    let d = tmpdir();
    let sock = d.path().join("none.sock");
    let alias = mors(d.path());
    for bin in [ms(), alias] {
        let (code, _, err) = run(&bin, &["add", "stripe/test"], &sock, CANARY.as_bytes());
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("--stdin"), "{err}");

        let (code, _, err) = run(&bin, &["add", "--stdin", "stripe/test"], &sock, b"\n");
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("empty"), "{err}");

        let (code, _, err) = run(&bin, &["add", "--stdin", "Bad Name"], &sock, b"x");
        assert_eq!(code, 2, "{err}");

        let (code, out, err) = run(
            &bin,
            &["add", "--stdin", "stripe/test"],
            &sock,
            CANARY.as_bytes(),
        );
        assert_eq!(code, 1, "{err}");
        assert!(err.contains("daemon not running"), "{err}");
        no_canary(&out, &err);
    }
    // There is no way to pass the value as an argument.
    let (code, _, err) = run(&ms(), &["add", "stripe/test", CANARY], &sock, b"");
    assert_eq!(code, 2);
    assert!(
        !err.contains("CANARY") || err.contains("unexpected argument"),
        "{err}"
    );
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

// protects=a .env that was ever committed triggers the rotate warning; fails_when=it is silent
// for a committed file or warns for a never-committed one; no_claim=history outside this clone
#[test]
fn warns_when_committed() {
    let d = tmpdir();
    let (p, _) = env_file(d.path());
    git(d.path(), &["init", "-q"]);
    let sock = d.path().join("none.sock");
    let (_, _, err) = run(
        &ms(),
        &["import", "--dry-run", p.to_str().unwrap()],
        &sock,
        b"",
    );
    assert!(!err.contains("rotate"), "{err}");
    git(d.path(), &["add", ".env"]);
    git(d.path(), &["commit", "-q", "-m", "oops"]);
    let (code, out, err) = run(
        &ms(),
        &["import", "--dry-run", p.to_str().unwrap()],
        &sock,
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        err.contains("1 commit(s)") && err.contains("rotate"),
        "{err}"
    );
    no_canary(&out, &err);
}
