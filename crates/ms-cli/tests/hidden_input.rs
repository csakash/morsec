//! Hidden terminal input (`ms add` without `--stdin`) on a real pseudo-terminal.
//!
//! `ms add` only prompts once the daemon can list keys, which IPC v1 can't answer yet (L07), so
//! this drives `read_hidden` directly: the test re-runs itself as a child whose stdin is the pty's
//! terminal side, types into the controller side, and checks what the terminal showed.

#![allow(clippy::print_stdout)]

#[allow(dead_code)]
#[path = "../src/tty.rs"]
mod tty;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, tcgetattr};

const CHILD_ENV: &str = "MS_HIDDEN_INPUT_CHILD";

/// Child mode: read one hidden value and report it (test values only) on stdout.
fn child() {
    match tty::read_hidden("Value: ") {
        Ok(Some(v)) => println!("GOT:{}", String::from_utf8_lossy(&v)),
        Ok(None) => println!("CANCELLED"),
        Err(e) => println!("ERR:{e}"),
    }
}

struct Pty {
    controller: File,
    terminal_path: std::path::PathBuf,
}

fn open_pty() -> Pty {
    let c: OwnedFd = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&c).unwrap();
    unlockpt(&c).unwrap();
    let name = ptsname(&c, Vec::new()).unwrap();
    Pty {
        controller: File::from(c),
        terminal_path: std::path::PathBuf::from(name.to_str().unwrap()),
    }
}

/// Reads from the controller until `needle` shows up or 10 s pass.
fn read_until(c: &mut File, seen: &mut Vec<u8>, needle: &[u8]) {
    rustix::io::ioctl_fionbio(c.as_fd(), true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 256];
    while !seen.windows(needle.len()).any(|w| w == needle) {
        assert!(Instant::now() < deadline, "timed out; saw {seen:?}");
        match rustix::io::read(c.as_fd(), &mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Runs the child on a fresh pty, types `input` after the prompt appears, and returns
/// (child stdout, what the terminal displayed, ECHO flag after the child exited).
fn type_into_child(input: &[u8]) -> (String, String, bool) {
    let mut pty = open_pty();
    let terminal: File = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pty.terminal_path)
        .unwrap();
    let before = tcgetattr(terminal.as_fd()).unwrap();
    assert!(before.local_modes.contains(LocalModes::ECHO));
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::from(terminal.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::from(terminal.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let mut shown = Vec::new();
    read_until(&mut pty.controller, &mut shown, b"Value: ");
    pty.controller.write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "child failed: {out:?}");
    // Anything the terminal showed after the prompt.
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 256];
    while let Ok(n) = rustix::io::read(pty.controller.as_fd(), &mut buf) {
        if n == 0 {
            break;
        }
        shown.extend_from_slice(&buf[..n]);
    }
    let after = tcgetattr(terminal.as_fd()).unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&shown).into_owned(),
        after.local_modes.contains(LocalModes::ECHO)
            && after.local_modes.contains(LocalModes::ICANON)
            && after.local_modes.contains(LocalModes::ISIG),
    )
}

#[test]
fn child_entry() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
    }
}

// protects=typed secrets are not echoed, backspace edits, and the terminal's echo, line mode and
// signals are restored; fails_when=the value appears on the terminal or the modes stay off;
// no_claim=terminals other than the system pty driver
#[test]
fn value_is_not_echoed_and_terminal_is_restored() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    let (out, shown, restored) = type_into_child(b"QAsecretX\x7fZ\r");
    assert!(out.contains("GOT:QAsecretZ"), "{out}");
    assert!(!shown.contains("QAsecret"), "terminal showed: {shown:?}");
    assert!(restored, "terminal modes not restored");
}

// protects=Ctrl-C cancels cleanly (no signal kills the process with echo off) and restores the
// terminal; fails_when=the child dies, returns a value, or leaves echo off
#[test]
fn ctrl_c_cancels_and_restores() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return;
    }
    let (out, shown, restored) = type_into_child(b"QApartial\x03");
    assert!(out.contains("CANCELLED"), "{out}");
    assert!(!shown.contains("QApartial"), "{shown:?}");
    assert!(restored);
}
