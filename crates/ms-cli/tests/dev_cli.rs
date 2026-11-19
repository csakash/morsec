//! `ms dev` from the command line (L34).

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

// protects=L34 SPEC criterion 1 / design §7.1: `ms dev` inside an agent session refuses before
// it contacts msd (the socket here doesn't exist, so reaching it would print a daemon error
// instead) and never runs the command (its marker file stays absent); exit 77;
// fails_when=an agent's ms dev reaches DevStart or runs the command; no_claim=msd's own refusal
// (daemon dev_refused_in_agent_session)
#[test]
fn dev_refused_in_agent_session() {
    let d = tempfile::Builder::new()
        .prefix("msdev")
        .tempdir_in("/tmp")
        .unwrap();
    // A copy of `ms` named `claude`: it is the agent, so `claude dev …` runs inside its session.
    let agent = d.path().join("claude");
    std::fs::copy(ms(), &agent).unwrap();
    let marker = d.path().join("ran");
    let o = Command::new(&agent)
        .args(["dev", "--", "/usr/bin/touch"])
        .arg(&marker)
        .current_dir(d.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", d.path())
        .env("MORSEC_SOCKET", d.path().join("no.sock"))
        .env("MORSEC_DEV_UNVERIFIED_DAEMON", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&o.stderr).into_owned() + &String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.status.code(), Some(77), "{text}");
    assert!(text.contains("not inside an agent session"), "{text}");
    assert!(!marker.exists());
}
