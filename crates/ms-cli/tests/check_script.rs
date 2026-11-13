//! scripts/check.sh must fail closed when a tool is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn which(tool: &str) -> PathBuf {
    let out = Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{tool} not found; this test needs it present"
    );
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

// protects=the gate refuses to run (exit 1, install hint) when cargo-deny is missing, before
// running any other step; fails_when=it skips the step, passes, or starts cargo; no_claim=that the
// other steps pass (scripts/check.sh itself proves that)
#[test]
fn fails_closed_without_cargo_deny() {
    let tools = tempfile::Builder::new()
        .prefix("mschk")
        .tempdir_in("/tmp")
        .unwrap();
    // Everything check.sh needs except cargo-deny.
    for t in ["cargo", "cargo-audit", "python3", "bash", "dirname"] {
        std::os::unix::fs::symlink(which(t), tools.path().join(t)).unwrap();
    }
    let out = Command::new(which("bash"))
        .arg(repo_root().join("scripts/check.sh"))
        .env_clear()
        .env("PATH", tools.path())
        .env("HOME", std::env::var_os("HOME").unwrap())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains("cargo-deny is not installed")
            && stderr.contains("cargo install --locked cargo-deny"),
        "{stderr}"
    );
    assert!(
        !stdout.contains("== 1/"),
        "a step ran before the tool check: {stdout}"
    );
}
