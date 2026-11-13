//! Embeds the git short SHA for `ms --version`. Falls back to "unknown" outside a git checkout.

// Build scripts talk to cargo through stdout.
#![allow(clippy::print_stdout)]

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=MS_GIT_SHA={sha}");
}
