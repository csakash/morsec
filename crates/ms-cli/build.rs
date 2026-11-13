//! Embeds the git short SHA for `ms --version`. Falls back to "unknown" outside a git checkout.
//!
//! Cargo reruns this script only when a file named by `rerun-if-changed` changes, so it watches
//! git's HEAD and the current branch ref (resolved with `--git-path`, which works in worktrees
//! where `.git` is a file). Without that, the SHA goes stale after the next commit.

// Build scripts talk to cargo through stdout.
#![allow(clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// `git rev-parse --git-path <p>` may print a path relative to the current directory.
fn git_path(p: &str) -> Option<PathBuf> {
    let out = PathBuf::from(git(&["rev-parse", "--git-path", p])?);
    Some(if out.is_absolute() {
        out
    } else {
        std::env::current_dir().ok()?.join(out)
    })
}

fn watch(path: &Path) {
    // Only existing files: cargo treats a missing rerun-if-changed file as always changed.
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(head) = git_path("HEAD") {
        watch(&head);
    }
    // The per-worktree reflog gets a line on every commit, checkout and reset, even when the
    // branch ref lives only in packed-refs and no loose ref file changes.
    if let Some(reflog) = git_path("logs/HEAD") {
        watch(&reflog);
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(p) = git_path(&reference) {
            watch(&p);
        }
        if let Some(p) = git_path("packed-refs") {
            watch(&p);
        }
    }
    let sha = git(&["rev-parse", "--short=7", "HEAD"])
        .filter(|s| s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=MS_GIT_SHA={sha}");
}
