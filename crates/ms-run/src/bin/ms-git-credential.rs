//! `ms-git-credential`: the git credential helper morsec gives a run with
//! `MS_GIT_CREDENTIAL=ms://<key>` (L16).
//!
//! git runs it as `ms-git-credential get` with its request on stdin. It forwards the request to
//! the run's credential socket (`MS_GIT_CREDENTIAL_SOCK`, set by msd for that run only) and
//! prints msd's answer. msd decides: only the key's HTTPS hosts get an answer. `store` and
//! `erase` do nothing. On any failure it prints nothing, and git fails without a prompt.

#![allow(clippy::print_stderr)] // a git helper reports on stderr, like ms-shim

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use ms_run::adapters::ssh_git::{CRED_SOCK_VAR, cred::MAX_MESSAGE, helper_get};

fn main() -> ExitCode {
    let op = std::env::args().nth(1).unwrap_or_default();
    let mut request = Vec::new();
    let _ = std::io::stdin()
        .take(MAX_MESSAGE as u64)
        .read_to_end(&mut request);
    if op != "get" {
        return ExitCode::SUCCESS;
    }
    let Some(sock) = std::env::var_os(CRED_SOCK_VAR) else {
        eprintln!(
            "morsec: ms-git-credential runs only inside a morsec run (ms run with MS_GIT_CREDENTIAL)"
        );
        return ExitCode::SUCCESS;
    };
    let sock = Path::new(&sock);
    if !sock.is_absolute() {
        return ExitCode::SUCCESS;
    }
    let answer = helper_get(sock, &request);
    if answer.is_empty() {
        eprintln!(
            "morsec: no credential for this host (only the key's HTTPS hosts get one; see ms log)"
        );
        return ExitCode::SUCCESS;
    }
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&answer);
    let _ = out.flush();
    ExitCode::SUCCESS
}
