//! The client side of run mode, shared by `ms-shim` and `ms run` (SPEC D6, D7, D9).
//!
//! It finds refs in the arguments and the environment, forwards the call to msd as a
//! `RunStream` (argv, working directory, the ref-bearing variables, stdin), writes the redacted
//! output to its own stdout and stderr, and turns the result into an exit code. It never has a
//! value: only refs leave this process.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use ms_core::{Error, SecretRef};
use ms_ipc::{Client, ErrorCode, OutStream, RequestBody, ResponseBody, RunEnv};

use crate::input::{MAX_ENV, env_name_allowed};

/// Exit code: usage error (sysexits `EX_USAGE`).
pub const EXIT_USAGE: i32 = 64;
/// Exit code: the daemon is not reachable (`EX_UNAVAILABLE`).
pub const EXIT_UNAVAILABLE: i32 = 69;
/// Exit code: morsec failed (`EX_SOFTWARE`).
pub const EXIT_INTERNAL: i32 = 70;
/// Exit code: refused by a rule, a check or a person (`EX_NOPERM`).
pub const EXIT_REFUSED: i32 = 77;

/// What became of a forwarded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Exit with this code (the child's, or morsec's on failure).
    Exit(i32),
    /// msd found no run-mode key among the refs: run the real tool unchanged.
    NotRun,
}

/// True when an argument holds a ref. A ref in an argument that is not UTF-8 can't be
/// forwarded (IPC carries strings), so that is an error rather than a silent pass-through.
pub fn args_have_ref(args: &[OsString]) -> Result<bool, String> {
    let mut found = false;
    for a in args {
        match a.to_str() {
            Some(s) => found |= !SecretRef::find_all(s).is_empty(),
            None if a.to_string_lossy().contains("ms://") => {
                return Err(
                    "morsec: an argument with an ms:// reference is not valid UTF-8, so it can't be sent to the broker"
                        .into(),
                );
            }
            None => {}
        }
    }
    Ok(found)
}

/// The variables to forward: those whose value holds a ref and whose name may carry one.
pub fn ref_env(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<Vec<RunEnv>, String> {
    let mut out = Vec::new();
    for (k, v) in vars {
        let (Some(name), Some(value)) = (k.to_str(), v.to_str()) else {
            if v.to_string_lossy().contains("ms://") {
                return Err(format!(
                    "morsec: the environment variable {} holds an ms:// reference but is not valid UTF-8",
                    k.to_string_lossy()
                ));
            }
            continue;
        };
        if SecretRef::find_all(value).is_empty() || !env_name_allowed(name) {
            continue;
        }
        out.push(RunEnv {
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    if out.len() > MAX_ENV {
        return Err(format!(
            "morsec: more than {MAX_ENV} environment variables hold references; morsec forwards at most {MAX_ENV}"
        ));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Drops control characters (escape sequences, bidi overrides) from daemon text before it
/// reaches a terminal.
pub fn terminal_safe(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

fn say(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{}", terminal_safe(msg));
}

/// Forwards a call to msd at `socket` and streams it. Blocking: runs its own runtime.
/// `stdin` decides whether this process's stdin is forwarded (otherwise the child gets an
/// immediate end of input).
pub fn forward(
    argv: Vec<String>,
    cwd: PathBuf,
    env: Vec<RunEnv>,
    socket: &Path,
    stdin: bool,
) -> Outcome {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            say(&format!("morsec: could not start: {e}"));
            return Outcome::Exit(EXIT_INTERNAL);
        }
    };
    let out = rt.block_on(forward_async(argv, cwd, env, socket, stdin));
    // A read of our stdin may still be blocked on a pool thread (a terminal nobody types into);
    // waiting for it would hang after the command already finished.
    rt.shutdown_background();
    out
}

async fn forward_async(
    argv: Vec<String>,
    cwd: PathBuf,
    env: Vec<RunEnv>,
    socket: &Path,
    stdin: bool,
) -> Outcome {
    let client = match Client::connect(socket).await {
        Ok(c) => c,
        Err(e) => {
            say(&e.to_string());
            return Outcome::Exit(EXIT_UNAVAILABLE);
        }
    };
    let req = RequestBody::RunStream { argv, cwd, env };
    let input = stdin.then(tokio::io::stdin);
    let result = client
        .run_stream(req, input, |stream, bytes| {
            let _ = match stream {
                OutStream::Stdout => {
                    let mut o = std::io::stdout().lock();
                    o.write_all(bytes).and_then(|()| o.flush())
                }
                OutStream::Stderr => {
                    let mut e = std::io::stderr().lock();
                    e.write_all(bytes).and_then(|()| e.flush())
                }
            };
        })
        .await;
    outcome(result)
}

/// Maps the last frame of a stream to an outcome, printing morsec's own errors.
pub fn outcome(result: ms_core::Result<ResponseBody>) -> Outcome {
    match result {
        Ok(ResponseBody::RunExit { code, signal }) => {
            Outcome::Exit(crate::Exit { code, signal }.shell_code())
        }
        Ok(ResponseBody::Error {
            code: ErrorCode::NotRun,
            ..
        }) => Outcome::NotRun,
        Ok(ResponseBody::Error { code, message }) => {
            say(&message);
            Outcome::Exit(match code {
                ErrorCode::Denied | ErrorCode::NeedsApproval | ErrorCode::PeerRejected => {
                    EXIT_REFUSED
                }
                ErrorCode::Invalid => EXIT_USAGE,
                ErrorCode::Busy | ErrorCode::NotInitialized => EXIT_UNAVAILABLE,
                _ => EXIT_INTERNAL,
            })
        }
        Ok(other) => {
            say(&format!(
                "morsec: unexpected answer from the daemon ({})",
                kind(&other)
            ));
            Outcome::Exit(EXIT_INTERNAL)
        }
        Err(e @ (Error::DaemonUnavailable { .. } | Error::DaemonNotVerified { .. })) => {
            say(&e.to_string());
            Outcome::Exit(EXIT_UNAVAILABLE)
        }
        Err(e) => {
            say(&e.to_string());
            Outcome::Exit(EXIT_INTERNAL)
        }
    }
}

fn kind(r: &ResponseBody) -> &'static str {
    match r {
        ResponseBody::Status { .. } => "status",
        ResponseBody::Ok { .. } => "ok",
        ResponseBody::Keys { .. } => "keys",
        ResponseBody::Rules { .. } => "rules",
        ResponseBody::ScanReport { .. } => "scan report",
        ResponseBody::Approval { .. } => "approval",
        ResponseBody::Probe { .. } => "doctor probe",
        ResponseBody::RunStarted => "run started",
        ResponseBody::RunOutput { .. } => "run output",
        ResponseBody::RunExit { .. } => "run exit",
        ResponseBody::RunResult { .. } => "run result",
        ResponseBody::Projects { .. } => "projects",
        ResponseBody::Project { .. } => "project",
        ResponseBody::Error { .. } => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=only ref-bearing variables with allowed names are forwarded, sorted, and a
    // non-UTF-8 ref is an error rather than a silent skip; fails_when=a plain variable (a token
    // the agent holds) is forwarded, or PATH is; no_claim=what msd does with them
    #[test]
    fn env_forwarding() {
        use std::os::unix::ffi::OsStringExt;
        let vars = vec![
            ("Z_TOKEN".into(), "ms://a/b".into()),
            ("PLAIN".into(), "hunter2".into()),
            ("PATH".into(), "/x:ms://a".into()),
            ("A_URL".into(), "postgres://h/d?password=ms://pg/x".into()),
        ];
        let got = ref_env(vars).unwrap();
        let names: Vec<_> = got.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["A_URL", "Z_TOKEN"]);
        let bad = vec![(
            OsString::from("X"),
            OsString::from_vec(b"ms://a\xff".to_vec()),
        )];
        assert!(ref_env(bad).is_err());
    }

    // protects=args are checked for refs; a non-UTF-8 arg with a ref is refused;
    // fails_when=a ref is missed; no_claim=-
    #[test]
    fn arg_refs() {
        use std::os::unix::ffi::OsStringExt;
        assert!(!args_have_ref(&["ls".into(), "-la".into()]).unwrap());
        assert!(args_have_ref(&["x".into(), "--key=ms://k".into()]).unwrap());
        assert!(args_have_ref(&[OsString::from_vec(b"ms://k\xff".to_vec())]).is_err());
        assert!(!args_have_ref(&[OsString::from_vec(b"\xff".to_vec())]).unwrap());
    }

    // protects=exit codes: the child's code passes through, a signal becomes 128+N, not_run asks
    // for pass-through, and morsec's own failures map to 77/64/69/70; fails_when=any mapping
    // differs from SPEC D9; no_claim=-
    #[test]
    fn exit_mapping() {
        let exit = |code, signal| outcome(Ok(ResponseBody::RunExit { code, signal }));
        assert_eq!(exit(Some(3), None), Outcome::Exit(3));
        assert_eq!(exit(None, Some(15)), Outcome::Exit(143));
        let err = |code| outcome(Ok(ResponseBody::error(code, "morsec: x")));
        assert_eq!(err(ErrorCode::NotRun), Outcome::NotRun);
        assert_eq!(err(ErrorCode::Denied), Outcome::Exit(EXIT_REFUSED));
        assert_eq!(err(ErrorCode::NeedsApproval), Outcome::Exit(EXIT_REFUSED));
        assert_eq!(err(ErrorCode::Invalid), Outcome::Exit(EXIT_USAGE));
        assert_eq!(err(ErrorCode::Internal), Outcome::Exit(EXIT_INTERNAL));
        assert_eq!(
            outcome(Err(Error::DaemonUnavailable { detail: "x".into() })),
            Outcome::Exit(EXIT_UNAVAILABLE)
        );
    }
}
