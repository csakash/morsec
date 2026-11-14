//! `ms-shim`: hard-linked as `psql`, `stripe`… in `~/.morsec/shims`, which connectors put first
//! on the agent's `PATH` (SPEC D6).
//!
//! - No `ms://` ref in the arguments or the environment: `exec` the next real binary of the
//!   same name on `PATH`, unchanged.
//! - A ref: forward the call to msd (`RunStream`), which runs it under the key's rules and
//!   streams back redacted output. If msd says no run-mode key is involved (`not_run`), `exec`
//!   the real binary unchanged; the literal refs reach it, exactly as without morsec.
//! - msd unreachable with a ref present: refuse loudly (exit 69). Nothing runs with a raw ref
//!   behind the user's back, and no value exists on this side to leak.
//!
//! Loops: the search for the real binary starts after this shim's own directory in `PATH`, and
//! skips any file that is this shim (same device and inode). When this shim was exec'd straight
//! from another shim (`MORSEC_SHIM_NEXT` carries this PID), it continues after the directory the
//! previous shim found it in, so every hop moves forward through `PATH` and can't cycle.

// A command-line tool reports on its own stderr.
#![allow(clippy::print_stderr)]

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use ms_run::client::{self, EXIT_USAGE, Outcome};

/// Set on the binary a shim execs: `<pid>:<index of the PATH entry it was found in>`.
const NEXT_ENV: &str = "MORSEC_SHIM_NEXT";
/// Exit code when no real binary is found (like a shell's "command not found").
const EXIT_NOT_FOUND: i32 = 127;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    let name = args
        .first()
        .map(Path::new)
        .and_then(Path::file_name)
        .map(OsStr::to_owned)
        .unwrap_or_default();
    if name.is_empty() || name == "ms-shim" {
        eprintln!(
            "morsec: ms-shim runs as a link named after a tool (psql, stripe…) in ~/.morsec/shims; create the links with: ms run --link-shims"
        );
        std::process::exit(EXIT_USAGE);
    }
    let code = match decide(&name, &args) {
        Ok(Some(code)) => code,
        Ok(None) => exec_real(&name, &args),
        Err(msg) => {
            eprintln!("{}", client::terminal_safe(&msg));
            client::EXIT_REFUSED
        }
    };
    std::process::exit(code);
}

/// `Ok(None)`: run the real tool. `Ok(Some(code))`: done, exit with `code`.
fn decide(name: &OsStr, args: &[OsString]) -> Result<Option<i32>, String> {
    let rest = args.get(1..).unwrap_or_default();
    let env = client::ref_env(std::env::vars_os())?;
    if !client::args_have_ref(rest)? && env.is_empty() {
        return Ok(None);
    }
    let Some(tool) = name.to_str() else {
        return Err("morsec: this tool's name is not valid UTF-8".into());
    };
    let mut argv = vec![tool.to_owned()];
    for a in rest {
        // args_have_ref already refused a non-UTF-8 argument that holds a ref; other non-UTF-8
        // arguments can't travel either.
        argv.push(
            a.to_str()
                .ok_or("morsec: an argument is not valid UTF-8, so the call can't be sent to the broker")?
                .to_owned(),
        );
    }
    let cwd = std::env::current_dir()
        .map_err(|e| format!("morsec: can't read the current directory: {e}"))?;
    let socket = ms_ipc::default_socket_path().map_err(|e| e.to_string())?;
    match client::forward(argv, cwd, env, &socket, true) {
        Outcome::Exit(code) => Ok(Some(code)),
        Outcome::NotRun => Ok(None),
    }
}

/// Execs the next real `name` on `PATH`. Returns only on failure.
fn exec_real(name: &OsStr, args: &[OsString]) -> i32 {
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(&p).ok().map(|m| (p, m)));
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    let start = start_index(&dirs, me.as_ref().map(|(p, _)| p.as_path()));
    let own = me.as_ref().map(|(_, m)| (m.dev(), m.ino()));
    for (i, dir) in dirs.iter().enumerate().skip(start) {
        if !dir.is_absolute() {
            continue;
        }
        let cand = dir.join(name);
        let Ok(m) = std::fs::metadata(&cand) else {
            continue;
        };
        if !m.is_file() || own == Some((m.dev(), m.ino())) {
            continue;
        }
        let err = std::process::Command::new(&cand)
            .arg0(&args[0])
            .args(&args[1..])
            .env(NEXT_ENV, format!("{}:{i}", std::process::id()))
            .exec();
        eprintln!(
            "morsec: could not run {}: {err}",
            client::terminal_safe(&cand.to_string_lossy())
        );
        return 126;
    }
    eprintln!(
        "morsec: {}: command not found on PATH after the morsec shims",
        client::terminal_safe(&name.to_string_lossy())
    );
    EXIT_NOT_FOUND
}

/// Where to start looking: after the directory a previous shim found us in (when it exec'd us
/// directly), and in any case after our own directory.
fn start_index(dirs: &[PathBuf], me: Option<&Path>) -> usize {
    let mut start = 0;
    if let Some(v) = std::env::var_os(NEXT_ENV)
        && let Some((pid, idx)) = v.to_str().and_then(|s| s.split_once(':'))
        && pid.parse::<u32>().ok() == Some(std::process::id())
        && let Ok(idx) = idx.parse::<usize>()
    {
        start = idx.saturating_add(1);
    }
    let own_dir = me
        .and_then(Path::parent)
        .and_then(|d| std::fs::canonicalize(d).ok());
    if let Some(own) = own_dir
        && let Some(i) = dirs
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, d)| std::fs::canonicalize(d).ok().as_ref() == Some(&own))
            .map(|(i, _)| i)
    {
        start = i + 1;
    }
    start
}
