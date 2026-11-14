//! `ms run -- <cmd>`: run a command through the broker (L12, SPEC D7), and
//! `ms run --link-shims`: keep `~/.morsec/shims` in step with the run rules.
//!
//! `ms run` is the explicit form of what the shim does: the command, its working directory, the
//! environment variables that hold `ms://` refs and stdin go to msd, which runs it under the
//! key's rules and streams back redacted output. The exit code is the command's own; morsec's
//! failures use 77 (refused), 69 (daemon unavailable), 64 (usage) and 70 (internal).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use ms_ipc::{Client, RequestBody, ResponseBody};
use ms_run::client::{self, EXIT_USAGE, Outcome};

use crate::terminal_safe;

#[derive(Debug, Args)]
#[command(after_help = "\
The command runs inside msd, not here: its program comes from morsec's trusted search path, its \
environment is minimal (PATH, HOME, USER, LOGNAME, LANG, TMPDIR and the variables you pass that \
hold ms:// references, with run-mode references replaced by the value), and it must be allowed \
by the key's rules (ms rules <key>): an allowlisted command, run inside one of the key's project \
roots. Put references in environment variables, not arguments: \
  TOKEN=ms://deploy/staging ms run -- deploy-cli push

Output is redacted (the value in raw, base64, base64url, hex, URL and JSON-escaped form).

Exit status: the command's own; 77 refused by a rule or a person, 69 the daemon is not running, \
64 usage error (or no ms:// reference at all), 70 morsec failed.")]
pub(crate) struct RunArgs {
    /// Don't forward stdin (the command reads an empty input).
    #[arg(long)]
    no_stdin: bool,
    /// Create or update the shims in ~/.morsec/shims for every program your run rules allow,
    /// and remove shims for programs no rule names any more.
    #[arg(long, conflicts_with_all = ["no_stdin", "command"])]
    link_shims: bool,
    /// The command and its arguments, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CMD"
    )]
    command: Vec<OsString>,
}

/// `ms run`.
pub(crate) fn run(a: &RunArgs) -> ExitCode {
    if a.link_shims {
        return link_shims();
    }
    match forward(a) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err((msg, code)) => {
            eprintln!("{}", terminal_safe(&msg));
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
    }
}

fn forward(a: &RunArgs) -> Result<i32, (String, i32)> {
    let usage = |m: &str| (m.to_owned(), EXIT_USAGE);
    if a.command.is_empty() {
        return Err(usage(
            "morsec: give the command after --, e.g. TOKEN=ms://deploy/staging ms run -- deploy-cli push",
        ));
    }
    let has_ref = client::args_have_ref(&a.command).map_err(|m| usage(&m))?;
    let env = client::ref_env(std::env::vars_os()).map_err(|m| usage(&m))?;
    if !has_ref && env.is_empty() {
        return Err(usage(
            "morsec: there is no ms:// reference in the command or its environment, so there is nothing for morsec to do. Run the command directly",
        ));
    }
    let argv = a
        .command
        .iter()
        .map(|s| s.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| usage("morsec: an argument is not valid UTF-8"))?;
    let cwd = std::env::current_dir()
        .map_err(|e| usage(&format!("morsec: can't read the current directory: {e}")))?;
    let socket =
        ms_ipc::default_socket_path().map_err(|e| (e.to_string(), client::EXIT_UNAVAILABLE))?;
    match client::forward(argv, cwd, env, &socket, !a.no_stdin) {
        Outcome::Exit(c) => Ok(c),
        Outcome::NotRun => Err(usage(
            "morsec: none of the references is a run-mode key, so msd won't run this. Swap keys work through the proxy; run the command directly",
        )),
    }
}

/// Program names a shim may take: a bare file name, nothing morsec uses itself.
fn shim_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n != "."
        && n != ".."
        && !matches!(n, "ms" | "mors" | "msd" | "ms-shim")
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// The bare program names the run rules allow (first token of each literal-program pattern).
fn wanted(rules: &ms_rules::Rules) -> BTreeSet<String> {
    rules
        .keys
        .values()
        .filter(|r| r.mode == ms_core::Mode::Run)
        .flat_map(|r| r.commands.iter())
        .filter_map(|c| c.to_strings().into_iter().next())
        .filter(|n| shim_name_ok(n))
        .collect()
}

fn link_shims() -> ExitCode {
    let rules = match fetch_rules() {
        Ok(r) => r,
        Err(m) => {
            eprintln!("{}", terminal_safe(&m));
            return ExitCode::from(client::EXIT_UNAVAILABLE as u8);
        }
    };
    let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        eprintln!("morsec: HOME is not set, so ~/.morsec/shims can't be found");
        return ExitCode::FAILURE;
    };
    let shim = match std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map(|p| p.with_file_name("ms-shim"))
    {
        Ok(p) if p.is_file() => p,
        _ => {
            eprintln!("morsec: ms-shim is not installed next to ms; reinstall morsec");
            return ExitCode::FAILURE;
        }
    };
    match sync_shims(&home.join(".morsec/shims"), &shim, &wanted(&rules)) {
        Ok(lines) => {
            for l in lines {
                println!("{}", terminal_safe(&l));
            }
            ExitCode::SUCCESS
        }
        Err(m) => {
            eprintln!("{}", terminal_safe(&m));
            ExitCode::FAILURE
        }
    }
}

fn fetch_rules() -> Result<ms_rules::Rules, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: {e}"))?;
    let resp = rt
        .block_on(async {
            let path = ms_ipc::default_socket_path()?;
            Client::connect(&path)
                .await?
                .request(RequestBody::RulesGet { key: None })
                .await
        })
        .map_err(|e| e.to_string())?;
    match resp {
        ResponseBody::Rules { toml, .. } => {
            ms_rules::Rules::from_toml(&toml, "the daemon's rules").map_err(|e| e.to_string())
        }
        ResponseBody::Error { message, .. } => Err(message),
        _ => Err("morsec: unexpected reply from the daemon".into()),
    }
}

/// Makes `dir` hold exactly one shim per name in `want` (hard links of `shim`, or copies when a
/// link can't cross file systems). Files that are not shims are left alone and reported.
fn sync_shims(dir: &Path, shim: &Path, want: &BTreeSet<String>) -> Result<Vec<String>, String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("morsec: can't create {}: {e}", dir.display()))?;
    let shim_meta =
        std::fs::metadata(shim).map_err(|e| format!("morsec: {}: {e}", shim.display()))?;
    let shim_bytes = std::fs::read(shim).map_err(|e| format!("morsec: {}: {e}", shim.display()))?;
    // A shim is a hard link of ms-shim, or a byte-identical copy (cross-device fallback).
    let same_at = |p: &Path, m: &std::fs::Metadata| {
        (m.dev(), m.ino()) == (shim_meta.dev(), shim_meta.ino())
            || (m.file_type().is_file()
                && m.len() == shim_meta.len()
                && std::fs::read(p).is_ok_and(|b| b == shim_bytes))
    };
    let mut lines = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| format!("morsec: {}: {e}", dir.display()))? {
        let e = e.map_err(|e| format!("morsec: {}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(m) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        if !want.contains(&name) && same_at(&e.path(), &m) {
            std::fs::remove_file(e.path()).map_err(|err| format!("morsec: {name}: {err}"))?;
            lines.push(format!("removed {name}"));
        }
    }
    for name in want {
        let p = dir.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if (m.dev(), m.ino()) == (shim_meta.dev(), shim_meta.ino()) => {}
            Ok(m) if same_at(&p, &m) => {
                std::fs::remove_file(&p).map_err(|e| format!("morsec: {name}: {e}"))?;
                place(shim, &p)?;
                lines.push(format!("updated {name}"));
            }
            Ok(_) => lines.push(format!(
                "skipped {name}: {} exists and is not a morsec shim",
                p.display()
            )),
            Err(_) => {
                place(shim, &p)?;
                lines.push(format!("linked {name}"));
            }
        }
    }
    lines.push(format!(
        "{} shim{} in {}",
        want.len(),
        if want.len() == 1 { "" } else { "s" },
        dir.display()
    ));
    Ok(lines)
}

fn place(shim: &Path, at: &Path) -> Result<(), String> {
    if std::fs::hard_link(shim, at).is_ok() {
        return Ok(());
    }
    std::fs::copy(shim, at)
        .map(drop)
        .map_err(|e| format!("morsec: can't create {}: {e}", at.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=shim names are bare file names and never morsec's own binaries; fails_when=a path,
    // `..` or `ms` passes; no_claim=-
    #[test]
    fn shim_names() {
        for ok in ["psql", "stripe", "aws", "pg_dump", "python3.12", "g++"] {
            assert!(shim_name_ok(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "/usr/bin/x",
            "ms",
            "mors",
            "msd",
            "ms-shim",
            "a b",
            "*",
        ] {
            assert!(!shim_name_ok(bad), "{bad}");
        }
    }

    // protects=sync creates links for wanted names, removes stale shims, and never touches a
    // file that isn't a shim; fails_when=a user file is removed or a stale shim stays;
    // no_claim=the shim's behaviour (ms-run tests)
    #[test]
    fn sync() {
        let d = tempfile::tempdir().unwrap();
        let shim = d.path().join("ms-shim");
        std::fs::write(&shim, "shim-binary").unwrap();
        let dir = d.path().join("shims");
        let want: BTreeSet<String> = ["psql".into(), "stripe".into()].into();
        sync_shims(&dir, &shim, &want).unwrap();
        assert!(dir.join("psql").exists() && dir.join("stripe").exists());
        std::fs::write(dir.join("mine"), "user file, different size").unwrap();
        // Same size as the shim but different bytes: not a shim, never removed.
        std::fs::write(dir.join("lookalike"), "shim-BINARY").unwrap();
        let want2: BTreeSet<String> = ["psql".into(), "mine".into()].into();
        let lines = sync_shims(&dir, &shim, &want2).unwrap();
        assert!(!dir.join("stripe").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("mine")).unwrap(),
            "user file, different size"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("skipped mine")),
            "{lines:?}"
        );
    }
}
