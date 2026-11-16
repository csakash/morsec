//! `ms run -- <cmd>`: run a command through the broker (L12, SPEC D7), and
//! `ms run --link-shims`: keep `~/.morsec/shims` in step with the run rules.
//!
//! `ms run` is the explicit form of what the shim does: the command, its working directory, the
//! environment variables that hold `ms://` refs and stdin go to msd, which runs it under the
//! key's rules and streams back redacted output. The exit code is the command's own; morsec's
//! failures use 77 (refused), 69 (daemon unavailable), 64 (usage) and 70 (internal).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use ms_ipc::{Client, RequestBody, ResponseBody};
use ms_run::client::{self, EXIT_USAGE, Outcome};

use crate::brew::{self, Entry};
use crate::terminal_safe;

#[derive(Debug, Args)]
#[command(after_help = "\
The command runs inside msd, not here: its program comes from morsec's trusted search path, its \
environment is minimal (PATH, HOME, USER, LOGNAME, LANG, TMPDIR and the variables you pass that \
hold ms:// references, with run-mode references replaced by the value), and it must be allowed \
by the key's rules (ms rules <key>): an allowlisted command, run inside one of the key's project \
roots. Put each reference, alone, in an environment variable the key's rule names \
(ms rules <key> --add-env TOKEN), not in an argument: \
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
    // The shim skips these silently; an explicit `ms run` says why they were not sent.
    let refused: Vec<String> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .filter(|(k, v)| {
            !ms_core::SecretRef::find_all(v).is_empty() && !ms_run::input::env_name_allowed(k)
        })
        .map(|(k, _)| k)
        .collect();
    if !refused.is_empty() {
        return Err((
            format!(
                "morsec: {} can't carry an ms:// reference: it changes how programs load code or run commands. Use a variable the key's rule names (ms rules <key> --add-env NAME)",
                refused.join(", ")
            ),
            client::EXIT_REFUSED,
        ));
    }
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
pub(crate) fn wanted(rules: &ms_rules::Rules) -> BTreeSet<String> {
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
    let shim = match brew::sibling("ms-shim")
        .and_then(|(real, _)| brew::Shim::open(&real, brew::stable_path(&real)))
    {
        Ok(s) if s.real.is_file() => s,
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

pub(crate) fn fetch_rules() -> Result<ms_rules::Rules, String> {
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

/// Makes `dir` hold exactly one shim per name in `want`: symlinks to the stable
/// `opt/morsec/bin/ms-shim` in a Homebrew install (they follow `brew upgrade`), else hard links of
/// `ms-shim`, or copies when a link can't cross file systems. Shims left by an older version are
/// replaced. Files that are not shims are left alone and reported.
fn sync_shims(
    dir: &Path,
    shim: &brew::Shim,
    want: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("morsec: can't create {}: {e}", dir.display()))?;
    let mut lines = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| format!("morsec: {}: {e}", dir.display()))? {
        let e = e.map_err(|e| format!("morsec: {}: {e}", dir.display()))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if want.contains(&name) {
            continue;
        }
        if matches!(
            shim.classify(&e.path()),
            Entry::Linked | Entry::Pinned | Entry::Stale
        ) {
            std::fs::remove_file(e.path()).map_err(|err| format!("morsec: {name}: {err}"))?;
            lines.push(format!("removed {name}"));
        }
    }
    for name in want {
        let p = dir.join(name);
        match shim.classify(&p) {
            Entry::Linked => {}
            Entry::Pinned | Entry::Stale => {
                std::fs::remove_file(&p).map_err(|e| format!("morsec: {name}: {e}"))?;
                shim.place(&p)?;
                lines.push(format!("updated {name}"));
            }
            Entry::Foreign => lines.push(format!(
                "skipped {name}: {} exists and is not a morsec shim",
                p.display()
            )),
            Entry::Missing => {
                shim.place(&p)?;
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
        let shim_path = d.path().join("ms-shim");
        std::fs::write(&shim_path, crate::brew::tests::shim_bytes("dev")).unwrap();
        let shim = brew::Shim::open(&shim_path, None).unwrap();
        let dir = d.path().join("shims");
        let want: BTreeSet<String> = ["psql".into(), "stripe".into()].into();
        sync_shims(&dir, &shim, &want).unwrap();
        assert!(dir.join("psql").exists() && dir.join("stripe").exists());
        assert!(
            !std::fs::symlink_metadata(dir.join("psql"))
                .unwrap()
                .is_symlink()
        );
        std::fs::write(dir.join("mine"), "user file, different size").unwrap();
        // Same size as the shim but different bytes and no marker: not a shim, never removed.
        let mut look = crate::brew::tests::shim_bytes("dev");
        look[0] = b'#';
        std::fs::write(dir.join("lookalike"), &look).unwrap();
        let want2: BTreeSet<String> = ["psql".into(), "mine".into()].into();
        let lines = sync_shims(&dir, &shim, &want2).unwrap();
        assert!(!dir.join("stripe").exists());
        assert!(dir.join("lookalike").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("mine")).unwrap(),
            "user file, different size"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("skipped mine")),
            "{lines:?}"
        );
        assert_eq!(shim.classify(&dir.join("psql")), Entry::Linked);
    }

    // protects=in a Homebrew install shims are symlinks to opt/morsec/bin/ms-shim, so after
    // `brew upgrade` (new keg, opt moved, old keg deleted) they run the new ms-shim with no
    // relink; hard links left by an older version are migrated; fails_when=a shim points into a
    // versioned keg or an old hard link is skipped as foreign; no_claim=brew itself (never run)
    #[test]
    fn sync_follows_brew_upgrade() {
        use crate::brew::tests::{FakeBrew, shim_bytes};
        let b = FakeBrew::new();
        let v1 = b.install("1.0.0", &shim_bytes("1"));
        b.point_opt("1.0.0");
        let shims = b.prefix.join("home/.morsec/shims");
        std::fs::create_dir_all(&shims).unwrap();
        // What an older ms left: a hard link of the 1.0.0 keg's ms-shim, and a stale extra one.
        std::fs::hard_link(v1.join("ms-shim"), shims.join("psql")).unwrap();
        std::fs::hard_link(v1.join("ms-shim"), shims.join("gone")).unwrap();
        std::fs::write(shims.join("mine"), "user file").unwrap();

        let real = v1.join("ms-shim");
        let shim = brew::Shim::open(&real, brew::stable_path(&real)).unwrap();
        assert_eq!(shim.stable.as_deref(), Some(b.opt_bin("ms-shim").as_path()));
        assert_eq!(shim.classify(&shims.join("psql")), Entry::Pinned);
        let want: BTreeSet<String> = ["psql".into(), "stripe".into()].into();
        let lines = sync_shims(&shims, &shim, &want).unwrap();
        assert!(lines.contains(&"updated psql".to_owned()), "{lines:?}");
        assert!(lines.contains(&"linked stripe".to_owned()), "{lines:?}");
        assert!(lines.contains(&"removed gone".to_owned()), "{lines:?}");
        for n in ["psql", "stripe"] {
            assert_eq!(
                std::fs::read_link(shims.join(n)).unwrap(),
                b.opt_bin("ms-shim")
            );
            assert_eq!(shim.classify(&shims.join(n)), Entry::Linked);
        }
        assert!(shims.join("mine").exists());

        // brew upgrade: 1.1.0 installed, opt moved, 1.0.0 deleted.
        let v2 = b.install("1.1.0", &shim_bytes("2"));
        b.point_opt("1.1.0");
        b.uninstall("1.0.0");
        for n in ["psql", "stripe"] {
            assert_eq!(
                std::fs::read(shims.join(n)).unwrap(),
                shim_bytes("2"),
                "{n} runs the new ms-shim"
            );
        }
        // The new ms sees them as linked: nothing to do.
        let real2 = v2.join("ms-shim");
        let shim2 = brew::Shim::open(&real2, brew::stable_path(&real2)).unwrap();
        let lines = sync_shims(&shims, &shim2, &want).unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
    }

    // protects=a dev build's copies of an older ms-shim are recognised by the marker and
    // replaced, and a dangling symlink to an ms-shim counts as stale; fails_when=they are
    // skipped as foreign files; no_claim=-
    #[test]
    fn sync_migrates_old_dev_shims() {
        use crate::brew::tests::shim_bytes;
        let d = tempfile::tempdir().unwrap();
        let shim_path = d.path().join("ms-shim");
        std::fs::write(&shim_path, shim_bytes("new")).unwrap();
        let shim = brew::Shim::open(&shim_path, None).unwrap();
        let dir = d.path().join("shims");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("psql"), shim_bytes("old build")).unwrap();
        std::os::unix::fs::symlink(d.path().join("deleted/ms-shim"), dir.join("stripe")).unwrap();
        std::os::unix::fs::symlink(d.path().join("deleted/other"), dir.join("aws")).unwrap();
        assert_eq!(shim.classify(&dir.join("psql")), Entry::Stale);
        assert_eq!(shim.classify(&dir.join("stripe")), Entry::Stale);
        assert_eq!(shim.classify(&dir.join("aws")), Entry::Foreign);
        let want: BTreeSet<String> = ["psql".into(), "stripe".into(), "aws".into()].into();
        let lines = sync_shims(&dir, &shim, &want).unwrap();
        assert!(lines.contains(&"updated psql".to_owned()), "{lines:?}");
        assert!(lines.contains(&"updated stripe".to_owned()), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.starts_with("skipped aws")),
            "{lines:?}"
        );
        assert_eq!(std::fs::read(dir.join("psql")).unwrap(), shim_bytes("new"));
    }
}
