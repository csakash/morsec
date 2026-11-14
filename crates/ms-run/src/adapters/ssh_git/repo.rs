//! The repository config check for git runs with a morsec key (SPEC D6).
//!
//! Before git starts, msd lists the repository's effective config (no system or global config,
//! which the run turns off) and refuses the run if the repository's own files set anything but
//! data keys.

use std::ffi::OsString;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Longest the repository config check may take.
const CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Most config output read.
const MAX_CONFIG_OUTPUT: u64 = 1024 * 1024;

/// Config keys a repository's own files (`local`, `worktree`) may set for a git run with a
/// morsec key. Everything else refuses the run before git starts: the repository's config is
/// writable by the agent, and git keys that run programs (`remote.*.receivepack`, `alias.*`,
/// `protocol.*`, `remote.*.vcs`, filters, `core.*` commands) would run them inside the run's
/// process group, where they could use the run's SSH agent; keys that send traffic elsewhere or
/// pull in other files are refused too. Those are too many to list one by one, so this is an
/// allowlist of keys that hold data only.
pub(crate) fn allowed_repo_key(scope: &str, name: &str) -> bool {
    if scope != "local" && scope != "worktree" {
        return true;
    }
    let n = name.to_ascii_lowercase();
    const PLAIN: &[&str] = &[
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.symlinks",
        "core.autocrlf",
        "core.eol",
        "user.name",
        "user.email",
        "pull.rebase",
        "pull.ff",
        "push.default",
        "push.autosetupremote",
        "fetch.prune",
        "init.defaultbranch",
        "extensions.objectformat",
        "extensions.worktreeconfig",
        "core.excludesfile",
        "core.sparsecheckout",
        "core.sparsecheckoutcone",
        "core.untrackedcache",
        "core.commitgraph",
        "core.quotepath",
        "core.whitespace",
        "index.version",
        "feature.manyfiles",
        "gc.auto",
        "gc.autodetach",
        "maintenance.auto",
        "rerere.enabled",
        "status.showuntrackedfiles",
    ];
    if PLAIN.contains(&n.as_str()) {
        return true;
    }
    // remote.<name>.<key> and branch.<name>.<key>: the name may hold dots, the key is last.
    let last = n.rsplit('.').next().unwrap_or("");
    (n.starts_with("remote.")
        && [
            "url",
            "pushurl",
            "fetch",
            "tagopt",
            "prune",
            "mirror",
            "promisor",
            "partialclonefilter",
        ]
        .contains(&last))
        || (n.starts_with("branch.")
            && [
                "remote",
                "merge",
                "rebase",
                "pushremote",
                "description",
                "vscode-merge-base",
            ]
            .contains(&last))
        // Data for Git LFS (its programs are `filter.lfs.*`, which stay refused).
        || n.starts_with("lfs.")
}

/// The repository's effective git config, as `git config --list --show-scope --includes -z`
/// prints it, run in `cwd` with the run's git environment (no system or global config). A
/// failure or a timeout (an include pointing at a FIFO) is an error: callers fail closed.
pub(crate) fn read_config(
    git: &Path,
    cwd: &Path,
    env: &[(OsString, OsString)],
) -> Result<Vec<u8>, String> {
    const CANT: &str = "the repository's git config could not be checked";
    let mut child = Command::new(git)
        .args(["config", "--list", "--show-scope", "--includes", "-z"])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CANT.to_owned())?;
    // Read on a thread so a hung git can't block msd.
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut raw = Vec::new();
        if let Some(out) = stdout {
            let _ = out.take(MAX_CONFIG_OUTPUT).read_to_end(&mut raw);
        }
        raw
    });
    let deadline = Instant::now() + CONFIG_CHECK_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let raw = reader.join().unwrap_or_default();
    if status.is_some_and(|s| s.success()) {
        Ok(raw)
    } else {
        Err(CANT.to_owned())
    }
}

/// Why `raw` (from [`read_config`]) is unsafe for a run with a morsec key, if it is: any key in
/// the repository's own files outside [`allowed_repo_key`].
pub(crate) fn config_violation(raw: &[u8]) -> Option<String> {
    let mut fields = raw.split(|b| *b == 0);
    let mut bad = Vec::new();
    while let (Some(scope), Some(entry)) = (fields.next(), fields.next()) {
        let scope = String::from_utf8_lossy(scope);
        let name_bytes = entry.split(|b| *b == b'\n').next().unwrap_or_default();
        let name = String::from_utf8_lossy(name_bytes);
        if !allowed_repo_key(&scope, &name) && bad.len() < 3 {
            bad.push(
                name.chars()
                    .take(80)
                    .flat_map(char::escape_default)
                    .collect::<String>(),
            );
        }
    }
    if bad.is_empty() {
        None
    } else {
        Some(format!(
            "the repository's git config sets {} (with a morsec key a repository may set only data keys such as remote.<name>.url and branch.<name>.merge: others can run programs inside the run); remove them from .git/config",
            bad.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D6 (review R1/R10): the repository's own config may hold only data keys;
    // keys that run programs (receivepack, uploadpack, vcs, alias, protocol, filters, core
    // commands), route traffic (http, proxy, url) or pull in files are refused; common data keys
    // editors and LFS write pass; command-line keys (morsec's own) pass; fails_when=one of those
    // passes or a plain repository is refused; no_claim=-
    #[test]
    fn repo_config_allowlist() {
        for ok in [
            "core.repositoryformatversion",
            "core.bare",
            "remote.origin.url",
            "remote.my.fork.fetch",
            "branch.main.merge",
            "branch.main.description",
            "branch.main.vscode-merge-base",
            "lfs.repositoryformatversion",
            "user.email",
        ] {
            assert!(allowed_repo_key("local", ok), "{ok}");
        }
        for bad in [
            "http.sslVerify",
            "Credential.https://x.helper",
            "includeIf.gitdir:/x.path",
            "remote.origin.proxy",
            "remote.origin.receivepack",
            "remote.origin.uploadpack",
            "remote.origin.vcs",
            "protocol.ext.allow",
            "alias.c",
            "url.https://x.insteadof",
            "submodule.a.url",
            "filter.lfs.clean",
            "core.sshcommand",
            "core.askpass",
            "core.pager",
            "gpg.program",
        ] {
            assert!(!allowed_repo_key("worktree", bad), "{bad}");
        }
        assert!(allowed_repo_key("command", "credential.helper"));
    }

    // protects=the check reads real git output and names the offending key; a self-erasing key
    // present before git starts is caught here; fails_when=a program-running key passes;
    // no_claim=-
    #[test]
    fn reads_real_config() {
        let git = Path::new("/usr/bin/git");
        if !git.exists() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let env: Vec<(OsString, OsString)> = vec![
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ];
        let run = |a: &[&str]| {
            assert!(
                Command::new(git)
                    .args(a)
                    .current_dir(d.path())
                    .envs(env.clone())
                    .status()
                    .unwrap()
                    .success()
            );
        };
        run(&["init", "-q"]);
        let raw = read_config(git, d.path(), &env).unwrap();
        assert_eq!(config_violation(&raw), None);
        run(&[
            "config",
            "--local",
            "alias.x",
            "!sh -c 'git config --unset alias.x'",
        ]);
        let raw = read_config(git, d.path(), &env).unwrap();
        assert!(config_violation(&raw).unwrap().contains("alias.x"));
    }
}
