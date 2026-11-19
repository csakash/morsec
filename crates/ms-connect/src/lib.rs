//! Agent connectors: write and remove the settings each coding agent needs.
//!
//! L00 freezes [`Connector`] and ships [`fake::FakeConnector`]. Claude Code (L08), Codex (L13),
//! Cursor and Gemini CLI (L22) implement it.

use std::path::PathBuf;

use ms_core::Result;

/// Whether the agent is installed and where its settings live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The agent was found.
    pub installed: bool,
    /// Settings files the connector manages.
    pub config_paths: Vec<PathBuf>,
}

/// Inputs for a connector plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectCfg {
    /// Proxy port of the broker.
    pub proxy_port: u16,
    /// Hosts some key or rule allows.
    pub allowed_domains: Vec<String>,
    /// Env vars to set (name, value). Values are references or proxy settings, never secrets.
    pub env: Vec<(String, String)>,
    /// Directory of run-mode shims to put first on `PATH`.
    pub shim_dir: Option<PathBuf>,
}

/// One file change a connector would make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// File.
    pub path: PathBuf,
    /// Content before (None if the file does not exist).
    pub before: Option<String>,
    /// Content after.
    pub after: String,
}

/// The full set of changes, shown to the user before `apply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// Changes in order.
    pub changes: Vec<FileChange>,
}

/// One `ms doctor` check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// Passed.
    pub ok: bool,
    /// Detail or fix.
    pub detail: String,
}

/// A coding-agent connector. `apply` and `remove` must be idempotent, and `remove` restores the
/// original files exactly.
pub trait Connector: Send + Sync {
    /// Stable id, e.g. `claude-code`.
    fn id(&self) -> &'static str;
    /// Finds the agent and its settings.
    fn detect(&self) -> Detection;
    /// Computes the changes for `cfg` without writing anything.
    fn plan(&self, cfg: &ConnectCfg) -> ConfigDiff;
    /// Writes a plan.
    fn apply(&self, diff: &ConfigDiff) -> Result<()>;
    /// Removes everything this connector added.
    fn remove(&self) -> Result<()>;
    /// Checks for `ms doctor`.
    fn verify(&self) -> Vec<Check>;
}

pub mod claude;
pub mod codex;
pub mod view;

/// Whether `dir` may hold the `ms` that agent settings run at every session start (outside the
/// sandbox): not under `home` or `cwd` (a repo checkout or a temp dir could repoint it), and no
/// one but its owner (the user `uid` or root) can write it. Used by `ms connect` (`ms_path`) and
/// by msd for the dashboard's Connect (L35 SPEC D-6). `home` is `None` to skip that part (debug
/// msd runs from `target/debug`).
pub fn stable_dir(
    dir: &std::path::Path,
    home: Option<&std::path::Path>,
    cwd: Option<&std::path::Path>,
    uid: u32,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(cd) = std::fs::canonicalize(dir) else {
        return false;
    };
    let under = |base: Option<&std::path::Path>| base.is_some_and(|b| cd.starts_with(b));
    !under(home)
        && !under(cwd)
        && std::fs::metadata(&cd)
            .is_ok_and(|m| m.mode() & 0o022 == 0 && (m.uid() == uid || m.uid() == 0))
}

/// Fake connector for tests.
pub mod fake {
    use std::sync::Mutex;

    use ms_core::Result;

    use crate::{Check, ConfigDiff, ConnectCfg, Connector, Detection};

    /// Records applies and removes; `verify` reports whether it is currently applied.
    #[derive(Debug, Default)]
    pub struct FakeConnector {
        applied: Mutex<bool>,
    }

    impl FakeConnector {
        /// A fresh fake, not applied.
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Connector for FakeConnector {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn detect(&self) -> Detection {
            Detection {
                installed: true,
                config_paths: vec![],
            }
        }
        fn plan(&self, _cfg: &ConnectCfg) -> ConfigDiff {
            ConfigDiff::default()
        }
        fn apply(&self, _diff: &ConfigDiff) -> Result<()> {
            *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = true;
            Ok(())
        }
        fn remove(&self) -> Result<()> {
            *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = false;
            Ok(())
        }
        fn verify(&self) -> Vec<Check> {
            let ok = *self.applied.lock().unwrap_or_else(|e| e.into_inner());
            vec![Check {
                name: "fake connected".into(),
                ok,
                detail: String::new(),
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeConnector;
    use super::*;

    // protects=apply/remove toggle what verify reports, through &dyn Connector; fails_when=verify
    // disagrees with the last apply/remove; no_claim=any real agent settings file
    #[test]
    fn apply_remove_verify() {
        let f = FakeConnector::new();
        let d: &dyn Connector = &f;
        assert_eq!(d.id(), "fake");
        assert!(!d.verify()[0].ok);
        d.apply(&d.plan(&ConnectCfg::default())).unwrap();
        assert!(d.verify()[0].ok);
        d.remove().unwrap();
        assert!(!d.verify()[0].ok);
    }
}
