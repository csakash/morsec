//! Connector settings drift (PLAN §3.3): an agent that edits its own settings to skip the proxy
//! never had a value, so nothing leaks, but the user should know. msd hashes the connector
//! settings files at start and raises an alert when one changes. L08/L13 refine the list.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::daemon::Daemon;

/// How often the files are checked.
pub const INTERVAL: Duration = Duration::from_secs(10);
/// Largest file hashed; bigger files count as changed when their size changes.
const MAX_BYTES: u64 = 4 << 20;

/// The connector settings files watched, under `home`.
pub fn watched(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".claude/settings.json"),
        home.join(".codex/config.toml"),
    ]
}

/// A fingerprint of `p`: `None` when missing.
pub fn fingerprint(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if m.len() > MAX_BYTES {
        return Some(format!("size:{}", m.len()));
    }
    let bytes = std::fs::read(p).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Compares the current fingerprints with `seen`, updates `seen`, and returns the changed paths.
pub fn changed(seen: &mut [(PathBuf, Option<String>)]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (p, fp) in seen.iter_mut() {
        let now = fingerprint(p);
        if now != *fp {
            out.push(p.clone());
            *fp = now;
        }
    }
    out
}

/// Polls until `shutdown`.
pub async fn watch_loop(d: Arc<Daemon>, home: PathBuf, mut shutdown: watch::Receiver<bool>) {
    let mut seen: Vec<(PathBuf, Option<String>)> = watched(&home)
        .into_iter()
        .map(|p| {
            let fp = fingerprint(&p);
            (p, fp)
        })
        .collect();
    loop {
        tokio::select! {
            () = tokio::time::sleep(INTERVAL) => {},
            _ = shutdown.changed() => return,
        }
        for p in changed(&mut seen) {
            tracing::warn!(path = %p.display(), "connector settings changed");
            d.alert(format!(
                "{} changed while morsec was running; check that the agent still routes through morsec (ms doctor)",
                p.display()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=a change, creation or removal of a watched file is reported once; an untouched
    // file is not; fails_when=drift goes unnoticed or is reported every poll; no_claim=edits that
    // restore the exact original bytes between two polls
    #[test]
    fn detects_changes_once() {
        let d = tempfile::tempdir().unwrap();
        let files = watched(d.path());
        std::fs::create_dir_all(files[0].parent().unwrap()).unwrap();
        std::fs::write(&files[0], b"{}").unwrap();
        let mut seen: Vec<_> = files.iter().map(|p| (p.clone(), fingerprint(p))).collect();
        assert!(changed(&mut seen).is_empty());
        std::fs::write(&files[0], br#"{"env":{}}"#).unwrap();
        assert_eq!(changed(&mut seen), [files[0].clone()]);
        assert!(changed(&mut seen).is_empty());
        std::fs::create_dir_all(files[1].parent().unwrap()).unwrap();
        std::fs::write(&files[1], b"x").unwrap();
        std::fs::remove_file(&files[0]).unwrap();
        assert_eq!(changed(&mut seen).len(), 2);
    }
}
