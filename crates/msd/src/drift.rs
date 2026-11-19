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

/// A fingerprint of `p`: `None` when missing. The file is opened without following a symlink and
/// without blocking, must be a regular file, and at most [`MAX_BYTES`] are read, so a planted
/// symlink to `/dev/zero` or a FIFO can't hang or exhaust msd. Anything else is fingerprinted by
/// its type, so a swap still counts as a change. An oversized file is fingerprinted by the hash
/// of its first [`MAX_BYTES`] and its size, and one that can't be read by the error's kind, its
/// inode and its modification time, so an edit to either still counts as a change (review N10).
pub fn fingerprint(p: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.file_type().is_file() {
        return Some(format!("not-a-file:{:?}", m.file_type()));
    }
    let unreadable = |e: std::io::Error| {
        Some(format!(
            "unreadable:{:?}:{}:{}.{}:{}",
            e.kind(),
            m.ino(),
            m.mtime(),
            m.mtime_nsec(),
            m.size()
        ))
    };
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
    {
        Ok(f) => f,
        Err(e) => return unreadable(e),
    };
    match f.metadata() {
        Ok(fm) if fm.is_file() => {}
        Ok(_) => return Some("not-a-file".into()),
        Err(e) => return unreadable(e),
    }
    let mut bytes = Vec::new();
    if let Err(e) = f.take(MAX_BYTES + 1).read_to_end(&mut bytes) {
        return unreadable(e);
    }
    if bytes.len() as u64 > MAX_BYTES {
        bytes.truncate(MAX_BYTES as usize);
        return Some(format!(
            "size>{MAX_BYTES}:{}:{}",
            m.size(),
            hex::encode(Sha256::digest(&bytes))
        ));
    }
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
        let checked = {
            let mut s = std::mem::take(&mut seen);
            match tokio::task::spawn_blocking(move || {
                let c = changed(&mut s);
                (s, c)
            })
            .await
            {
                Ok((s, c)) => {
                    seen = s;
                    c
                }
                Err(_) => return,
            }
        };
        for p in checked {
            tracing::warn!(path = %p.display(), "connector settings changed");
            let fingerprint = seen
                .iter()
                .find(|(q, _)| *q == p)
                .and_then(|(_, f)| f.clone());
            d.alert(
                crate::daemon::AlertKind::SettingsChanged {
                    path: p.clone(),
                    fingerprint,
                },
                format!(
                    "{} changed while morsec was running; check that the agent still routes through morsec (ms doctor)",
                    p.display()
                ),
            );
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
        // A symlink to a device is reported as a change, never read.
        std::os::unix::fs::symlink("/dev/zero", &files[0]).unwrap();
        assert_eq!(changed(&mut seen), [files[0].clone()]);
        assert!(fingerprint(&files[0]).unwrap().starts_with("not-a-file"));
    }

    // protects=review N10: an oversized watched file and one msd can't read still show a change
    // when they are edited: the oversized one by the hash of its first MAX_BYTES and its size,
    // the unreadable one by error kind, inode and modification time; fails_when=two different
    // oversized files, or an unreadable file before and after an edit, fingerprint the same;
    // no_claim=edits past MAX_BYTES that keep the size (residual: the file is not a settings
    // file any agent writes at that size)
    #[test]
    fn oversized_and_unreadable_files_still_drift() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("big.json");
        let mut big = vec![b'a'; MAX_BYTES as usize + 10];
        std::fs::write(&p, &big).unwrap();
        let a = fingerprint(&p).unwrap();
        assert!(a.starts_with("size>"), "{a}");
        big[0] = b'b';
        std::fs::write(&p, &big).unwrap();
        let b = fingerprint(&p).unwrap();
        assert_ne!(a, b, "an edit in the first MAX_BYTES");
        big.push(b'c');
        std::fs::write(&p, &big).unwrap();
        assert_ne!(fingerprint(&p).unwrap(), b, "a size change");

        let q = d.path().join("locked.json");
        std::fs::write(&q, b"{}").unwrap();
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o000)).unwrap();
        let first = fingerprint(&q).unwrap();
        // Root can read it anyway; then the plain hash is the fingerprint.
        if first.starts_with("unreadable:") {
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&q, b"{\"env\":{}}").unwrap();
            std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o000)).unwrap();
            let second = fingerprint(&q).unwrap();
            assert!(second.starts_with("unreadable:"));
            assert_ne!(first, second, "an edit to an unreadable file");
        }
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
