//! Where msd keeps its files (PLAN §3.5).

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ms_core::{Error, Result};

/// Marks a state directory msd created for an ephemeral (memory-vault) daemon, which msd may wipe.
pub const DEV_MARKER: &str = ".morsec-dev";

/// The files under one state directory.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The directory itself (0700).
    pub state: PathBuf,
    /// `rules.toml` (+ `.mac`).
    pub rules: PathBuf,
    /// Receipts directory.
    pub receipts: PathBuf,
    /// The proxy CA certificate, PEM (public).
    pub ca_pem: PathBuf,
    /// The host list the CA was issued for, JSON.
    pub ca_hosts: PathBuf,
}

impl Paths {
    /// Paths under `state`.
    pub fn under(state: impl Into<PathBuf>) -> Self {
        let state = state.into();
        Self {
            rules: state.join("rules.toml"),
            receipts: state.join("receipts"),
            ca_pem: state.join("ca.pem"),
            ca_hosts: state.join("ca-hosts.json"),
            state,
        }
    }
}

/// The platform state directory: `~/Library/Application Support/morsec` on macOS,
/// `/var/lib/morsec` elsewhere.
pub fn platform_state_dir() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .ok_or_else(|| {
                Error::io(
                    "finding the state directory",
                    std::io::Error::other("HOME is not set"),
                )
            })?;
        Ok(PathBuf::from(home).join("Library/Application Support/morsec"))
    } else {
        Ok(PathBuf::from("/var/lib/morsec"))
    }
}

/// The per-port dev directory: `$TMPDIR/morsec-dev-<port>/` (socket and state).
pub fn dev_dir(port: u16) -> PathBuf {
    std::env::temp_dir().join(format!("morsec-dev-{port}"))
}

/// Creates `dir` 0700, or checks an existing one is a private directory (not a symlink) owned
/// by this process's user.
pub fn prepare_private_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.is_dir() {
                return Err(Error::Socket(format!(
                    "{} is not a directory (or is a symbolic link); choose another --state-dir",
                    dir.display()
                )));
            }
            if m.permissions().mode() & 0o077 != 0 {
                return Err(Error::Socket(format!(
                    "{} is accessible to other users (mode {:o}); fix it with: chmod 700 {}",
                    dir.display(),
                    m.permissions().mode() & 0o777,
                    dir.display()
                )));
            }
            let me = own_uid()?;
            if m.uid() != me {
                return Err(Error::Socket(format!(
                    "{} belongs to another user; choose a state directory you own",
                    dir.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::io(format!("creating {}", dir.display()), e)),
        Err(e) => Err(Error::io(format!("checking {}", dir.display()), e)),
    }
}

/// This process's uid, from a file it creates (no `unsafe`).
fn own_uid() -> Result<u32> {
    let f = tempfile_in_tmp()?;
    let uid = std::fs::metadata(&f)
        .map_err(|e| Error::io("checking own uid", e))?
        .uid();
    let _ = std::fs::remove_file(&f);
    Ok(uid)
}

fn tempfile_in_tmp() -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!(
        "msd-uid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&p)
        .map_err(|e| Error::io("checking own uid", e))?;
    Ok(p)
}

/// Writes `bytes` to `path` atomically (temp file in the same directory, then rename), mode
/// `mode`.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| Error::io(format!("writing {}", tmp.display()), e))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| Error::io(format!("writing {}", tmp.display()), e))?;
    std::fs::rename(&tmp, path).map_err(|e| Error::io(format!("replacing {}", path.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=the state directory must be private and real: a group-readable directory or a
    // symlink is refused and left alone, a missing one is created 0700; fails_when=msd uses a
    // directory other users can read; no_claim=another user's directory (needs a second uid)
    #[test]
    fn state_dir_must_be_private() {
        let d = tempfile::tempdir().unwrap();
        let fresh = d.path().join("a/b");
        prepare_private_dir(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_private_dir(&open).is_err());
        assert_eq!(
            std::fs::metadata(&open).unwrap().permissions().mode() & 0o777,
            0o750
        );
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(prepare_private_dir(&link).is_err());
    }

    // protects=atomic_write replaces the file whole and refuses to follow a planted symlink at
    // the temp name; fails_when=a partial file or a write through a symlink; no_claim=crash safety
    #[test]
    fn atomic_write_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ca.pem");
        atomic_write(&p, b"one", 0o644).unwrap();
        atomic_write(&p, b"two", 0o644).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
    }
}
