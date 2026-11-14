//! Reading and writing agent settings files safely (SPEC D8, "Writes").

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Largest settings file read.
pub const MAX_BYTES: u64 = 4 << 20;

/// Reads `p` as UTF-8 text. `Ok(None)` when it does not exist. Refuses a symlink, anything but a
/// regular file, a file over [`MAX_BYTES`] and non-UTF-8 content. The open never follows a
/// symlink and never blocks (a planted FIFO can't hang `ms`).
pub fn read_text(p: &Path) -> Result<Option<String>, String> {
    read_capped(p, MAX_BYTES)
}

/// [`read_text`] with a size cap.
pub fn read_capped(p: &Path, cap: u64) -> Result<Option<String>, String> {
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink. morsec won't edit through a link (it would replace the link with a file). Point it at the real file, or connect with the real file in place",
            p.display()
        ));
    }
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    let mut bytes = Vec::new();
    f.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if bytes.len() as u64 > cap {
        return Err(format!(
            "{} is larger than {} KiB; morsec won't edit it",
            p.display(),
            cap / 1024
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("{} is not UTF-8 text", p.display()))
}

/// Creates `dir` (and parents) with mode 0700 for any directory it creates.
pub fn ensure_dir(dir: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))
}

/// Writes `text` to `p` atomically: a new temp file in the same directory, fsync, rename. Keeps
/// the mode of an existing regular file; new files get `new_mode`. The rename replaces whatever
/// is at `p` without following it.
pub fn atomic_write(p: &Path, text: &str, new_mode: u32) -> Result<(), String> {
    let dir = p
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", p.display()))?;
    ensure_dir(dir)?;
    let mode = std::fs::symlink_metadata(p)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map_or(new_mode, |m| m.permissions().mode() & 0o7777);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp: PathBuf = dir.join(format!(".{name}.morsec-{}.tmp", std::process::id()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&tmp, p)?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok::<(), std::io::Error>(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", p.display()));
    }
    Ok(())
}

/// Removes `p` if it exists (never follows a link: removes the link itself).
pub fn remove(p: &Path) -> Result<(), String> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D8: a symlinked or non-regular settings file is refused, never followed;
    // fails_when=read_text follows the link or opens the FIFO; no_claim=races after the check
    #[test]
    fn refuses_links_and_specials() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.json");
        std::fs::write(&real, "{}").unwrap();
        let link = d.path().join("settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_text(&link).unwrap_err().contains("symlink"));
        let fifo = d.path().join("fifo");
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(read_text(&fifo).unwrap_err().contains("not a regular file"));
        assert!(
            read_text(d.path())
                .unwrap_err()
                .contains("not a regular file")
        );
        assert_eq!(read_text(&d.path().join("missing")).unwrap(), None);
    }

    #[test]
    fn refuses_big_and_binary() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        std::fs::write(&p, vec![b' '; 2048]).unwrap();
        assert!(read_capped(&p, 1024).unwrap_err().contains("larger"));
        std::fs::write(&p, [0xff, 0xfe]).unwrap();
        assert!(read_text(&p).unwrap_err().contains("UTF-8"));
    }

    // protects=atomic writes keep an existing file's mode, give new files 0600, and replace a
    // planted symlink instead of writing through it; fails_when=mode changes or the link target
    // is written
    #[test]
    fn atomic_write_modes_and_links() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/new.json");
        atomic_write(&p, "{}", 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write(&p, "{\"a\":1}", 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let target = d.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        atomic_write(&link, "new", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(&link).unwrap().is_file());
    }
}
