//! The short-lived passfile (SPEC D2).
//!
//! libpq reads the password from the file `PGPASSFILE` names, so the password never has to be
//! in argv or the environment. The file lives in a fresh 0700 directory under a 0700
//! `morsec-pg` directory in msd's temp dir, is created `O_EXCL` with mode 0600, and is removed
//! (after being overwritten) as soon as it has been read: its access time is set to the epoch
//! after writing and a watcher removes it the moment the access time changes. libpq reads the
//! file once, while it sets up the connection and before any statement runs. If nothing reads
//! it, it goes after [`TTL`]; it also goes when the [`Passfile`] is dropped (the run ended), and
//! stale ones from an earlier msd are swept the first time one is made.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

/// Longest a passfile lives when nothing reads it.
pub const TTL: Duration = Duration::from_secs(15);
/// How often the watcher looks at the access time while a read is most likely (libpq reads the
/// file right after the program starts), and afterwards.
const POLL_FAST: Duration = Duration::from_millis(1);
const POLL_SLOW: Duration = Duration::from_millis(10);
const FAST_FOR: Duration = Duration::from_secs(3);
/// Name of the parent directory in the temp dir.
const PARENT: &str = "morsec-pg";

/// One passfile. Dropping it removes the file.
pub struct Passfile {
    shared: Arc<Shared>,
}

struct Shared {
    path: PathBuf,
    dir: Mutex<Option<tempfile::TempDir>>,
}

impl std::fmt::Debug for Passfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passfile")
            .field("path", &self.shared.path)
            .finish()
    }
}

impl crate::context::RunGuard for Passfile {}

/// Escapes one passfile field (`\` and `:`).
fn field(s: &[u8], out: &mut Zeroizing<Vec<u8>>) {
    for &b in s {
        if b == b'\\' || b == b':' {
            out.push(b'\\');
        }
        out.push(b);
    }
}

/// The passfile line: `host:*:*:user:password`.
pub fn line(host: &str, user: Option<&str>, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if password.iter().any(|&b| b == b'\n' || b == b'\r' || b == 0) {
        return Err(
            "the key's password contains a line break or NUL, which a passfile can't hold".into(),
        );
    }
    let mut out = Zeroizing::new(Vec::with_capacity(host.len() + password.len() * 2 + 64));
    if host == "*" {
        out.push(b'*');
    } else {
        field(host.as_bytes(), &mut out);
    }
    out.extend_from_slice(b":*:*:");
    match user {
        Some(u) => field(u.as_bytes(), &mut out),
        None => out.push(b'*'),
    }
    out.push(b':');
    field(password, &mut out);
    out.push(b'\n');
    Ok(out)
}

/// The `morsec-pg` parent: created 0700, or checked to be a real directory of ours that only we
/// can use. Stale entries from an earlier msd are swept once per process.
fn parent() -> Result<PathBuf, String> {
    let p = std::env::temp_dir().join(PARENT);
    ensure_private_dir(&p)?;
    static SWEEP: Once = Once::new();
    SWEEP.call_once(|| {
        if let Ok(entries) = std::fs::read_dir(&p) {
            for e in entries.flatten() {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    });
    Ok(p)
}

/// Creates `p` 0700, or checks that it is a real directory (not a link) owned by this user and
/// closed to everyone else.
fn ensure_private_dir(p: &Path) -> Result<(), String> {
    match DirBuilder::new().mode(0o700).create(p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("could not create {}: {e}", p.display())),
    }
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let me = rustix::process::getuid().as_raw();
    if !m.file_type().is_dir() || m.uid() != me || m.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} is not a private directory of this user (a link, someone else's, or open to others), so morsec won't put a password there",
            p.display()
        ));
    }
    Ok(())
}

impl Passfile {
    /// Writes `contents` to a new passfile and starts its watcher.
    pub fn create(contents: &[u8]) -> Result<Self, String> {
        Self::create_in(&parent()?, contents)
    }

    fn create_in(parent: &Path, contents: &[u8]) -> Result<Self, String> {
        let dir = tempfile::Builder::new()
            .prefix("p-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .map_err(|e| format!("could not make a passfile directory: {e}"))?;
        let path = dir.path().join("pgpass");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|e| format!("could not create the passfile: {e}"))?;
        f.write_all(contents)
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("could not write the passfile: {e}"))?;
        // Reading the file later moves the access time off the epoch: that's the signal.
        f.set_times(std::fs::FileTimes::new().set_accessed(SystemTime::UNIX_EPOCH))
            .map_err(|e| format!("could not set the passfile's times: {e}"))?;
        drop(f);
        let shared = Arc::new(Shared {
            path,
            dir: Mutex::new(Some(dir)),
        });
        let w = shared.clone();
        std::thread::Builder::new()
            .name("ms-pg-passfile".into())
            .spawn(move || watch(&w))
            .map_err(|e| format!("could not start the passfile watcher: {e}"))?;
        Ok(Self { shared })
    }

    /// The file's path, for `PGPASSFILE`.
    pub fn path(&self) -> &Path {
        &self.shared.path
    }
}

fn watch(s: &Shared) {
    let start = Instant::now();
    loop {
        std::thread::sleep(if start.elapsed() < FAST_FOR {
            POLL_FAST
        } else {
            POLL_SLOW
        });
        if s.dir.lock().map(|d| d.is_none()).unwrap_or(true) {
            return;
        }
        let read = std::fs::symlink_metadata(&s.path)
            .map(|m| m.atime() != 0 || m.atime_nsec() != 0)
            .unwrap_or(true);
        if read || start.elapsed() >= TTL {
            s.remove();
            return;
        }
    }
}

impl Shared {
    /// Overwrites the file with zeros and removes its directory. Idempotent.
    fn remove(&self) {
        let Ok(mut guard) = self.dir.lock() else {
            return;
        };
        let Some(dir) = guard.take() else { return };
        if let Ok(m) = std::fs::symlink_metadata(&self.path)
            && m.file_type().is_file()
            && let Ok(mut f) = OpenOptions::new()
                .write(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&self.path)
        {
            let len = usize::try_from(m.len()).unwrap_or(0);
            let _ = f
                .write_all(&vec![0u8; len])
                .and_then(|()| File::sync_all(&f));
        }
        if let Err(e) = dir.close() {
            tracing::warn!(error = %e, "could not remove a passfile directory");
        }
    }
}

impl Drop for Passfile {
    fn drop(&mut self) {
        self.shared.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // protects=SPEC D2: the passfile line escapes ':' and '\' and refuses a password libpq
    // couldn't read back; fails_when=a field can spill into the next one; no_claim=-
    #[test]
    fn line_escapes() {
        let l = line("db", Some("a:b"), b"p\\w:d").unwrap();
        assert_eq!(&l[..], b"db:*:*:a\\:b:p\\\\w\\:d\n");
        assert_eq!(&line("*", None, b"x").unwrap()[..], b"*:*:*:*:x\n");
        assert!(line("h", None, b"a\nb").is_err());
    }

    // protects=SPEC D2: the file is 0600 in a 0700 directory, is removed right after the first
    // read, and on drop when nothing read it; fails_when=it is readable by others or outlives
    // its read; no_claim=libpq's own reading (live tests)
    #[test]
    fn removed_after_first_read_and_on_drop() {
        let top = tempfile::tempdir().unwrap();
        let pf = Passfile::create_in(top.path(), b"h:*:*:u:pw\n").unwrap();
        let path = pf.path().to_path_buf();
        let m = std::fs::metadata(&path).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        let dm = std::fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(dm.permissions().mode() & 0o777, 0o700);
        std::thread::sleep(Duration::from_millis(50));
        assert!(path.exists(), "removed before anything read it");
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "h:*:*:u:pw\n");
        let deadline = Instant::now() + Duration::from_secs(2);
        while path.exists() {
            assert!(Instant::now() < deadline, "still there after it was read");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!path.parent().unwrap().exists());
        drop(pf);

        let pf = Passfile::create_in(top.path(), b"x").unwrap();
        let path = pf.path().to_path_buf();
        drop(pf);
        assert!(!path.exists() && !path.parent().unwrap().exists());
    }

    // protects=SPEC D2: a `morsec-pg` parent that isn't a private directory of ours is refused;
    // fails_when=a group/world-accessible or linked parent is used; no_claim=another user's
    // directory (needs a second account)
    #[test]
    fn parent_must_be_private() {
        let top = tempfile::tempdir().unwrap();
        let fresh = top.path().join("fresh");
        ensure_private_dir(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let open = top.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(ensure_private_dir(&open).is_err());
        let link = top.path().join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
    }
}
