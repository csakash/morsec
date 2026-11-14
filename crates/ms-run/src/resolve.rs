//! Finding the binary to run (SPEC D3).
//!
//! A bare name is looked up in a fixed, trusted search path, never in the agent's `PATH`. The
//! shim directory is skipped, and so is any file that is a hard link of a shim, so a call can't
//! loop back into morsec. The result must be a regular, executable file that is not group- or
//! world-writable, in a directory that isn't either.

use std::collections::HashSet;
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::RunError;

/// Where bare names are looked up, in order.
#[cfg(target_os = "macos")]
pub const TRUSTED_PATH: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
];
/// Where bare names are looked up, in order.
#[cfg(not(target_os = "macos"))]
pub const TRUSTED_PATH: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

/// Most entries read from a shim directory when looking for shim inodes.
const MAX_SHIM_ENTRIES: usize = 4096;

/// Resolves program names to absolute paths.
#[derive(Debug, Clone)]
pub struct Resolver {
    search: Vec<PathBuf>,
    shim_dirs: Vec<PathBuf>,
}

impl Resolver {
    /// [`TRUSTED_PATH`], skipping `<home>/.morsec/shims`.
    pub fn trusted(home: Option<&Path>) -> Self {
        Self::new(
            TRUSTED_PATH.iter().map(PathBuf::from).collect(),
            home.map(|h| vec![h.join(".morsec/shims")])
                .unwrap_or_default(),
        )
    }

    /// A resolver with an explicit search path (tests).
    pub fn new(search: Vec<PathBuf>, shim_dirs: Vec<PathBuf>) -> Self {
        Self { search, shim_dirs }
    }

    /// The search path as a `PATH` value for the child.
    pub fn path_var(&self) -> OsString {
        std::env::join_paths(&self.search).unwrap_or_default()
    }

    /// Resolves `argv0`: an absolute path is checked as is; a bare name is looked up in the
    /// search path. Returns the canonical path of the file.
    pub fn resolve(&self, argv0: &str) -> Result<PathBuf, RunError> {
        let shims = self.shim_inodes();
        if argv0.starts_with('/') {
            return self.check_file(Path::new(argv0), &shims);
        }
        if argv0.contains('/') {
            return Err(RunError::denied(format!(
                "morsec: {} is a relative path; morsec only runs bare tool names or absolute paths",
                crate::printable(argv0)
            )));
        }
        let shim_dirs: Vec<PathBuf> = self
            .shim_dirs
            .iter()
            .filter_map(|d| std::fs::canonicalize(d).ok())
            .collect();
        for dir in &self.search {
            let Ok(real_dir) = std::fs::canonicalize(dir) else {
                continue;
            };
            if shim_dirs.contains(&real_dir) {
                continue;
            }
            let cand = real_dir.join(argv0);
            match std::fs::metadata(&cand) {
                Ok(m) if shims.contains(&(m.dev(), m.ino())) => continue,
                Ok(_) => return self.check_file(&cand, &shims),
                Err(_) => continue,
            }
        }
        Err(RunError::denied(format!(
            "morsec: {} was not found in morsec's trusted search path ({}). Install it there, or allowlist it by absolute path",
            crate::printable(argv0),
            self.search
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        )))
    }

    /// (device, inode) of every file in the shim directories.
    fn shim_inodes(&self) -> HashSet<(u64, u64)> {
        let mut out = HashSet::new();
        for d in &self.shim_dirs {
            let Ok(rd) = std::fs::read_dir(d) else {
                continue;
            };
            for e in rd.flatten().take(MAX_SHIM_ENTRIES) {
                if let Ok(m) = std::fs::metadata(e.path()) {
                    out.insert((m.dev(), m.ino()));
                }
            }
        }
        out
    }

    fn check_file(&self, p: &Path, shims: &HashSet<(u64, u64)>) -> Result<PathBuf, RunError> {
        let refuse = |why: &str| {
            Err(RunError::denied(format!(
                "morsec: won't run {}: {why}",
                p.display()
            )))
        };
        let Ok(real) = std::fs::canonicalize(p) else {
            return refuse("it does not exist");
        };
        let Ok(m) = std::fs::metadata(&real) else {
            return refuse("it can't be read");
        };
        if !m.is_file() {
            return refuse("it is not a regular file");
        }
        if shims.contains(&(m.dev(), m.ino())) {
            return refuse("it is a morsec shim");
        }
        let mode = m.permissions().mode();
        if mode & 0o111 == 0 {
            return refuse("it is not executable");
        }
        if mode & 0o022 != 0 {
            return refuse("other users can modify it (group- or world-writable)");
        }
        if let Some(dir) = real.parent()
            && std::fs::metadata(dir).is_ok_and(|d| d.permissions().mode() & 0o022 != 0)
        {
            return refuse("its directory is group- or world-writable");
        }
        Ok(real)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RunErrorKind;

    fn exe(path: &Path, mode: u32) {
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // protects=bare names resolve only from the given search path, never the caller's PATH; the
    // shim directory and shim hard links are skipped; unsafe files are refused; fails_when=a
    // shim, a writable binary, a directory or a missing file resolves; no_claim=what policy
    // allows (ms-rules)
    #[test]
    fn resolves_safely() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let (bin, shims, early) = (base.join("bin"), base.join("shims"), base.join("early"));
        for p in [&bin, &shims, &early] {
            std::fs::create_dir(p).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        exe(&bin.join("tool"), 0o755);
        exe(&shims.join("ms-shim"), 0o755);
        std::fs::hard_link(shims.join("ms-shim"), shims.join("tool")).unwrap();
        // A shim hard link outside the shim dir (a copy of the link elsewhere) is skipped too.
        std::fs::hard_link(shims.join("ms-shim"), early.join("tool")).unwrap();
        exe(&bin.join("loose"), 0o777);
        std::fs::create_dir(bin.join("adir")).unwrap();
        exe(&bin.join("noexec"), 0o644);

        let r = Resolver::new(
            vec![shims.clone(), early.clone(), bin.clone()],
            vec![shims.clone()],
        );
        assert_eq!(r.resolve("tool").unwrap(), bin.join("tool"));
        assert_eq!(
            r.resolve(bin.join("tool").to_str().unwrap()).unwrap(),
            bin.join("tool")
        );
        for bad in ["loose", "adir", "noexec", "missing", "./tool", "bin/tool"] {
            let e = r.resolve(bad).unwrap_err();
            assert_eq!(e.kind, RunErrorKind::Denied, "{bad}: {e}");
        }
        let e = r.resolve(shims.join("tool").to_str().unwrap()).unwrap_err();
        assert!(e.message.contains("shim"), "{e}");

        // The caller's PATH plays no part.
        let only_shims = Resolver::new(vec![shims.clone()], vec![shims]);
        assert!(only_shims.resolve("tool").is_err());
        assert_eq!(
            r.path_var(),
            std::env::join_paths([base.join("shims"), early, bin]).unwrap()
        );
    }

    // protects=a binary in a group/world-writable directory is refused; fails_when=it resolves;
    // no_claim=same-user tampering with the user's own directories (OUT-4 residual)
    #[test]
    fn writable_directory_refused() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        exe(&open.join("t"), 0o755);
        let r = Resolver::new(vec![open], vec![]);
        assert!(r.resolve("t").is_err());
    }
}
