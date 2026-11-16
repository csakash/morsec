//! Homebrew install paths that survive `brew upgrade` (launchagent-opt-path).
//!
//! Homebrew installs each version in its own keg, `<prefix>/Cellar/morsec/<version>`, and keeps
//! a stable link to the current one, `<prefix>/opt/morsec -> ../Cellar/morsec/<version>`.
//! `brew upgrade` deletes the old keg, so anything that names a keg path (msd's LaunchAgent, the
//! run shims) breaks. This module derives the stable `opt` path from a binary's canonical path,
//! without running `brew` and without reading the environment, and checks that the `opt` link
//! really points at that same file. Anything it can't prove falls back to the canonical path.
//!
//! The process launchd or a shell starts through the `opt` path is the very same signed file in
//! the keg (the kernel resolves the symlink), so the keychain ACL and `ms`'s check of msd's
//! signature, both keyed on the designated requirement, see no difference.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// The formula's name, as it appears in `Cellar/<name>` and `opt/<name>`.
const FORMULA: &str = "morsec";

/// The Homebrew prefix and version when `real` is `<prefix>/Cellar/morsec/<version>/bin/<tool>`.
/// Purely lexical: nothing is read from disk.
pub(crate) fn keg_of(real: &Path) -> Option<(&Path, &str)> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    let mut p = real;
    // Walk up five components: <tool>, bin, <version>, morsec, Cellar.
    for _ in 0..5 {
        match p.components().next_back()? {
            Component::Normal(s) => parts.push(s),
            _ => return None,
        }
        p = p.parent()?;
    }
    let [tool, bin, version, formula, cellar] = parts[..] else {
        return None;
    };
    let version = version.to_str()?;
    if bin != "bin"
        || formula != FORMULA
        || cellar != "Cellar"
        || tool.is_empty()
        || version.is_empty()
        || !p.is_absolute()
    {
        return None;
    }
    Some((p, version))
}

/// `<prefix>/opt/morsec/bin/<tool>` for a keg binary at canonical path `real`, only when that
/// path resolves to exactly `real` (the `opt` link points at this keg). `None` otherwise: not a
/// Homebrew keg, no `opt` link (a custom `HOMEBREW_CELLAR`), or `opt` on another version.
///
/// Defence in depth: `<prefix>/opt` and the `opt/morsec` link must belong to this user or root
/// and `opt` must not be group- or world-writable, so another user can't repoint the link later.
/// (The keg itself sits in the same prefix, so this asks no more of `opt` than of the keg.)
pub(crate) fn stable_path(real: &Path) -> Option<PathBuf> {
    let (prefix, _) = keg_of(real)?;
    let tool = real.file_name()?;
    let opt = prefix.join("opt");
    let link = opt.join(FORMULA);
    let uid = rustix::process::getuid().as_raw();
    let owned = |m: &std::fs::Metadata| m.uid() == uid || m.uid() == 0;
    let opt_meta = std::fs::symlink_metadata(&opt).ok()?;
    let link_meta = std::fs::symlink_metadata(&link).ok()?;
    if !opt_meta.is_dir() || !owned(&opt_meta) || opt_meta.mode() & 0o022 != 0 || !owned(&link_meta)
    {
        return None;
    }
    let stable = link.join("bin").join(tool);
    let resolved = std::fs::canonicalize(&stable).ok()?;
    (resolved == real).then_some(stable)
}

/// The path to record for a binary whose canonical path is `real`: the stable `opt` path in a
/// Homebrew install, else `real` itself (a dev build or a manual install keeps its path).
pub(crate) fn preferred(real: &Path) -> PathBuf {
    stable_path(real).unwrap_or_else(|| real.to_path_buf())
}

/// A morsec tool installed next to this `ms`: `(canonical path, path to record)`.
pub(crate) fn sibling(tool: &str) -> std::io::Result<(PathBuf, PathBuf)> {
    let me = std::fs::canonicalize(std::env::current_exe()?)?;
    let real = me.with_file_name(tool);
    let pref = preferred(&real);
    Ok((real, pref))
}

/// Text every `ms-shim` build carries (its own-name usage message, `ms_run::SHIM_MARKER`). It
/// lets `--link-shims` recognise, and so replace, a shim left by an older version.
fn has_marker(bytes: &[u8]) -> bool {
    let exe_magic = [
        &[0xcf, 0xfa, 0xed, 0xfe][..], // Mach-O 64-bit
        &[0xca, 0xfe, 0xba, 0xbe][..], // universal
        b"\x7fELF",
    ];
    exe_magic.iter().any(|m| bytes.starts_with(m))
        && bytes
            .windows(ms_run::SHIM_MARKER.len())
            .any(|w| w == ms_run::SHIM_MARKER.as_bytes())
}

/// The installed `ms-shim`: where it is, its identity and bytes, and (Homebrew) the stable path
/// shims should link to.
pub(crate) struct Shim {
    pub(crate) real: PathBuf,
    pub(crate) stable: Option<PathBuf>,
    meta: std::fs::Metadata,
    bytes: Vec<u8>,
}

/// What a file in `~/.morsec/shims` is, relative to the installed `ms-shim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    /// The current `ms-shim`, linked the way this install wants (symlink to `opt` for
    /// Homebrew, hard link otherwise).
    Linked,
    /// The current `ms-shim`, but pinned to this version (a hard link or copy in a Homebrew
    /// install) or linked another way: it works now, it should be relinked.
    Pinned,
    /// A morsec shim, but not the current one (an older build, or a dangling link).
    Stale,
    /// Not a morsec shim: never touched.
    Foreign,
    /// Nothing there.
    Missing,
}

impl Shim {
    pub(crate) fn open(real: &Path, stable: Option<PathBuf>) -> std::io::Result<Self> {
        let meta = std::fs::metadata(real)?;
        let bytes = std::fs::read(real)?;
        Ok(Self {
            real: real.to_path_buf(),
            stable,
            meta,
            bytes,
        })
    }

    fn same_file(&self, m: &std::fs::Metadata) -> bool {
        (m.dev(), m.ino()) == (self.meta.dev(), self.meta.ino())
    }

    fn same_bytes(&self, p: &Path, m: &std::fs::Metadata) -> bool {
        m.is_file() && m.len() == self.meta.len() && std::fs::read(p).is_ok_and(|b| b == self.bytes)
    }

    /// The current `ms-shim` reached through `p` (following links), by identity or bytes.
    fn is_current(&self, p: &Path) -> bool {
        std::fs::metadata(p).is_ok_and(|m| self.same_file(&m) || self.same_bytes(p, &m))
    }

    pub(crate) fn classify(&self, p: &Path) -> Entry {
        let Ok(lm) = std::fs::symlink_metadata(p) else {
            return Entry::Missing;
        };
        if lm.file_type().is_symlink() {
            let target = std::fs::read_link(p).ok();
            if self.is_current(p) {
                return if self.stable.is_some() && target == self.stable {
                    Entry::Linked
                } else {
                    Entry::Pinned
                };
            }
            // Pointing at some other ms-shim (an old keg or dev build), or dangling at one.
            let names_shim = target
                .as_deref()
                .and_then(Path::file_name)
                .is_some_and(|n| n == "ms-shim");
            let marked = std::fs::read(p).is_ok_and(|b| has_marker(&b));
            return if marked || (names_shim && std::fs::metadata(p).is_err()) {
                Entry::Stale
            } else {
                Entry::Foreign
            };
        }
        if !lm.is_file() {
            return Entry::Foreign;
        }
        if self.same_file(&lm) || self.same_bytes(p, &lm) {
            // A hard link, or a copy where a link can't cross file systems, is right for a dev
            // or manual install; in a Homebrew install it is pinned to this version.
            return if self.stable.is_none() {
                Entry::Linked
            } else {
                Entry::Pinned
            };
        }
        if std::fs::read(p).is_ok_and(|b| has_marker(&b)) {
            Entry::Stale
        } else {
            Entry::Foreign
        }
    }

    /// Creates a shim at `at` (nothing may be there): a symlink to the stable path in a Homebrew
    /// install, else a hard link of `ms-shim`, or a copy when a link can't cross file systems.
    pub(crate) fn place(&self, at: &Path) -> Result<(), String> {
        if let Some(stable) = &self.stable {
            return std::os::unix::fs::symlink(stable, at)
                .map_err(|e| format!("morsec: can't create {}: {e}", at.display()));
        }
        if std::fs::hard_link(&self.real, at).is_ok() {
            return Ok(());
        }
        std::fs::copy(&self.real, at)
            .map(drop)
            .map_err(|e| format!("morsec: can't create {}: {e}", at.display()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake Homebrew prefix with `versions` installed as kegs, `opt/morsec` pointing at
    /// `current`. Each keg's `bin/` holds `ms`, `msd` and `ms-shim` with the given bytes.
    pub(crate) struct FakeBrew {
        _dir: tempfile::TempDir,
        pub(crate) prefix: PathBuf,
    }

    impl FakeBrew {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            // canonicalize: macOS temp dirs live behind the /var -> /private/var symlink.
            let prefix = std::fs::canonicalize(dir.path()).unwrap();
            Self { _dir: dir, prefix }
        }

        pub(crate) fn keg_bin(&self, version: &str) -> PathBuf {
            self.prefix.join("Cellar/morsec").join(version).join("bin")
        }

        pub(crate) fn install(&self, version: &str, shim_bytes: &[u8]) -> PathBuf {
            let bin = self.keg_bin(version);
            std::fs::create_dir_all(&bin).unwrap();
            for t in ["ms", "msd"] {
                std::fs::write(bin.join(t), format!("{t} {version}")).unwrap();
            }
            std::fs::write(bin.join("ms-shim"), shim_bytes).unwrap();
            bin
        }

        /// `brew link`/`brew upgrade`'s opt link: `opt/morsec -> ../Cellar/morsec/<version>`.
        pub(crate) fn point_opt(&self, version: &str) {
            let opt = self.prefix.join("opt");
            std::fs::create_dir_all(&opt).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&opt, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let link = opt.join("morsec");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(format!("../Cellar/morsec/{version}"), link).unwrap();
        }

        pub(crate) fn opt_bin(&self, tool: &str) -> PathBuf {
            self.prefix.join("opt/morsec/bin").join(tool)
        }

        pub(crate) fn uninstall(&self, version: &str) {
            std::fs::remove_dir_all(self.prefix.join("Cellar/morsec").join(version)).unwrap();
        }
    }

    /// Fake ms-shim bytes: a Mach-O header and the marker, like a real build.
    pub(crate) fn shim_bytes(build: &str) -> Vec<u8> {
        let mut b = vec![0xcf, 0xfa, 0xed, 0xfe];
        b.extend_from_slice(format!("build {build} ").as_bytes());
        b.extend_from_slice(ms_run::SHIM_MARKER.as_bytes());
        b
    }

    // protects=the keg path is recognised exactly and only for Cellar/morsec/<ver>/bin/<tool>;
    // fails_when=another formula, a `..` version, a relative path or a non-bin dir is a keg;
    // no_claim=what is on disk (stable_path)
    #[test]
    fn keg_paths() {
        let p = Path::new("/opt/homebrew/Cellar/morsec/1.2.3_1/bin/msd");
        assert_eq!(keg_of(p), Some((Path::new("/opt/homebrew"), "1.2.3_1")));
        for bad in [
            "/opt/homebrew/Cellar/other/1.0/bin/msd",
            "/opt/homebrew/Cellar/morsec/../bin/msd",
            "/opt/homebrew/Cellar/morsec/1.0/libexec/msd",
            "/opt/homebrew/Kegs/morsec/1.0/bin/msd",
            "Cellar/morsec/1.0/bin/msd",
            "/Cellar/morsec/1.0/bin/msd/..",
            "/Users/me/code/morsec/target/debug/msd",
            "/bin/msd",
        ] {
            assert_eq!(keg_of(Path::new(bad)), None, "{bad}");
        }
        // The shortest valid form: a prefix of `/`.
        assert_eq!(
            keg_of(Path::new("/Cellar/morsec/1.0/bin/ms")),
            Some((Path::new("/"), "1.0"))
        );
    }

    // protects=the opt path is used only when it resolves to this very keg file; fails_when=an
    // opt link to another version, a missing opt link or a dev path yields an opt path;
    // no_claim=brew itself (never run)
    #[test]
    fn stable_path_needs_opt_on_this_keg() {
        let b = FakeBrew::new();
        let v1 = b.install("1.0.0", &shim_bytes("1"));
        let msd1 = v1.join("msd");
        assert_eq!(stable_path(&msd1), None, "no opt link yet");
        assert_eq!(preferred(&msd1), msd1);
        b.point_opt("1.0.0");
        assert_eq!(stable_path(&msd1), Some(b.opt_bin("msd")));
        assert_eq!(preferred(&msd1), b.opt_bin("msd"));
        // opt moves on to 1.1.0: the 1.0.0 binary no longer gets the opt path.
        b.install("1.1.0", &shim_bytes("2"));
        b.point_opt("1.1.0");
        assert_eq!(stable_path(&msd1), None);
        assert_eq!(
            stable_path(&b.keg_bin("1.1.0").join("msd")),
            Some(b.opt_bin("msd"))
        );
        // A group-writable opt dir (another user could repoint the link): not trusted.
        use std::os::unix::fs::PermissionsExt;
        let opt = b.prefix.join("opt");
        std::fs::set_permissions(&opt, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(stable_path(&b.keg_bin("1.1.0").join("msd")), None);
        std::fs::set_permissions(&opt, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(stable_path(&b.keg_bin("1.1.0").join("msd")).is_some());
        // A dev build is left alone.
        let dev = b.prefix.join("target/debug");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("msd"), "dev").unwrap();
        assert_eq!(preferred(&dev.join("msd")), dev.join("msd"));
    }

    // protects=only executables that carry the ms-shim marker count as old shims; fails_when=a
    // text file mentioning the marker, or a binary without it, is taken for a shim; no_claim=-
    #[test]
    fn marker_needs_an_executable() {
        assert!(has_marker(&shim_bytes("x")));
        assert!(!has_marker(ms_run::SHIM_MARKER.as_bytes()));
        assert!(!has_marker(&[0xcf, 0xfa, 0xed, 0xfe, b'x']));
    }
}
