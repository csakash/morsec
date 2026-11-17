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

/// macOS's `admin` group. Its members can already become root with sudo, so a directory only
/// `admin` can write grants no one more than they have. Homebrew makes its prefix directories
/// (`/opt/homebrew/opt`, `/opt/homebrew/lib`) `drwxrwxr-x <user>:admin` by default.
const ADMIN_GID: u32 = 80;

/// A directory no other user can change: owned by `uid` or root, and writable by no one else,
/// except the `admin` group (see [`ADMIN_GID`]) or, for a root-owned sticky directory such as
/// `/tmp`, everyone (they can't rename what they don't own there).
fn safe_dir(m: &std::fs::Metadata, uid: u32) -> bool {
    m.is_dir() && safe_owner_mode(m.uid(), m.gid(), m.mode(), uid)
}

fn safe_owner_mode(owner: u32, gid: u32, mode: u32, uid: u32) -> bool {
    let owner_ok = owner == uid || owner == 0;
    // gid 80 is `admin` on macOS only; elsewhere it means nothing special.
    let admin_only = cfg!(target_os = "macos") && mode & 0o002 == 0 && gid == ADMIN_GID;
    let writers_ok = mode & 0o022 == 0 || admin_only || (owner == 0 && mode & 0o1000 != 0);
    owner_ok && writers_ok
}

/// `<prefix>/opt/morsec/bin/<tool>` for a keg binary at canonical path `real`, only when that
/// path resolves to exactly `real` (the `opt` link points at this keg). `None` otherwise: not a
/// Homebrew keg, no `opt` link (a custom `HOMEBREW_CELLAR`), or `opt` on another version.
///
/// Defence in depth: `<prefix>/opt` must be a [`safe_dir`] and the `opt/morsec` link must belong
/// to this user or root, so another user can't repoint the link later.
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
    if !safe_dir(&opt_meta, uid) || !owned(&link_meta) {
        return None;
    }
    let stable = link.join("bin").join(tool);
    let resolved = std::fs::canonicalize(&stable).ok()?;
    (resolved == real).then_some(stable)
}

/// The npm platform package that holds the binaries (packaging/npm, loop distribution).
const NPM_PACKAGE: &str = "morsec-darwin-arm64";

/// Is `p` a tool of an npm install, `.../node_modules/morsec-darwin-arm64/bin/<tool>`? Purely
/// lexical: nothing is read from disk.
pub(crate) fn is_npm(p: &Path) -> bool {
    // The last four components, each a plain name (a `..` or `.` anywhere there refuses it).
    let names: Option<Vec<&std::ffi::OsStr>> = p
        .components()
        .rev()
        .take(4)
        .map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    // pnpm's store keeps a version in the path (.pnpm/<pkg>@<version>/...), so it would not
    // survive an upgrade: not treated as an npm install.
    let in_pnpm_store = p.components().any(|c| c.as_os_str() == ".pnpm");
    p.is_absolute()
        && !in_pnpm_store
        && matches!(names.as_deref(), Some([tool, bin, pkg, nm])
            if !tool.is_empty() && *bin == "bin" && *pkg == NPM_PACKAGE && *nm == "node_modules")
}

/// `real` itself when it is a tool of an npm install whose package directories nobody else can
/// write: `npm install -g morsec@<new>` replaces the files at this same path, so a symlink to it
/// follows upgrades the way Homebrew's `opt` link does (a hard link would keep the old file).
/// `None` otherwise. Defence in depth: every directory from `bin/` up to `/` must be a
/// [`safe_dir`], or another user could swap the file a shim runs.
pub(crate) fn npm_path(real: &Path) -> Option<PathBuf> {
    if !is_npm(real) {
        return None;
    }
    let uid = rustix::process::getuid().as_raw();
    for d in real.parent()?.ancestors() {
        let m = std::fs::symlink_metadata(d).ok()?;
        if !safe_dir(&m, uid) {
            return None;
        }
    }
    Some(real.to_path_buf())
}

/// What a run shim should be a symlink to so it survives upgrades: Homebrew's `opt` path, else
/// the npm package's own path. `None` (a dev or manual install): shims are hard links.
pub(crate) fn link_target(real: &Path) -> Option<PathBuf> {
    stable_path(real).or_else(|| npm_path(real))
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

/// Largest file read when looking for the marker; `ms-shim` is a few MiB.
const MAX_SHIM_BYTES: u64 = 64 * 1024 * 1024;

/// Is the file at `p` (following links) an older `ms-shim`? Only a regular file of plausible
/// size is read, so a planted link to a FIFO, a device or a huge file can't hang or exhaust
/// `--link-shims` and `ms doctor` (security review S1).
fn marked(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= MAX_SHIM_BYTES)
        && std::fs::read(p).is_ok_and(|b| has_marker(&b))
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
            return if marked(p) || (names_shim && std::fs::metadata(p).is_err()) {
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
        if marked(p) {
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

    // protects=npm installs are recognised exactly by .../node_modules/morsec-darwin-arm64/bin/<tool>
    // and shims link to that path only when no one else can write its directories;
    // fails_when=another package, a relative path or a group-writable package dir yields a link
    // target; no_claim=npm itself (never run)
    #[test]
    fn npm_paths() {
        assert!(is_npm(Path::new(
            "/Users/u/.nvm/versions/node/v22.1.0/lib/node_modules/morsec/node_modules/morsec-darwin-arm64/bin/msd"
        )));
        assert!(is_npm(Path::new(
            "/opt/homebrew/lib/node_modules/morsec-darwin-arm64/bin/ms-shim"
        )));
        for bad in [
            "/x/node_modules/morsec-darwin-x64/bin/msd",
            "/x/node_modules/morsec-darwin-arm64/lib/msd",
            "/x/vendor/morsec-darwin-arm64/bin/msd",
            "node_modules/morsec-darwin-arm64/bin/msd",
            "/x/node_modules/morsec-darwin-arm64/bin/../msd",
            "/morsec-darwin-arm64/bin/msd",
            "/g/.pnpm/morsec-darwin-arm64@0.1.0/node_modules/morsec-darwin-arm64/bin/msd",
        ] {
            assert!(!is_npm(Path::new(bad)), "{bad}");
        }
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let bin = root.join("lib/node_modules/morsec/node_modules/morsec-darwin-arm64/bin");
        std::fs::create_dir_all(&bin).unwrap();
        for p in [
            bin.as_path(),
            bin.parent().unwrap(),
            bin.parent().unwrap().parent().unwrap(),
        ] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let shim = bin.join("ms-shim");
        std::fs::write(&shim, shim_bytes("npm")).unwrap();
        assert_eq!(npm_path(&shim), Some(shim.clone()));
        assert_eq!(link_target(&shim), Some(shim.clone()));
        // The LaunchAgent records the npm path as it is (there is no opt link to prefer).
        assert_eq!(preferred(&shim), shim);
        let pkg = bin.parent().unwrap();
        std::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(npm_path(&shim), None, "group-writable package dir");
        assert_eq!(link_target(&shim), None);
        std::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Any ancestor counts, not just the package's own directories (security review S2).
        let lib = root.join("lib");
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(npm_path(&shim), None, "group-writable ancestor");
        std::fs::set_permissions(&lib, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(npm_path(&shim), Some(shim.clone()));
        // A dev build is not an npm install.
        assert_eq!(link_target(&root.join("target/debug/ms-shim")), None);
    }

    // protects=who may write a directory a LaunchAgent or shim trusts: owner or root, plus only
    // the admin group (sudoers anyway; Homebrew's default drwxrwxr-x <user>:admin) or a
    // root-owned sticky dir; fails_when=another user or group, or world write, is accepted, or
    // Homebrew's default prefix is refused; no_claim=ACLs (not consulted)
    #[test]
    fn safe_dir_rules() {
        let me = 501;
        assert!(safe_owner_mode(me, 20, 0o40755, me));
        assert!(safe_owner_mode(0, 0, 0o40755, me));
        assert!(
            safe_owner_mode(me, ADMIN_GID, 0o40775, me),
            "Homebrew's /opt/homebrew/opt"
        );
        assert!(safe_owner_mode(0, 0, 0o41777, me), "/tmp");
        assert!(
            !safe_owner_mode(me, 20, 0o40775, me),
            "group staff can write"
        );
        assert!(
            !safe_owner_mode(me, ADMIN_GID, 0o40777, me),
            "world-writable"
        );
        assert!(!safe_owner_mode(502, 20, 0o40755, me), "another user's dir");
        assert!(
            !safe_owner_mode(me, 20, 0o41777, me),
            "sticky but not root's"
        );
        assert!(
            !safe_owner_mode(502, ADMIN_GID, 0o40775, me),
            "another user's admin dir"
        );
        assert!(
            safe_owner_mode(0, ADMIN_GID, 0o40775, me),
            "root's admin dir"
        );
        assert!(
            !safe_owner_mode(0, 0, 0o40777, me),
            "root's, world-writable, not sticky"
        );
    }

    // protects=a planted link to a FIFO, a device or a huge file is classified without reading
    // it (no hang, no unbounded read); fails_when=classify blocks or reads /dev/zero;
    // no_claim=-
    #[test]
    fn classify_never_reads_special_files() {
        let d = tempfile::tempdir().unwrap();
        let shim_path = d.path().join("ms-shim");
        std::fs::write(&shim_path, shim_bytes("x")).unwrap();
        let shim = Shim::open(&shim_path, None).unwrap();
        let fifo = d.path().join("fifo");
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let big = d.path().join("big");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_SHIM_BYTES + 1)
            .unwrap();
        for (name, target) in [
            ("zero", Path::new("/dev/zero")),
            ("fifo", fifo.as_path()),
            ("big", big.as_path()),
        ] {
            let link = d.path().join(format!("link-{name}"));
            std::os::unix::fs::symlink(target, &link).unwrap();
            assert_eq!(shim.classify(&link), Entry::Foreign, "{name}");
        }
        assert_eq!(shim.classify(&fifo), Entry::Foreign);
        assert_eq!(shim.classify(&big), Entry::Foreign);
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
