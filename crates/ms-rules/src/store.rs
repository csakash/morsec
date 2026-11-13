//! The MAC'd rules store: `rules.toml` plus `rules.toml.mac`.
//!
//! The agent runs as the same Unix user and can write these files. What it can't do is produce a
//! valid MAC: the key lives in the vault and is only used inside a `with_secret` closure. So a
//! loosened, forged or swapped file fails to load, and the daemon then denies everything
//! (`Rules::tampered()`). Replaying an older, validly MAC'd file is caught by `min_version`, which
//! the daemon takes from the receipt chain.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use ms_core::KeyName;
use ms_vault::Vault;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::change::{Change, classify};
use crate::error::{Result, RulesError, printable};
use crate::model::Rules;

/// Default vault key name of the rules MAC key (created by `ms init`, L01/L07).
pub const DEFAULT_MAC_KEY: &str = "morsec/rules-mac";
/// Largest rules file read, bytes.
pub const MAX_RULES_FILE: u64 = 1 << 20;

const MAC_DOMAIN: &[u8] = b"morsec-rules-v1\0";
type HmacSha256 = Hmac<Sha256>;

/// Reads and writes the rules file, checking its MAC.
pub struct RulesStore<'v> {
    path: PathBuf,
    vault: &'v dyn Vault,
    mac_key: KeyName,
}

impl std::fmt::Debug for RulesStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RulesStore")
            .field("path", &self.path)
            .field("mac_key", &self.mac_key)
            .finish_non_exhaustive()
    }
}

impl<'v> RulesStore<'v> {
    /// A store for the rules file at `path`, MAC'd with the vault key `mac_key`.
    pub fn new(path: impl Into<PathBuf>, vault: &'v dyn Vault, mac_key: KeyName) -> Self {
        Self {
            path: path.into(),
            vault,
            mac_key,
        }
    }

    /// The rules file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The MAC file path: the rules path with `.mac` appended.
    pub fn mac_path(&self) -> PathBuf {
        mac_path(&self.path)
    }

    /// Loads and verifies the rules. Fails closed on a missing, malformed or wrong MAC, a missing
    /// MAC key, a parse error, or a version older than `min_version` (rollback). On error the
    /// daemon must use [`Rules::tampered`].
    pub fn load(&self, min_version: u64) -> Result<Rules> {
        let text = match read_limited(&self.path, MAX_RULES_FILE) {
            Ok(t) => t,
            // A file that existed (a version was seen) and is now gone was removed: tampering.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && min_version > 0 => {
                return Err(RulesError::Tampered {
                    why: "the rules file is missing".into(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RulesError::NotInitialized {
                    path: self.path.display().to_string(),
                });
            }
            Err(e) => {
                return Err(RulesError::io(
                    format!("reading {}", self.path.display()),
                    e,
                ));
            }
        };
        let mac_hex = read_limited(&self.mac_path(), 256).map_err(|e| RulesError::Tampered {
            why: format!("can't read {}: {e}", self.mac_path().display()),
        })?;
        let mac = hex::decode(mac_hex.trim_ascii()).map_err(|_| RulesError::Tampered {
            why: "the .mac file is not hex".into(),
        })?;
        self.verify(&text, &mac)?;
        let text = std::str::from_utf8(&text).map_err(|_| RulesError::Tampered {
            why: "the rules file is not UTF-8".into(),
        })?;
        let rules = Rules::from_toml(text, &self.path.display().to_string())?;
        if rules.version < min_version {
            return Err(RulesError::Tampered {
                why: format!(
                    "version {} is older than the last seen version {min_version} (an old file was put back)",
                    rules.version
                ),
            });
        }
        Ok(rules)
    }

    /// Writes the first rules file. Refuses to overwrite an existing one.
    pub fn create(&self, rules: &Rules) -> Result<Rules> {
        if self.path.exists() || self.mac_path().exists() {
            return Err(RulesError::invalid(
                self.path.display().to_string(),
                "a rules file already exists; change it with ms rules",
            ));
        }
        let mut first = rules.clone();
        first.version = 1;
        self.write(&first)?;
        Ok(first)
    }

    /// Replaces the rules with `new`. The current file is loaded and verified first (with
    /// `min_version`), the change is classified, and a loosening change is refused unless
    /// `approved` (the caller got an approval for exactly this change). The saved version is the
    /// current version plus one. Returns the saved rules.
    pub fn save(&self, new: &Rules, approved: bool, min_version: u64) -> Result<Rules> {
        let current = self.load(min_version)?;
        let version = current
            .version
            .checked_add(1)
            .ok_or_else(|| RulesError::Tampered {
                why: "rules version overflow".into(),
            })?;
        // Validate exactly what will be written (same limits and per-mode checks as load), so a
        // bad rule is refused here instead of locking every key out on the next load.
        let mut draft = new.clone();
        draft.version = version;
        let text = draft.to_toml();
        if text.len() as u64 > MAX_RULES_FILE {
            return Err(RulesError::invalid(
                "the new rules",
                format!("larger than {MAX_RULES_FILE} bytes; remove keys or patterns"),
            ));
        }
        let next = Rules::from_toml(&text, "the new rules")?;
        let (change, loosened) = classify(&current, &next);
        if change == Change::Loosen && !approved {
            let keys: Vec<String> = loosened.iter().map(ToString::to_string).collect();
            return Err(RulesError::NeedsApproval {
                keys: keys.join(", "),
            });
        }
        self.write(&next)?;
        Ok(next)
    }

    fn compute_mac(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out: Option<Result<Zeroizing<Vec<u8>>>> = None;
        self.vault
            .with_secret(&self.mac_key, &mut |key| {
                out = Some(if key.len() < 32 {
                    Err(RulesError::MacKey {
                        name: self.mac_key.to_string(),
                        detail: "the key is shorter than 32 bytes".into(),
                    })
                } else {
                    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
                        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                    m.update(MAC_DOMAIN);
                    m.update(data);
                    Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
                });
            })
            .map_err(|e| RulesError::MacKey {
                name: self.mac_key.to_string(),
                detail: e.to_string(),
            })?;
        out.unwrap_or_else(|| {
            Err(RulesError::MacKey {
                name: self.mac_key.to_string(),
                detail: "the vault returned no value".into(),
            })
        })
    }

    fn verify(&self, data: &[u8], mac: &[u8]) -> Result<()> {
        let mut result: Option<Result<()>> = None;
        self.vault
            .with_secret(&self.mac_key, &mut |key| {
                result = Some(if key.len() < 32 {
                    Err(RulesError::MacKey {
                        name: self.mac_key.to_string(),
                        detail: "the key is shorter than 32 bytes".into(),
                    })
                } else {
                    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
                        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                    m.update(MAC_DOMAIN);
                    m.update(data);
                    // Constant-time comparison.
                    m.verify_slice(mac).map_err(|_| RulesError::Tampered {
                        why: "the MAC does not match the file".into(),
                    })
                });
            })
            .map_err(|e| RulesError::MacKey {
                name: self.mac_key.to_string(),
                detail: e.to_string(),
            })?;
        result.unwrap_or_else(|| {
            Err(RulesError::MacKey {
                name: self.mac_key.to_string(),
                detail: "the vault returned no value".into(),
            })
        })
    }

    fn write(&self, rules: &Rules) -> Result<()> {
        let text = rules.to_toml();
        let mac = self.compute_mac(text.as_bytes())?;
        // Rules first, then the MAC. A crash in between leaves a mismatch, which fails closed.
        atomic_write(&self.path, text.as_bytes())?;
        atomic_write(&self.mac_path(), hex::encode(&*mac).as_bytes())?;
        Ok(())
    }
}

/// `<path>.mac`.
pub fn mac_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".mac");
    PathBuf::from(p)
}

/// Reads at most `limit` bytes; a longer file is an error rather than a truncated read.
pub fn read_limited(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    // Non-blocking open so a FIFO swapped in for the file can't hang the reader; then refuse
    // anything that is not a regular file.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut buf = Vec::new();
    f.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {limit} bytes"),
        ));
    }
    Ok(buf)
}

/// Writes `data` to a new 0600 temp file in the same directory, syncs it, and renames it over
/// `path`.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules".into());
    let ctx = |what: &str| format!("{what} {}", printable(&path.display().to_string(), 200));
    for attempt in 0..16u32 {
        let tmp = dir.join(format!(".{name}.tmp.{}.{attempt}", std::process::id()));
        let mut f = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(RulesError::io(ctx("creating a temp file for"), e)),
        };
        let res = f
            .write_all(data)
            .and_then(|()| f.sync_all())
            .and_then(|()| fs::rename(&tmp, path));
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(RulesError::io(ctx("writing"), e));
        }
        return Ok(());
    }
    Err(RulesError::io(
        ctx("creating a temp file for"),
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "too many stale temp files",
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KeyRule;
    use crate::pattern::HostPattern;
    use ms_core::{KeyMeta, Mode, SecretBytes, Tier};
    use ms_vault::memory::MemoryVault;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    fn mac_key() -> KeyName {
        KeyName::new(DEFAULT_MAC_KEY).unwrap()
    }

    fn vault_with_key(byte: u8, len: usize) -> MemoryVault {
        let v = MemoryVault::new();
        v.put(
            &mac_key(),
            SecretBytes::from(vec![byte; len]),
            KeyMeta {
                name: mac_key(),
                mode: Mode::Swap,
                tier: Tier::Test,
                created_unix_ms: 0,
            },
        )
        .unwrap();
        v
    }

    fn sample() -> Rules {
        let mut r = KeyRule::new(Mode::Swap, Tier::Test);
        r.hosts = vec![HostPattern::parse("api.stripe.com").unwrap()];
        Rules {
            version: 0,
            keys: BTreeMap::from([(KeyName::new("stripe/test").unwrap(), r)]),
            ..Rules::default()
        }
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // protects=create/load round-trips through the MAC'd files with 0600 permissions;
    // fails_when=a saved file doesn't load, has wider permissions, or carries runtime state;
    // no_claim=the macOS Keychain backend (L01)
    #[test]
    fn create_and_load() {
        let d = tmp();
        let v = vault_with_key(7, 32);
        let s = RulesStore::new(d.path().join("rules.toml"), &v, mac_key());
        assert!(matches!(s.load(0), Err(RulesError::NotInitialized { .. })));
        assert!(matches!(s.load(1), Err(RulesError::Tampered { .. })));
        let created = s.create(&sample()).unwrap();
        assert_eq!(created.version, 1);
        assert_eq!(s.load(1).unwrap(), created);
        for p in [s.path().to_path_buf(), s.mac_path()] {
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", p.display());
        }
        assert!(s.create(&sample()).is_err(), "create overwrote a file");
    }

    // protects=any tampering fails closed: edited rules, edited/missing/garbage MAC, a file
    // swapped from another vault, a missing or short MAC key, and a rolled-back version;
    // fails_when=any of these loads; no_claim=what the daemon does next (L07 uses Rules::tampered)
    #[test]
    fn tampering_fails_closed() {
        let d = tmp();
        let v = vault_with_key(7, 32);
        let s = RulesStore::new(d.path().join("rules.toml"), &v, mac_key());
        s.create(&sample()).unwrap();
        let good_text = fs::read_to_string(s.path()).unwrap();
        let good_mac = fs::read_to_string(s.mac_path()).unwrap();
        let restore = || {
            fs::write(s.path(), &good_text).unwrap();
            fs::write(s.mac_path(), &good_mac).unwrap();
        };

        // The agent widens the hosts.
        fs::write(s.path(), good_text.replace("api.stripe.com", "*.com")).unwrap();
        assert!(matches!(s.load(0), Err(RulesError::Tampered { .. })));
        restore();
        // Whitespace-only change still fails: the MAC covers the exact bytes.
        fs::write(s.path(), format!("{good_text}\n")).unwrap();
        assert!(matches!(s.load(0), Err(RulesError::Tampered { .. })));
        restore();
        // Flipped MAC bit, garbage, empty, missing, oversized.
        let mut flipped = hex::decode(good_mac.trim()).unwrap();
        flipped[0] ^= 1;
        for bad in [
            hex::encode(flipped),
            "zz".into(),
            String::new(),
            "a".repeat(300),
        ] {
            fs::write(s.mac_path(), bad).unwrap();
            assert!(matches!(s.load(0), Err(RulesError::Tampered { .. })));
        }
        fs::remove_file(s.mac_path()).unwrap();
        assert!(matches!(s.load(0), Err(RulesError::Tampered { .. })));
        restore();
        assert!(s.load(0).is_ok());

        // A file MAC'd by another vault (attacker's own key) is rejected.
        let other = vault_with_key(8, 32);
        let d2 = tmp();
        let s2 = RulesStore::new(d2.path().join("rules.toml"), &other, mac_key());
        let mut loose = sample();
        loose
            .keys
            .values_mut()
            .for_each(|r| r.hosts = vec![HostPattern::parse("*.com").unwrap()]);
        s2.create(&loose).unwrap();
        fs::copy(s2.path(), s.path()).unwrap();
        fs::copy(s2.mac_path(), s.mac_path()).unwrap();
        assert!(matches!(s.load(0), Err(RulesError::Tampered { .. })));
        restore();

        // Missing and too-short MAC keys.
        let empty = MemoryVault::new();
        let s3 = RulesStore::new(s.path(), &empty, mac_key());
        assert!(matches!(s3.load(0), Err(RulesError::MacKey { .. })));
        let short = vault_with_key(7, 16);
        let s4 = RulesStore::new(s.path(), &short, mac_key());
        assert!(matches!(s4.load(0), Err(RulesError::MacKey { .. })));

        // Rollback: version 1 file put back after version 2 was seen.
        let mut tighter = s.load(0).unwrap();
        tighter.keys.clear();
        let saved = s.save(&tighter, false, 1).unwrap();
        assert_eq!(saved.version, 2);
        restore();
        assert!(s.load(1).is_ok());
        assert!(matches!(s.load(2), Err(RulesError::Tampered { .. })));
    }

    // protects=save bumps the version, allows tightening without approval and refuses loosening
    // without it; fails_when=a loosening is written unapproved or the version doesn't grow;
    // no_claim=how approval is obtained (L07/L11)
    #[test]
    fn save_requires_approval_to_loosen() {
        let d = tmp();
        let v = vault_with_key(1, 32);
        let s = RulesStore::new(d.path().join("rules.toml"), &v, mac_key());
        let first = s.create(&sample()).unwrap();
        let before = fs::read(s.path()).unwrap();

        let mut looser = first.clone();
        looser
            .keys
            .values_mut()
            .for_each(|r| r.hosts.push(HostPattern::parse("evil.net").unwrap()));
        let err = s.save(&looser, false, 1).unwrap_err();
        assert!(matches!(err, RulesError::NeedsApproval { ref keys } if keys == "stripe/test"));
        assert_eq!(
            fs::read(s.path()).unwrap(),
            before,
            "file changed on refusal"
        );

        let saved = s.save(&looser, true, 1).unwrap();
        assert_eq!(saved.version, 2);
        assert_eq!(s.load(2).unwrap(), saved);

        let mut tighter = saved.clone();
        tighter
            .keys
            .values_mut()
            .for_each(|r| r.tier = Tier::Production);
        tighter.stopped = true;
        let saved = s.save(&tighter, false, 2).unwrap();
        assert_eq!(saved.version, 3);
        assert!(!saved.stopped);

        // An invalid rule is refused before anything is written (no self-inflicted lockout).
        let mut invalid = saved.clone();
        invalid
            .keys
            .values_mut()
            .for_each(|r| r.session_ttl_secs = 0);
        assert!(matches!(
            s.save(&invalid, true, 3),
            Err(RulesError::Invalid { .. })
        ));
        assert_eq!(s.load(3).unwrap(), saved);
        // Rules too big to load again are refused before writing.
        let mut huge = saved.clone();
        for i in 0..4000 {
            let mut r = KeyRule::new(Mode::Swap, Tier::Test);
            r.hosts = (0..4)
                .map(|j| HostPattern::parse(&format!("{}{j}.example.com", "a".repeat(60))).unwrap())
                .collect();
            huge.keys.insert(KeyName::new(&format!("k{i}")).unwrap(), r);
        }
        assert!(matches!(
            s.save(&huge, true, 3),
            Err(RulesError::Invalid { .. })
        ));
        assert_eq!(s.load(3).unwrap(), saved);

        // Saving over a tampered file is refused (no "repair by overwrite" without verification).
        fs::write(s.mac_path(), "00").unwrap();
        assert!(s.save(&saved, true, 3).is_err());
    }

    // protects=oversized files are refused rather than truncated; fails_when=a >1 MiB rules file
    // is read; no_claim=memory use of the TOML parser below the limit
    #[test]
    fn oversized_rules_file() {
        let d = tmp();
        let v = vault_with_key(1, 32);
        let s = RulesStore::new(d.path().join("rules.toml"), &v, mac_key());
        s.create(&sample()).unwrap();
        fs::write(s.path(), vec![b'#'; (MAX_RULES_FILE + 1) as usize]).unwrap();
        assert!(matches!(s.load(0), Err(RulesError::Io { .. })));
        // A FIFO in place of the file is refused at once rather than blocking the reader.
        fs::remove_file(s.path()).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(s.path())
            .status()
            .unwrap();
        assert!(made.success());
        assert!(matches!(s.load(0), Err(RulesError::Io { .. })));
    }
}
