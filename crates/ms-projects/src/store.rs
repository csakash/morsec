//! The MAC'd project records: `projects.toml` plus `projects.toml.mac` in msd's state directory,
//! mirrored on `ms_rules::RulesStore` with its own HMAC key in the vault (`morsec/projects-hmac`).
//!
//! A same-user process can write the files but can't make a valid MAC. A changed file, a
//! foreign MAC, a removed file (after a version was seen) and an older valid file put back (its
//! `version` below the floor msd keeps in the vault) all fail closed: msd answers `Denied` for
//! the project requests, and keys and rules keep working.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use ms_core::KeyName;
use ms_rules::store::{mac_path, read_limited};
use ms_vault::Vault;
use sha2::Sha256;

use crate::Error;
use crate::record::ProjectsFile;

/// The vault key the store's MAC key lives under.
pub const PROJECTS_HMAC_KEY: &str = "morsec/projects-hmac";
/// Largest `projects.toml` read.
pub const MAX_FILE: u64 = 16 << 20;

const MAC_DOMAIN: &[u8] = b"morsec-projects-v1\0";
type HmacSha256 = Hmac<Sha256>;

/// Reads and writes `projects.toml`, checking its MAC.
pub struct ProjectsStore<'v> {
    path: PathBuf,
    vault: &'v dyn Vault,
    mac_key: KeyName,
}

impl std::fmt::Debug for ProjectsStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectsStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn tampered(why: impl Into<String>) -> Error {
    Error::Tampered(why.into())
}

impl<'v> ProjectsStore<'v> {
    /// A store at `path`, MAC'd with the vault key `mac_key`.
    pub fn new(path: impl Into<PathBuf>, vault: &'v dyn Vault, mac_key: KeyName) -> Self {
        Self {
            path: path.into(),
            vault,
            mac_key,
        }
    }

    /// Loads and verifies. No file and `min_version == 0`: no projects yet. Fails closed on a
    /// missing file after a version was seen, a bad or missing MAC, a parse error, or a version
    /// below `min_version`.
    pub fn load(&self, min_version: u64) -> Result<ProjectsFile, Error> {
        let text = match read_limited(&self.path, MAX_FILE) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && min_version == 0 => {
                if mac_path(&self.path).exists() {
                    return Err(tampered("projects.toml is missing but its MAC is there"));
                }
                return Ok(ProjectsFile::default());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(tampered("projects.toml was removed"));
            }
            Err(e) => return Err(tampered(format!("projects.toml can't be read: {e}"))),
        };
        let mac_hex = read_limited(&mac_path(&self.path), 256)
            .map_err(|e| tampered(format!("projects.toml.mac can't be read: {e}")))?;
        let mac = hex::decode(mac_hex.trim_ascii())
            .map_err(|_| tampered("projects.toml.mac is not hex"))?;
        self.verify(&text, &mac)?;
        let text =
            std::str::from_utf8(&text).map_err(|_| tampered("projects.toml is not UTF-8"))?;
        let file = ProjectsFile::from_toml(text).map_err(|e| tampered(e.to_string()))?;
        if file.version < min_version {
            return Err(tampered(format!(
                "version {} is older than the last saved version {min_version} (an old file was put back)",
                file.version
            )));
        }
        Ok(file)
    }

    /// Saves `file` as the next version after the verified current one. Returns the version
    /// written.
    pub fn save(&self, file: &ProjectsFile, min_version: u64) -> Result<u64, Error> {
        let current = self.load(min_version)?;
        let mut next = file.clone();
        next.version = current
            .version
            .max(min_version)
            .checked_add(1)
            .ok_or_else(|| tampered("version overflow"))?;
        let text = next.to_toml();
        // What is written must load again.
        ProjectsFile::from_toml(&text)?;
        if text.len() as u64 > MAX_FILE {
            return Err(Error::Invalid(format!(
                "projects.toml would be larger than {MAX_FILE} bytes"
            )));
        }
        let mac = self.mac(text.as_bytes())?;
        atomic_write(&self.path, text.as_bytes())?;
        atomic_write(&mac_path(&self.path), hex::encode(mac).as_bytes())?;
        Ok(next.version)
    }

    fn with_key<R>(&self, f: impl FnOnce(&[u8]) -> Result<R, Error>) -> Result<R, Error> {
        let mut f = Some(f);
        let mut out: Option<Result<R, Error>> = None;
        self.vault
            .with_secret(&self.mac_key, &mut |key| {
                if let Some(f) = f.take() {
                    out = Some(if key.len() < 32 {
                        Err(tampered("the projects MAC key is shorter than 32 bytes"))
                    } else {
                        f(key)
                    });
                }
            })
            .map_err(|e| tampered(format!("the projects MAC key can't be read: {e}")))?;
        out.unwrap_or_else(|| Err(tampered("the vault returned no projects MAC key")))
    }

    fn mac(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.with_key(|key| {
            let mut m = <HmacSha256 as Mac>::new_from_slice(key)
                .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
            m.update(MAC_DOMAIN);
            m.update(data);
            Ok(m.finalize().into_bytes().to_vec())
        })
    }

    fn verify(&self, data: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.with_key(|key| {
            let mut m = <HmacSha256 as Mac>::new_from_slice(key)
                .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
            m.update(MAC_DOMAIN);
            m.update(data);
            m.verify_slice(mac)
                .map_err(|_| tampered("the MAC does not match the file"))
        })
    }
}

/// A 0600 temp file in the same directory, synced, renamed over `path`.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "projects".into());
    for attempt in 0..16u32 {
        let tmp = dir.join(format!(".{name}.tmp.{}.{attempt}", std::process::id()));
        let mut f = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::io(format!("writing {}", path.display()), e)),
        };
        let res = f
            .write_all(data)
            .and_then(|()| f.sync_all())
            .and_then(|()| fs::rename(&tmp, path));
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(Error::io(format!("writing {}", path.display()), e));
        }
        return Ok(());
    }
    Err(Error::io(
        format!("writing {}", path.display()),
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "too many stale temp files",
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::sample;
    use ms_core::{KeyMeta, Mode, SecretBytes, Tier};
    use ms_vault::memory::MemoryVault;

    fn vault(byte: u8) -> MemoryVault {
        let v = MemoryVault::new();
        let k = KeyName::new(PROJECTS_HMAC_KEY).unwrap();
        v.put(
            &k,
            SecretBytes::from(vec![byte; 32]),
            KeyMeta {
                name: k.clone(),
                mode: Mode::Swap,
                tier: Tier::Production,
                created_unix_ms: 0,
            },
        )
        .unwrap();
        v
    }

    fn file() -> ProjectsFile {
        ProjectsFile {
            version: 0,
            projects: vec![sample()],
        }
    }

    // protects=SPEC criterion 7 at the store: a byte flip, a MAC made with another key, an older
    // valid file put back (version below the floor), a removed file after a save, a removed MAC
    // and a garbage MAC all fail closed; a good save loads back; fails_when=any tampered case
    // loads; no_claim=msd's reply and floor keeping (daemon projects_toml_tamper_fails_closed)
    #[test]
    fn tamper_table() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("projects.toml");
        let v = vault(7);
        let s = ProjectsStore::new(&path, &v, KeyName::new(PROJECTS_HMAC_KEY).unwrap());
        assert_eq!(s.load(0).unwrap(), ProjectsFile::default());
        let v1 = s.save(&file(), 0).unwrap();
        assert_eq!(v1, 1);
        let old_text = fs::read(&path).unwrap();
        let old_mac = fs::read(mac_path(&path)).unwrap();
        let v2 = s.save(&file(), v1).unwrap();
        assert_eq!(v2, 2);
        assert_eq!(s.load(v2).unwrap().projects, vec![sample()]);

        // Rollback: the older, validly MAC'd file.
        fs::write(&path, &old_text).unwrap();
        fs::write(mac_path(&path), &old_mac).unwrap();
        assert!(matches!(s.load(v2), Err(Error::Tampered(_))));
        s.save(&file(), 0).unwrap();
        let good = fs::read(&path).unwrap();

        // Byte flip.
        let mut flipped = good.clone();
        let i = flipped.len() / 2;
        flipped[i] ^= 0x01;
        fs::write(&path, &flipped).unwrap();
        assert!(matches!(s.load(0), Err(Error::Tampered(_))));
        fs::write(&path, &good).unwrap();

        // Foreign MAC: a file MAC'd with another key.
        let other = vault(9);
        let d2 = tempfile::tempdir().unwrap();
        let p2 = d2.path().join("projects.toml");
        let s2 = ProjectsStore::new(&p2, &other, KeyName::new(PROJECTS_HMAC_KEY).unwrap());
        s2.save(&file(), 0).unwrap();
        fs::copy(&p2, &path).unwrap();
        fs::copy(mac_path(&p2), mac_path(&path)).unwrap();
        assert!(matches!(s.load(0), Err(Error::Tampered(_))));

        // Garbage and missing MAC, removed file.
        fs::write(&path, &good).unwrap();
        fs::write(mac_path(&path), "zz").unwrap();
        assert!(matches!(s.load(0), Err(Error::Tampered(_))));
        fs::remove_file(mac_path(&path)).unwrap();
        assert!(matches!(s.load(0), Err(Error::Tampered(_))));
        fs::remove_file(&path).unwrap();
        assert!(matches!(s.load(3), Err(Error::Tampered(_))));
        // A save never goes over a file that fails its check.
        fs::write(&path, &flipped).unwrap();
        assert!(s.save(&file(), 0).is_err());
        assert_eq!(fs::read(&path).unwrap(), flipped);
    }
}
