//! Which vault msd uses, and the daemon-only operations on it.
//!
//! - `keychain` (macOS): L01's [`ms_vault::macos::KeychainVault`]. Items are ACL-bound to the
//!   signed msd, so the internal HMAC keys, the kill-switch flag and the CA key can't be read or
//!   rewritten by another binary of the same user.
//! - `memory`: an ephemeral [`MemoryVault`] for dev loops and tests. Everything is lost when msd
//!   exits, and the internal keys are fresh random bytes every start.

use std::sync::Arc;

use ms_core::{Error, KeyMeta, KeyName, Mode, Result, SecretBytes, Tier};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

/// Receipts HMAC key (L02).
pub const RECEIPTS_HMAC_KEY: &str = "morsec/receipts-hmac";
/// Rules MAC key (L01 creates it under this name; SPEC D-B).
pub const RULES_HMAC_KEY: &str = "morsec/rules-hmac";
/// The kill-switch flag (SPEC D-C).
pub const DAEMON_STATE_KEY: &str = "morsec/daemon-state";
/// The swap proxy CA private key, PEM (SPEC D-C, D-D).
pub const CA_PEM_KEY: &str = "morsec/ca";

const HMAC_LEN: usize = 32;

/// The vault backend.
#[derive(Debug, Clone)]
pub enum Backend {
    /// The macOS login keychain.
    #[cfg(target_os = "macos")]
    Keychain(Arc<ms_vault::macos::KeychainVault>),
    /// In memory, for dev and tests.
    Memory(Arc<MemoryVault>),
}

/// 32 random bytes from the kernel.
pub fn random_32() -> Result<SecretBytes> {
    use std::io::Read;
    let mut buf = vec![0u8; HMAC_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::io("reading /dev/urandom", e))?;
    Ok(SecretBytes::new(buf))
}

fn internal_meta(name: &KeyName) -> KeyMeta {
    KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 0,
    }
}

impl Backend {
    /// The vault as a trait object.
    pub fn vault(&self) -> Arc<dyn Vault> {
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keychain(v) => v.clone(),
            Backend::Memory(v) => v.clone(),
        }
    }

    /// `keychain` or `dev-memory`, for `ms status`.
    pub fn label(&self) -> &'static str {
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keychain(_) => "keychain",
            Backend::Memory(_) => "dev-memory",
        }
    }

    /// True for the ephemeral dev backend.
    pub fn is_memory(&self) -> bool {
        matches!(self, Backend::Memory(_))
    }

    /// At start: the internal HMAC keys must exist. The keychain backend needs `ms init` first;
    /// the memory backend creates fresh ones.
    pub fn ensure_ready(&self) -> Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keychain(v) => v.ensure_internal_keys(),
            Backend::Memory(v) => {
                for raw in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY] {
                    let k = KeyName::new(raw)?;
                    if v.list_names().contains(&k) {
                        continue;
                    }
                    v.put(&k, random_32()?, internal_meta(&k))?;
                }
                Ok(())
            }
        }
    }

    /// `ms init`: new seal key and internal HMAC keys, replacing any that exist.
    pub fn reset(&self) -> Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keychain(v) => v.reset_internal_keys(),
            Backend::Memory(v) => {
                for raw in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY] {
                    let k = KeyName::new(raw)?;
                    v.put(&k, random_32()?, internal_meta(&k))?;
                }
                Ok(())
            }
        }
    }

    /// Writes one of the daemon's own items ([`DAEMON_STATE_KEY`], [`CA_PEM_KEY`]). Every other
    /// write path refuses `morsec/` names.
    pub fn put_internal(&self, name: &KeyName, value: SecretBytes) -> Result<()> {
        if name.as_str() != DAEMON_STATE_KEY && name.as_str() != CA_PEM_KEY {
            return Err(Error::io(
                format!("refusing to write {name}"),
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "not a daemon-owned item",
                ),
            ));
        }
        match self {
            #[cfg(target_os = "macos")]
            Backend::Keychain(v) => v.put_internal(name, value),
            Backend::Memory(v) => v.put(name, value, internal_meta(name)),
        }
    }
}

/// Lets `ms_proxy::Ca::store` (which writes through `Vault::put`) store the CA key through
/// [`Backend::put_internal`]. Only `put` of [`CA_PEM_KEY`] is supported.
#[derive(Debug)]
pub struct CaKeyWriter<'a>(pub &'a Backend);

impl Vault for CaKeyWriter<'_> {
    fn put(&self, name: &KeyName, value: SecretBytes, _meta: KeyMeta) -> Result<()> {
        if name.as_str() != CA_PEM_KEY {
            return Err(Error::io(
                format!("refusing to write {name}"),
                std::io::Error::other("the CA writer stores only the CA key"),
            ));
        }
        self.0.put_internal(name, value)
    }

    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        self.0.vault().with_secret(name, f)
    }

    fn delete(&self, name: &KeyName) -> Result<()> {
        Err(Error::io(
            format!("refusing to delete {name}"),
            std::io::Error::other("the CA writer never deletes"),
        ))
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        Ok(Vec::new())
    }
}

/// `MemoryVault` helper: names present, without values.
trait ListNames {
    fn list_names(&self) -> Vec<KeyName>;
}

impl ListNames for MemoryVault {
    fn list_names(&self) -> Vec<KeyName> {
        self.list()
            .map(|v| v.into_iter().map(|m| m.name).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_vault::VaultExt;

    // protects=put_internal writes only the two daemon items; the CA writer only the CA key;
    // fails_when=either path can write an HMAC key or a user key; no_claim=the keychain backend
    // (ms-vault's put_internal_only_daemon_items covers it)
    #[test]
    fn internal_writes_are_narrow() {
        let b = Backend::Memory(Arc::new(MemoryVault::new()));
        b.ensure_ready().unwrap();
        let state = KeyName::new(DAEMON_STATE_KEY).unwrap();
        b.put_internal(&state, SecretBytes::new(b"stopped".to_vec()))
            .unwrap();
        assert_eq!(
            b.vault().read_with(&state, |v| v.to_vec()).unwrap(),
            b"stopped"
        );
        for bad in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY, "stripe/test"] {
            let k = KeyName::new(bad).unwrap();
            assert!(b.put_internal(&k, SecretBytes::new(vec![1])).is_err());
            assert!(
                CaKeyWriter(&b)
                    .put(&k, SecretBytes::new(vec![1]), internal_meta(&k))
                    .is_err()
            );
        }
        let ca = KeyName::new(CA_PEM_KEY).unwrap();
        CaKeyWriter(&b)
            .put(&ca, SecretBytes::new(b"pem".to_vec()), internal_meta(&ca))
            .unwrap();
        assert!(CaKeyWriter(&b).delete(&ca).is_err());
    }

    // protects=ensure_ready keeps existing HMAC keys (rotating them would break every MAC) and
    // reset replaces them; fails_when=a restart in memory mode changes keys mid-run;
    // no_claim=randomness quality
    #[test]
    fn ensure_keeps_reset_replaces() {
        let b = Backend::Memory(Arc::new(MemoryVault::new()));
        b.ensure_ready().unwrap();
        let k = KeyName::new(RULES_HMAC_KEY).unwrap();
        let first = b.vault().read_with(&k, |v| v.to_vec()).unwrap();
        assert_eq!(first.len(), 32);
        b.ensure_ready().unwrap();
        assert_eq!(b.vault().read_with(&k, |v| v.to_vec()).unwrap(), first);
        b.reset().unwrap();
        assert_ne!(b.vault().read_with(&k, |v| v.to_vec()).unwrap(), first);
    }
}
