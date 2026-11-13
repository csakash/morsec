//! The vault: where secret values live.
//!
//! The [`Vault`] trait is frozen by L00. Values never leave a closure: callers get a borrowed
//! slice for the duration of `with_secret` and nothing else. Backends: [`memory`] (tests, L00),
//! macOS Keychain (L01), Linux TPM/system user (L21).

pub mod memory;

use ms_core::{KeyMeta, KeyName, Result, SecretBytes};

/// Secret storage. Object-safe, so it can be passed as `&dyn Vault`.
pub trait Vault: Send + Sync {
    /// Stores `value` under `name`, replacing any existing value (the old one is wiped).
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<()>;

    /// Calls `f` with the value, borrowed. Returns [`ms_core::Error::NoSuchKey`] when absent.
    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()>;

    /// Deletes the key and wipes its value.
    fn delete(&self, name: &KeyName) -> Result<()>;

    /// Metadata for every key. Never values.
    fn list(&self) -> Result<Vec<KeyMeta>>;
}

/// Convenience methods for every [`Vault`], kept out of the trait so it stays object-safe.
pub trait VaultExt: Vault {
    /// Like [`Vault::with_secret`] but returns the closure's result.
    fn read_with<R>(&self, name: &KeyName, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        let mut f = Some(f);
        let mut out = None;
        self.with_secret(name, &mut |v| {
            if let Some(f) = f.take() {
                out = Some(f(v));
            }
        })?;
        // with_secret returned Ok, so the backend called the closure exactly once.
        out.ok_or_else(|| ms_core::Error::NoSuchKey(name.to_string()))
    }
}

impl<V: Vault + ?Sized> VaultExt for V {}
