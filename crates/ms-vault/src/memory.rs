//! In-memory vault for tests and fakes. Not for real secrets: nothing persists and there is no
//! access control beyond the process boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use ms_core::{Error, KeyMeta, KeyName, Result, SecretBytes};

use crate::Vault;

/// A [`Vault`] backed by a map. Values are [`SecretBytes`], so they are zeroized when replaced,
/// deleted or when the vault is dropped.
#[derive(Debug, Default)]
pub struct MemoryVault {
    entries: Mutex<BTreeMap<KeyName, (SecretBytes, KeyMeta)>>,
    /// Names standing in for keys another morsec build stored ([`MemoryVault::mark_unusable`]).
    unusable: Mutex<BTreeSet<KeyName>>,
}

impl MemoryVault {
    /// An empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Test stand-in for a key another morsec build stored: present, but this build may not
    /// read, replace or delete it. It shows up in [`Vault::scan`] as unusable, and reading it
    /// fails with access denied, as the keychain does.
    pub fn mark_unusable(&self, name: KeyName) {
        self.unusable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name);
    }

    fn is_unusable(&self, name: &KeyName) -> bool {
        self.unusable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(name)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<KeyName, (SecretBytes, KeyMeta)>> {
        // A poisoned lock only means another test thread panicked; the map itself is intact.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Vault for MemoryVault {
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<()> {
        self.lock().insert(name.clone(), (value, meta));
        Ok(())
    }

    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        if self.is_unusable(name) {
            return Err(Error::io(
                format!("reading {name}"),
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("access denied: {}", crate::unusable_hint(name)),
                ),
            ));
        }
        let map = self.lock();
        let (value, _) = map
            .get(name)
            .ok_or_else(|| Error::NoSuchKey(name.to_string()))?;
        f(value.expose());
        Ok(())
    }

    fn delete(&self, name: &KeyName) -> Result<()> {
        // Dropping the removed SecretBytes zeroizes its buffer.
        self.lock()
            .remove(name)
            .map(drop)
            .ok_or_else(|| Error::NoSuchKey(name.to_string()))
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        Ok(self.lock().values().map(|(_, m)| m.clone()).collect())
    }

    fn scan(&self) -> Result<crate::Listing> {
        Ok(crate::Listing {
            keys: self.list()?,
            unusable: self
                .unusable
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultExt;
    use ms_core::{Mode, Tier};

    fn meta(name: &KeyName) -> KeyMeta {
        KeyMeta {
            name: name.clone(),
            mode: Mode::Swap,
            tier: Tier::Test,
            created_unix_ms: 1,
        }
    }

    // protects=put/read/list/delete behave as a vault; fails_when=a value is lost, readable after
    // delete, or listed metadata leaks the value; no_claim=persistence or OS access control
    #[test]
    fn put_read_list_delete() {
        let v = MemoryVault::new();
        let k = KeyName::new("stripe/test").unwrap();
        v.put(&k, SecretBytes::from("sk_test_CANARY".to_owned()), meta(&k))
            .unwrap();
        assert_eq!(v.read_with(&k, |b| b.to_vec()).unwrap(), b"sk_test_CANARY");
        let listed = format!("{:?}", v.list().unwrap());
        assert!(
            listed.contains("stripe/test") && !listed.contains("CANARY"),
            "{listed}"
        );
        assert!(!format!("{v:?}").contains("CANARY"));
        v.delete(&k).unwrap();
        assert!(matches!(
            v.read_with(&k, |b| b.len()),
            Err(Error::NoSuchKey(_))
        ));
        assert!(matches!(v.delete(&k), Err(Error::NoSuchKey(_))));
        assert!(v.list().unwrap().is_empty());
    }

    // protects=put replaces the value; fails_when=the old value is still returned;
    // no_claim=the replaced buffer's memory contents (zeroize-on-drop is the zeroize crate's job)
    #[test]
    fn put_replaces() {
        let v = MemoryVault::new();
        let k = KeyName::new("a").unwrap();
        v.put(&k, SecretBytes::from(b"one".to_vec()), meta(&k))
            .unwrap();
        v.put(&k, SecretBytes::from(b"two".to_vec()), meta(&k))
            .unwrap();
        assert_eq!(v.read_with(&k, |b| b.to_vec()).unwrap(), b"two");
        assert_eq!(v.list().unwrap().len(), 1);
    }

    // protects=read_with on a missing key is NoSuchKey and the closure never runs;
    // fails_when=the closure runs or another error is returned; no_claim=other backends
    #[test]
    fn missing_key() {
        let v = MemoryVault::new();
        let k = KeyName::new("nope").unwrap();
        let mut called = false;
        let r = v.with_secret(&k, &mut |_| called = true);
        assert!(matches!(r, Err(Error::NoSuchKey(ref n)) if n == "nope"));
        assert!(!called);
    }

    // protects=the vault works through &dyn Vault (object safety) and VaultExt on dyn;
    // fails_when=the trait stops being object-safe; no_claim=nothing beyond compiling and one read
    #[test]
    fn usable_as_dyn() {
        let v = MemoryVault::new();
        let k = KeyName::new("a").unwrap();
        v.put(&k, SecretBytes::from(b"x".to_vec()), meta(&k))
            .unwrap();
        let d: &dyn Vault = &v;
        assert_eq!(d.read_with(&k, |b| b.len()).unwrap(), 1);
    }
}
