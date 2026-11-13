//! macOS Keychain vault (L01).
//!
//! Backend: the legacy (file-based) login keychain. The day-one spike showed the data-protection
//! keychain needs a provisioning profile we don't have yet (`docs/evidence/vault-macos.md`), so
//! this is the card's fallback:
//!
//! - Every item is created by `msd`, so the keychain's default ACL trusts only `msd`'s
//!   **designated requirement** (for a Developer ID build: its identifier and team). Another
//!   binary, or a replaced `msd`, is denied; it can't read silently.
//! - Every call runs with keychain **user interaction disabled**, so a denied access is an error
//!   and never a dialog that `msd` itself asks the user to click.
//! - Values arrive in a [`SecretBytes`] straight from the keychain call and are zeroized on drop;
//!   [`Vault::with_secret`] lends them to the closure and never copies them out.
//!
//! Residual (recorded in the evidence file): Security.framework copies the value into its own
//! `CFData` on the way in and out and frees it without wiping. Production-tier user presence is
//! enforced by the approval path (L11), not by the Keychain, on this backend.

mod ffi;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ms_core::{Error, KeyMeta, KeyName, Mode, Result, SecretBytes, Tier};
use security_framework::base::Error as SfError;
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Reference, SearchResult,
};
use security_framework::key::{Algorithm, SecKey};
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
};
use security_framework::passwords_options::PasswordOptions;
use security_framework::random::SecRandom;

use crate::Vault;

/// Keychain service for every morsec item. The account is the key name.
pub const SERVICE: &str = "cc.morsec.vault";

/// Names under this prefix belong to morsec itself. The trait can't write, delete or list them.
pub const RESERVED_PREFIX: &str = "morsec/";

/// HMAC key for receipts (L02 reads it by this name through [`Vault::with_secret`]).
pub const RECEIPTS_HMAC_KEY: &str = "morsec/receipts-hmac";

/// HMAC key for the rules file (L03).
pub const RULES_HMAC_KEY: &str = "morsec/rules-hmac";

/// Length of each internal HMAC key, in bytes.
pub const HMAC_KEY_LEN: usize = 32;

// errSec* codes we treat specially.
const ERR_NOT_FOUND: i32 = -25300;
const ERR_DUPLICATE: i32 = -25299;
const ERR_AUTH_FAILED: i32 = -25293;
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_USER_CANCELED: i32 = -128;
const ERR_NO_SUCH_KEYCHAIN: i32 = -25294;
const ERR_NO_DEFAULT_KEYCHAIN: i32 = -25307;
const ERR_MISSING_ENTITLEMENT: i32 = -34018;

/// `SecKeychainSetUserInteractionAllowed` is process-wide, so every keychain call in this process
/// holds this lock while interaction is disabled; one call can't re-enable it under another.
static KEYCHAIN: Mutex<()> = Mutex::new(());

/// Holds the process lock and keeps keychain dialogs off for one operation.
struct Quiet {
    _interaction: KeychainUserInteractionLock,
    _lock: MutexGuard<'static, ()>,
}

fn quiet() -> Result<Quiet> {
    // A poisoned lock only means another thread panicked mid-call; the keychain itself is fine.
    let lock = KEYCHAIN.lock().unwrap_or_else(|e| e.into_inner());
    let interaction = SecKeychain::disable_user_interaction()
        .map_err(|e| keychain_error("turning off Keychain dialogs", "", e))?;
    Ok(Quiet {
        _interaction: interaction,
        _lock: lock,
    })
}

/// Maps a Security.framework status to a morsec error that says what happened and the fix.
/// Never includes a value: only the action, the key name and the status code.
fn keychain_error(action: &str, name: &str, e: SfError) -> Error {
    let code = e.code();
    let hint = match code {
        ERR_AUTH_FAILED | ERR_USER_CANCELED => {
            "access denied: only the signed msd that stored this key may use it. Run the signed msd \
             (ms start), or re-add the key with: ms add"
        }
        ERR_INTERACTION_NOT_ALLOWED => {
            "the login keychain is locked or the access needs approval. Unlock it (log in, or run: \
             security unlock-keychain) and run the signed msd (ms start)"
        }
        ERR_NO_SUCH_KEYCHAIN | ERR_NO_DEFAULT_KEYCHAIN => {
            "no login keychain. Open Keychain Access and create or reset the login keychain"
        }
        ERR_MISSING_ENTITLEMENT => {
            "this build lacks a Keychain entitlement. Reinstall morsec from the signed release"
        }
        _ => "macOS Keychain error. Run: ms doctor",
    };
    let target = if name.is_empty() {
        String::new()
    } else {
        format!(" {name}")
    };
    Error::io(
        format!("{action}{target} (OSStatus {code})"),
        std::io::Error::other(hint),
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn reserved(name: &KeyName) -> bool {
    name.as_str().starts_with(RESERVED_PREFIX)
}

fn reserved_error(name: &KeyName) -> Error {
    Error::io(
        format!("refusing to change {name}"),
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "names under morsec/ are morsec's own keys. Pick another name, e.g. myapp/key",
        ),
    )
}

/// A [`Vault`] in the macOS login keychain. Only the binary that created an item can read it.
#[derive(Debug, Clone)]
pub struct KeychainVault {
    service: String,
}

impl Default for KeychainVault {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainVault {
    /// The vault under service [`SERVICE`].
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }

    /// A vault under another service name. Tests use this so they never touch real keys.
    #[cfg(test)]
    pub(crate) fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn options(&self, name: &KeyName) -> PasswordOptions {
        PasswordOptions::new_generic_password(&self.service, name.as_str())
    }

    fn ca_label(&self) -> String {
        format!("{}.ca", self.service)
    }

    /// Writes an item. The caller has already checked the name.
    fn store(&self, name: &KeyName, value: &SecretBytes, meta: &KeyMeta) -> Result<()> {
        if meta.name != *name {
            return Err(Error::io(
                format!("storing {name}"),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "metadata names {} but the key is {name}. This is a morsec bug: report it",
                        meta.name
                    ),
                ),
            ));
        }
        let comment = serde_json::to_string(meta).map_err(|e| {
            Error::io(
                format!("storing {name}"),
                std::io::Error::other(e.to_string()),
            )
        })?;
        let _q = quiet()?;
        // Delete then add, so the comment (metadata) is replaced along with the value. A delete we
        // are not allowed to do fails here, closed, before anything is written.
        match delete_generic_password_options(self.options(name)) {
            Ok(()) => {}
            Err(e) if e.code() == ERR_NOT_FOUND => {}
            Err(e) => return Err(keychain_error("replacing", name.as_str(), e)),
        }
        let mut opts = self.options(name);
        opts.set_label(&format!("morsec {name}"));
        opts.set_comment(&comment);
        set_generic_password_options(value.expose(), opts).map_err(|e| {
            if e.code() == ERR_DUPLICATE {
                // Someone re-created it between our delete and add. Fail rather than overwrite.
                keychain_error("storing (raced with another writer)", name.as_str(), e)
            } else {
                keychain_error("storing", name.as_str(), e)
            }
        })
    }

    fn read(&self, name: &KeyName) -> Result<SecretBytes> {
        let _q = quiet()?;
        // The Vec moves into SecretBytes; it is not copied.
        match generic_password(self.options(name)) {
            Ok(v) => Ok(SecretBytes::new(v)),
            Err(e) if e.code() == ERR_NOT_FOUND => Err(Error::NoSuchKey(name.to_string())),
            Err(e) => Err(keychain_error("reading", name.as_str(), e)),
        }
    }

    fn remove(&self, name: &KeyName) -> Result<()> {
        let _q = quiet()?;
        match delete_generic_password_options(self.options(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_NOT_FOUND => Err(Error::NoSuchKey(name.to_string())),
            Err(e) => Err(keychain_error("deleting", name.as_str(), e)),
        }
    }

    /// Creates the internal HMAC keys ([`RECEIPTS_HMAC_KEY`], [`RULES_HMAC_KEY`]) when missing:
    /// [`HMAC_KEY_LEN`] random bytes from `SecRandomCopyBytes`. Existing keys are kept. Fails if
    /// an existing key has the wrong length, rather than replacing it (that would break every
    /// receipt and rules MAC made with it).
    pub fn ensure_internal_keys(&self) -> Result<()> {
        for raw in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY] {
            let name = KeyName::new(raw)?;
            match self.read(&name) {
                Ok(v) if v.len() == HMAC_KEY_LEN => continue,
                Ok(v) => {
                    return Err(Error::io(
                        format!("checking {name}"),
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "the key is {} bytes, expected {HMAC_KEY_LEN}. Run: ms doctor",
                                v.len()
                            ),
                        ),
                    ));
                }
                Err(Error::NoSuchKey(_)) => {}
                Err(e) => return Err(e),
            }
            let mut buf = vec![0u8; HMAC_KEY_LEN];
            SecRandom::default()
                .copy_bytes(&mut buf)
                .map_err(|e| Error::io(format!("generating {name}"), e))?;
            let value = SecretBytes::new(buf);
            let meta = KeyMeta {
                name: name.clone(),
                // Internal keys are never used for swap, run or mint; these fields only satisfy
                // KeyMeta. Production, so nothing ever treats them as low-risk.
                mode: Mode::Run,
                tier: Tier::Production,
                created_unix_ms: now_unix_ms(),
            };
            self.store(&name, &value, &meta)?;
        }
        Ok(())
    }

    /// Returns the CA signing key, creating it on first use: a P-256 key pair in the login
    /// keychain whose private key is non-extractable. The private key bytes never exist in this
    /// process; [`CaKey`] can only sign and give out the public key.
    pub fn ensure_ca_key(&self) -> Result<CaKey> {
        let label = self.ca_label();
        let _q = quiet()?;
        if let Some(key) = find_private_key(&label)? {
            return Ok(CaKey { key });
        }
        let key = ffi::generate_ca_key(&label).map_err(|e| {
            Error::io(
                "creating the CA key in the login keychain",
                std::io::Error::other(format!(
                    "{} (code {}). Unlock the login keychain and retry, or run: ms doctor",
                    e.description(),
                    e.code()
                )),
            )
        })?;
        Ok(CaKey { key })
    }

    /// Deletes the CA key pair (for example to rotate it). No error when there is none.
    pub fn delete_ca_key(&self) -> Result<()> {
        let label = self.ca_label();
        let _q = quiet()?;
        // Deletes both the private and the public half: they share the label.
        match ItemSearchOptions::new()
            .class(ItemClass::key())
            .label(&label)
            .limit(Limit::All)
            .delete()
        {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_NOT_FOUND => Ok(()),
            Err(e) => Err(keychain_error("deleting the CA key", "", e)),
        }
    }
}

fn find_private_key(label: &str) -> Result<Option<SecKey>> {
    let found = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(Limit::Max(1))
        .search();
    match found {
        Ok(items) => Ok(items.into_iter().find_map(|r| match r {
            SearchResult::Ref(Reference::Key(k)) => Some(k),
            _ => None,
        })),
        Err(e) if e.code() == ERR_NOT_FOUND => Ok(None),
        Err(e) => Err(keychain_error("looking up the CA key", "", e)),
    }
}

impl Vault for KeychainVault {
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<()> {
        if reserved(name) {
            return Err(reserved_error(name));
        }
        // `value` is dropped (zeroized) when this returns.
        self.store(name, &value, &meta)
    }

    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        let value = self.read(name)?;
        f(value.expose());
        Ok(())
        // `value` is dropped here, which zeroizes the buffer.
    }

    fn delete(&self, name: &KeyName) -> Result<()> {
        if reserved(name) {
            return Err(reserved_error(name));
        }
        self.remove(name)
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        let found = {
            let _q = quiet()?;
            // Attributes only: no item data is requested, so no value is decrypted.
            ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(&self.service)
                .load_attributes(true)
                .limit(Limit::All)
                .search()
        };
        let items = match found {
            Ok(items) => items,
            Err(e) if e.code() == ERR_NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(keychain_error("listing keys", "", e)),
        };
        let mut out = Vec::new();
        for item in items {
            let SearchResult::Dict(_) = &item else {
                continue;
            };
            let attrs: HashMap<String, String> = item.simplify_dict().unwrap_or_default();
            let account = attrs.get("acct").map(String::as_str).unwrap_or_default();
            let name = KeyName::new(account)?;
            if reserved(&name) {
                continue;
            }
            let meta = attrs
                .get("icmt")
                .and_then(|c| serde_json::from_str::<KeyMeta>(c).ok())
                .filter(|m| m.name == name)
                .ok_or_else(|| {
                    Error::io(
                        format!("listing {name}"),
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "its metadata is missing or does not match. Re-add it with: ms add",
                        ),
                    )
                })?;
            out.push(meta);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// The CA private key, held in the keychain. Can sign; can't be exported, even by `msd`.
pub struct CaKey {
    key: SecKey,
}

impl std::fmt::Debug for CaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CaKey(P-256, non-extractable)")
    }
}

impl CaKey {
    /// The public key as an uncompressed SEC1 point (65 bytes, `04 || X || Y`).
    pub fn public_key_sec1(&self) -> Result<Vec<u8>> {
        self.key
            .public_key()
            .and_then(|p| p.external_representation())
            .map(|d| d.to_vec())
            .ok_or_else(|| {
                Error::io(
                    "reading the CA public key",
                    std::io::Error::other("the keychain returned none. Run: ms doctor"),
                )
            })
    }

    /// Signs `msg` with ECDSA P-256 over SHA-256. Returns the DER (X9.62) signature.
    pub fn sign_sha256(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let _q = quiet()?;
        self.key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .map_err(|e| {
                Error::io(
                    "signing with the CA key",
                    std::io::Error::other(format!(
                        "{} (code {}). Run the signed msd (ms start); only it may use the CA key",
                        e.description(),
                        e.code()
                    )),
                )
            })
    }

    /// True when the keychain refuses to export the private key (it should, always).
    pub fn is_non_extractable(&self) -> bool {
        self.key.external_representation().is_none()
    }
}
