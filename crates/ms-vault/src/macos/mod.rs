//! macOS Keychain vault (L01).
//!
//! Backend: the legacy (file-based) login keychain. The day-one spike showed the data-protection
//! keychain needs a provisioning profile we don't have yet (`docs/evidence/vault-macos.md`), so
//! this is the card's fallback:
//!
//! - Every operation is **pinned to the login keychain** by path (home directory from the user
//!   database, not `$HOME`; no symlinks), so a keychain another process adds to the search list,
//!   makes the default, or points `$HOME` at is never read or written.
//! - Every item is created by `msd` (add-only, after deleting whatever held the name), so the
//!   keychain's default ACL trusts only `msd`'s **designated requirement** (for a Developer ID
//!   build: its identifier and team). Another binary, or a replaced `msd`, can't read it.
//! - Every item is **sealed**: its data carries an ECDSA signature over (service, account,
//!   metadata, value) made with a non-extractable seal key, pinned by its public-key hash in an
//!   item only `msd` can read. `list()` returns the sealed metadata, never the comment attribute. The legacy
//!   keychain lets any binary of the user overwrite an item's data; a changed or planted item
//!   fails the seal (or the ACL) and is refused, never used.
//! - Every call runs with keychain **user interaction disabled**, so a denied access is an error
//!   and never a dialog that `msd` itself asks the user to click. Every keychain call in this
//!   module holds [`quiet`]; dropping it turns dialogs back on process-wide, so `msd` (L07) should
//!   also disable them for its whole life.
//! - Values arrive in a [`SecretBytes`] straight from the keychain call and are zeroized on drop;
//!   [`Vault::with_secret`] lends them to the closure and never copies them out.
//!
//! Residuals (recorded in `docs/evidence/vault-macos.md`): Security.framework copies the data into
//! its own `CFData` on the way in and out and frees it without wiping. Production-tier user
//! presence is enforced by the approval path (L11), not by the Keychain. Another binary of the
//! user can make items unusable (delete key items, overwrite data): denial of service, fail
//! closed. Signing keys (seal, CA) are created only by the `reset_*` functions (`ms init`)
//! and pinned by public-key hash; `ensure_*` never create them. A user who clicks "Always Allow" on a keychain dialog raised by another binary
//! grants it access. The keychain *file* belongs to the user: restoring an older copy (rollback)
//! or swapping in another keychain at the same path is not detected here (`ms doctor`, L07).

mod ffi;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use core_foundation::data::CFData;
use ms_core::{Error, KeyMeta, KeyName, Mode, Result, SecretBytes, Tier};
use security_framework::base::Error as SfError;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, KeyClass, Limit, Location,
    Reference, SearchResult,
};
use security_framework::key::{Algorithm, SecKey};
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
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

/// Pins the seal key: SHA-256 of its public key, in an item only `msd` can read (not sealed).
const SEAL_PIN: &str = "morsec/seal-id";

/// Pins the CA key the same way.
const CA_PIN: &str = "morsec/ca-id";

/// The daemon's persistent state (the `ms stop` flag), written by msd with
/// [`KeychainVault::put_internal`] (L07).
pub const DAEMON_STATE_KEY: &str = "morsec/daemon-state";

/// The swap proxy's CA private key (PEM), written by msd with [`KeychainVault::put_internal`]
/// (L07). Kept in a sealed item only msd can read.
pub const CA_PEM_KEY: &str = "morsec/ca";

/// The proxy CA certificate and its host list (public, but kept here so no same-user process can
/// substitute them), written by msd with [`KeychainVault::put_internal`] (L07).
pub const CA_CERT_KEY: &str = "morsec/ca-cert";

/// The only reserved names [`KeychainVault::put_internal`] writes.
pub const INTERNAL_WRITABLE: [&str; 3] = [DAEMON_STATE_KEY, CA_PEM_KEY, CA_CERT_KEY];

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

    /// Search options for one item, pinned to the login keychain (so a keychain an attacker adds
    /// to the search list, or makes the default, is never consulted).
    fn item_query(&self, kc: &SecKeychain, name: &KeyName) -> ItemSearchOptions {
        let mut q = ItemSearchOptions::new();
        q.keychains(std::slice::from_ref(kc))
            .class(ItemClass::generic_password())
            .service(&self.service)
            .account(name.as_str());
        q
    }

    fn ca_label(&self) -> String {
        format!("{}.ca", self.service)
    }

    fn seal_label(&self) -> String {
        format!("{}.seal", self.service)
    }

    // --- Inner operations. The caller holds `quiet()`. ---

    /// Reads one item and checks its seal.
    fn read_locked(&self, kc: &SecKeychain, name: &KeyName) -> Result<Opened> {
        let blob = self.read_raw_locked(kc, name)?;
        self.open(kc, name, blob)
    }

    /// Reads one item's data, unchecked. The keychain hands back a buffer sized exactly to the
    /// item data, which moves into a `SecretBytes` without another copy.
    fn read_raw_locked(&self, kc: &SecKeychain, name: &KeyName) -> Result<SecretBytes> {
        let found = self
            .item_query(kc, name)
            .load_data(true)
            // The keychain rejects returning data for "all matches" (-50). (service, account) is
            // unique within one keychain, and the search is pinned to the login keychain.
            .limit(Limit::Max(1))
            .search();
        let mut items = match found {
            Ok(items) => items,
            Err(e) if e.code() == ERR_NOT_FOUND => return Err(Error::NoSuchKey(name.to_string())),
            Err(e) => return Err(keychain_error("reading", name.as_str(), e)),
        };
        if items.len() != 1 {
            // Not expected with a limit of 1; refuse rather than guess which value is ours.
            return Err(Error::io(
                format!("reading {name}"),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the keychain returned more than one item. Run: ms doctor",
                ),
            ));
        }
        match items.pop() {
            Some(SearchResult::Data(v)) => Ok(SecretBytes::new(v)),
            _ => Err(Error::io(
                format!("reading {name}"),
                std::io::Error::other("the keychain returned no data. Run: ms doctor"),
            )),
        }
    }

    /// Checks an item's seal and finds the value inside it. Any change made outside morsec (a
    /// direct `SecItemUpdate` of the data, which the legacy keychain lets any binary of the user
    /// do, or an item planted by another binary) fails here, closed.
    fn open(&self, kc: &SecKeychain, name: &KeyName, blob: SecretBytes) -> Result<Opened> {
        let tampered = || {
            Error::io(
                format!("reading {name}"),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the stored item was changed outside morsec (seal check failed), so it is not \
                     used. Re-add it with: ms add (or, for morsec/ keys: ms init)",
                ),
            )
        };
        let b = blob.expose();
        let rest = b.strip_prefix(SEAL_MAGIC.as_slice()).ok_or_else(tampered)?;
        let (&sig_len, rest) = rest.split_first().ok_or_else(tampered)?;
        let sig_len = usize::from(sig_len);
        if rest.len() < sig_len + 2 {
            return Err(tampered());
        }
        let (sig, rest) = rest.split_at(sig_len);
        let meta_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let rest = &rest[2..];
        if rest.len() < meta_len {
            return Err(tampered());
        }
        let (meta_json, value) = rest.split_at(meta_len);
        // Verify first; parse only bytes the seal vouches for.
        let seal = self.seal_key_locked(kc)?;
        let digest = seal_digest(&self.service, name, meta_json, value);
        if !seal.verify_digest_locked(&digest, sig) {
            return Err(tampered());
        }
        let meta: KeyMeta = serde_json::from_slice(meta_json).map_err(|_| tampered())?;
        if meta.name != *name {
            return Err(tampered());
        }
        let start = b.len() - value.len();
        Ok(Opened { blob, start, meta })
    }

    /// The vault seal key: the non-extractable P-256 key whose public key matches the pin
    /// [`SEAL_PIN`]. Created only by [`Self::reset_internal_keys`] (`ms init`).
    fn seal_key_locked(&self, kc: &SecKeychain) -> Result<CaKey> {
        self.load_pinned_key(kc, &self.seal_label(), SEAL_PIN, "the vault seal key")
    }

    /// Loads the signing key under `label` whose public key hash equals the pin stored in item
    /// `pin`. The pin item was created by this binary, so only it can read it; another binary
    /// can neither delete it nor overwrite it into something readable (both tested). Keys planted
    /// under the same label, even ones this binary may sign with, don't match the pin and are
    /// ignored; if ours was deleted, nothing matches and this fails closed.
    fn load_pinned_key(
        &self,
        kc: &SecKeychain,
        label: &str,
        pin: &str,
        what: &str,
    ) -> Result<CaKey> {
        let pin_name = KeyName::new(pin)?;
        let want = match self.read_raw_locked(kc, &pin_name) {
            Ok(v) if v.len() == 32 => v,
            Ok(_) => return Err(untrusted(what, "its pin is malformed")),
            Err(Error::NoSuchKey(_)) => {
                return Err(untrusted(
                    what,
                    "it has not been created yet (or its pin is missing)",
                ));
            }
            Err(e) => return Err(e),
        };
        for key in find_private_keys(kc, label)? {
            let k = CaKey { key };
            // The pin binds the label too, so one pin can't stand in for the other; and a probe
            // signature verified against the public key we hashed proves the private key found is
            // really its pair.
            if k.pin_hash_locked(label).is_some_and(|h| h == want.expose())
                && k.is_non_extractable_locked()
                && k.proves_pair_locked()
            {
                return Ok(k);
            }
        }
        Err(untrusted(
            what,
            "it is missing or replaced (deleted outside morsec)",
        ))
    }

    /// Creates a fresh signing key under `label` and pins it in item `pin`, replacing both. Keys
    /// already under the label (ours or planted) are deleted first; a key we may not delete fails
    /// closed.
    fn reset_pinned_key(&self, kc: &SecKeychain, label: &str, pin: &str) -> Result<CaKey> {
        delete_keys_locked(kc, label)?;
        let key = generate_key(kc, label)?;
        let hash = key.pin_hash_locked(label).ok_or_else(|| {
            Error::io(
                "pinning a new signing key",
                std::io::Error::other("the keychain returned no public key. Run: ms doctor"),
            )
        })?;
        let pin_name = KeyName::new(pin)?;
        self.delete_locked(kc, &pin_name)?;
        self.add_raw_locked(kc, &pin_name, &hash)?;
        Ok(key)
    }

    /// Adds an unsealed item (pins only), add-only.
    fn add_raw_locked(&self, kc: &SecKeychain, name: &KeyName, data: &[u8]) -> Result<()> {
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(data),
        });
        add.set_service(&self.service)
            .set_account_name(name.as_str())
            .set_label(format!("morsec {name}"))
            .set_location(Location::FileKeychain(kc.clone()));
        add.add()
            .map_err(|e| keychain_error("storing", name.as_str(), e))
    }

    /// Deletes one item. `Ok(false)` when there was none.
    fn delete_locked(&self, kc: &SecKeychain, name: &KeyName) -> Result<bool> {
        match self.item_query(kc, name).delete() {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_NOT_FOUND => Ok(false),
            Err(e) => Err(keychain_error("deleting", name.as_str(), e)),
        }
    }

    /// Adds a new item with `SecItemAdd` only: it never updates an existing item. Created by this
    /// binary, so the keychain's ACL trusts only this binary's designated requirement.
    fn add_locked(
        &self,
        kc: &SecKeychain,
        name: &KeyName,
        value: &SecretBytes,
        meta: &KeyMeta,
    ) -> Result<()> {
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
        // Seal: sign (service, account, metadata, value) with the seal key, and store the
        // signature and metadata with the value, so a change made outside morsec is detected.
        let seal = self.seal_key_locked(kc)?;
        let digest = seal_digest(&self.service, name, comment.as_bytes(), value.expose());
        let sig = seal.sign_digest_locked(&digest)?;
        let (Ok(sig_len), Ok(meta_len)) = (u8::try_from(sig.len()), u16::try_from(comment.len()))
        else {
            return Err(Error::io(
                format!("storing {name}"),
                std::io::Error::other("seal or metadata too long. This is a morsec bug: report it"),
            ));
        };
        let mut blob =
            Vec::with_capacity(SEAL_MAGIC.len() + 1 + sig.len() + 2 + comment.len() + value.len());
        blob.extend_from_slice(SEAL_MAGIC);
        blob.push(sig_len);
        blob.extend_from_slice(&sig);
        blob.extend_from_slice(&meta_len.to_be_bytes());
        blob.extend_from_slice(comment.as_bytes());
        blob.extend_from_slice(value.expose());
        // Exact capacity, so no reallocation left a stray copy; wiped on drop.
        let blob = SecretBytes::new(blob);
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            // Security.framework keeps its own copy of the data (see the module docs).
            data: CFData::from_buffer(blob.expose()),
        });
        add.set_service(&self.service)
            .set_account_name(name.as_str())
            .set_label(format!("morsec {name}"))
            .set_comment(comment)
            .set_location(Location::FileKeychain(kc.clone()));
        add.add().map_err(|e| {
            if e.code() == ERR_DUPLICATE {
                Error::io(
                    format!("storing {name} (OSStatus {ERR_DUPLICATE})"),
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "another writer stored it at the same moment. Retry",
                    ),
                )
            } else {
                keychain_error("storing", name.as_str(), e)
            }
        })
    }

    /// Replaces an item: delete, then add-only. Deleting first is deliberate: an item another
    /// process planted (with its own, perhaps open, ACL) is removed rather than updated, so the
    /// value always lands in an item this binary created. A planted item we may not delete fails
    /// here, closed, before the value is written anywhere. Not atomic: if the add then fails, the
    /// old value is gone (the error says so).
    fn replace_locked(
        &self,
        kc: &SecKeychain,
        name: &KeyName,
        value: &SecretBytes,
        meta: &KeyMeta,
    ) -> Result<()> {
        let had_old = self.delete_locked(kc, name).map_err(|e| {
            Error::io(
                format!("replacing {name}"),
                std::io::Error::other(e.to_string()),
            )
        })?;
        self.add_locked(kc, name, value, meta).map_err(|e| {
            if had_old {
                Error::io(
                    format!(
                        "replacing {name}: the old value was removed but the new one was not stored"
                    ),
                    std::io::Error::other(format!("{e}. Add the key again with: ms add")),
                )
            } else {
                e
            }
        })
    }

    /// Generates one internal HMAC key value.
    fn new_hmac_value(name: &KeyName) -> Result<(SecretBytes, KeyMeta)> {
        let mut buf = vec![0u8; HMAC_KEY_LEN];
        SecRandom::default()
            .copy_bytes(&mut buf)
            .map_err(|e| Error::io(format!("generating {name}"), e))?;
        let meta = KeyMeta {
            name: name.clone(),
            // Internal keys are never used for swap, run or mint; these fields only satisfy
            // KeyMeta. Production, so nothing ever treats them as low-risk.
            mode: Mode::Run,
            tier: Tier::Production,
            created_unix_ms: now_unix_ms(),
        };
        Ok((SecretBytes::new(buf), meta))
    }

    // --- Internal keys and the CA key. ---

    /// At startup: makes sure the internal HMAC keys ([`RECEIPTS_HMAC_KEY`], [`RULES_HMAC_KEY`])
    /// exist, creating a missing one ([`HMAC_KEY_LEN`] bytes from `SecRandomCopyBytes`).
    /// Existing keys are kept, never rotated: that would break every MAC made with them. A key
    /// of the wrong length, or one that fails its seal, is an error. Needs the seal key, so
    /// [`Self::reset_internal_keys`] (`ms init`) must have run.
    pub fn ensure_internal_keys(&self) -> Result<()> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        for raw in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY] {
            let name = KeyName::new(raw)?;
            match self.read_locked(&kc, &name) {
                Ok(v) if v.value().len() == HMAC_KEY_LEN => continue,
                Ok(v) => return Err(bad_hmac_len(&name, v.value().len())),
                Err(Error::NoSuchKey(_)) => {}
                Err(e) => return Err(e),
            }
            let (value, meta) = Self::new_hmac_value(&name)?;
            match self.add_locked(&kc, &name, &value, &meta) {
                Ok(()) => {}
                // Another msd created it between our read and add: keep theirs.
                Err(Error::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    match self.read_locked(&kc, &name) {
                        Ok(v) if v.value().len() == HMAC_KEY_LEN => {}
                        Ok(v) => return Err(bad_hmac_len(&name, v.value().len())),
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// For `ms init` on a new vault: creates and pins a fresh seal key and replaces both internal
    /// HMAC keys, removing anything already stored under their names (including keys another
    /// process planted before morsec was set up). Fails closed if an existing item may not be
    /// deleted. Items sealed with the old seal key can no longer be read afterwards.
    pub fn reset_internal_keys(&self) -> Result<()> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        self.reset_pinned_key(&kc, &self.seal_label(), SEAL_PIN)?;
        for raw in [RECEIPTS_HMAC_KEY, RULES_HMAC_KEY] {
            let name = KeyName::new(raw)?;
            let (value, meta) = Self::new_hmac_value(&name)?;
            self.replace_locked(&kc, &name, &value, &meta)?;
        }
        Ok(())
    }

    /// At startup: returns the CA signing key that [`Self::reset_ca_key`] (`ms init`) created
    /// and pinned. The private key is a non-extractable P-256 key in the login keychain; its bytes
    /// never exist in this process, and [`CaKey`] can only sign and give out the public key.
    /// Fails closed when the pinned key is gone; keys planted under the label are ignored.
    pub fn ensure_ca_key(&self) -> Result<CaKey> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        self.load_pinned_key(&kc, &self.ca_label(), CA_PIN, "the CA key")
    }

    /// For `ms init` and rotation: deletes every key with the CA label, then creates and pins a
    /// new one. Fails closed if a key may not be deleted.
    pub fn reset_ca_key(&self) -> Result<CaKey> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        self.reset_pinned_key(&kc, &self.ca_label(), CA_PIN)
    }

    /// Writes one of morsec's own items: only the names in [`INTERNAL_WRITABLE`] (the daemon state
    /// and the proxy CA key, L07). [`Vault::put`] refuses every `morsec/` name so no client can
    /// overwrite these; this is the daemon's own path. The item is sealed and ACL-bound to the
    /// signed msd like any other, so another binary can neither read nor rewrite it unnoticed.
    pub fn put_internal(&self, name: &KeyName, value: SecretBytes) -> Result<()> {
        if !INTERNAL_WRITABLE.contains(&name.as_str()) {
            return Err(reserved_error(name));
        }
        let meta = KeyMeta {
            name: name.clone(),
            mode: ms_core::Mode::Swap,
            tier: ms_core::Tier::Production,
            created_unix_ms: 0,
        };
        let _q = quiet()?;
        let kc = login_keychain()?;
        self.replace_locked(&kc, name, &value, &meta)
    }

    /// Deletes the CA key pair and its pin. No error when there is none.
    pub fn delete_ca_key(&self) -> Result<()> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        delete_keys_locked(&kc, &self.ca_label())?;
        self.delete_locked(&kc, &KeyName::new(CA_PIN)?).map(drop)
    }
}

fn bad_hmac_len(name: &KeyName, len: usize) -> Error {
    Error::io(
        format!("checking {name}"),
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the key is {len} bytes, expected {HMAC_KEY_LEN}. Re-initialise with: ms init"),
        ),
    )
}

fn untrusted(what: &str, why: &str) -> Error {
    Error::io(
        format!("loading {what}"),
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{why}. Re-create it with: ms init"),
        ),
    )
}

const SEAL_MAGIC: &[u8; 4] = b"MSV1";

/// What the seal signs: SHA-256 over a domain tag and the length-prefixed service, account,
/// metadata and value. Hashed incrementally, so the value is never copied into a buffer.
fn seal_digest(service: &str, name: &KeyName, meta: &[u8], value: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"morsec-vault-seal-v1\0");
    for part in [service.as_bytes(), name.as_str().as_bytes(), meta, value] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// An item read from the keychain whose seal checked out. The whole item data is wiped on drop.
struct Opened {
    blob: SecretBytes,
    start: usize,
    meta: KeyMeta,
}

impl Opened {
    fn value(&self) -> &[u8] {
        &self.blob.expose()[self.start..]
    }
}

/// Opens the user's login keychain by path. Every operation is pinned to it. The home directory
/// comes from the user database, never `$HOME`, and the path must contain no symlink: otherwise
/// whoever starts `msd` could point it at a keychain whose password they know.
fn login_keychain() -> Result<SecKeychain> {
    let fail = |why: &str| {
        Error::io(
            "finding the login keychain",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_owned()),
        )
    };
    let home = ffi::home_dir_from_passwd().ok_or_else(|| {
        fail("no home directory in the user database. Run msd as a logged-in user")
    })?;
    // The home directory itself may sit under a system symlink (/var -> /private/var); what must
    // not be a symlink is anything from the home directory down to the keychain file.
    let home = std::fs::canonicalize(&home)
        .map_err(|_| fail("the home directory in the user database does not exist"))?;
    let path = home.join("Library/Keychains/login.keychain-db");
    match std::fs::canonicalize(&path) {
        Ok(real) if real == path => {}
        _ => {
            return Err(fail(
                "~/Library/Keychains/login.keychain-db is missing or reached through a symlink. \
                 Restore the login keychain (Keychain Access), then run: ms doctor",
            ));
        }
    }
    SecKeychain::open(&path).map_err(|e| keychain_error("opening the login keychain", "", e))
}

fn generate_key(kc: &SecKeychain, label: &str) -> Result<CaKey> {
    let key = ffi::generate_signing_key(kc, label).map_err(|e| {
        Error::io(
            "creating a signing key in the login keychain",
            std::io::Error::other(format!(
                "{} (code {}). Unlock the login keychain and retry, or run: ms doctor",
                e.description(),
                e.code()
            )),
        )
    })?;
    Ok(CaKey { key })
}

fn delete_keys_locked(kc: &SecKeychain, label: &str) -> Result<()> {
    // Deletes both the private and the public half: they share the label.
    match ItemSearchOptions::new()
        .keychains(std::slice::from_ref(kc))
        .class(ItemClass::key())
        .label(label)
        .limit(Limit::All)
        .delete()
    {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERR_NOT_FOUND => Ok(()),
        Err(e) => Err(keychain_error("deleting a signing key", "", e)),
    }
}

fn find_private_keys(kc: &SecKeychain, label: &str) -> Result<Vec<SecKey>> {
    let found = ItemSearchOptions::new()
        .keychains(std::slice::from_ref(kc))
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(Limit::All)
        .search();
    match found {
        Ok(items) => Ok(items
            .into_iter()
            .filter_map(|r| match r {
                SearchResult::Ref(Reference::Key(k)) => Some(k),
                _ => None,
            })
            .collect()),
        Err(e) if e.code() == ERR_NOT_FOUND => Ok(Vec::new()),
        Err(e) => Err(keychain_error("looking up a signing key", "", e)),
    }
}

impl Vault for KeychainVault {
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<()> {
        if reserved(name) {
            return Err(reserved_error(name));
        }
        let _q = quiet()?;
        let kc = login_keychain()?;
        self.replace_locked(&kc, name, &value, &meta)
        // `value` is dropped (zeroized) when this returns.
    }

    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        let value = {
            let _q = quiet()?;
            let kc = login_keychain()?;
            self.read_locked(&kc, name)?
        };
        // The lock is released before the closure runs, so the closure may use the vault.
        f(value.value());
        Ok(())
        // `value` is dropped here, which zeroizes the buffer.
    }

    fn delete(&self, name: &KeyName) -> Result<()> {
        if reserved(name) {
            return Err(reserved_error(name));
        }
        let _q = quiet()?;
        let kc = login_keychain()?;
        if self.delete_locked(&kc, name)? {
            Ok(())
        } else {
            Err(Error::NoSuchKey(name.to_string()))
        }
    }

    /// Metadata of every key, taken from inside each item's seal. The comment attribute is only
    /// a display copy (any binary of the user can rewrite it), so it is never trusted. Each item
    /// is read and checked, in `msd` only, and wiped right after. Items that fail (left by
    /// another version, planted, or changed outside morsec) are skipped, so one bad item can't
    /// hide the rest; reading such a key reports why.
    fn list(&self) -> Result<Vec<KeyMeta>> {
        let _q = quiet()?;
        let kc = login_keychain()?;
        // Attributes only, to find the names.
        let found = ItemSearchOptions::new()
            .keychains(std::slice::from_ref(&kc))
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let items = match found {
            Ok(items) => items,
            Err(e) if e.code() == ERR_NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(keychain_error("listing keys", "", e)),
        };
        // A missing or replaced seal key is an error ("run ms init"), not an empty list.
        self.seal_key_locked(&kc)?;
        let mut out: Vec<KeyMeta> = items
            .iter()
            .filter(|item| matches!(item, SearchResult::Dict(_)))
            .filter_map(|item| {
                let attrs: HashMap<String, String> = item.simplify_dict()?;
                let name = KeyName::new(attrs.get("acct")?).ok()?;
                if reserved(&name) {
                    return None;
                }
                Some(self.read_locked(&kc, &name).map(|o| o.meta.clone()))
            })
            .filter_map(|r| match r {
                Ok(meta) => Some(Ok(meta)),
                // Skip items that fail their seal or vanished mid-list; a bad item can't hide the
                // rest. Anything else (locked keychain, missing seal key) is an error, not "no keys".
                Err(Error::NoSuchKey(_)) => None,
                Err(Error::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::InvalidData =>
                {
                    None
                }
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<_>>()?;
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
        let _q = quiet()?;
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
        self.sign_locked(msg)
    }

    fn sign_digest_locked(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.key
            .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest)
            .map_err(|e| {
                Error::io(
                    "sealing a vault item",
                    std::io::Error::other(format!(
                        "{} (code {}). Run the signed msd (ms start)",
                        e.description(),
                        e.code()
                    )),
                )
            })
    }

    /// The pin: SHA-256 over a domain tag, the key's label and its public key (SEC1).
    fn pin_hash_locked(&self, label: &str) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let pubkey = self.key.public_key()?.external_representation()?;
        let mut h = Sha256::new();
        h.update(b"morsec-pin-v1\0");
        h.update((label.len() as u64).to_be_bytes());
        h.update(label.as_bytes());
        h.update(pubkey.bytes());
        Some(h.finalize().into())
    }

    /// Signs a probe and verifies it with the public key: true only when this binary may sign
    /// with the key and the private key is the pair of the public key we pinned.
    fn proves_pair_locked(&self) -> bool {
        // A fixed digest is fine: only that the signature verifies matters.
        let digest = [0x5a_u8; 32];
        self.sign_digest_locked(&digest)
            .is_ok_and(|sig| self.verify_digest_locked(&digest, &sig))
    }

    fn verify_digest_locked(&self, digest: &[u8; 32], sig: &[u8]) -> bool {
        self.key.public_key().is_some_and(|p| {
            p.verify_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest, sig)
                .unwrap_or(false)
        })
    }

    fn sign_locked(&self, msg: &[u8]) -> Result<Vec<u8>> {
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
        // Asking for the private key's bytes on the file-based keychain can raise an export
        // dialog, so do it with dialogs off.
        match quiet() {
            Ok(_q) => self.is_non_extractable_locked(),
            Err(_) => false,
        }
    }

    fn is_non_extractable_locked(&self) -> bool {
        self.key.external_representation().is_none()
    }
}
