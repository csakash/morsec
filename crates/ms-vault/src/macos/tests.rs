//! Tests against the real login keychain.
//!
//! Each test uses its own service name (`cc.morsec.test.<pid>.<n>`), so real morsec keys are never
//! touched, and deletes everything it made, even on failure. Every call runs with keychain
//! dialogs off, so a test never waits on a prompt. Set `MORSEC_SKIP_KEYCHAIN_TESTS=1` to skip them
//! (for example over SSH, where the login keychain is locked); the skip is printed, never silent.
//!
//! The ACL test copies this test binary, re-signs the copy, and runs one `#[ignore]`d child test
//! in it (`acl_child`) to act as "another binary".
//!
//! No test may raise a keychain dialog, because a dialog blocks the gate until someone clicks it.
//! Turning interaction off (`quiet`, `SecKeychainSetUserInteractionAllowed(false)`) covers ACL
//! prompts but not one kind: when a differently signed binary *modifies* our item
//! (`SecItemUpdate`), securityd asks the user about the item's partition list (a "XARA" dialog)
//! whatever the flag says (seen on macOS 26.2, `docs/evidence/cli-scope.md`). So the re-signed
//! child never modifies items; tampering is done by the trusted copy instead. And every child runs
//! under [`CHILD_TIMEOUT`]: one that hangs is killed (which withdraws any dialog) and the test
//! fails, rather than waiting on a human.

// The child tests report to the parent over stdout, and skips are printed so they are never silent.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use core_foundation::data::CFData;
use ms_core::{Error, KeyMeta, KeyName, Mode, SecretBytes, Tier};
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue,
    Limit, Location, update_item,
};
use security_framework::key::Algorithm;

use super::*;
use crate::{Vault, VaultExt};

const CANARY: &str = "sk_test_MORSEC_CANARY_9d41e7b2";

fn skip() -> bool {
    if std::env::var_os("MORSEC_SKIP_KEYCHAIN_TESTS").is_some() {
        eprintln!("SKIPPED: macOS keychain test (MORSEC_SKIP_KEYCHAIN_TESTS is set)");
        return true;
    }
    false
}

/// A vault under a unique test service; deletes its items, pins and keys when dropped.
struct TestVault {
    vault: KeychainVault,
    service: String,
}

impl TestVault {
    /// Initialised, as after `ms init`: seal key and internal keys exist.
    fn new() -> Self {
        let t = Self::bare();
        t.vault.reset_internal_keys().unwrap();
        t
    }

    /// Not initialised.
    fn bare() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let service = format!(
            "cc.morsec.test.{}.{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        Self {
            vault: KeychainVault::with_service(service.clone()),
            service,
        }
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        let _q = quiet();
        let Ok(kc) = login_keychain() else { return };
        let left = ItemSearchOptions::new()
            .keychains(std::slice::from_ref(&kc))
            .class(ItemClass::generic_password())
            .service(&self.service)
            .limit(Limit::All)
            .delete();
        drop(_q);
        let ca = self.vault.delete_ca_key();
        let seal = quiet().and_then(|_q| delete_keys_locked(&kc, &self.vault.seal_label()));
        if left.is_err_and(|e| e.code() != -25300) || ca.is_err() || seal.is_err() {
            eprintln!(
                "WARNING: test items may remain under service {} (remove with: security \
                 delete-generic-password -s {})",
                self.service, self.service
            );
        }
    }
}

fn meta(name: &KeyName, tier: Tier) -> KeyMeta {
    KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier,
        created_unix_ms: 1_700_000_000_000,
    }
}

fn key(s: &str) -> KeyName {
    KeyName::new(s).unwrap()
}

// protects=put/with_secret/list/delete work against the real keychain and list carries metadata
// only; fails_when=a value is lost, readable after delete, or appears in list/Debug output;
// no_claim=access control against other binaries (see acl_other_binary_is_denied)
#[test]
fn round_trip() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let v = &t.vault;
    let k = key("stripe/test");
    v.put(
        &k,
        SecretBytes::from(CANARY.to_owned()),
        meta(&k, Tier::Test),
    )
    .unwrap();
    assert_eq!(v.read_with(&k, |b| b.to_vec()).unwrap(), CANARY.as_bytes());

    let listed = v.list().unwrap();
    assert_eq!(listed, vec![meta(&k, Tier::Test)]);
    let shown = format!("{listed:?} {v:?}");
    assert!(!shown.contains("CANARY"), "{shown}");

    v.delete(&k).unwrap();
    assert!(matches!(
        v.read_with(&k, |b| b.len()),
        Err(Error::NoSuchKey(_))
    ));
    assert!(matches!(v.delete(&k), Err(Error::NoSuchKey(_))));
    assert!(v.list().unwrap().is_empty());
}

// protects=put replaces both value and metadata; fails_when=the old value or old tier survives;
// no_claim=the old CFData copy inside Security.framework is wiped (it is not; see evidence)
#[test]
fn put_replaces_value_and_meta() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let v = &t.vault;
    let k = key("db/prod");
    v.put(&k, SecretBytes::from(b"one".to_vec()), meta(&k, Tier::Test))
        .unwrap();
    v.put(
        &k,
        SecretBytes::from(b"two".to_vec()),
        meta(&k, Tier::Production),
    )
    .unwrap();
    assert_eq!(v.read_with(&k, |b| b.to_vec()).unwrap(), b"two");
    assert_eq!(v.list().unwrap(), vec![meta(&k, Tier::Production)]);
}

// protects=a missing key is NoSuchKey and the closure never runs; fails_when=the closure runs or
// another error comes back; no_claim=nothing about denied keys
#[test]
fn missing_key() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let mut called = false;
    let r = t.vault.with_secret(&key("nope"), &mut |_| called = true);
    assert!(
        matches!(r, Err(Error::NoSuchKey(ref n)) if n == "nope"),
        "{r:?}"
    );
    assert!(!called);
}

// protects=metadata whose name disagrees with the key is refused; fails_when=it is stored;
// no_claim=other metadata validation
#[test]
fn meta_name_must_match() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let k = key("a");
    let r = t.vault.put(
        &k,
        SecretBytes::from(b"x".to_vec()),
        meta(&key("b"), Tier::Test),
    );
    assert!(r.is_err());
    assert!(t.vault.list().unwrap().is_empty());
}

// protects=names under morsec/ can't be written or deleted through the trait, and internal keys
// are 32 random bytes, stable across ensure, rotated only by reset, readable by msd and hidden
// from list; fails_when=a user put overwrites an HMAC key, ensure rotates an existing key, or
// list shows internal keys or pins; no_claim=randomness quality (SecRandomCopyBytes)
#[test]
fn internal_keys() {
    if skip() {
        return;
    }
    let bare = TestVault::bare();
    let e = bare.vault.ensure_internal_keys().unwrap_err().to_string();
    assert!(e.contains("ms init"), "needs init first: {e}");

    let t = TestVault::new();
    let v = &t.vault;
    let rk = key(RECEIPTS_HMAC_KEY);
    let err = v
        .put(
            &rk,
            SecretBytes::from(b"evil".to_vec()),
            meta(&rk, Tier::Test),
        )
        .unwrap_err();
    assert!(err.to_string().contains("morsec's own keys"), "{err}");

    let first = v.read_with(&rk, |b| b.to_vec()).unwrap();
    assert_eq!(first.len(), HMAC_KEY_LEN);
    assert_ne!(first, vec![0u8; HMAC_KEY_LEN]);
    let rules = v.read_with(&key(RULES_HMAC_KEY), |b| b.to_vec()).unwrap();
    assert_ne!(first, rules, "the two HMAC keys must differ");

    v.ensure_internal_keys().unwrap();
    assert_eq!(
        v.read_with(&rk, |b| b.to_vec()).unwrap(),
        first,
        "ensure must not rotate"
    );

    assert!(
        v.list().unwrap().is_empty(),
        "internal keys and pins are hidden"
    );
    assert!(v.delete(&rk).is_err());
    assert!(v.delete(&key(SEAL_PIN)).is_err());
    assert_eq!(v.read_with(&rk, |b| b.len()).unwrap(), HMAC_KEY_LEN);

    v.reset_internal_keys().unwrap();
    assert_ne!(
        v.read_with(&rk, |b| b.to_vec()).unwrap(),
        first,
        "reset rotates"
    );
}

// protects=the CA private key is non-extractable, signs verifiably, and is reused; fails_when=the
// keychain exports the private key, a signature fails to verify, or a second ensure makes a new
// key; no_claim=certificate issuance (L05)
#[test]
fn ca_key() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let e = t.vault.ensure_ca_key().unwrap_err().to_string();
    assert!(e.contains("ms init"), "created only by reset: {e}");
    let ca = t.vault.reset_ca_key().unwrap();
    assert!(
        ca.is_non_extractable(),
        "CA private key must not be exportable"
    );
    let pubkey = ca.public_key_sec1().unwrap();
    assert_eq!(pubkey.len(), 65);
    assert_eq!(pubkey[0], 0x04);

    let sig = ca.sign_sha256(b"tbs certificate").unwrap();
    let verifier = ca.key.public_key().unwrap();
    assert!(
        verifier
            .verify_signature(
                Algorithm::ECDSASignatureMessageX962SHA256,
                b"tbs certificate",
                &sig
            )
            .unwrap()
    );
    assert!(
        !verifier
            .verify_signature(Algorithm::ECDSASignatureMessageX962SHA256, b"other", &sig)
            .unwrap_or(false)
    );

    let again = t.vault.ensure_ca_key().unwrap();
    assert_eq!(
        again.public_key_sec1().unwrap(),
        pubkey,
        "must reuse the key"
    );
    assert_eq!(format!("{again:?}"), "CaKey(P-256, non-extractable)");

    let fresh = t.vault.reset_ca_key().unwrap();
    assert_ne!(fresh.public_key_sec1().unwrap(), pubkey);
    t.vault.delete_ca_key().unwrap();
    assert!(t.vault.ensure_ca_key().is_err());
}

// protects=errors carry the status, the key name and a fix, and never the value;
// fails_when=an error message lacks the fix or the OSStatus; no_claim=every OSStatus is mapped
#[test]
fn error_messages() {
    let e = keychain_error(
        "reading",
        "stripe/test",
        SfError::from_code(ERR_AUTH_FAILED),
    );
    let s = e.to_string();
    assert!(
        s.starts_with("morsec: reading stripe/test (OSStatus -25293)"),
        "{s}"
    );
    assert!(s.contains("only the signed msd"), "{s}");
    let s = keychain_error("listing keys", "", SfError::from_code(-1)).to_string();
    assert!(s.contains("ms doctor"), "{s}");
}

// --- ACL: another binary can't read --------------------------------------------------------

/// Child mode, run inside a copied and re-signed test binary by `run_child`. Prints one
/// `ACL_RESULT=` line. Never prints the value.
#[test]
#[ignore = "child process for the ACL tests; run by them"]
fn acl_child() {
    let (Some(service), Some(name), Some(op)) = (
        std::env::var_os("MORSEC_ACL_SERVICE"),
        std::env::var_os("MORSEC_ACL_KEY"),
        std::env::var_os("MORSEC_ACL_OP"),
    ) else {
        return;
    };
    let v = KeychainVault::with_service(service.to_string_lossy().into_owned());
    let k = key(&name.to_string_lossy());
    let op = op.to_string_lossy().into_owned();
    let result = match op.as_str() {
        "get" => v
            .read_with(&k, |b| b.len())
            .map(|n| format!("READ {n} bytes")),
        "put" => v
            .put(
                &k,
                SecretBytes::from(CANARY.to_owned()),
                meta(&k, Tier::Production),
            )
            .map(|()| "STORED".to_owned()),
        "del" => v.delete(&k).map(|()| "DELETED".to_owned()),
        "ca" => v
            .ensure_ca_key()
            .and_then(|c| c.sign_sha256(b"x"))
            .map(|_| "SIGNED".to_owned()),
        // A direct SecItemUpdate, the way `security add-generic-password -U` would do it, without
        // going through KeychainVault (which deletes first).
        "update-data" | "update-attr" => {
            let kc = login_keychain().unwrap();
            let mut q = ItemSearchOptions::new();
            q.keychains(std::slice::from_ref(&kc))
                .class(ItemClass::generic_password())
                .service(&v.service)
                .account(k.as_str());
            let mut u = ItemUpdateOptions::new();
            if op == "update-data" {
                u.set_value(ItemUpdateValue::Data(CFData::from_buffer(b"EVIL")));
            } else {
                u.set_comment(
                    r#"{"name":"stripe/live","mode":"swap","tier":"test","created_unix_ms":1}"#,
                );
            }
            let _q = quiet().unwrap();
            update_item(&q, &u)
                .map(|()| "UPDATED".to_owned())
                .map_err(|e| keychain_error("updating", k.as_str(), e))
        }
        // Plants a CA key under our label, created by this (other) binary.
        "plantca" => {
            let _q = quiet().unwrap();
            let kc = login_keychain().unwrap();
            ffi::generate_signing_key(&kc, &v.ca_label())
                .map(|_| "PLANTED".to_owned())
                .map_err(|e| Error::io("planting", std::io::Error::other(e.to_string())))
        }
        // Deletes every key under the CA label (ours too: key items are deletable by any binary).
        "delca" => {
            let _q = quiet().unwrap();
            let kc = login_keychain().unwrap();
            delete_keys_locked(&kc, &v.ca_label()).map(|()| "DELETED".to_owned())
        }
        "init" => v.reset_internal_keys().map(|()| "INIT".to_owned()),
        // Removes everything this binary made under the service (its items and keys).
        "wipe" => {
            let _q = quiet().unwrap();
            let kc = login_keychain().unwrap();
            let _ = ItemSearchOptions::new()
                .keychains(std::slice::from_ref(&kc))
                .class(ItemClass::generic_password())
                .service(&v.service)
                .limit(Limit::All)
                .delete();
            delete_keys_locked(&kc, &v.seal_label()).map(|()| "WIPED".to_owned())
        }
        other => panic!("unknown op {other}"),
    };
    match result {
        Ok(s) => println!("ACL_RESULT={s}"),
        Err(e) => println!("ACL_RESULT=DENIED {e}"),
    }
}

/// Copies this test binary into `dir` under `file` and re-signs it with `identity` (`-` for
/// ad-hoc) and code-signing identifier `ident`, so its designated requirement differs.
fn signed_copy(dir: &Path, file: &str, identity: &str, ident: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dst = dir.join(file);
    std::fs::copy(&exe, &dst).unwrap();
    let out = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", identity, "--identifier", ident])
        .arg(&dst)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "codesign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    dst
}

/// How long one child may run. A child op takes well under a second; one that runs this long is
/// almost certainly waiting on a keychain dialog.
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs `cmd` to completion like `Command::output`, but kills it after [`CHILD_TIMEOUT`] and
/// fails the test, so a keychain dialog can never block the gate until someone clicks it. Killing
/// the child also withdraws its dialog.
fn output_within(cmd: &mut Command, what: &str) -> Output {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = r.read_to_end(&mut b);
            b
        })
    };
    let out = drain(Box::new(child.stdout.take().unwrap()));
    let err = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{what} ran longer than {CHILD_TIMEOUT:?}, so it was killed. It was most likely \
                 waiting on a keychain dialog (SecurityAgent); a keychain test must never prompt"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

fn run_child(bin: &Path, service: &str, name: &str, op: &str) -> String {
    let out = output_within(
        Command::new(bin)
            .args([
                "--exact",
                "macos::tests::acl_child",
                "--ignored",
                "--nocapture",
            ])
            .env("MORSEC_ACL_SERVICE", service)
            .env("MORSEC_ACL_KEY", name)
            .env("MORSEC_ACL_OP", op),
        &format!("child op {op} ({})", bin.display()),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!stdout.contains(CANARY), "child printed the value");
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("ACL_RESULT=").map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "child gave no result. stdout: {stdout} stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

// protects=GW-1: a value stored by this binary can't be read, deleted, replaced through the vault
// or signed with by a differently signed binary, while an exact copy (same signature) can read
// it; a direct SecItemUpdate of the data is detected by the seal and refused; no step raises a
// keychain dialog; fails_when=the re-signed copy reads, deletes or replaces the item, uses the
// CA key, or overwritten data is returned as the value, or a child hangs on a dialog;
// no_claim=Developer ID binding (acl_developer_id), protection against the user clicking
// "Always Allow" in a keychain dialog raised by another binary, or what macOS does when another
// binary SecItemUpdates our item (it asks the user, so the test can't run that unattended)
#[test]
fn acl_other_binary_is_denied() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let k = key("stripe/live");
    t.vault
        .put(
            &k,
            SecretBytes::from(CANARY.to_owned()),
            meta(&k, Tier::Production),
        )
        .unwrap();
    t.vault.reset_ca_key().unwrap();

    let dir = tempfile::tempdir().unwrap();
    // Positive control: a byte-identical copy keeps our signature, so the keychain trusts it.
    let same = dir.path().join("same");
    std::fs::copy(std::env::current_exe().unwrap(), &same).unwrap();
    let r = run_child(&same, &t.service, k.as_str(), "get");
    assert_eq!(
        r,
        format!("READ {} bytes", CANARY.len()),
        "positive control"
    );

    let other = signed_copy(dir.path(), "other", "-", "cc.morsec.test.attacker");
    for op in ["get", "del", "put", "ca"] {
        let r = run_child(&other, &t.service, k.as_str(), op);
        assert!(r.starts_with("DENIED"), "{op} by another binary: {r}");
    }
    assert_eq!(
        t.vault.read_with(&k, |b| b.to_vec()).unwrap(),
        CANARY.as_bytes()
    );

    // Tampering with SecItemUpdate. When a differently signed binary does it, macOS shows a
    // partition ("XARA") dialog even with interaction disabled, and if the user clicks Allow the
    // update goes through (docs/evidence/cli-scope.md). A test can't wait on that dialog, so the
    // trusted copy tampers instead: the worst case, as if the user had clicked Allow for an
    // attacker. The seal must still catch it.
    // Attributes: the comment is only a display copy of the metadata, so nothing we trust changes.
    let r = run_child(&same, &t.service, k.as_str(), "update-attr");
    assert_eq!(r, "UPDATED");
    assert_eq!(
        t.vault.read_with(&k, |b| b.to_vec()).unwrap(),
        CANARY.as_bytes()
    );
    assert_eq!(
        t.vault.list().unwrap(),
        vec![meta(&k, Tier::Production)],
        "list must report the sealed tier, not the rewritten comment"
    );
    let r = run_child(&other, &t.service, k.as_str(), "get");
    assert!(r.starts_with("DENIED"), "after update-attr: {r}");
    // Data: the item becomes unusable (refused by the seal), never a value we use, and stays
    // unreadable by the other binary. Denial of service, not a leak.
    let r = run_child(&same, &t.service, k.as_str(), "update-data");
    assert_eq!(r, "UPDATED");
    let e = t
        .vault
        .read_with(&k, |b| b.to_vec())
        .unwrap_err()
        .to_string();
    assert!(e.contains("seal check failed"), "{e}");
    let r = run_child(&other, &t.service, k.as_str(), "get");
    assert!(r.starts_with("DENIED"), "after update-data: {r}");
}

// protects=GW-1 with real signing: an item written by a Developer ID-signed binary is readable by
// a re-signed build with the same identifier and team (an msd upgrade) and denied to an ad-hoc
// binary; fails_when=the ad-hoc binary reads or an upgrade can't; no_claim=runs only when
// MORSEC_SIGN_IDENTITY names a Developer ID identity (it is skipped, loudly, otherwise)
#[test]
fn acl_developer_id() {
    if skip() {
        return;
    }
    let Ok(identity) = std::env::var("MORSEC_SIGN_IDENTITY") else {
        eprintln!(
            "SKIPPED: acl_developer_id (set MORSEC_SIGN_IDENTITY to a Developer ID identity)"
        );
        return;
    };
    let t = TestVault::bare();
    let name = "stripe/live";
    let dir = tempfile::tempdir().unwrap();
    let ident = "cc.morsec.test.msd";
    let writer = signed_copy(dir.path(), "writer", &identity, ident);
    // Only the writer may delete its item, so clean up through it even if an assert fails.
    struct WriterCleanup<'a>(&'a Path, &'a str, &'a str);
    impl Drop for WriterCleanup<'_> {
        fn drop(&mut self) {
            let _ = run_child(self.0, self.1, self.2, "wipe");
        }
    }
    let _cleanup = WriterCleanup(&writer, &t.service, name);
    assert_eq!(run_child(&writer, &t.service, name, "init"), "INIT");
    let upgrade = signed_copy(dir.path(), "upgrade", &identity, ident);
    let adhoc = signed_copy(dir.path(), "adhoc", "-", ident);

    assert_eq!(run_child(&writer, &t.service, name, "put"), "STORED");
    let up = run_child(&upgrade, &t.service, name, "get");
    let ad = run_child(&adhoc, &t.service, name, "get");
    let ours = t.vault.read_with(&key(name), |b| b.len());
    // Clean up through the writer: only it may delete.
    let del = run_child(&writer, &t.service, name, "del");

    assert_eq!(
        up,
        format!("READ {} bytes", CANARY.len()),
        "upgrade must read"
    );
    assert!(ad.starts_with("DENIED"), "ad-hoc same identifier: {ad}");
    assert!(
        ours.is_err(),
        "the test binary itself is another binary here"
    );
    assert_eq!(del, "DELETED");
}

// --- Memory: canary core-dump scan ----------------------------------------------------------

/// Child for `core_dump_scan`: reads a canary from stdin straight into a fixed-size buffer
/// (no reallocation, so no stray copies), stores it, reads it back, deletes it, then aborts so
/// the OS writes a core file.
#[test]
#[ignore = "child process for core_dump_scan; run by it"]
fn core_child() {
    use std::io::Read;
    let Some(service) = std::env::var_os("MORSEC_CORE_SERVICE") else {
        return;
    };
    let mut buf = vec![0u8; 40];
    // Unbuffered: std's Stdin keeps an 8 KiB buffer that would hold a stray copy.
    std::fs::File::open("/dev/stdin")
        .unwrap()
        .read_exact(&mut buf)
        .unwrap();
    let v = KeychainVault::with_service(service.to_string_lossy().into_owned());
    let k = key("core/canary");
    v.reset_internal_keys().unwrap();
    v.put(&k, SecretBytes::new(buf), meta(&k, Tier::Production))
        .unwrap();
    let mut sum = 0u64;
    v.with_secret(&k, &mut |b| sum = b.iter().map(|&x| u64::from(x)).sum())
        .unwrap();
    v.delete(&k).unwrap();
    println!("CORE_CHILD_SUM={sum}");
    std::process::abort();
}

// protects=after use, the value is not left in msd-side memory (core-dump scan with a runtime
// canary); fails_when=the canary is found in the core of a process that stored, used and deleted
// it; no_claim=runs only when /cores is writable by this user (macOS default: root only), so it is
// #[ignore]d in the gate and run by hand (see docs/evidence/vault-macos.md)
#[test]
#[ignore = "needs a writable /cores (sudo chmod 1777 /cores); run by hand"]
fn core_dump_scan() {
    use std::io::Write;
    if skip() {
        return;
    }
    let mut canary = [0u8; 20];
    SecRandom::default().copy_bytes(&mut canary).unwrap();
    let canary = hex(&canary); // 40 ASCII bytes
    let t = TestVault::new();
    let dir = tempfile::tempdir().unwrap();
    let same = dir.path().join("core-child");
    std::fs::copy(std::env::current_exe().unwrap(), &same).unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "ulimit -c unlimited; exec \"$0\" --exact macos::tests::core_child --ignored --nocapture"])
        .arg(&same)
        .env("MORSEC_CORE_SERVICE", &t.service)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(canary.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("CORE_CHILD_SUM="));
    let core = PathBuf::from(format!("/cores/core.{pid}"));
    assert!(
        core.exists(),
        "no core file at {} (is /cores writable?)",
        core.display()
    );
    let bytes = std::fs::read(&core).unwrap();
    let _ = std::fs::remove_file(&core);
    let hits = bytes
        .windows(canary.len())
        .filter(|w| *w == canary.as_bytes())
        .count();
    eprintln!(
        "core_dump_scan: {} byte core, {hits} canary hit(s)",
        bytes.len()
    );
    assert_eq!(hits, 0, "canary found {hits} time(s) in the core dump");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- Planted items --------------------------------------------------------------------------

/// Plants an item the way a same-user attacker would: Apple's `security` tool, with an ACL that
/// lets any application read it (`-A`), in the login keychain.
fn plant(service: &str, account: &str, value: &str) {
    let kc = std::env::home_dir()
        .unwrap()
        .join("Library/Keychains/login.keychain-db");
    let out = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-A",
            "-s",
            service,
            "-a",
            account,
            "-w",
            value,
        ])
        .arg(&kc)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "plant failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Adds an item without a seal, as this binary, so the vault can read it: a stand-in for an item
/// planted with an ACL that lets msd read it.
fn add_raw(service: &str, account: &str, data: &[u8]) {
    let _q = quiet().unwrap();
    let kc = login_keychain().unwrap();
    let mut add = ItemAddOptions::new(ItemAddValue::Data {
        class: ItemClass::generic_password(),
        data: CFData::from_buffer(data),
    });
    add.set_service(service)
        .set_account_name(account)
        .set_location(Location::FileKeychain(kc));
    add.add().unwrap();
}

// protects=a value never lands in an item someone else planted with an open ACL: put and
// reset_internal_keys replace planted items with ones only this binary can read;
// fails_when=after put/reset another binary can still read the item, or the planted value
// survives; no_claim=keychain-file rollback or replacement (documented residual)
#[test]
fn planted_items_are_replaced() {
    if skip() {
        return;
    }
    let t = TestVault::bare();
    let planted = "PLANTED_known_to_attacker_0123456";
    plant(&t.service, "stripe/live", planted);
    plant(&t.service, RULES_HMAC_KEY, planted);
    let k = key("stripe/live");
    t.vault.reset_internal_keys().unwrap();
    t.vault
        .put(
            &k,
            SecretBytes::from(CANARY.to_owned()),
            meta(&k, Tier::Production),
        )
        .unwrap();
    let rules = t
        .vault
        .read_with(&key(RULES_HMAC_KEY), |b| b.to_vec())
        .unwrap();
    assert_ne!(rules, planted.as_bytes());
    assert_eq!(rules.len(), HMAC_KEY_LEN);

    let dir = tempfile::tempdir().unwrap();
    let other = signed_copy(dir.path(), "other", "-", "cc.morsec.test.attacker");
    for name in ["stripe/live", RULES_HMAC_KEY] {
        let r = run_child(&other, &t.service, name, "get");
        assert!(
            r.starts_with("DENIED"),
            "{name} still open after replace: {r}"
        );
    }
}

// protects=the CA key can't be swapped (round-2 review): ensure_ca_key accepts only the key whose
// public key matches the pin written by reset_ca_key, so a key planted under the label, even one
// this binary may sign with, is never used, and a deleted CA fails closed; fails_when=ensure
// returns a key other than the pinned one; no_claim=keychain-file rollback or replacement
#[test]
fn ca_rejects_planted_keys() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let dir = tempfile::tempdir().unwrap();
    let other = signed_copy(dir.path(), "other", "-", "cc.morsec.test.attacker");
    // A byte-identical copy: keys it makes are ones this binary may sign with, the strongest
    // plant (like an attacker key with an open ACL).
    let same = dir.path().join("same");
    std::fs::copy(std::env::current_exe().unwrap(), &same).unwrap();
    struct Cleanup<'a>(&'a Path, &'a str);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = run_child(self.0, self.1, "x", "delca");
        }
    }
    let _cleanup = Cleanup(&other, &t.service);

    // Before init: a planted key is not adopted.
    assert_eq!(run_child(&same, &t.service, "x", "plantca"), "PLANTED");
    let e = t.vault.ensure_ca_key().unwrap_err().to_string();
    assert!(e.contains("ms init"), "{e}");
    // reset removes it and pins our own.
    let ours = t.vault.reset_ca_key().unwrap().public_key_sec1().unwrap();
    assert_eq!(
        t.vault.ensure_ca_key().unwrap().public_key_sec1().unwrap(),
        ours
    );

    // A second key planted next to ours, by another binary or by a trusted copy: ignored.
    assert_eq!(run_child(&other, &t.service, "x", "plantca"), "PLANTED");
    assert_eq!(run_child(&same, &t.service, "x", "plantca"), "PLANTED");
    assert_eq!(
        t.vault.ensure_ca_key().unwrap().public_key_sec1().unwrap(),
        ours
    );

    // Delete ours and plant a usable replacement: refused, fail closed (denial of service).
    assert_eq!(run_child(&other, &t.service, "x", "delca"), "DELETED");
    assert_eq!(run_child(&same, &t.service, "x", "plantca"), "PLANTED");
    let e = t.vault.ensure_ca_key().unwrap_err().to_string();
    assert!(e.contains("missing or replaced"), "{e}");
}

// protects=values stored before are refused once their seal is broken: an item planted without a
// seal, or any item after the seal key is deleted, is never returned; fails_when=an unsealed
// planted value is read, or a read succeeds without the seal key; no_claim=a seal key planted
// with an open ACL before ms init (reset_internal_keys replaces it)
#[test]
fn seal_failures_fail_closed() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let k = key("stripe/live");
    // An unsealed item this binary can read (the case `security -A` no longer produces on macOS
    // 26, where the partition list keeps us out, but an attacker's own SecAccess could).
    add_raw(&t.service, k.as_str(), b"PLANTED_value");
    let e = t
        .vault
        .read_with(&k, |b| b.to_vec())
        .unwrap_err()
        .to_string();
    assert!(e.contains("seal check failed"), "{e}");
    // An unsealed internal key planted before morsec ran is refused, not adopted.
    let t2 = TestVault::new();
    {
        let _q = quiet().unwrap();
        t2.vault
            .delete_locked(&login_keychain().unwrap(), &key(RULES_HMAC_KEY))
            .unwrap();
    }
    add_raw(&t2.service, RULES_HMAC_KEY, &[b'x'; HMAC_KEY_LEN]);
    let e = t2.vault.ensure_internal_keys().unwrap_err().to_string();
    assert!(e.contains("seal check failed"), "{e}");
    t2.vault.reset_internal_keys().unwrap();
    t2.vault.ensure_internal_keys().unwrap();

    // Without the seal key, nothing reads.
    t.vault
        .put(
            &k,
            SecretBytes::from(CANARY.to_owned()),
            meta(&k, Tier::Test),
        )
        .unwrap();
    {
        let _q = quiet().unwrap();
        delete_keys_locked(&login_keychain().unwrap(), &t.vault.seal_label()).unwrap();
    }
    let e = t.vault.read_with(&k, |b| b.len()).unwrap_err().to_string();
    assert!(e.contains("missing or replaced"), "{e}");
    let e = t.vault.list().unwrap_err().to_string();
    assert!(
        e.contains("ms init"),
        "a missing seal key is an error, not an empty list: {e}"
    );
}

// protects=the keychain path comes from the user database, not $HOME (round-2 review): a run
// with HOME pointing at an attacker directory still uses the real login keychain;
// fails_when=the child follows HOME; no_claim=a symlinked or swapped keychain file at the real
// path beyond the symlink check
#[test]
fn home_env_is_ignored() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let k = key("stripe/test");
    t.vault
        .put(
            &k,
            SecretBytes::from(CANARY.to_owned()),
            meta(&k, Tier::Test),
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("Library/Keychains")).unwrap();
    let same = dir.path().join("same");
    std::fs::copy(std::env::current_exe().unwrap(), &same).unwrap();
    let out = output_within(
        Command::new(&same)
            .args([
                "--exact",
                "macos::tests::acl_child",
                "--ignored",
                "--nocapture",
            ])
            .env("HOME", dir.path())
            .env("MORSEC_ACL_SERVICE", &t.service)
            .env("MORSEC_ACL_KEY", k.as_str())
            .env("MORSEC_ACL_OP", "get"),
        "child op get with HOME changed",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("ACL_RESULT=READ {} bytes", CANARY.len())),
        "{stdout}"
    );
}

// protects=the pins can't be swapped (round-3 review): another binary overwriting the CA or seal
// pin's data never makes msd trust a key of its choosing; the vault fails closed;
// fails_when=ensure_ca_key or a read succeeds after the pin was overwritten; no_claim=a future
// macOS where an overwritten item stays readable by its creator (this test would catch it)
#[test]
fn pin_overwrite_fails_closed() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let k = key("stripe/test");
    t.vault
        .put(
            &k,
            SecretBytes::from(CANARY.to_owned()),
            meta(&k, Tier::Test),
        )
        .unwrap();
    t.vault.reset_ca_key().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let other = signed_copy(dir.path(), "other", "-", "cc.morsec.test.attacker");

    let r = run_child(&other, &t.service, CA_PIN, "update-data");
    assert!(r == "UPDATED" || r.starts_with("DENIED"), "{r}");
    if r == "UPDATED" {
        assert!(
            t.vault.ensure_ca_key().is_err(),
            "CA pin overwritten, CA must fail closed"
        );
    }
    let r = run_child(&other, &t.service, SEAL_PIN, "update-data");
    assert!(r == "UPDATED" || r.starts_with("DENIED"), "{r}");
    if r == "UPDATED" {
        assert!(
            t.vault.read_with(&k, |b| b.len()).is_err(),
            "seal pin overwritten"
        );
    }
}

// protects=put_internal writes and replaces only the daemon items (state flag, CA key, CA cert), which
// then read back through with_secret but stay out of list(); every other reserved name, and every
// ordinary name, is refused; fails_when=put_internal can write a rules/receipts HMAC key or a
// user key, or the items show up in list(); no_claim=ACL against other binaries (the shared
// replace path is covered by acl_other_binary_is_denied)
#[test]
fn put_internal_only_daemon_items() {
    if skip() {
        return;
    }
    let t = TestVault::new();
    let state = KeyName::new(DAEMON_STATE_KEY).unwrap();
    t.vault
        .put_internal(&state, SecretBytes::new(b"stopped".to_vec()))
        .unwrap();
    t.vault
        .put_internal(&state, SecretBytes::new(b"running".to_vec()))
        .unwrap();
    assert_eq!(
        t.vault.read_with(&state, |v| v.to_vec()).unwrap(),
        b"running"
    );
    let cert = KeyName::new(CA_CERT_KEY).unwrap();
    t.vault
        .put_internal(&cert, SecretBytes::new(b"{}".to_vec()))
        .unwrap();
    assert_eq!(t.vault.read_with(&cert, |v| v.to_vec()).unwrap(), b"{}");
    assert!(t.vault.list().unwrap().is_empty());
    for bad in [
        RECEIPTS_HMAC_KEY,
        RULES_HMAC_KEY,
        "morsec/other",
        "stripe/test",
    ] {
        let k = KeyName::new(bad).unwrap();
        assert!(
            t.vault
                .put_internal(&k, SecretBytes::new(b"x".to_vec()))
                .is_err(),
            "{bad}"
        );
    }
    // The ordinary path still refuses the daemon items.
    assert!(
        t.vault
            .put(
                &state,
                SecretBytes::new(b"x".to_vec()),
                meta(&state, Tier::Test)
            )
            .is_err()
    );
}
