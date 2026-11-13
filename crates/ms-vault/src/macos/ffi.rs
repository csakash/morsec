//! The only `unsafe` in the macOS vault: building the attribute dictionary for a non-extractable
//! signing key (the CA key and the vault seal key), and finding the user's home directory from
//! the user database rather than `$HOME` (which whoever starts `msd` controls).
//!
//! `security-framework` has no safe way to set `kSecAttrIsExtractable`, and
//! `security-framework-sys` does not export that constant, so it is declared here. Every `unsafe`
//! block below only reads an immutable `CFStringRef` constant exported by Security.framework, or
//! wraps it with the "get" rule (no ownership taken, so no double release).
#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::key::SecKey;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::item::{
    kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrLabel, kSecPrivateKeyAttrs, kSecPublicKeyAttrs, kSecUseKeychain,
};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrIsExtractable: CFStringRef;
    static kSecAttrIsSensitive: CFStringRef;
}

/// Wraps an Apple-exported `CFStringRef` constant without taking ownership.
///
/// # Safety
/// `r` must be a valid, non-null CFString that stays alive for the call, such as one of
/// Security.framework's exported constants (which live for the whole process).
unsafe fn constant(r: CFStringRef) -> CFString {
    // SAFETY: guaranteed by the caller (see above). The get rule retains the string, so dropping
    // the wrapper releases only our own retain.
    unsafe { CFString::wrap_under_get_rule(r) }
}

/// Generates a permanent P-256 key pair in keychain `kc` (the login keychain) whose private key is
/// non-extractable and sensitive. The creating binary is the only trusted application on the
/// item's ACL, so only it can sign with the key.
pub(super) fn generate_signing_key(
    kc: &SecKeychain,
    label: &str,
) -> Result<SecKey, core_foundation::error::CFError> {
    // SAFETY: each read is of an immutable `extern static` CFStringRef exported by
    // Security.framework (linked above and by security-framework-sys); reading it has no side
    // effects and the value is never written.
    let (extractable, sensitive, permanent, key_type, ec, bits, lbl, private, public, use_kc) = unsafe {
        (
            kSecAttrIsExtractable,
            kSecAttrIsSensitive,
            kSecAttrIsPermanent,
            kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits,
            kSecAttrLabel,
            kSecPrivateKeyAttrs,
            kSecPublicKeyAttrs,
            kSecUseKeychain,
        )
    };

    // SAFETY: every argument is a Security.framework constant read just above: non-null,
    // immutable and alive for the life of the process.
    let [
        extractable,
        sensitive,
        permanent,
        key_type,
        ec,
        bits,
        lbl,
        private,
        public,
        use_kc,
    ] = unsafe {
        [
            constant(extractable),
            constant(sensitive),
            constant(permanent),
            constant(key_type),
            constant(ec),
            constant(bits),
            constant(lbl),
            constant(private),
            constant(public),
            constant(use_kc),
        ]
    };

    let yes = CFBoolean::true_value().as_CFType();
    let no = CFBoolean::false_value().as_CFType();
    let private_attrs: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (permanent.clone(), yes.clone()),
        (extractable.clone(), no.clone()),
        (sensitive.clone(), yes.clone()),
    ]);
    let public_attrs: CFDictionary<CFString, CFType> =
        CFDictionary::from_CFType_pairs(&[(permanent.clone(), yes)]);

    let attrs: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (key_type.clone(), ec.as_CFType()),
        (bits.clone(), CFNumber::from(256i32).as_CFType()),
        (lbl.clone(), CFString::new(label).as_CFType()),
        // On the file-based keychain the CSSM key-generation path reads these from the top level,
        // not from the private-key attributes (verified by the ca_key test).
        (extractable.clone(), CFBoolean::false_value().as_CFType()),
        (sensitive.clone(), CFBoolean::true_value().as_CFType()),
        (private.clone(), private_attrs.as_CFType()),
        (public.clone(), public_attrs.as_CFType()),
        (use_kc.clone(), kc.as_CFType()),
    ]);

    #[allow(deprecated)] // SecKey::new only takes GenerateKeyOptions, which cannot set extractable.
    SecKey::generate(attrs.to_untyped())
}

/// The current user's home directory from the user database (`getpwuid_r(getuid())`). Never
/// reads `$HOME`.
pub(super) fn home_dir_from_passwd() -> Option<std::path::PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut size = 4096usize;
    while size <= 1 << 20 {
        let mut buf: Vec<libc::c_char> = vec![0; size];
        // SAFETY: `passwd` is a plain C struct of integers and pointers, for which all-zero bytes
        // are a valid (empty) value; getpwuid_r fills it in.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call: `pwd` and `result` are live locals and
        // `buf` is a live buffer of `buf.len()` bytes. getpwuid_r writes only within them.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == libc::ERANGE {
            size *= 2;
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success `pw_dir` points to a NUL-terminated string inside `buf`, which is
        // still alive; the bytes are copied out before `buf` is dropped.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(std::path::PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
    None
}
