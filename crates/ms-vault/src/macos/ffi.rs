//! The only `unsafe` in the macOS vault: building the attribute dictionary for a non-extractable
//! CA key.
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
use security_framework_sys::item::{
    kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrLabel, kSecPrivateKeyAttrs, kSecPublicKeyAttrs,
};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrIsExtractable: CFStringRef;
    static kSecAttrIsSensitive: CFStringRef;
}

/// Wraps an Apple-exported `CFStringRef` constant without taking ownership.
fn constant(r: CFStringRef) -> CFString {
    // SAFETY: `r` is one of Security.framework's exported constant CFStrings: non-null, immutable
    // and alive for the life of the process. The get rule retains it, so dropping the wrapper
    // releases only our retain.
    unsafe { CFString::wrap_under_get_rule(r) }
}

/// Generates a permanent P-256 key pair in the default (login) keychain whose private key is
/// non-extractable and sensitive. The creating binary is the only trusted application on the
/// item's ACL, so only it can sign with the key.
pub(super) fn generate_ca_key(label: &str) -> Result<SecKey, core_foundation::error::CFError> {
    // SAFETY: each read is of an immutable `extern static` CFStringRef exported by
    // Security.framework (linked above and by security-framework-sys); reading it has no side
    // effects and the value is never written.
    let (extractable, sensitive, permanent, key_type, ec, bits, lbl, private, public) = unsafe {
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
        )
    };

    let yes = CFBoolean::true_value().as_CFType();
    let no = CFBoolean::false_value().as_CFType();
    let private_attrs: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (constant(permanent), yes.clone()),
        (constant(extractable), no.clone()),
        (constant(sensitive), yes.clone()),
    ]);
    let public_attrs: CFDictionary<CFString, CFType> =
        CFDictionary::from_CFType_pairs(&[(constant(permanent), yes)]);

    let attrs: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (constant(key_type), constant(ec).as_CFType()),
        (constant(bits), CFNumber::from(256i32).as_CFType()),
        (constant(lbl), CFString::new(label).as_CFType()),
        // On the file-based keychain the CSSM key-generation path reads these from the top level,
        // not from the private-key attributes (verified by the ca_key test).
        (constant(extractable), CFBoolean::false_value().as_CFType()),
        (constant(sensitive), CFBoolean::true_value().as_CFType()),
        (constant(private), private_attrs.as_CFType()),
        (constant(public), public_attrs.as_CFType()),
    ]);

    #[allow(deprecated)] // SecKey::new only takes GenerateKeyOptions, which cannot set extractable.
    SecKey::generate(attrs.to_untyped())
}
