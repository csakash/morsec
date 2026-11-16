//! The only `unsafe` in ms-ipc: reading the peer's audit token from a connected Unix socket
//! (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`) and reading this process's own Team ID
//! (`SecCodeCopySigningInformation`, which security-framework does not wrap).
//!
//! Everything else goes through security-framework's safe `SecCode` / `SecRequirement` API.
#![allow(unsafe_code)]

use std::os::fd::{AsRawFd, BorrowedFd};

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::SecStaticCodeRef;

/// `sizeof(audit_token_t)`: eight 32-bit words.
const AUDIT_TOKEN_LEN: usize = 32;
/// `kSecCSSigningInformation` (CSCommon.h): include certificate-derived fields such as the team.
const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
}

/// The audit token of the process that listens on the other end of `fd`.
fn peer_audit_token(fd: BorrowedFd<'_>) -> Result<[u8; AUDIT_TOKEN_LEN], String> {
    let mut token = [0u8; AUDIT_TOKEN_LEN];
    let mut len = libc::socklen_t::try_from(AUDIT_TOKEN_LEN).map_err(|e| e.to_string())?;
    // SAFETY: `fd` is a live descriptor borrowed for this call; `token` is a writable buffer of
    // `len` bytes and `len` is a valid in/out length. The kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "can't read the peer's audit token: {}",
            std::io::Error::last_os_error()
        ));
    }
    if usize::try_from(len).ok() != Some(AUDIT_TOKEN_LEN) {
        return Err(format!("the kernel returned a {len}-byte audit token"));
    }
    Ok(token)
}

/// Checks the live code behind the peer's audit token against `requirement`.
pub(super) fn verify_peer(fd: BorrowedFd<'_>, requirement: &str) -> Result<(), String> {
    let token = peer_audit_token(fd)?;
    let requirement: SecRequirement = requirement
        .parse()
        .map_err(|e| format!("bad code requirement: {e}"))?;
    let data = CFData::from_buffer(&token);
    let mut attrs = GuestAttributes::new();
    // The dictionary retains `data`, and `data` outlives the lookup anyway.
    attrs.set_audit_token(data.as_concrete_TypeRef());
    // Host `None`: the kernel is asked. A token whose PID version no longer matches (the process
    // exited, or exec'd since it called listen()) is an error here, never another process.
    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
        .map_err(|e| format!("the peer's code can't be identified: {e}"))?;
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|e| e.to_string())
}

/// This process's Team ID: `Ok(None)` for unsigned, ad-hoc and linker-signed code.
pub(super) fn own_team_id() -> Result<Option<String>, String> {
    let me = SecCode::for_self(Flags::NONE).map_err(|e| e.to_string())?;
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `me` is a valid SecCodeRef for the call (Apple documents that a SecCodeRef may be
    // passed where a SecStaticCodeRef is expected); `info` is a valid out-pointer.
    let status = unsafe {
        SecCodeCopySigningInformation(
            me.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return Err(format!(
            "SecCodeCopySigningInformation failed (OSStatus {status})"
        ));
    }
    // SAFETY: `info` is a non-null CFDictionary returned under the create rule; wrapping it hands
    // that single reference to `dict`, which releases it on drop.
    let dict: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    // SAFETY: an immutable CFStringRef constant exported by Security.framework (linked above),
    // wrapped with the get rule, so no ownership is taken.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
    match dict.find(&key) {
        None => Ok(None),
        Some(v) => v
            .downcast::<CFString>()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| "the Team ID in this program's signature is not a string".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=a cargo-built (ad-hoc / linker-signed) binary reports no Team ID, so dev builds
    // take the refuse-or-opt-out path; fails_when=reading the own signature errors or invents a
    // team; no_claim=a Developer ID-signed binary (needs the release identity)
    #[test]
    fn test_binary_has_no_team() {
        assert_eq!(own_team_id(), Ok(None));
    }

    // protects=the Developer ID requirement for msd is valid requirement language;
    // fails_when=SecRequirementCreateWithString rejects it (every release client would refuse);
    // no_claim=that a real release msd satisfies it (manual check in PROOF.md)
    #[test]
    fn requirement_compiles() {
        let r = super::super::developer_id_requirement(super::super::MSD_IDENTIFIER, "ABCDE12345")
            .unwrap();
        assert!(r.parse::<SecRequirement>().is_ok(), "{r}");
    }
}
