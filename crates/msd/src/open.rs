//! msd opens the dashboard's sign-in URL in the user's browser itself (L32 SPEC D-12, security
//! review S1): the single-use launch token goes from msd to LaunchServices and never crosses the
//! IPC socket, so a process that sends `DashOpen` (an agent's detached child included) can only
//! make the user's own browser sign in; it never holds the token.
//!
//! LaunchServices (`LSOpenCFURLRef`) hands the URL to the default browser without a child
//! process, so the token is in no process's argv (the `open(1)` exposure of T-71 is gone). It
//! needs the user's GUI session: msd runs as a LaunchAgent there; without one the call fails and
//! `DashOpen` answers `opened: false`.
//!
//! A *debug* build started with the memory vault accepts `--test-open-to FILE`: the URL is
//! appended to FILE instead (end-to-end tests). Release builds refuse the flag and don't contain
//! the file writer.

// The only `unsafe` in msd: two CoreFoundation/LaunchServices calls and a release.
#![allow(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

/// Opens a URL in the user's browser; true when it was handed over.
pub type Opener = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[cfg(target_os = "macos")]
mod ls {
    use core_foundation_sys::base::{CFIndex, CFRelease, CFTypeRef, OSStatus, kCFAllocatorDefault};
    use core_foundation_sys::string::kCFStringEncodingUTF8;
    use core_foundation_sys::url::{CFURLCreateWithBytes, CFURLRef};

    #[link(name = "CoreServices", kind = "framework")]
    unsafe extern "C" {
        fn LSOpenCFURLRef(in_url: CFURLRef, out_launched_url: *mut CFURLRef) -> OSStatus;
    }

    /// `LSOpenCFURLRef` on `url`.
    pub fn open(url: &str) -> Result<(), String> {
        let len = CFIndex::try_from(url.len()).map_err(|_| "URL too long".to_owned())?;
        // SAFETY: `url` is a live UTF-8 buffer of `len` bytes for the duration of the call;
        // CFURLCreateWithBytes copies it and returns an owned reference or null. A null base URL
        // is allowed.
        let cf = unsafe {
            CFURLCreateWithBytes(
                kCFAllocatorDefault,
                url.as_ptr(),
                len,
                kCFStringEncodingUTF8,
                std::ptr::null(),
            )
        };
        if cf.is_null() {
            return Err("the URL could not be made".into());
        }
        // SAFETY: `cf` is a valid CFURLRef we own; a null out-pointer is documented as allowed.
        let status = unsafe { LSOpenCFURLRef(cf, std::ptr::null_mut()) };
        // SAFETY: `cf` came from a Create function, so we hold one reference and release it once.
        unsafe { CFRelease(cf as CFTypeRef) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("LaunchServices answered {status}"))
        }
    }
}

/// The browser opener for this platform.
fn launch_services() -> Opener {
    Arc::new(|url: &str| {
        #[cfg(target_os = "macos")]
        {
            match ls::open(url) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "could not open the dashboard in a browser");
                    false
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = url;
            false
        }
    })
}

/// Appends each URL to `file` (0600). Debug builds only.
#[cfg(debug_assertions)]
fn to_file(file: PathBuf) -> Opener {
    Arc::new(move |url: &str| {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&file)
            .and_then(|mut f| writeln!(f, "{url}"))
            .is_ok()
    })
}

/// The opener msd runs with. `test_to` is honoured only in a debug build with the memory vault.
pub fn opener(test_to: Option<PathBuf>, memory_vault: bool) -> Result<Opener, String> {
    match test_to {
        None => Ok(launch_services()),
        Some(_) if !cfg!(debug_assertions) => {
            Err("morsec: --test-open-to exists only in debug builds".into())
        }
        Some(_) if !memory_vault => Err(
            "morsec: --test-open-to only works with --vault memory (an ephemeral dev vault)".into(),
        ),
        #[cfg(debug_assertions)]
        Some(file) => {
            tracing::warn!("TEST BUILD: dashboard URLs go to --test-open-to, not a browser");
            Ok(to_file(file))
        }
        #[cfg(not(debug_assertions))]
        Some(_) => Err("morsec: --test-open-to exists only in debug builds".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D-12: the file opener (which would put the launch token in a file) is refused
    // with the keychain vault and absent from release builds, so a real msd only ever hands the
    // URL to LaunchServices; fails_when=--test-open-to is accepted with the keychain vault;
    // no_claim=the release-build branch (tests run debug)
    #[test]
    fn test_open_to_needs_the_memory_vault() {
        let f = PathBuf::from("/tmp/x");
        assert!(opener(Some(f.clone()), false).is_err());
        assert!(opener(Some(f), true).is_ok());
        assert!(opener(None, false).is_ok());
    }
}
