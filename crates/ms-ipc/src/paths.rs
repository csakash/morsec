//! Where the daemon socket lives.

use std::path::PathBuf;

use ms_core::{Error, Result};

/// Env var that overrides the socket path (dev loops, tests).
pub const SOCKET_ENV: &str = "MORSEC_SOCKET";

/// The daemon socket path: `$MORSEC_SOCKET` if set, otherwise
/// `~/Library/Application Support/morsec/msd.sock` on macOS and
/// `$XDG_RUNTIME_DIR/morsec/msd.sock` elsewhere.
pub fn default_socket_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    platform_default()
}

#[cfg(target_os = "macos")]
fn platform_default() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| Error::DaemonUnavailable {
            detail: "HOME is not set, so the socket can't be found".into(),
        })?;
    Ok(PathBuf::from(home).join("Library/Application Support/morsec/msd.sock"))
}

#[cfg(not(target_os = "macos"))]
fn platform_default() -> Result<PathBuf> {
    let run = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| Error::DaemonUnavailable {
            detail:
                "XDG_RUNTIME_DIR is not set, so the socket can't be found (or set MORSEC_SOCKET)"
                    .into(),
        })?;
    Ok(PathBuf::from(run).join("morsec/msd.sock"))
}
