//! Platform calls. Only `macos` contains `unsafe`.

#[cfg(target_os = "macos")]
pub(crate) mod macos;
