//! Adapters for families of tools, used before the generic one.
//!
//! - [`ssh_git`] (L16): `ssh` and `git` with a key held by msd, as an SSH agent bound to pinned
//!   host keys and a git credential helper bound to the key's HTTPS hosts.

pub mod ssh_git;
