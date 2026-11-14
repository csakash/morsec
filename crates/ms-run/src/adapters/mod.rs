//! Adapters for families of tools, used before the generic one.
//!
//! - [`ssh_git`] (L16): `ssh` and `git` with an SSH key msd holds, as a per-run SSH agent bound
//!   to pinned host keys.

pub mod ssh_git;
