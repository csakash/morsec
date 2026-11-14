//! Tool-specific run adapters, used before the generic one. Each owns its folder; msd registers
//! them in `crates/msd/src/daemon/run.rs`.
//!
//! - [`pg`] (L15): `psql` and `prisma` with a Postgres URL msd holds.
//! - [`ssh_git`] (L16): `ssh` and `git` with an SSH key msd holds, as a per-run SSH agent bound
//!   to pinned host keys.

pub mod pg;
pub mod ssh_git;
