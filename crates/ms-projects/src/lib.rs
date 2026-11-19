//! Guided setup (L31, `docs/design/guided-setup-dashboard.md` §4 and §5).
//!
//! - [`mode`]: machine or project mode, from the directory `ms init` runs in.
//! - [`slug`]: the project's name.
//! - [`walk`]: the deep scan (directory fd + `openat(O_NOFOLLOW)`, one device, budgets).
//! - [`naming`]: project-wide import naming on top of `ms_import::plan`.
//! - [`record`]: the project record (`projects.toml` schema). It never holds a value.
//! - [`store`]: the MAC'd `projects.toml` store, mirrored on `ms_rules::RulesStore`.
//! - [`save`]: what msd accepts in a `ProjectSave` (and the rules the CLI proposes).
//! - [`hint`]: the agent hint block for `CLAUDE.md` / `AGENTS.md`.
//!
//! - [`setup`]: the project steps themselves (prepare, then execute), run by `ms init` over IPC
//!   and by msd for the dashboard's Add project (L35).

pub mod hint;
pub mod mode;
pub mod naming;
pub mod record;
pub mod save;
pub mod setup;
pub mod slug;
pub mod store;
pub mod undo;
pub mod walk;

/// Errors from this crate. Messages carry paths, key and variable names, never values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input that can't be accepted as is.
    #[error("morsec: {0}")]
    Invalid(String),
    /// The project records failed their integrity check (bad MAC, rollback, removed file).
    #[error("morsec: the project records failed their integrity check ({0})")]
    Tampered(String),
    /// I/O failed.
    #[error("morsec: {context}: {source}")]
    Io {
        /// What morsec was doing.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }
}
