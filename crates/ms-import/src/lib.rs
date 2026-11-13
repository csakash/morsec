//! dotenv import, provider catalog and key classification (L04).
//!
//! - [`dotenv`]: a parser that keeps byte positions, and a rewriter that changes only chosen
//!   values.
//! - [`catalog`]: `catalog/providers.toml`, compiled in.
//! - [`classify`]: secret or not, provider, tier hint.
//! - [`plan`]: the review table (pure).
//! - [`envfile`]: reading the file safely, storing keys through a [`KeyStore`], and the atomic
//!   rewrite.
//!
//! Values live in [`ms_core::SecretBytes`] or zeroizing buffers and are never formatted.

pub mod catalog;
pub mod classify;
pub mod dotenv;
pub mod envfile;
pub mod plan;

use ms_core::{KeyMeta, KeyName, SecretBytes};
use ms_vault::Vault;

/// Errors from importing. Messages carry variable names, key names and line numbers only, never
/// values or file text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file can't be parsed.
    #[error("morsec: {path}: {source}. Fix the file and run the import again; nothing was changed")]
    Parse {
        /// File, as given.
        path: String,
        /// Where.
        #[source]
        source: dotenv::ParseError,
    },
    /// Bad command-line input.
    #[error("morsec: {0}")]
    Usage(String),
    /// The file is unsafe or impossible to import as is.
    #[error("morsec: {0}")]
    Refused(String),
    /// The key store failed.
    #[error("morsec: {0}")]
    Store(String),
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

/// Where imported keys go. Every [`Vault`] is one; the CLI's implementation talks to msd.
pub trait KeyStore {
    /// Metadata of every stored key.
    fn list(&self) -> Result<Vec<KeyMeta>, Error>;
    /// Stores a new key.
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<(), Error>;
}

impl<V: Vault + ?Sized> KeyStore for V {
    fn list(&self) -> Result<Vec<KeyMeta>, Error> {
        Vault::list(self).map_err(|e| Error::Store(strip(&e.to_string())))
    }

    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<(), Error> {
        Vault::put(self, name, value, meta).map_err(|e| Error::Store(strip(&e.to_string())))
    }
}

fn strip(msg: &str) -> String {
    msg.strip_prefix("morsec: ").unwrap_or(msg).to_owned()
}
