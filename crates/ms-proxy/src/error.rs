//! Errors from setting up the proxy. Runtime refusals are HTTP responses (see `respond`).

/// A setup error. Every message says what is wrong and the fix, and never carries a value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// The configuration is invalid.
    #[error("morsec: proxy config: {0}")]
    Config(String),
    /// The CA could not be created, loaded or used.
    #[error("morsec: CA: {0}")]
    Ca(String),
    /// TLS setup failed.
    #[error("morsec: TLS setup: {0}")]
    Tls(String),
    /// A vault operation failed.
    #[error(transparent)]
    Core(#[from] ms_core::Error),
    /// Socket I/O failed.
    #[error("morsec: proxy {context}: {source}")]
    Io {
        /// What the proxy was doing.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}
