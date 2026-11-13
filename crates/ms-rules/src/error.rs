//! Rules errors. Every message says what happened and the fix, and every caller fails closed.

/// Result alias for this crate.
pub type Result<T, E = RulesError> = std::result::Result<T, E>;

/// Something wrong with a rules file, a project file or the store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RulesError {
    /// A file did not parse or broke a rule of the format.
    #[error("morsec: {file} is not valid: {why}. Fix that and try again")]
    Invalid {
        /// Which file (or "rules" for in-memory input).
        file: String,
        /// What is wrong, already escaped.
        why: String,
    },

    /// The rules file failed its integrity check. Everything is denied until it is fixed.
    #[error(
        "morsec: the rules file failed its integrity check ({why}); every key is blocked. Put back the last good rules.toml and rules.toml.mac, or run ms init to start over"
    )]
    Tampered {
        /// What failed.
        why: String,
    },

    /// There is no rules file yet.
    #[error("morsec: no rules file at {path}. Create it with: ms init")]
    NotInitialized {
        /// Expected location.
        path: String,
    },

    /// A rules change loosens a rule and no approval was given.
    #[error(
        "morsec: this change loosens the rules for {keys} and needs an approval. Make it with ms rules, which asks for Touch ID"
    )]
    NeedsApproval {
        /// The loosened keys, comma-separated.
        keys: String,
    },

    /// The MAC key is not in the vault.
    #[error("morsec: the rules signing key {name} is not in the vault ({detail}). Run ms init")]
    MacKey {
        /// Vault key name.
        name: String,
        /// Vault error text.
        detail: String,
    },

    /// Filesystem I/O failed.
    #[error("morsec: {context}: {source}. Check the path and its permissions")]
    Io {
        /// What morsec was doing.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl RulesError {
    pub(crate) fn invalid(file: impl Into<String>, why: impl Into<String>) -> Self {
        RulesError::Invalid {
            file: printable(&file.into(), 200),
            why: printable(&why.into(), 400),
        }
    }

    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        RulesError::Io {
            context: context.into(),
            source,
        }
    }
}

/// Escapes control characters and truncates, so file content can't rewrite a terminal or flood a
/// log through an error message.
pub(crate) fn printable(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .take(max_chars)
        .flat_map(char::escape_default)
        .collect();
    if s.chars().count() > max_chars {
        out.push('…');
    }
    out
}
