//! Errors. Every message says what happened and how to fix it, and fails closed.

/// Result alias for morsec.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A morsec error. `Display` text is shown to people as is, so each variant states the problem
/// and the next step.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The broker daemon is not reachable. Nothing falls back to raw secrets.
    #[error("morsec: daemon not running ({detail}). Start it with: ms start")]
    DaemonUnavailable {
        /// Why the connection failed.
        detail: String,
    },

    /// A key name failed validation.
    #[error(
        "morsec: invalid key name \"{name}\": {why}. Use lowercase a-z, 0-9 and '-', with '/' between parts, e.g. stripe/test"
    )]
    InvalidKeyName {
        /// The rejected name, escaped and truncated.
        name: String,
        /// What rule it broke.
        why: &'static str,
    },

    /// A reference failed validation.
    #[error(
        "morsec: invalid reference \"{reference}\": {why}. References look like ms://stripe/test"
    )]
    InvalidRef {
        /// The rejected reference, escaped and truncated.
        reference: String,
        /// What rule it broke.
        why: &'static str,
    },

    /// The IPC peer broke the protocol.
    #[error(
        "morsec: protocol error: {0}. Make sure ms and msd are the same version (ms --version)"
    )]
    Protocol(String),

    /// The daemon refused a client (for example, a different Unix user).
    #[error("morsec: connection refused by the daemon: {0}. Run ms as the user that ran ms init")]
    PeerRejected(String),

    /// The requested key does not exist.
    #[error("morsec: no key named {0}. List keys with: ms rules")]
    NoSuchKey(String),

    /// The command or request is planned but not built yet.
    #[error("morsec: '{command}' is not built yet (planned in loop {loop_id}).")]
    NotImplemented {
        /// The command as the user typed it, e.g. `mors import`.
        command: String,
        /// The loop that builds it, e.g. `L04 import-env`.
        loop_id: &'static str,
    },

    /// Filesystem or socket I/O failed.
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
    /// Wraps an I/O error with what morsec was doing at the time.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=user-facing errors carry the next step; fails_when=the fix text disappears from a
    // variant; no_claim=wording quality beyond the presence of the fix
    #[test]
    fn messages_carry_a_fix() {
        let cases = [
            (
                Error::DaemonUnavailable {
                    detail: "no socket".into(),
                }
                .to_string(),
                "ms start",
            ),
            (
                Error::InvalidKeyName {
                    name: "X".into(),
                    why: "w",
                }
                .to_string(),
                "stripe/test",
            ),
            (
                Error::InvalidRef {
                    reference: "x".into(),
                    why: "w",
                }
                .to_string(),
                "ms://stripe/test",
            ),
            (Error::Protocol("bad".into()).to_string(), "ms --version"),
            (Error::PeerRejected("uid".into()).to_string(), "ms init"),
            (Error::NoSuchKey("a".into()).to_string(), "ms rules"),
            (
                Error::NotImplemented {
                    command: "mors import".into(),
                    loop_id: "L04 import-env",
                }
                .to_string(),
                "planned in loop L04 import-env",
            ),
        ];
        for (msg, needle) in cases {
            assert!(msg.starts_with("morsec: "), "{msg}");
            assert!(msg.contains(needle), "{msg} lacks {needle}");
        }
    }
}
