//! Errors. All of them fail closed: the daemon refuses the caller.

use std::io;

/// Why a caller could not be identified.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The kernel gave no peer PID for the connection.
    #[error("the kernel reported no process id for this connection")]
    NoPeerPid,

    /// A process could not be read (it exited, or belongs to another user).
    #[error("process {pid} is gone or unreadable ({source})")]
    Unreadable {
        /// The process.
        pid: u32,
        /// Why.
        #[source]
        source: io::Error,
    },

    /// The PID now belongs to a different process than the one that connected.
    #[error("process {pid} changed owner while it was being identified")]
    PidChanged {
        /// The process.
        pid: u32,
    },

    /// The ancestor chain is longer than the walk allows.
    #[error("process tree above {pid} is deeper than {max} levels")]
    TooDeep {
        /// Where the walk started.
        pid: u32,
        /// The limit.
        max: usize,
    },

    /// The caller runs as a different Unix user from the daemon.
    #[error("uid {uid} is not the daemon's user")]
    WrongUser {
        /// The caller's uid.
        uid: u32,
    },

    /// No process holds the client end of a proxy connection.
    #[error("no local process owns the connection from port {port}")]
    NoSocketOwner {
        /// Client source port.
        port: u16,
    },

    /// Processes from different sessions hold the same client socket.
    #[error("the connection from port {port} is shared by processes in different sessions")]
    AmbiguousOwner {
        /// Client source port.
        port: u16,
    },

    /// The proxy username names no known agent.
    #[error("proxy user {user} is not a known agent")]
    UnknownProxyUser {
        /// The username, escaped and truncated (it is client-supplied).
        user: String,
    },

    /// The proxy username names a different agent from the one the connection came from.
    #[error("proxy user {user} does not match the calling process ({found})")]
    ProxyUserMismatch {
        /// The username, escaped and truncated.
        user: String,
        /// What the process tree says the caller is.
        found: String,
    },

    /// Reading the system's socket table failed.
    #[error("could not read the socket table ({0})")]
    SocketTable(#[source] io::Error),
}

impl From<SessionError> for ms_core::Error {
    fn from(e: SessionError) -> Self {
        ms_core::Error::PeerRejected(e.to_string())
    }
}

/// Makes a client-supplied string safe to show: escaped (no control characters) and at most
/// 64 characters, so it can't forge or hide text in logs or prompts.
pub(crate) fn inert(s: &str) -> String {
    const MAX: usize = 64;
    let mut out: String = s.chars().take(MAX).flat_map(char::escape_debug).collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    format!("\"{out}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=INJ-3 inert display of client-supplied proxy usernames; fails_when=control
    // characters or unbounded text reach an error message; no_claim=display width of unicode
    #[test]
    fn inert_escapes_and_truncates() {
        assert_eq!(inert("codex"), "\"codex\"");
        let s = inert("a\nb\u{1b}[31m");
        assert!(!s.contains('\n') && !s.contains('\u{1b}'), "{s}");
        let long = "x".repeat(500);
        assert!(inert(&long).chars().count() < 80);
    }

    // protects=identity failures reach clients as peer_rejected; fails_when=the conversion
    // picks another variant; no_claim=wording
    #[test]
    fn converts_to_peer_rejected() {
        let e: ms_core::Error = SessionError::NoPeerPid.into();
        assert!(matches!(e, ms_core::Error::PeerRejected(_)));
    }
}
