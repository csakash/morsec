//! Run errors, mapped to IPC error codes and exit codes.

use std::fmt;

/// What kind of failure, so the daemon can answer with the right code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunErrorKind {
    /// Malformed or unacceptable request (`invalid`, exit 64).
    Invalid,
    /// Refused by a rule, a check or a person (`denied`, exit 77).
    Denied,
    /// No run-mode key among the refs: the shim runs the real tool (`not_run`).
    NotRun,
    /// morsec itself failed (`internal`, exit 70).
    Internal,
}

/// A run failure. The message is shown to people as is and says what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    /// Kind.
    pub kind: RunErrorKind,
    /// Text, starting with `morsec:`.
    pub message: String,
}

impl RunError {
    /// An `Invalid` error.
    pub fn invalid(m: impl Into<String>) -> Self {
        Self {
            kind: RunErrorKind::Invalid,
            message: m.into(),
        }
    }
    /// A `Denied` error.
    pub fn denied(m: impl Into<String>) -> Self {
        Self {
            kind: RunErrorKind::Denied,
            message: m.into(),
        }
    }
    /// A `NotRun` error.
    pub fn not_run(m: impl Into<String>) -> Self {
        Self {
            kind: RunErrorKind::NotRun,
            message: m.into(),
        }
    }
    /// An `Internal` error.
    pub fn internal(m: impl Into<String>) -> Self {
        Self {
            kind: RunErrorKind::Internal,
            message: m.into(),
        }
    }

    /// The IPC error code for this error.
    pub fn code(&self) -> ms_ipc::ErrorCode {
        match self.kind {
            RunErrorKind::Invalid => ms_ipc::ErrorCode::Invalid,
            RunErrorKind::Denied => ms_ipc::ErrorCode::Denied,
            RunErrorKind::NotRun => ms_ipc::ErrorCode::NotRun,
            RunErrorKind::Internal => ms_ipc::ErrorCode::Internal,
        }
    }

    /// The IPC error reply for this error.
    pub fn reply(&self) -> ms_ipc::ResponseBody {
        ms_ipc::ResponseBody::error(self.code(), self.message.clone())
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RunError {}

/// An adapter's refusal, through the frozen `RunAdapter::plan` error type: an
/// [`ms_core::Error::Io`] with kind `PermissionDenied`, mapped back to [`RunErrorKind::Denied`]
/// by [`from_core`]. Adapters (L15, L16) use this and [`adapter_invalid`] so their refusals
/// reach the agent with the right code.
pub fn adapter_refuse(message: impl Into<String>) -> ms_core::Error {
    ms_core::Error::io(
        message,
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "refused"),
    )
}

/// An adapter's "this request is malformed" (`InvalidInput`), see [`adapter_refuse`].
pub fn adapter_invalid(message: impl Into<String>) -> ms_core::Error {
    ms_core::Error::io(
        message,
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid"),
    )
}

/// Maps an adapter or vault error to a run error.
pub fn from_core(e: &ms_core::Error) -> RunError {
    if let ms_core::Error::Io { context, source } = e {
        match source.kind() {
            std::io::ErrorKind::PermissionDenied => {
                return RunError::denied(format!("morsec: {context}"));
            }
            std::io::ErrorKind::InvalidInput => {
                return RunError::invalid(format!("morsec: {context}"));
            }
            _ => {}
        }
    }
    if let ms_core::Error::NoSuchKey(_) = e {
        return RunError::denied(e.to_string());
    }
    RunError::internal(e.to_string())
}
