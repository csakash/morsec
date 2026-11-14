//! The user-presence check behind a trait (SPEC D-10), so the approval logic is testable without
//! a finger. The real one is [`crate::macos::TouchId`] (feature `touch-id`, macOS only).

use std::time::Instant;

/// Result of one Touch ID / password check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The device owner confirmed.
    Approved,
    /// Cancelled, failed, or refused (the text says which).
    Denied(String),
    /// The deadline passed first; the sheet was taken down.
    TimedOut,
    /// No way to check on this machine (no GUI session, not macOS…). Treated as a denial.
    Unavailable(String),
}

/// Asks the device owner to confirm, showing `reason` (built by msd from the real request).
pub trait Authenticator: Send + Sync {
    /// Blocks until confirmed, refused, or `deadline`.
    fn authenticate(&self, reason: &str, deadline: Instant) -> AuthOutcome;
}

/// Denies everything: the authenticator where there is no Touch ID (Linux until L21, or a
/// build without the `touch-id` feature).
#[derive(Debug, Default, Clone, Copy)]
pub struct Unavailable;

impl Authenticator for Unavailable {
    fn authenticate(&self, _reason: &str, _deadline: Instant) -> AuthOutcome {
        AuthOutcome::Unavailable("Touch ID is not available in this build or on this system".into())
    }
}

/// Scripted authenticator for tests (and msd's debug-only `--test-touch-id`).
pub mod fake {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{AuthOutcome, Authenticator};

    /// Always gives the same answer, optionally after a delay; records every reason shown.
    #[derive(Debug)]
    pub struct FakeAuthenticator {
        answer: AuthOutcome,
        delay: Duration,
        reasons: Mutex<Vec<String>>,
    }

    impl FakeAuthenticator {
        /// Confirms every time.
        pub fn approve() -> Self {
            Self {
                answer: AuthOutcome::Approved,
                delay: Duration::ZERO,
                reasons: Mutex::default(),
            }
        }

        /// Refuses every time with `why`.
        pub fn deny(why: &str) -> Self {
            Self {
                answer: AuthOutcome::Denied(why.into()),
                delay: Duration::ZERO,
                reasons: Mutex::default(),
            }
        }

        /// Answers only after `d` (ignoring the deadline, like a slow finger).
        pub fn after(mut self, d: Duration) -> Self {
            self.delay = d;
            self
        }

        /// Reasons shown so far.
        pub fn reasons(&self) -> Vec<String> {
            self.reasons
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl Authenticator for FakeAuthenticator {
        fn authenticate(&self, reason: &str, _deadline: Instant) -> AuthOutcome {
            self.reasons
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(reason.to_owned());
            std::thread::sleep(self.delay);
            self.answer.clone()
        }
    }
}
