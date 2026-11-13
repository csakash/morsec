//! Approvals for production-tier requests.
//!
//! L00 freezes [`Approver`] and ships [`fake::FakeApprover`]. L11 builds the macOS Touch ID
//! helper and the token binding; L21 the Linux polkit prompt.

use std::time::Duration;

use ms_core::ApprovalRequest;

/// Proof that a person approved one exact request. L11 makes `mac` an HMAC over
/// (session, key, argv hash, cwd, scope, expiry) that the executor checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    /// Opaque id, recorded in receipts.
    pub id: String,
    /// Binding MAC.
    pub mac: [u8; 32],
    /// Expiry, Unix milliseconds.
    pub expires_unix_ms: u64,
}

/// What came back from a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Approved; the token is bound to the request.
    Approved(ApprovalToken),
    /// Denied.
    Denied,
    /// Nobody answered in time. Treated like a denial.
    TimedOut,
}

/// Asks a person. Implementations draw their own UI from `req`; nothing the agent supplies is
/// rendered as anything but inert text.
pub trait Approver: Send + Sync {
    /// Blocks until approved, denied or `timeout`.
    fn ask(&self, req: &ApprovalRequest, timeout: Duration) -> ApprovalOutcome;
}

/// Scripted approver for tests.
pub mod fake {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use ms_core::ApprovalRequest;

    use crate::{ApprovalOutcome, Approver};

    /// Returns scripted outcomes in order, then [`ApprovalOutcome::Denied`] when the script runs
    /// out (fail closed). Records every request it was asked.
    #[derive(Debug, Default)]
    pub struct FakeApprover {
        script: Mutex<VecDeque<ApprovalOutcome>>,
        asked: Mutex<Vec<ApprovalRequest>>,
    }

    impl FakeApprover {
        /// A fake that answers with `outcomes`, in order.
        pub fn new(outcomes: impl IntoIterator<Item = ApprovalOutcome>) -> Self {
            Self {
                script: Mutex::new(outcomes.into_iter().collect()),
                asked: Mutex::default(),
            }
        }

        /// Requests seen so far.
        pub fn asked(&self) -> Vec<ApprovalRequest> {
            self.asked.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl Approver for FakeApprover {
        fn ask(&self, req: &ApprovalRequest, _timeout: Duration) -> ApprovalOutcome {
            self.asked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.clone());
            self.script
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
                .unwrap_or(ApprovalOutcome::Denied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeApprover;
    use super::*;
    use ms_core::{AgentKind, KeyName, SessionId, Tier};
    use std::path::PathBuf;

    fn req() -> ApprovalRequest {
        ApprovalRequest {
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 1,
                started_unix_ms: 1,
            },
            key: KeyName::new("pg/production").unwrap(),
            tier: Tier::Production,
            argv_display: vec!["psql".into(), "-c".into(), "update orders".into()],
            argv_hash: [1; 32],
            cwd: PathBuf::from("/tmp"),
            effect: Some("3 rows in orders".into()),
        }
    }

    // protects=the fake replays its script in order then fails closed with Denied, and records
    // requests; fails_when=an extra request is approved or a request isn't recorded;
    // no_claim=any real approval UI or token binding (L11)
    #[test]
    fn scripted_then_denied() {
        let tok = ApprovalToken {
            id: "a1".into(),
            mac: [9; 32],
            expires_unix_ms: 5,
        };
        let f = FakeApprover::new([
            ApprovalOutcome::Approved(tok.clone()),
            ApprovalOutcome::TimedOut,
        ]);
        let d: &dyn Approver = &f;
        let t = Duration::from_secs(1);
        assert_eq!(d.ask(&req(), t), ApprovalOutcome::Approved(tok));
        assert_eq!(d.ask(&req(), t), ApprovalOutcome::TimedOut);
        assert_eq!(d.ask(&req(), t), ApprovalOutcome::Denied);
        assert_eq!(f.asked().len(), 3);
    }
}
