//! Approvals until L11.
//!
//! SPEC D-A (user decision, 2026-11-13): real Touch ID approvals arrive with L11. Until then msd's
//! [`ms_approve::Approver`] is [`DenyApprover`], which denies every request it is asked about. So
//! production-tier keys can't be used yet, and loosening a rule or resuming after `ms stop` goes
//! through the pre-L11 terminal path in `daemon.rs` instead (weaker; recorded in ARI42.md).

use std::time::Duration;

use ms_approve::{ApprovalOutcome, Approver};
use ms_core::ApprovalRequest;

/// What every denial from the stub says.
pub const PRE_L11: &str = "approvals with Touch ID are not built yet (loop L11 approvals-macos), so morsec refuses anything that needs one";

/// Denies everything, and logs that it did.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyApprover;

impl Approver for DenyApprover {
    fn ask(&self, req: &ApprovalRequest, _timeout: Duration) -> ApprovalOutcome {
        tracing::warn!(key = %req.key, "approval needed but denied: {PRE_L11}");
        ApprovalOutcome::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{AgentKind, KeyName, SessionId, Tier};

    // protects=AUTH-3 pre-L11: the stub never approves anything; fails_when=it returns Approved;
    // no_claim=the L11 Touch ID approver
    #[test]
    fn always_denies() {
        let req = ApprovalRequest {
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 1,
                started_unix_ms: 1,
            },
            key: KeyName::new("stripe/production").unwrap(),
            tier: Tier::Production,
            argv_display: vec!["swap".into(), "api.stripe.com".into()],
            argv_hash: [0; 32],
            cwd: "/".into(),
            effect: None,
        };
        for _ in 0..3 {
            assert_eq!(
                DenyApprover.ask(&req, Duration::from_secs(1)),
                ApprovalOutcome::Denied
            );
        }
    }
}
