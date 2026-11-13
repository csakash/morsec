//! Rules and the policy decision function.
//!
//! L00 freezes the signature of [`decide`] and makes it deny everything. L03 builds the rules
//! model, the MAC'd store and the tighten-only project merge.

use ms_core::{Decision, Reason, Request, SessionId};

/// The effective rules. Placeholder until L03.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// Monotonic version, recorded in every receipt.
    pub version: u64,
}

/// Decides a request. Pure: no I/O, no clock, no vault access.
///
/// Until L03 this denies every request with [`Reason::NotImplemented`] (deny by default).
pub fn decide(_rules: &Rules, _session: &SessionId, _request: &Request) -> Decision {
    Decision::Deny {
        reason: Reason::NotImplemented,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{AgentKind, KeyName};
    use std::path::PathBuf;

    // protects=deny-by-default before L03; fails_when=any request kind is allowed or sent to
    // approval; no_claim=real rule evaluation
    #[test]
    fn denies_everything() {
        let s = SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 1,
            started_unix_ms: 1,
        };
        let key = KeyName::new("pg/production").unwrap();
        let reqs = [
            Request::Swap {
                key: key.clone(),
                host: "api.stripe.com".into(),
            },
            Request::Run {
                key: key.clone(),
                argv_hash: [0; 32],
                cwd: PathBuf::from("/"),
            },
            Request::Mint {
                key,
                scope: "read".into(),
            },
        ];
        for r in reqs {
            assert_eq!(
                decide(&Rules::default(), &s, &r),
                Decision::Deny {
                    reason: Reason::NotImplemented
                }
            );
        }
    }
}
