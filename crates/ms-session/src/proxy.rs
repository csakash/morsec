//! Cross-check of the per-connector proxy username against the process tree.

use ms_core::{AgentKind, SessionId};

use crate::error::{SessionError, inert};
use crate::walk::Caller;

/// The agent a connector's proxy username stands for. Connectors write these into the agent's
/// `HTTPS_PROXY` (`http://<username>@127.0.0.1:<port>`).
pub fn agent_for_proxy_user(user: &str) -> Option<AgentKind> {
    match user {
        "claude-code" => Some(AgentKind::ClaudeCode),
        "codex" => Some(AgentKind::Codex),
        "cursor" => Some(AgentKind::Cursor),
        "gemini-cli" => Some(AgentKind::GeminiCli),
        _ => None,
    }
}

/// The proxy username for an agent, for connectors writing `HTTPS_PROXY`.
pub fn proxy_user_for(agent: &AgentKind) -> Option<&'static str> {
    match agent {
        AgentKind::ClaudeCode => Some("claude-code"),
        AgentKind::Codex => Some("codex"),
        AgentKind::Cursor => Some("cursor"),
        AgentKind::GeminiCli => Some("gemini-cli"),
        AgentKind::Other(_) => None,
    }
}

fn describe(c: &Caller) -> String {
    match c {
        Caller::Agent(s) => format!("{:?} session {}", s.agent, s.pid),
        Caller::Unattributed { pid, .. } => format!("process {pid} with no agent above it"),
    }
}

/// Checks that the proxy username names the same agent the connection came from, and returns
/// that session. The username is only a cross-check: identity always comes from the process
/// tree. An unknown username, a mismatch, or an unattributed caller presenting an agent's
/// username is refused.
pub fn cross_check<'c>(caller: &'c Caller, user: &str) -> Result<&'c SessionId, SessionError> {
    let Some(claimed) = agent_for_proxy_user(user) else {
        return Err(SessionError::UnknownProxyUser { user: inert(user) });
    };
    match caller {
        Caller::Agent(s) if s.agent == claimed => Ok(s),
        _ => Err(SessionError::ProxyUserMismatch {
            user: inert(user),
            found: describe(caller),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(kind: AgentKind) -> Caller {
        Caller::Agent(SessionId {
            agent: kind,
            pid: 7,
            started_unix_ms: 1,
        })
    }

    // protects=proxy username cross-check; fails_when=a mismatched, unknown or unattributed
    // claim is accepted; no_claim=the username authenticates anything on its own
    #[test]
    fn cross_check_cases() {
        let c = agent(AgentKind::ClaudeCode);
        assert_eq!(cross_check(&c, "claude-code").unwrap().pid, 7);
        assert!(matches!(
            cross_check(&c, "codex"),
            Err(SessionError::ProxyUserMismatch { .. })
        ));
        assert!(matches!(
            cross_check(&c, "Claude-Code"),
            Err(SessionError::UnknownProxyUser { .. })
        ));
        assert!(matches!(
            cross_check(&c, ""),
            Err(SessionError::UnknownProxyUser { .. })
        ));
        let u = Caller::Unattributed {
            pid: 9,
            started_unix_ms: 1,
        };
        assert!(matches!(
            cross_check(&u, "claude-code"),
            Err(SessionError::ProxyUserMismatch { .. })
        ));
        let e = cross_check(&c, "x\n\u{1b}]0;pwn\u{7}")
            .unwrap_err()
            .to_string();
        assert!(
            !e.contains('\n') && !e.contains('\u{1b}') && !e.contains('\u{7}'),
            "{e}"
        );
    }

    // protects=connector and cross-check agree on names; fails_when=the two maps drift;
    // no_claim=Other agents get a username
    #[test]
    fn names_round_trip() {
        for k in [
            AgentKind::ClaudeCode,
            AgentKind::Codex,
            AgentKind::Cursor,
            AgentKind::GeminiCli,
        ] {
            let u = proxy_user_for(&k).unwrap();
            assert_eq!(agent_for_proxy_user(u), Some(k));
        }
        assert_eq!(proxy_user_for(&AgentKind::Other("x".into())), None);
    }
}
