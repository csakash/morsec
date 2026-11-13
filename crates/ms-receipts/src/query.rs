//! Filtering receipts for `ms log` and exports.

use ms_core::{AgentKind, KeyName, ReceiptResult};
use serde::Serialize;

use crate::read::StoredRecord;
use crate::record::Entry;

/// Result classes a filter can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultClass {
    /// Allowed by rules.
    Allowed,
    /// Approved by a person.
    Approved,
    /// Blocked by rules.
    Blocked,
    /// Denied by a person or timed out.
    Denied,
    /// Failed while executing.
    Failed,
    /// A LOG-2 alert.
    Alert,
}

impl ResultClass {
    /// Class of a receipt result.
    pub fn of(r: &ReceiptResult) -> Self {
        match r {
            ReceiptResult::Allowed => ResultClass::Allowed,
            ReceiptResult::Approved => ResultClass::Approved,
            ReceiptResult::Blocked(_) => ResultClass::Blocked,
            ReceiptResult::Denied => ResultClass::Denied,
            ReceiptResult::Failed(_) => ResultClass::Failed,
        }
    }

    /// Parses `allowed`, `approved`, `blocked`, `denied`, `failed` or `alert`.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "allowed" => ResultClass::Allowed,
            "approved" => ResultClass::Approved,
            "blocked" => ResultClass::Blocked,
            "denied" => ResultClass::Denied,
            "failed" => ResultClass::Failed,
            "alert" => ResultClass::Alert,
            _ => return None,
        })
    }
}

/// Parses an agent name as typed: `claude-code`, `codex`, `cursor`, `gemini-cli`, else any
/// other process name.
pub fn parse_agent(s: &str) -> AgentKind {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "claude-code" | "claude" => AgentKind::ClaudeCode,
        "codex" => AgentKind::Codex,
        "cursor" => AgentKind::Cursor,
        "gemini-cli" | "gemini" => AgentKind::GeminiCli,
        _ => AgentKind::Other(s.to_owned()),
    }
}

/// Short display name of an agent.
pub fn agent_label(a: &AgentKind) -> String {
    match a {
        AgentKind::ClaudeCode => "claude-code".into(),
        AgentKind::Codex => "codex".into(),
        AgentKind::Cursor => "cursor".into(),
        AgentKind::GeminiCli => "gemini-cli".into(),
        AgentKind::Other(n) => n.clone(),
    }
}

/// A filter. Empty fields match everything.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// At or after, Unix ms.
    pub since: Option<u64>,
    /// Before, Unix ms.
    pub until: Option<u64>,
    /// Agent.
    pub agent: Option<AgentKind>,
    /// Key.
    pub key: Option<KeyName>,
    /// Result class.
    pub result: Option<ResultClass>,
    /// Session root PID.
    pub pid: Option<u32>,
    /// Keep only the most recent N matches.
    pub limit: Option<usize>,
}

impl Query {
    /// True when `r` is a receipt or alert that matches. Checkpoints never match.
    pub fn matches(&self, r: &StoredRecord) -> bool {
        let t = r.rec.time_unix_ms;
        if self.since.is_some_and(|s| t < s) || self.until.is_some_and(|u| t >= u) {
            return false;
        }
        let (session, key, class) = match &r.rec.entry {
            Entry::Receipt(x) => (&x.session, Some(&x.key), ResultClass::of(&x.result)),
            Entry::Alert(a) => (&a.session, None, ResultClass::Alert),
            Entry::Checkpoint(_) => return false,
        };
        if self.agent.as_ref().is_some_and(|a| *a != session.agent)
            || self.pid.is_some_and(|p| p != session.pid)
            || self.result.is_some_and(|c| c != class)
        {
            return false;
        }
        match &self.key {
            Some(k) => key == Some(k),
            None => true,
        }
    }

    /// The matching records, oldest first, cut to the most recent `limit`.
    pub fn run(&self, records: &[StoredRecord]) -> Vec<StoredRecord> {
        let mut out: Vec<StoredRecord> = records
            .iter()
            .filter(|r| self.matches(r))
            .cloned()
            .collect();
        if let Some(n) = self.limit {
            let drop_n = out.len().saturating_sub(n);
            out.drain(..drop_n);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Alert, AlertAction, Checkpoint, Rec, Receipt};
    use crate::stats::stats;
    use ms_core::{Mode, Reason, SessionId};

    fn sess(agent: AgentKind, pid: u32) -> SessionId {
        SessionId {
            agent,
            pid,
            started_unix_ms: 5,
        }
    }

    fn rec(seq: u64, t: u64, entry: Entry) -> StoredRecord {
        StoredRecord {
            seq,
            hash: String::new(),
            rec: Rec {
                v: 1,
                seq,
                prev: String::new(),
                time_unix_ms: t,
                entry,
            },
        }
    }

    fn receipt(
        seq: u64,
        t: u64,
        agent: AgentKind,
        pid: u32,
        key: &str,
        r: ReceiptResult,
    ) -> StoredRecord {
        rec(
            seq,
            t,
            Entry::Receipt(Receipt {
                session: sess(agent, pid),
                key: KeyName::new(key).unwrap(),
                mechanism: Mode::Swap,
                target: "h".into(),
                argv_hash: None,
                argv_redacted: None,
                rule_version: 1,
                approval: None,
                result: r,
            }),
        )
    }

    fn sample() -> Vec<StoredRecord> {
        let day = 86_400_000;
        vec![
            receipt(
                1,
                0,
                AgentKind::ClaudeCode,
                1,
                "a/b",
                ReceiptResult::Allowed,
            ),
            receipt(
                2,
                10,
                AgentKind::ClaudeCode,
                1,
                "a/b",
                ReceiptResult::Approved,
            ),
            receipt(3, 20, AgentKind::Codex, 2, "c/d", ReceiptResult::Denied),
            rec(
                4,
                20,
                Entry::Checkpoint(Checkpoint {
                    through_seq: 3,
                    head: String::new(),
                }),
            ),
            receipt(
                5,
                30,
                AgentKind::Codex,
                2,
                "c/d",
                ReceiptResult::Blocked(Reason::HostNotAllowed),
            ),
            receipt(
                6,
                day + 1,
                AgentKind::Codex,
                2,
                "a/b",
                ReceiptResult::Blocked(Reason::Stopped),
            ),
            receipt(
                7,
                day + 2,
                AgentKind::Other("x".into()),
                3,
                "a/b",
                ReceiptResult::Failed("e".into()),
            ),
            rec(
                8,
                day + 3,
                Entry::Alert(Alert {
                    session: sess(AgentKind::Codex, 2),
                    blocked_count: 5,
                    window_ms: 1,
                    first_seq: 5,
                    last_seq: 6,
                    action: AlertAction::None,
                }),
            ),
        ]
    }

    fn seqs(q: Query) -> Vec<u64> {
        q.run(&sample()).iter().map(|r| r.seq).collect()
    }

    // protects=AC8: each filter returns exactly the expected records, checkpoints never appear,
    // and limit keeps the most recent; fails_when=a filter is ignored or leaks rows;
    // no_claim=performance on large logs
    #[test]
    fn filters() {
        assert_eq!(seqs(Query::default()), [1, 2, 3, 5, 6, 7, 8]);
        assert_eq!(
            seqs(Query {
                since: Some(20),
                until: Some(86_400_002),
                ..Query::default()
            }),
            [3, 5, 6]
        );
        assert_eq!(
            seqs(Query {
                agent: Some(AgentKind::Codex),
                ..Query::default()
            }),
            [3, 5, 6, 8]
        );
        assert_eq!(
            seqs(Query {
                agent: Some(parse_agent("x")),
                ..Query::default()
            }),
            [7]
        );
        assert_eq!(
            seqs(Query {
                key: Some(KeyName::new("a/b").unwrap()),
                ..Query::default()
            }),
            [1, 2, 6, 7]
        );
        assert_eq!(
            seqs(Query {
                result: Some(ResultClass::Blocked),
                ..Query::default()
            }),
            [5, 6]
        );
        assert_eq!(
            seqs(Query {
                result: Some(ResultClass::Alert),
                ..Query::default()
            }),
            [8]
        );
        assert_eq!(
            seqs(Query {
                pid: Some(1),
                ..Query::default()
            }),
            [1, 2]
        );
        assert_eq!(
            seqs(Query {
                limit: Some(2),
                ..Query::default()
            }),
            [7, 8]
        );
        assert_eq!(
            seqs(Query {
                limit: Some(0),
                ..Query::default()
            }),
            Vec::<u64>::new()
        );
        assert_eq!(parse_agent("Claude_Code"), AgentKind::ClaudeCode);
        assert_eq!(ResultClass::parse("nope"), None);
    }

    // protects=stats count prompts (approved + denied) per session, blocks per UTC day and
    // alerts; fails_when=a count is off or checkpoints are counted; no_claim=display format
    #[test]
    fn counts() {
        let s = stats(&sample());
        assert_eq!(
            (
                s.receipts, s.allowed, s.approved, s.denied, s.blocked, s.failed, s.alerts,
                s.prompts
            ),
            (6, 1, 1, 1, 2, 1, 1, 2)
        );
        assert_eq!(s.sessions.len(), 3);
        let codex = &s.sessions[1];
        assert_eq!(
            (
                codex.pid,
                codex.prompts,
                codex.denied,
                codex.blocked,
                codex.alerts
            ),
            (2, 1, 1, 2, 1)
        );
        assert_eq!(
            s.blocks_per_day.into_iter().collect::<Vec<_>>(),
            [("1970-01-01".to_string(), 1), ("1970-01-02".to_string(), 1)]
        );
    }
}
