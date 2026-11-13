//! `ms stats`: prompts per session, blocks per day, approvals.

use std::collections::BTreeMap;

use ms_core::{ReceiptResult, SessionId};
use serde::Serialize;

use crate::query::agent_label;
use crate::read::StoredRecord;
use crate::record::Entry;
use crate::time::format_day;

/// Counts for one session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SessionStats {
    /// Agent label.
    pub agent: String,
    /// Root PID.
    pub pid: u32,
    /// Root start time, Unix ms.
    pub started_unix_ms: u64,
    /// Approval prompts shown (approved + denied).
    pub prompts: u64,
    /// Approved.
    pub approved: u64,
    /// Denied or timed out.
    pub denied: u64,
    /// Blocked by rules.
    pub blocked: u64,
    /// Allowed by rules without a prompt.
    pub allowed: u64,
    /// Failed while executing.
    pub failed: u64,
    /// LOG-2 alerts.
    pub alerts: u64,
}

/// Totals and breakdowns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    /// Receipts counted.
    pub receipts: u64,
    /// Allowed.
    pub allowed: u64,
    /// Approved.
    pub approved: u64,
    /// Denied or timed out.
    pub denied: u64,
    /// Blocked.
    pub blocked: u64,
    /// Failed.
    pub failed: u64,
    /// Alerts.
    pub alerts: u64,
    /// Approval prompts (approved + denied).
    pub prompts: u64,
    /// Per session, in first-seen order.
    pub sessions: Vec<SessionStats>,
    /// Blocked receipts per UTC day (`YYYY-MM-DD`).
    pub blocks_per_day: BTreeMap<String, u64>,
}

/// Computes stats over `records` (checkpoints are ignored).
pub fn stats(records: &[StoredRecord]) -> Stats {
    let mut s = Stats::default();
    let mut index: BTreeMap<(String, u32, u64), usize> = BTreeMap::new();
    let mut slot = |s: &mut Stats, id: &SessionId| -> usize {
        let k = (agent_label(&id.agent), id.pid, id.started_unix_ms);
        *index.entry(k.clone()).or_insert_with(|| {
            s.sessions.push(SessionStats {
                agent: k.0,
                pid: k.1,
                started_unix_ms: k.2,
                ..SessionStats::default()
            });
            s.sessions.len() - 1
        })
    };
    for r in records {
        match &r.rec.entry {
            Entry::Receipt(x) => {
                s.receipts += 1;
                let i = slot(&mut s, &x.session);
                let sess = &mut s.sessions[i];
                match &x.result {
                    ReceiptResult::Allowed => {
                        s.allowed += 1;
                        sess.allowed += 1;
                    }
                    ReceiptResult::Approved => {
                        s.approved += 1;
                        s.prompts += 1;
                        sess.approved += 1;
                        sess.prompts += 1;
                    }
                    ReceiptResult::Denied => {
                        s.denied += 1;
                        s.prompts += 1;
                        sess.denied += 1;
                        sess.prompts += 1;
                    }
                    ReceiptResult::Blocked(_) => {
                        s.blocked += 1;
                        sess.blocked += 1;
                        *s.blocks_per_day
                            .entry(format_day(r.rec.time_unix_ms))
                            .or_default() += 1;
                    }
                    ReceiptResult::Failed(_) => {
                        s.failed += 1;
                        sess.failed += 1;
                    }
                }
            }
            Entry::Alert(a) => {
                s.alerts += 1;
                let i = slot(&mut s, &a.session);
                s.sessions[i].alerts += 1;
            }
            Entry::Checkpoint(_) => {}
        }
    }
    s
}
