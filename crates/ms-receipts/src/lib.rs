//! Receipts: one record per use of a key.
//!
//! L00 freezes [`ReceiptSink`] and ships [`memory::MemorySink`] for tests. L02 builds the
//! hash-chained, HMAC'd store, `ms log` and `ms stats`.

use ms_core::{ReceiptEvent, Result};

/// Sequence number of a stored receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiptId(pub u64);

/// Somewhere receipts go.
pub trait ReceiptSink: Send + Sync {
    /// Appends one receipt and returns its id.
    fn append(&self, event: ReceiptEvent) -> Result<ReceiptId>;
}

/// In-memory sink for tests.
pub mod memory {
    use std::sync::Mutex;

    use ms_core::{ReceiptEvent, Result};

    use crate::{ReceiptId, ReceiptSink};

    /// Keeps receipts in a `Vec`.
    #[derive(Debug, Default)]
    pub struct MemorySink {
        events: Mutex<Vec<ReceiptEvent>>,
    }

    impl MemorySink {
        /// An empty sink.
        pub fn new() -> Self {
            Self::default()
        }

        /// Everything appended so far.
        pub fn events(&self) -> Vec<ReceiptEvent> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ReceiptSink for MemorySink {
        fn append(&self, event: ReceiptEvent) -> Result<ReceiptId> {
            let mut v = self.events.lock().unwrap_or_else(|e| e.into_inner());
            v.push(event);
            Ok(ReceiptId(v.len() as u64))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemorySink;
    use super::*;
    use ms_core::{AgentKind, KeyName, Mode, ReceiptResult, SessionId};

    // protects=ids are sequential from 1 and events are kept in order, through &dyn ReceiptSink;
    // fails_when=an event is lost, reordered or ids repeat; no_claim=durability or tamper evidence
    #[test]
    fn appends_in_order() {
        let sink = MemorySink::new();
        let d: &dyn ReceiptSink = &sink;
        for i in 0..3 {
            let id = d
                .append(ReceiptEvent {
                    time_unix_ms: i,
                    session: SessionId {
                        agent: AgentKind::Codex,
                        pid: 7,
                        started_unix_ms: 1,
                    },
                    key: KeyName::new("stripe/test").unwrap(),
                    mode: Mode::Swap,
                    target: "api.stripe.com".into(),
                    argv_hash: None,
                    rule_version: 1,
                    approval_id: None,
                    result: ReceiptResult::Allowed,
                })
                .unwrap();
            assert_eq!(id, ReceiptId(i + 1));
        }
        let times: Vec<_> = sink.events().iter().map(|e| e.time_unix_ms).collect();
        assert_eq!(times, [0, 1, 2]);
    }
}
