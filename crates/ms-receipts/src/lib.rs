//! Receipts: one record per use of a key.
//!
//! L00 froze [`ReceiptSink`] and shipped [`memory::MemorySink`] for tests. L02 adds the real
//! store ([`ReceiptStore`]): append-only JSONL, every record hash-chained to the one before and
//! HMAC'd with a vault key, checkpoints, rotation, redaction before write and the LOG-2
//! blocked-attempt detector; plus [`verify`], [`Query`], [`stats()`] and the JSON/CSV exports that
//! back `ms log` and `ms stats`.

pub mod export;
pub mod query;
pub mod read;
pub mod record;
pub mod redact;
pub mod stats;
pub mod store;
pub mod time;
pub mod verify;

use std::path::PathBuf;

use ms_core::{Error, ReceiptEvent, Result};

pub use export::{export_csv, export_json};
pub use query::{Query, ResultClass};
pub use read::{StoredRecord, read_all};
pub use record::{
    Alert, AlertAction, Approval, Checkpoint, Entry, HMAC_KEY_NAME, MIN_KEY_LEN, Rec, Receipt,
};
pub use redact::{PatternRedactor, Redactor, ValueRedactor};
pub use stats::{SessionStats, Stats, stats};
pub use store::{AlertHandler, ReceiptDetail, ReceiptStore, StoreConfig};
pub use verify::{Problem, ProblemKind, VerifyReport, verify};

/// Sequence number of a stored receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiptId(pub u64);

/// Somewhere receipts go.
pub trait ReceiptSink: Send + Sync {
    /// Appends one receipt and returns its id.
    fn append(&self, event: ReceiptEvent) -> Result<ReceiptId>;
}

/// Env var that overrides the receipts directory (dev loops, tests).
pub const DIR_ENV: &str = "MORSEC_RECEIPTS_DIR";

/// The receipts directory: `$MORSEC_RECEIPTS_DIR` if set, otherwise
/// `~/Library/Application Support/morsec/receipts` on macOS and `/var/lib/morsec/receipts`
/// elsewhere (PLAN §3.5).
pub fn default_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(DIR_ENV).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    platform_dir()
}

#[cfg(target_os = "macos")]
fn platform_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            Error::io(
                "HOME is not set, so the receipts directory can't be found",
                std::io::Error::other("set HOME or MORSEC_RECEIPTS_DIR"),
            )
        })?;
    Ok(PathBuf::from(home).join("Library/Application Support/morsec/receipts"))
}

#[cfg(not(target_os = "macos"))]
fn platform_dir() -> Result<PathBuf> {
    // Keeps the signature identical across platforms.
    let _ = Error::io;
    Ok(PathBuf::from("/var/lib/morsec/receipts"))
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
