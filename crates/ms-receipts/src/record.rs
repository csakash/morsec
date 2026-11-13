//! The on-disk record format.
//!
//! One JSON object per line: `{"rec":{…},"mac":"<hex>"}`. The hash chain and the MAC both cover
//! the exact bytes of `rec` as written, read back through [`serde_json::value::RawValue`], so
//! there is no canonicalisation step that a reader and a writer could disagree on.

use hmac::{Hmac, Mac};
use ms_core::{KeyName, Mode, ReceiptResult, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

/// Version of the record format.
pub const FORMAT_VERSION: u32 = 1;

/// Vault key that MACs every record. L01 creates it; this crate only reads it, inside
/// [`ms_vault::Vault::with_secret`].
pub const HMAC_KEY_NAME: &str = "morsec/receipts-hmac";

/// Shortest HMAC key accepted, in bytes.
pub const MIN_KEY_LEN: usize = 32;

/// Domain separation for the MAC, so a receipts MAC can't be replayed as another MAC made with
/// the same vault key (rules, approvals).
const MAC_DOMAIN: &[u8] = b"morsec-receipt-v1\0";

/// `prev` of the first record.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

/// The MAC'd part of a line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rec {
    /// Format version, [`FORMAT_VERSION`].
    pub v: u32,
    /// Sequence number, from 1, +1 per record across every file.
    pub seq: u64,
    /// Hex SHA-256 of the previous record's `rec` bytes; 64 zeros for seq 1.
    pub prev: String,
    /// Unix milliseconds.
    pub time_unix_ms: u64,
    /// What happened.
    pub entry: Entry,
}

/// Kinds of record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// One use of a key, or an attempt.
    Receipt(Receipt),
    /// A MAC'd marker of the chain head, every N records and at rotation.
    Checkpoint(Checkpoint),
    /// LOG-2: a session hit the blocked-attempt threshold.
    Alert(Alert),
}

/// One use of a key (PLAN §3.4). Every field is always written, `null` when absent, so a reader
/// can tell "not applicable" from "missing".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Who: agent kind, root PID and its start time.
    pub session: SessionId,
    /// Which key.
    pub key: KeyName,
    /// Swap, run or mint.
    pub mechanism: Mode,
    /// Host, or the command as displayed. Redacted before write.
    pub target: String,
    /// Hex SHA-256 over the exact argv (run mode).
    pub argv_hash: Option<String>,
    /// The argv, redacted, one element per argument (run mode).
    pub argv_redacted: Option<Vec<String>>,
    /// Version of the rules that decided.
    pub rule_version: u64,
    /// Who approved and how, when a person did.
    pub approval: Option<Approval>,
    /// Outcome.
    pub result: ReceiptResult,
}

/// An approval, as recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// Approval token **id**: an opaque, non-secret identifier. Receipts are readable by the
    /// agent, so callers must never pass the approval token (an HMAC) itself.
    pub token_id: Option<String>,
    /// Who approved (for example the macOS user name).
    pub by: Option<String>,
    /// How (for example `touch_id`, `password`).
    pub method: Option<String>,
}

/// Chain head marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Last record covered.
    pub through_seq: u64,
    /// Hex hash of that record.
    pub head: String,
}

/// What the daemon should do about an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertAction {
    /// Record only.
    None,
    /// Stop the session (the daemon's alert handler does it).
    StopSession,
}

/// LOG-2 alert: `blocked_count` blocked or denied attempts by one session within `window_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// The session.
    pub session: SessionId,
    /// Blocked or denied attempts counted.
    pub blocked_count: u32,
    /// The window they fell in.
    pub window_ms: u64,
    /// First counted receipt.
    pub first_seq: u64,
    /// Last counted receipt.
    pub last_seq: u64,
    /// What was asked of the daemon.
    pub action: AlertAction,
}

/// A line as read from disk, borrowing the raw `rec` bytes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLine<'a> {
    #[serde(borrow)]
    pub rec: &'a RawValue,
    pub mac: String,
}

/// SHA-256 of a record's bytes.
pub fn hash_rec(rec_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(rec_bytes).into()
}

fn mac_state(key: &[u8], rec_bytes: &[u8]) -> Hmac<Sha256> {
    // new_from_slice only fails for fixed-size MACs; HMAC takes any key length.
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    m.update(MAC_DOMAIN);
    m.update(rec_bytes);
    m
}

/// HMAC-SHA-256 of a record's bytes under the receipts key.
pub(crate) fn mac_rec(key: &[u8], rec_bytes: &[u8]) -> [u8; 32] {
    mac_state(key, rec_bytes).finalize().into_bytes().into()
}

/// Constant-time check of a hex MAC. Only the canonical lowercase form is accepted, so the
/// bytes on disk have exactly one valid spelling.
pub(crate) fn mac_ok(key: &[u8], rec_bytes: &[u8], mac_hex: &str) -> bool {
    if mac_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    match hex::decode(mac_hex) {
        Ok(tag) if tag.len() == 32 => mac_state(key, rec_bytes).verify_slice(&tag).is_ok(),
        _ => false,
    }
}

/// Builds the full line (with trailing `\n`) for already-serialised `rec` bytes.
pub(crate) fn line(rec_json: &str, mac: &[u8; 32]) -> String {
    format!("{{\"rec\":{rec_json},\"mac\":\"{}\"}}\n", hex::encode(mac))
}

/// File name for a file whose first record is `seq`.
pub fn file_name(first_seq: u64) -> String {
    format!("receipts-{first_seq:020}.jsonl")
}

/// The first seq a receipts file name claims, or None for any other file name.
pub fn parse_file_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("receipts-")?.strip_suffix(".jsonl")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=file names sort in seq order and round-trip; fails_when=a non-canonical name is
    // accepted or seq 10 sorts before seq 9; no_claim=directory listing order (verify sorts)
    #[test]
    fn file_names() {
        assert_eq!(file_name(1), "receipts-00000000000000000001.jsonl");
        assert_eq!(parse_file_name(&file_name(42)), Some(42));
        assert!(file_name(9) < file_name(10));
        for bad in [
            "receipts-1.jsonl",
            "receipts-0000000000000000000a.jsonl",
            "x-00000000000000000001.jsonl",
            "receipts-00000000000000000001.json",
            "receipts-+0000000000000000001.jsonl",
        ] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
    }

    // protects=the MAC depends on key and bytes and rejects malformed tags; fails_when=a wrong
    // key, a flipped byte or a short tag verifies; no_claim=HMAC-SHA-256 itself (upstream crate)
    #[test]
    fn mac_binds_key_and_bytes() {
        let k = [7u8; 32];
        let m = mac_rec(&k, b"abc");
        let h = hex::encode(m);
        assert!(mac_ok(&k, b"abc", &h));
        assert!(!mac_ok(&[8u8; 32], b"abc", &h));
        assert!(!mac_ok(&k, b"abd", &h));
        assert!(!mac_ok(&k, b"abc", &h[..62]));
        assert!(!mac_ok(&k, b"abc", "zz"));
        assert!(!mac_ok(&k, b"abc", &h.to_ascii_uppercase()));
        // Domain separation: a bare HMAC over the same bytes is a different tag.
        let bare: [u8; 32] = <Hmac<Sha256> as Mac>::new_from_slice(&k)
            .unwrap()
            .chain_update(b"abc")
            .finalize()
            .into_bytes()
            .into();
        assert_ne!(bare, m);
    }
}
