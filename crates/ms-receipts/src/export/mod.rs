//! `ms log --export`: JSON and CSV (LOG-4, basic export). The ARI-42 bundle lives in
//! `export/ari42/` and is built by L27.

use std::fmt::Write as _;

use ms_core::ReceiptResult;
use serde::Serialize;

use crate::query::agent_label;
use crate::read::StoredRecord;
use crate::record::Entry;
use crate::time::format_utc;

/// Characters that can rewrite what a terminal or editor shows: C0/C1 controls, DEL, and the
/// bidi embedding, override and isolate marks.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// JSON export: `{"format":"morsec-receipts","version":1,"records":[…]}`. Each record keeps its
/// `seq` and `hash`, so a reader can line it up with `ms log --verify`. Control and bidi
/// characters are written as `\uXXXX` escapes (the same JSON value), so the output is inert in a
/// terminal.
pub fn export_json(records: &[StoredRecord]) -> String {
    #[derive(Serialize)]
    struct Doc<'a> {
        format: &'static str,
        version: u32,
        records: &'a [StoredRecord],
    }
    // Serialising plain data structs can't fail.
    let json = serde_json::to_string_pretty(&Doc {
        format: "morsec-receipts",
        version: 1,
        records,
    })
    .unwrap_or_else(|_| unreachable!());
    json_inert(&json)
}

/// Rewrites control and bidi characters in serde_json output as `\uXXXX` escapes. serde_json
/// already escapes C0 controls inside strings; outside strings there is only ASCII punctuation
/// and whitespace, so escaping the rest everywhere keeps the document's meaning.
pub fn json_inert(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if is_unsafe_char(c) && !matches!(c, '\n' | ' ') {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// CSV columns, in order.
pub const CSV_HEADER: &[&str] = &[
    "seq",
    "time_utc",
    "kind",
    "agent",
    "pid",
    "session_started_unix_ms",
    "key",
    "mechanism",
    "target",
    "argv",
    "argv_hash",
    "rule_version",
    "approval_token",
    "approved_by",
    "approval_method",
    "result",
    "detail",
    "hash",
];

/// One CSV cell: control and bidi characters shown as `\u{XXXX}` text (so the export is inert in
/// a terminal), RFC 4180 quoting, and a leading `'` on anything a spreadsheet would run as a
/// formula (`= + - @`, tab, carriage return).
pub fn csv_cell(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| {
            if is_unsafe_char(c) {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect();
    let neutral = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    if neutral.contains([',', '"', '\n', '\r']) || neutral != neutral.trim() {
        format!("\"{}\"", neutral.replace('"', "\"\""))
    } else {
        neutral
    }
}

fn result_parts(r: &ReceiptResult) -> (&'static str, String) {
    match r {
        ReceiptResult::Allowed => ("allowed", String::new()),
        ReceiptResult::Approved => ("approved", String::new()),
        ReceiptResult::Blocked(reason) => (
            "blocked",
            serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        ),
        ReceiptResult::Denied => ("denied", String::new()),
        ReceiptResult::Failed(m) => ("failed", m.clone()),
    }
}

/// CSV export of receipts and alerts (checkpoints are left out).
pub fn export_csv(records: &[StoredRecord]) -> String {
    let mut out = CSV_HEADER.join(",");
    out.push_str("\r\n");
    for r in records {
        let time = format_utc(r.rec.time_unix_ms);
        let row: Vec<String> = match &r.rec.entry {
            Entry::Receipt(x) => {
                let (result, detail) = result_parts(&x.result);
                let ap = x.approval.clone().unwrap_or_default();
                vec![
                    r.seq.to_string(),
                    time,
                    "receipt".into(),
                    agent_label(&x.session.agent),
                    x.session.pid.to_string(),
                    x.session.started_unix_ms.to_string(),
                    x.key.to_string(),
                    serde_json::to_value(x.mechanism)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                    x.target.clone(),
                    x.argv_redacted
                        .as_ref()
                        .map(|a| serde_json::to_string(a).unwrap_or_default())
                        .unwrap_or_default(),
                    x.argv_hash.clone().unwrap_or_default(),
                    x.rule_version.to_string(),
                    ap.token_id.unwrap_or_default(),
                    ap.by.unwrap_or_default(),
                    ap.method.unwrap_or_default(),
                    result.into(),
                    detail,
                    r.hash.clone(),
                ]
            }
            Entry::Alert(a) => {
                let mut detail = String::new();
                let _ = write!(
                    detail,
                    "{} blocked in {} s (records {}-{}); action {}",
                    a.blocked_count,
                    a.window_ms / 1000,
                    a.first_seq,
                    a.last_seq,
                    match a.action {
                        crate::AlertAction::None => "none",
                        crate::AlertAction::StopSession => "stop_session",
                    }
                );
                vec![
                    r.seq.to_string(),
                    time,
                    "alert".into(),
                    agent_label(&a.session.agent),
                    a.session.pid.to_string(),
                    a.session.started_unix_ms.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    "alert".into(),
                    detail,
                    r.hash.clone(),
                ]
            }
            Entry::Checkpoint(_) => continue,
        };
        out.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=CSV cells are quoted per RFC 4180, formula prefixes are neutralised, and control
    // or bidi characters become visible text; fails_when=a comma, quote or newline breaks the
    // row, "=cmd" stays live, or an escape sequence survives; no_claim=every spreadsheet's rules
    #[test]
    fn csv_cells() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("l1\nl2"), "l1\\u{000a}l2");
        assert_eq!(csv_cell("a\u{1b}[31m\u{202e}b"), "a\\u{001b}[31m\\u{202e}b");
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("-cmd"), "'-cmd");
        assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_cell(" pad"), "\" pad\"");
    }
}
