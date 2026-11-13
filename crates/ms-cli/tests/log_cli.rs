//! `ms log` and `ms stats` end to end, against a store written by the real `ReceiptStore`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ms_core::{
    AgentKind, KeyMeta, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, SecretBytes, SessionId,
    Tier,
};
use ms_receipts::{HMAC_KEY_NAME, ReceiptDetail, ReceiptSink, ReceiptStore, StoreConfig};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

const T0: u64 = 1_763_000_000_000; // 2025-11-13T02:13:20Z

fn seed(dir: &Path) {
    let vault = Arc::new(MemoryVault::new());
    let name = KeyName::new(HMAC_KEY_NAME).unwrap();
    vault
        .put(
            &name,
            SecretBytes::new(vec![3; 32]),
            KeyMeta {
                name: name.clone(),
                mode: Mode::Run,
                tier: Tier::Production,
                created_unix_ms: 0,
            },
        )
        .unwrap();
    let s = ReceiptStore::open(
        dir,
        vault,
        StoreConfig {
            fsync: false,
            max_file_bytes: 2000,
            ..StoreConfig::default()
        },
    )
    .unwrap();
    let sess = |agent, pid| SessionId {
        agent,
        pid,
        started_unix_ms: T0,
    };
    let ev = |i: u64, agent, pid, key: &str, result| ReceiptEvent {
        time_unix_ms: T0 + i * 60_000,
        session: sess(agent, pid),
        key: KeyName::new(key).unwrap(),
        mode: Mode::Swap,
        target: "api.stripe.com".into(),
        argv_hash: None,
        rule_version: 1,
        approval_id: None,
        result,
    };
    for i in 0..6 {
        s.append(ev(
            i,
            AgentKind::ClaudeCode,
            100,
            "stripe/test",
            ReceiptResult::Allowed,
        ))
        .unwrap();
    }
    s.append(ev(
        10,
        AgentKind::Codex,
        200,
        "pg/staging",
        ReceiptResult::Approved,
    ))
    .unwrap();
    s.append(ev(
        11,
        AgentKind::Codex,
        200,
        "pg/staging",
        ReceiptResult::Denied,
    ))
    .unwrap();
    let mut evil = ev(
        12,
        AgentKind::Other("bad\u{1b}]0;pwned\u{7}\u{202e}name".into()),
        300,
        "stripe/test",
        ReceiptResult::Blocked(Reason::HostNotAllowed),
    );
    evil.target = "=cmd|' /C calc'!A0 \u{1b}[2J".into();
    s.append_detailed(evil, ReceiptDetail::default()).unwrap();
    // A day later.
    s.append(ev(
        24 * 60,
        AgentKind::ClaudeCode,
        100,
        "stripe/test",
        ReceiptResult::Blocked(Reason::Stopped),
    ))
    .unwrap();
}

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let d = t.path().join("receipts");
    seed(&d);
    (t, d)
}

fn ms_at(bin: &Path, dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin)
        .args(args)
        .env("MORSEC_RECEIPTS_DIR", dir)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn ms(dir: &Path, args: &[&str]) -> (i32, String, String) {
    ms_at(Path::new(env!("CARGO_BIN_EXE_ms")), dir, args)
}

fn no_terminal_controls(s: &str) {
    assert!(
        !s.chars()
            .any(|c| (c.is_control() && c != '\n' && c != '\r') || c == '\u{202e}'),
        "{s:?}"
    );
}

// protects=AC10: `ms log` lists receipts and alerts, filters by key/agent/result/pid/time and
// limit, and strips terminal controls from agent-supplied strings; fails_when=a filter leaks
// other rows, or an escape sequence reaches the terminal; no_claim=column layout
#[test]
fn log_table_and_filters() {
    let (t, d) = tmp();
    let (code, out, err) = ms(&d, &["log"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 1 + 10, "{out}");
    no_terminal_controls(&out);
    assert!(out.contains("blocked:host_not_allowed"));

    let rows = |args: &[&str]| -> Vec<String> {
        let (code, out, err) = ms(&d, args);
        assert_eq!(code, 0, "{args:?}: {err}");
        out.lines().skip(1).map(str::to_owned).collect()
    };
    assert_eq!(rows(&["log", "--key", "pg/staging"]).len(), 2);
    assert_eq!(rows(&["log", "--agent", "codex"]).len(), 2);
    assert_eq!(rows(&["log", "--result", "blocked"]).len(), 2);
    assert_eq!(rows(&["log", "--pid", "100"]).len(), 7);
    assert_eq!(rows(&["log", "-n", "3"]).len(), 3);
    assert!(rows(&["log", "-n", "1"])[0].contains("blocked:stopped"));
    assert_eq!(
        rows(&["log", "--since", "2025-11-14", "--until", "2025-11-15"]).len(),
        1
    );
    assert_eq!(
        rows(&["log", "--until", "2025-11-13T02:15:00Z"]).len(),
        2,
        "records at +0 and +1 min"
    );

    let (code, _, err) = ms(&d, &["log", "--since", "yesterday"]);
    assert_eq!(code, 1);
    assert!(
        err.starts_with("morsec: invalid time") && !err.contains("morsec: morsec"),
        "{err}"
    );
    let (code, out, _) = ms(&t.path().join("empty"), &["log"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("No receipts yet"));
}

// protects=AC10/AC3: `ms log --verify` passes an intact store and fails (exit 1, naming the
// problem) after a record is removed; it says MACs were not checked; fails_when=verify passes
// a tampered store or claims a MAC check it didn't do; no_claim=MAC checking (needs msd, L07)
#[test]
fn verify_intact_and_tampered() {
    let (_t, d) = tmp();
    let (code, out, err) = ms(&d, &["log", "--verify"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("receipts intact") && out.contains("MACs not checked"),
        "{out}"
    );
    assert!(err.contains("only the daemon"), "{err}");

    let first = ms_receipts::read::list_files(&d).unwrap()[0].path.clone();
    let text = fs::read_to_string(&first).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| l)
        .collect();
    fs::write(&first, kept.join("\n") + "\n").unwrap();
    let (code, out, _) = ms(&d, &["log", "--verify"]);
    assert_eq!(code, 1);
    assert!(out.contains("FAILED") && out.contains("line 3"), "{out}");
}

// protects=AC9/LOG-4: CSV and JSON exports carry the filtered records, neutralise formulas and
// terminal controls, and --out writes a new 0600 file without overwriting; fails_when=an export
// row is live in a spreadsheet, prints an escape sequence, or clobbers a file;
// no_claim=the ARI-42 bundle (L27)
#[test]
fn exports() {
    let (t, d) = tmp();
    let (code, csv, err) = ms(&d, &["log", "--export", "csv"]);
    assert_eq!(code, 0, "{err}");
    no_terminal_controls(&csv);
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("seq,time_utc,kind,agent"));
    // 10 receipts + 1 header; no alert (threshold not reached).
    assert_eq!(lines.len(), 11, "{csv}");
    let evil = lines.iter().find(|l| l.contains("calc")).unwrap();
    assert!(evil.contains(",'=cmd|"), "{evil}");
    assert!(evil.contains("\\u{001b}"), "{evil}");

    let (code, json, _) = ms(&d, &["log", "--export", "json", "--key", "pg/staging"]);
    assert_eq!(code, 0);
    no_terminal_controls(&json);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"], "morsec-receipts");
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["rec"]["entry"]["key"], "pg/staging");
    assert_eq!(recs[0]["hash"].as_str().unwrap().len(), 64);

    // The escaped JSON still decodes to the original agent name.
    let (_, json, _) = ms(&d, &["log", "--export", "json", "--pid", "300"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["records"][0]["rec"]["entry"]["session"]["agent"]["other"],
        "bad\u{1b}]0;pwned\u{7}\u{202e}name"
    );

    let out = t.path().join("export.csv");
    let (code, stdout, err) = ms(
        &d,
        &["log", "--export", "csv", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code, 0, "{err}");
    assert!(stdout.is_empty());
    assert_eq!(fs::read_to_string(&out).unwrap(), csv);
    assert_eq!(
        ms_receipts::store::mode_of(&out).unwrap(),
        0o600,
        "export must be private"
    );
    let (code, _, err) = ms(
        &d,
        &["log", "--export", "csv", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code, 1);
    assert!(err.contains("never overwrite"), "{err}");

    let (code, _, _) = ms(&d, &["log", "--out", out.to_str().unwrap()]);
    assert_eq!(code, 2, "--out without --export is a usage error");
}

// protects=AC10: `ms stats` counts prompts per session, blocks per day and approvals, as text
// and JSON, with agent names inert; fails_when=a count is wrong or a control char is printed;
// no_claim=stats over a tampered store (run --verify first)
#[test]
fn stats_text_and_json() {
    let (_t, d) = tmp();
    let (code, out, err) = ms(&d, &["stats"]);
    assert_eq!(code, 0, "{err}");
    no_terminal_controls(&out);
    assert!(
        out.starts_with(
            "10 receipts: 6 allowed, 1 approved, 1 denied, 2 blocked, 0 failed; 0 alerts"
        ),
        "{out}"
    );
    assert!(out.contains("approval prompts: 2"));
    assert!(
        out.contains("2025-11-13  1") && out.contains("2025-11-14  1"),
        "{out}"
    );

    let (code, json, _) = ms(&d, &["stats", "--json"]);
    assert_eq!(code, 0);
    no_terminal_controls(&json);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["prompts"], 2);
    let codex = v["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["pid"] == 200)
        .unwrap();
    assert_eq!(
        (codex["prompts"].clone(), codex["denied"].clone()),
        (2.into(), 1.into())
    );

    let (_, out, _) = ms(&d, &["stats", "--since", "2025-11-14"]);
    assert!(out.starts_with("1 receipts"), "{out}");
}

// protects=`mors log` and `mors stats` behave exactly like `ms`; fails_when=output differs by
// invoked name; no_claim=install-time symlink creation (L10)
#[test]
fn mors_alias_matches() {
    let (t, d) = tmp();
    let alias = t.path().join("mors");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_ms"), &alias).unwrap();
    for args in [
        &["log"][..],
        &["stats"],
        &["log", "--verify"],
        &["log", "--export", "csv"],
    ] {
        assert_eq!(ms(&d, args), ms_at(&alias, &d, args), "{args:?}");
    }
}
