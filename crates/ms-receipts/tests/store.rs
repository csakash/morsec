//! Store, verify and LOG-2 tests against a real directory and the in-memory vault.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ms_core::{
    AgentKind, KeyMeta, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, SecretBytes, SessionId,
    Tier,
};
use ms_receipts::record::file_name;
use ms_receipts::store::mode_of;
use ms_receipts::{
    Alert, AlertAction, AlertHandler, Entry, HMAC_KEY_NAME, ProblemKind, ReceiptDetail,
    ReceiptSink, ReceiptStore, StoreConfig, ValueRedactor, read_all, verify,
};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

const KEY: [u8; 32] = [0x5a; 32];

fn vault_with(key: &[u8]) -> Arc<MemoryVault> {
    let v = Arc::new(MemoryVault::new());
    let name = KeyName::new(HMAC_KEY_NAME).unwrap();
    v.put(
        &name,
        SecretBytes::new(key.to_vec()),
        KeyMeta {
            name: name.clone(),
            mode: Mode::Run,
            tier: Tier::Production,
            created_unix_ms: 0,
        },
    )
    .unwrap();
    v
}

fn session(pid: u32) -> SessionId {
    SessionId {
        agent: AgentKind::ClaudeCode,
        pid,
        started_unix_ms: 1_000,
    }
}

fn event(i: u64, pid: u32, result: ReceiptResult) -> ReceiptEvent {
    ReceiptEvent {
        time_unix_ms: 1_700_000_000_000 + i * 1000,
        session: session(pid),
        key: KeyName::new("stripe/test").unwrap(),
        mode: Mode::Swap,
        target: format!("api.stripe.com/{i}"),
        argv_hash: None,
        rule_version: 3,
        approval_id: None,
        result,
    }
}

fn cfg() -> StoreConfig {
    StoreConfig {
        fsync: false,
        ..StoreConfig::default()
    }
}

fn store(dir: &Path, cfg: StoreConfig) -> ReceiptStore {
    ReceiptStore::open(dir, vault_with(&KEY), cfg).unwrap()
}

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let d = t.path().join("receipts");
    (t, d)
}

/// A store spread over several files: small max size, checkpoint every 4.
fn seeded(n: u64) -> (tempfile::TempDir, PathBuf) {
    let (t, d) = tmp();
    let s = store(
        &d,
        StoreConfig {
            max_file_bytes: 1500,
            checkpoint_every: 4,
            ..cfg()
        },
    );
    for i in 0..n {
        s.append(event(i, 10, ReceiptResult::Allowed)).unwrap();
    }
    (t, d)
}

fn files(d: &Path) -> Vec<PathBuf> {
    ms_receipts::read::list_files(d)
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect()
}

fn lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(p: &Path, l: &[String]) {
    let mut s = l.join("\n");
    s.push('\n');
    fs::write(p, s).unwrap();
}

fn check(d: &Path, with_key: bool) -> ms_receipts::VerifyReport {
    let v = vault_with(&KEY);
    verify(d, with_key.then_some(v.as_ref() as &dyn Vault)).unwrap()
}

// protects=a multi-file store with checkpoints verifies with the key and chain-only;
// fails_when=rotation or checkpoints break the chain, or files aren't 0600 in a 0700 dir;
// no_claim=crash safety during rotation
#[test]
fn rotation_checkpoints_and_permissions() {
    let (_t, d) = seeded(40);
    let fs_ = files(&d);
    assert!(fs_.len() >= 3, "only {} files", fs_.len());
    let r = check(&d, true);
    assert!(r.ok() && r.macs_checked, "{r}");
    assert!(check(&d, false).ok());
    let recs = read_all(&d).unwrap();
    let receipts = recs
        .iter()
        .filter(|r| matches!(r.rec.entry, Entry::Receipt(_)))
        .count();
    assert_eq!(receipts, 40);
    let checkpoints: Vec<_> = recs
        .iter()
        .filter_map(|r| match &r.rec.entry {
            Entry::Checkpoint(c) => Some((r.seq, c.through_seq)),
            _ => None,
        })
        .collect();
    assert!(checkpoints.len() >= 10, "{checkpoints:?}");
    assert!(checkpoints.iter().all(|(s, t)| *t + 1 == *s));
    assert_eq!(mode_of(&d).unwrap(), 0o700);
    for f in &fs_ {
        assert_eq!(mode_of(f).unwrap(), 0o600, "{}", f.display());
    }
    // Each file is named for its first record.
    for f in &fs_ {
        let first: serde_json::Value = serde_json::from_str(&lines(f)[0]).unwrap();
        let seq = first["rec"]["seq"].as_u64().unwrap();
        assert_eq!(f.file_name().unwrap().to_str().unwrap(), file_name(seq));
    }
}

/// Applies `tamper` to a fresh seeded store and returns (with key, chain only) reports.
fn tampered(
    tamper: impl FnOnce(&[PathBuf]),
) -> (ms_receipts::VerifyReport, ms_receipts::VerifyReport) {
    let (_t, d) = seeded(40);
    tamper(&files(&d));
    (check(&d, true), check(&d, false))
}

fn kind(r: &ms_receipts::VerifyReport) -> ProblemKind {
    r.problem
        .as_ref()
        .map(|p| p.kind)
        .unwrap_or_else(|| panic!("passed: {r}"))
}

// protects=AC3: every listed tampering fails verify with the key, at the right record;
// removal, reordering and duplication also fail chain-only; fails_when=any tampering passes;
// no_claim=tail truncation or rollback to an older consistent copy (documented residual risk)
#[test]
fn tampering_fails_verify() {
    // Edit a field in place.
    let (k, _) = tampered(|f| {
        let mut l = lines(&f[1]);
        l[1] = l[1].replace("api.stripe.com", "api.evil.com!");
        write_lines(&f[1], &l);
    });
    assert_eq!(kind(&k), ProblemKind::BadMac);

    // Edit a field and re-chain everything after it without the key: the MAC still catches it.
    let (_t, d) = seeded(12);
    {
        let f = files(&d);
        let mut l = lines(&f[0]);
        let mut prev: Option<String> = None;
        for line in l.iter_mut() {
            let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(p) = &prev {
                v["rec"]["prev"] = serde_json::Value::String(p.clone());
            }
            if v["rec"]["seq"] == 2 {
                v["rec"]["entry"]["target"] = "forged.example".into();
            }
            let rec = serde_json::to_string(&v["rec"]).unwrap();
            prev = Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                rec.as_bytes(),
            )));
            *line = format!("{{\"rec\":{rec},\"mac\":{}}}", v["mac"]);
        }
        write_lines(&f[0], &l);
    }
    let r = check(&d, true);
    assert_eq!(kind(&r), ProblemKind::BadMac);
    // Whoever re-chains consistently fools a chain-only check; that is why MACs exist.
    let chain_only = check(&d, false);
    assert!(
        chain_only.ok() || kind(&chain_only) == ProblemKind::BadCheckpoint,
        "{chain_only}"
    );

    // Delete a record.
    let (k, c) = tampered(|f| {
        let mut l = lines(&f[1]);
        l.remove(2);
        write_lines(&f[1], &l);
    });
    assert_eq!(kind(&k), ProblemKind::MissingRecords);
    assert_eq!(kind(&c), ProblemKind::MissingRecords);
    let p = k.problem.unwrap();
    assert_eq!(p.line, 3);

    // Swap two records.
    let (k, c) = tampered(|f| {
        let mut l = lines(&f[0]);
        l.swap(1, 2);
        write_lines(&f[0], &l);
    });
    // Record 3 now sits where 2 belongs: reported at line 2 as a gap.
    assert_eq!(kind(&k), ProblemKind::MissingRecords);
    assert_eq!(kind(&c), ProblemKind::MissingRecords);
    assert_eq!(k.problem.unwrap().line, 2);

    // Duplicate a record.
    let (k, c) = tampered(|f| {
        let mut l = lines(&f[0]);
        let dup = l[1].clone();
        l.insert(2, dup);
        write_lines(&f[0], &l);
    });
    assert_eq!(kind(&k), ProblemKind::OutOfOrder);
    assert_eq!(kind(&c), ProblemKind::OutOfOrder);

    // Delete a whole middle file.
    let (k, c) = tampered(|f| fs::remove_file(&f[1]).unwrap());
    assert_eq!(kind(&k), ProblemKind::MissingRecords);
    assert_eq!(kind(&c), ProblemKind::MissingRecords);

    // Delete the first file.
    let (k, c) = tampered(|f| fs::remove_file(&f[0]).unwrap());
    assert_eq!(kind(&k), ProblemKind::BadGenesis);
    assert_eq!(kind(&c), ProblemKind::BadGenesis);

    // Torn last line.
    let (k, c) = tampered(|f| {
        let last = f.last().unwrap();
        let s = fs::read_to_string(last).unwrap();
        fs::write(last, &s[..s.len() - 7]).unwrap();
    });
    assert_eq!(kind(&k), ProblemKind::TornLine);
    assert_eq!(kind(&c), ProblemKind::TornLine);

    // A record replaced by one MAC'd with another key.
    let (k, _) = tampered(|f| {
        let other = tempfile::tempdir().unwrap();
        let s = ReceiptStore::open(other.path().join("r"), vault_with(&[1u8; 32]), cfg()).unwrap();
        s.append(event(0, 10, ReceiptResult::Allowed)).unwrap();
        let forged = lines(&files(&other.path().join("r"))[0])[0].clone();
        let mut l = lines(&f[0]);
        l[0] = forged;
        write_lines(&f[0], &l);
    });
    assert_eq!(kind(&k), ProblemKind::BadMac);

    // Garbage line.
    let (k, c) = tampered(|f| {
        let mut l = lines(&f[0]);
        l[3] = "not json".into();
        write_lines(&f[0], &l);
    });
    assert_eq!(kind(&k), ProblemKind::Malformed);
    assert_eq!(kind(&c), ProblemKind::Malformed);
}

// protects=a checkpoint naming the wrong head fails, even when its MAC is valid (forged with
// the key, as only the store could); fails_when=a checkpoint is not checked;
// no_claim=checkpoints anchored outside this machine
#[test]
fn bad_checkpoint_detected() {
    use hmac::Mac;
    let (_t, d) = seeded(8);
    let f = files(&d);
    let mut l = lines(&f[0]);
    let idx = l
        .iter()
        .position(|x| x.contains("\"kind\":\"checkpoint\""))
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&l[idx]).unwrap();
    let mut rec = v["rec"].clone();
    rec["entry"]["head"] = "00".repeat(32).into();
    let rec_s = serde_json::to_string(&rec).unwrap();
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(&KEY).unwrap();
    m.update(b"morsec-receipt-v1\0");
    m.update(rec_s.as_bytes());
    let mac = hex::encode(m.finalize().into_bytes());
    l[idx] = format!("{{\"rec\":{rec_s},\"mac\":\"{mac}\"}}");
    // Keep only up to the checkpoint so the following link isn't what fails.
    l.truncate(idx + 1);
    write_lines(&f[0], &l);
    for g in &f[1..] {
        fs::remove_file(g).unwrap();
    }
    assert_eq!(kind(&check(&d, true)), ProblemKind::BadCheckpoint);
}

// protects=AC4/LOG-1: a stored receipt carries every PLAN §3.4 field; fails_when=a field is
// missing from the JSON on disk; no_claim=the PRD §9 wording beyond §3.4
#[test]
fn receipt_has_every_field() {
    let (_t, d) = tmp();
    let s = store(&d, cfg());
    let mut e = event(1, 42, ReceiptResult::Approved);
    e.mode = Mode::Run;
    e.argv_hash = Some([0xab; 32]);
    e.approval_id = Some("apr-1".into());
    e.target = "psql -c select 1".into();
    s.append_detailed(
        e,
        ReceiptDetail {
            argv: Some(vec!["psql".into(), "-c".into(), "select 1".into()]),
            approval_by: Some("akash".into()),
            approval_method: Some("touch_id".into()),
            redactor: None,
        },
    )
    .unwrap();
    let line = &lines(&files(&d)[0])[0];
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let rec = &v["rec"];
    for k in ["v", "seq", "prev", "time_unix_ms"] {
        assert!(!rec[k].is_null(), "{k}");
    }
    let e = &rec["entry"];
    assert_eq!(e["kind"], "receipt");
    assert_eq!(e["session"]["agent"], "claude_code");
    assert_eq!(e["session"]["pid"], 42);
    assert_eq!(e["session"]["started_unix_ms"], 1000);
    assert_eq!(e["key"], "stripe/test");
    assert_eq!(e["mechanism"], "run");
    assert_eq!(e["target"], "psql -c select 1");
    assert_eq!(e["argv_hash"], "ab".repeat(32));
    assert_eq!(e["argv_redacted"][2], "select 1");
    assert_eq!(e["rule_version"], 3);
    assert_eq!(e["approval"]["token_id"], "apr-1");
    assert_eq!(e["approval"]["by"], "akash");
    assert_eq!(e["approval"]["method"], "touch_id");
    assert_eq!(e["result"], "approved");
    assert_eq!(rec["prev"], "0".repeat(64));
    assert_eq!(v["mac"].as_str().unwrap().len(), 64);
    // Absent fields are written as null, not dropped.
    s.append(event(2, 42, ReceiptResult::Allowed)).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&lines(&files(&d)[0])[1]).unwrap();
    let obj = v2["rec"]["entry"].as_object().unwrap();
    for k in ["argv_hash", "argv_redacted", "approval"] {
        assert!(obj.contains_key(k) && obj[k].is_null(), "{k}");
    }
}

// protects=AC5: a canary value in target, argv, failure message, approver and agent name never
// reaches disk, via the value redactor and via shape patterns; fails_when=any byte run of the
// canary is in any receipts file; no_claim=encodings other than raw and percent-encoded
#[test]
fn canary_never_written() {
    let (_t, d) = tmp();
    let s = store(&d, cfg());
    let canary = "Zq9-CANARY-v4lue-7f3a";
    let key = KeyName::new("pg/staging").unwrap();
    let vr = ValueRedactor::new(vec![(&key, canary.as_bytes())]);
    let mut e = event(
        1,
        7,
        ReceiptResult::Failed(format!("auth failed for {canary}")),
    );
    e.target = format!("postgres://app:{canary}@db/x");
    e.session.agent = AgentKind::Other(format!("agent-{canary}"));
    e.approval_id = Some(canary.into());
    s.append_detailed(
        e,
        ReceiptDetail {
            argv: Some(vec![
                "psql".into(),
                format!("--dsn={canary}"),
                canary.into(),
            ]),
            approval_by: Some(canary.into()),
            approval_method: Some(format!("x {}", canary.replace('-', "%2D"))),
            redactor: Some(&vr),
        },
    )
    .unwrap();
    // Shape patterns alone, no value redactor.
    let shaped = "sk_test_CANARYshape0123456789";
    let mut e2 = event(2, 7, ReceiptResult::Allowed);
    e2.target = format!("curl -H 'Authorization: Bearer {shaped}' https://api.stripe.com");
    s.append_detailed(
        e2,
        ReceiptDetail {
            argv: Some(vec!["curl".into(), "--token".into(), shaped.into()]),
            ..ReceiptDetail::default()
        },
    )
    .unwrap();
    let all = fs::read_to_string(&files(&d)[0]).unwrap();
    assert!(!all.contains("CANARY"), "{all}");
    assert!(!all.contains("v4lue"), "{all}");
    assert!(all.contains("ms://pg/staging"));
    assert!(check(&d, true).ok());
}

struct Recorder(Mutex<Vec<Alert>>);
impl AlertHandler for Recorder {
    fn on_alert(&self, a: &Alert) {
        self.0.lock().unwrap().push(a.clone());
    }
}
struct Shared(Arc<Recorder>);
impl AlertHandler for Shared {
    fn on_alert(&self, a: &Alert) {
        self.0.on_alert(a);
    }
}

// protects=AC6/LOG-2: 5 blocked or denied attempts by one session within the window write one
// alert and call the handler with stop_session; 4 don't; other sessions and old attempts don't
// count; fails_when=no alert, a duplicate alert, or cross-session counting;
// no_claim=that the daemon actually stops the session (L07)
#[test]
fn alert_detector() {
    let (_t, d) = tmp();
    let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
    let s = store(
        &d,
        StoreConfig {
            stop_session_on_alert: true,
            alert_window_ms: 60_000,
            ..cfg()
        },
    )
    .with_alert_handler(Box::new(Shared(rec.clone())));
    let blocked = || ReceiptResult::Blocked(Reason::HostNotAllowed);
    // 4 blocks from pid 1, interleaved with another session's blocks and allowed calls.
    for i in 0..4 {
        s.append(event(i, 1, blocked())).unwrap();
        s.append(event(i, 2, blocked())).unwrap();
        s.append(event(i, 1, ReceiptResult::Allowed)).unwrap();
    }
    assert!(rec.0.lock().unwrap().is_empty());
    // The 5th (a denial) within the window fires.
    s.append(event(5, 1, ReceiptResult::Denied)).unwrap();
    let alerts = rec.0.lock().unwrap().clone();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].session.pid, 1);
    assert_eq!(alerts[0].blocked_count, 5);
    assert_eq!(alerts[0].action, AlertAction::StopSession);
    // Exactly one alert record, chained and MAC'd.
    let recs = read_all(&d).unwrap();
    let on_disk: Vec<_> = recs
        .iter()
        .filter(|r| matches!(r.rec.entry, Entry::Alert(_)))
        .collect();
    assert_eq!(on_disk.len(), 1);
    assert!(check(&d, true).ok());
    // Five more blocks inside the same window: still one alert (one per window per session).
    for i in 6..11 {
        s.append(event(i, 1, blocked())).unwrap();
    }
    assert_eq!(rec.0.lock().unwrap().len(), 1);
    // After the window has passed, a new burst alerts again.
    for i in 0..5 {
        s.append(event(200 + i, 1, blocked())).unwrap();
    }
    assert_eq!(rec.0.lock().unwrap().len(), 2);
    // Attempts spread wider than the window never fire.
    for i in 0..10 {
        s.append(event(100 + i * 61, 3, blocked())).unwrap();
    }
    assert_eq!(rec.0.lock().unwrap().len(), 2);
}

// protects=AC7: reopening resumes seq and prev; a wrong key, a missing key, a short key and a
// torn tail all fail closed with a fix; fails_when=a reopen restarts at 1, forks the chain or
// opens over a tampered tail; no_claim=detection of tail truncation
#[test]
fn reopen_and_fail_closed() {
    let (_t, d) = tmp();
    {
        let s = store(&d, cfg());
        for i in 0..3 {
            s.append(event(i, 1, ReceiptResult::Allowed)).unwrap();
        }
    }
    let s = store(&d, cfg());
    assert_eq!(s.next_seq(), 4);
    s.append(event(9, 1, ReceiptResult::Allowed)).unwrap();
    drop(s);
    assert!(check(&d, true).ok());

    let wrong = ReceiptStore::open(&d, vault_with(&[9u8; 32]), cfg()).unwrap_err();
    assert!(wrong.to_string().contains("ms log --verify"), "{wrong}");

    let missing = ReceiptStore::open(&d, Arc::new(MemoryVault::new()), cfg()).unwrap_err();
    assert!(missing.to_string().contains(HMAC_KEY_NAME), "{missing}");

    let (_t2, d2) = tmp();
    let short = ReceiptStore::open(&d2, vault_with(&[1u8; 16]), cfg()).unwrap_err();
    assert!(short.to_string().contains("ms init"), "{short}");

    let f = files(&d)[0].clone();
    let s = fs::read_to_string(&f).unwrap();
    fs::write(&f, &s[..s.len() - 3]).unwrap();
    let torn = ReceiptStore::open(&d, vault_with(&KEY), cfg()).unwrap_err();
    assert!(torn.to_string().contains("incomplete"), "{torn}");
}

// protects=AC11: an existing receipts dir open to group/other, a symlinked dir and a symlink
// planted at the current file name are refused; fails_when=the store writes through any of
// them; no_claim=protection against the same Unix user (L23)
#[test]
fn refuses_unsafe_paths() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_t, d) = tmp();
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    let e = ReceiptStore::open(&d, vault_with(&KEY), cfg()).unwrap_err();
    assert!(e.to_string().contains("chmod 700"), "{e}");

    let (t, d) = tmp();
    let real = t.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, &d).unwrap();
    assert!(ReceiptStore::open(&d, vault_with(&KEY), cfg()).is_err());

    let (t, d) = tmp();
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    let target = t.path().join("elsewhere");
    fs::write(&target, "").unwrap();
    symlink(&target, d.join(file_name(1))).unwrap();
    assert!(ReceiptStore::open(&d, vault_with(&KEY), cfg()).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "");
}

// protects=concurrent appends from many threads keep one valid chain with unique seqs;
// fails_when=interleaved writes fork or corrupt the chain; no_claim=multiple processes
// appending to one directory (only msd writes)
#[test]
fn concurrent_appends_keep_the_chain() {
    let (_t, d) = tmp();
    let s = Arc::new(store(
        &d,
        StoreConfig {
            max_file_bytes: 4000,
            checkpoint_every: 7,
            ..cfg()
        },
    ));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let s = s.clone();
            std::thread::spawn(move || {
                (0..25)
                    .map(|i| s.append(event(i, t, ReceiptResult::Allowed)).unwrap().0)
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut ids: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 200);
    let r = check(&d, true);
    assert!(r.ok(), "{r}");
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        // protects=any sequence of appends verifies, and flipping any single byte of any line
        // fails verify with the key; fails_when=a mutation passes; no_claim=multi-byte
        // edits crafted with the key
        #[test]
        fn any_byte_flip_fails(n in 1u64..12, pick in any::<prop::sample::Index>(), bit in 0u8..8) {
            let (_t, d) = tmp();
            let s = store(&d, cfg());
            for i in 0..n {
                let r = if i % 3 == 0 { ReceiptResult::Blocked(Reason::HostNotAllowed) } else { ReceiptResult::Allowed };
                s.append(event(i, (i % 2) as u32, r)).unwrap();
            }
            drop(s);
            prop_assert!(check(&d, true).ok());
            let f = files(&d)[0].clone();
            let mut bytes = fs::read(&f).unwrap();
            // Flip a bit of any byte except the final newline.
            let i = pick.index(bytes.len() - 1);
            bytes[i] ^= 1 << bit;
            fs::write(&f, &bytes).unwrap();
            prop_assert!(!check(&d, true).ok());
        }
    }
}
