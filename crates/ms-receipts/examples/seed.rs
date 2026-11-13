//! Dev only: writes sample receipts into a directory, for manual QA of `ms log` and `ms stats`.
//!
//! `cargo run -p ms-receipts --example seed -- <dir>`
//!
//! Uses the in-memory vault and a fixed, public dev key, so these receipts prove nothing. Never
//! used by `ms` or `msd`.

#![allow(clippy::print_stdout)]

use std::sync::Arc;

use ms_core::{
    AgentKind, KeyMeta, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, SecretBytes, SessionId,
    Tier,
};
use ms_receipts::{HMAC_KEY_NAME, ReceiptDetail, ReceiptStore, StoreConfig};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args_os()
        .nth(1)
        .ok_or("usage: seed <receipts dir>")?;
    let vault = Arc::new(MemoryVault::new());
    let name = KeyName::new(HMAC_KEY_NAME)?;
    vault.put(
        &name,
        SecretBytes::new(vec![0x42; 32]),
        KeyMeta {
            name: name.clone(),
            mode: Mode::Run,
            tier: Tier::Production,
            created_unix_ms: 0,
        },
    )?;
    let store = ReceiptStore::open(
        &dir,
        vault,
        StoreConfig {
            max_file_bytes: 4096,
            checkpoint_every: 10,
            ..StoreConfig::default()
        },
    )?;
    let base = 1_763_000_000_000u64; // 2025-11-13
    let claude = SessionId {
        agent: AgentKind::ClaudeCode,
        pid: 4242,
        started_unix_ms: base - 60_000,
    };
    let codex = SessionId {
        agent: AgentKind::Codex,
        pid: 5151,
        started_unix_ms: base - 30_000,
    };
    let odd = SessionId {
        agent: AgentKind::Other("evil\u{1b}[31mRED\u{1b}[0m\u{202e}agent".into()),
        pid: 6161,
        started_unix_ms: base,
    };
    let stripe = KeyName::new("stripe/test")?;
    let pg = KeyName::new("pg/staging")?;
    let ev = |t: u64, s: &SessionId, k: &KeyName, mode, target: &str, r| ReceiptEvent {
        time_unix_ms: base + t * 1000,
        session: s.clone(),
        key: k.clone(),
        mode,
        target: target.into(),
        argv_hash: None,
        rule_version: 2,
        approval_id: None,
        result: r,
    };
    for i in 0..8 {
        store.append_detailed(
            ev(
                i,
                &claude,
                &stripe,
                Mode::Swap,
                "api.stripe.com",
                ReceiptResult::Allowed,
            ),
            ReceiptDetail::default(),
        )?;
    }
    let mut run = ev(
        20,
        &codex,
        &pg,
        Mode::Run,
        "psql postgres://app:hunter2@db/x -c select 1",
        ReceiptResult::Approved,
    );
    run.argv_hash = Some([7; 32]);
    run.approval_id = Some("apr-1".into());
    store.append_detailed(
        run,
        ReceiptDetail {
            argv: Some(vec![
                "psql".into(),
                "postgres://app:hunter2@db/x".into(),
                "-c".into(),
                "select 1".into(),
            ]),
            approval_by: Some("dev".into()),
            approval_method: Some("touch_id".into()),
            redactor: None,
        },
    )?;
    store.append_detailed(
        ev(
            25,
            &codex,
            &pg,
            Mode::Run,
            "psql -c drop table x",
            ReceiptResult::Denied,
        ),
        ReceiptDetail::default(),
    )?;
    for i in 0..5 {
        store.append_detailed(
            ev(
                30 + i,
                &odd,
                &stripe,
                Mode::Swap,
                "=HYPERLINK(\"http://exfil.example\")",
                ReceiptResult::Blocked(Reason::HostNotAllowed),
            ),
            ReceiptDetail::default(),
        )?;
    }
    store.append_detailed(
        ev(
            90_000,
            &claude,
            &stripe,
            Mode::Swap,
            "api.stripe.com",
            ReceiptResult::Blocked(Reason::Stopped),
        ),
        ReceiptDetail::default(),
    )?;
    println!(
        "seeded {} records into {}",
        store.next_seq() - 1,
        store.dir().display()
    );
    Ok(())
}
