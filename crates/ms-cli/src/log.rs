//! `ms log`: show, verify and export receipts (L02).
//!
//! Reads the receipts directory directly: receipts hold no secret values, only references and
//! redacted commands. The HMAC key stays in the vault, bound to `msd`, so `--verify` here checks
//! the hash chain and says that record MACs are checked by the daemon.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use ms_core::{KeyName, ReceiptResult};
use ms_receipts::query::{agent_label, parse_agent};
use ms_receipts::time::{format_utc, now_ms, parse_time};
use ms_receipts::{Entry, Query, ResultClass, StoredRecord, export_csv, export_json, read_all};

use crate::terminal_safe;

/// Rows shown when no `-n` is given.
const DEFAULT_ROWS: usize = 50;
/// Widest target shown in the table.
const TARGET_WIDTH: usize = 72;

/// Export formats.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// JSON document with every field, seq and hash.
    Json,
    /// One row per receipt or alert.
    Csv,
}

/// Filters shared by `ms log` and `ms stats`.
#[derive(Debug, Args)]
pub struct Filters {
    /// Only records at or after this time: 30m, 2h, 7d, 2026-11-13 or 2026-11-13T09:30:00Z.
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Only records before this time (same forms as --since).
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
    /// Only this agent: claude-code, codex, cursor, gemini-cli, or a process name.
    #[arg(long)]
    pub agent: Option<String>,
    /// Only this key, e.g. stripe/test.
    #[arg(long)]
    pub key: Option<String>,
    /// Only this result.
    #[arg(long, value_parser = ["allowed", "approved", "blocked", "denied", "failed", "alert"])]
    pub result: Option<String>,
    /// Only the session whose agent process has this PID.
    #[arg(long)]
    pub pid: Option<u32>,
}

impl Filters {
    /// Builds a query, or an error message for the user (starting `morsec: `).
    pub fn query(&self, limit: Option<usize>) -> Result<Query, String> {
        let now = now_ms();
        let time = |s: &str| parse_time(s, now).map_err(|e| format!("morsec: {e}"));
        Ok(Query {
            since: self.since.as_deref().map(time).transpose()?,
            until: self.until.as_deref().map(time).transpose()?,
            agent: self.agent.as_deref().map(parse_agent),
            key: self
                .key
                .as_deref()
                .map(KeyName::new)
                .transpose()
                .map_err(|e| e.to_string())?,
            result: self.result.as_deref().and_then(ResultClass::parse),
            pid: self.pid,
            limit,
        })
    }
}

/// `ms log` arguments.
#[derive(Debug, Args)]
pub struct LogArgs {
    #[command(flatten)]
    filters: Filters,
    /// Show at most this many of the most recent records (default 50; exports default to all).
    #[arg(short = 'n', long)]
    limit: Option<usize>,
    /// Check the hash chain of every receipts file.
    #[arg(long, conflicts_with_all = ["export", "limit"])]
    verify: bool,
    /// Export for a security review instead of printing a table.
    #[arg(long, value_enum, value_name = "FORMAT")]
    export: Option<Format>,
    /// Write the export to this new file (created 0600; never overwritten). Default: stdout.
    #[arg(long, requires = "export", value_name = "FILE")]
    out: Option<PathBuf>,
}

fn err(msg: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", terminal_safe(msg.as_ref()));
    ExitCode::FAILURE
}

/// The receipts directory, or a message.
pub fn dir() -> Result<PathBuf, String> {
    ms_receipts::default_dir().map_err(|e| e.to_string())
}

/// Runs `ms log`.
pub fn run(args: &LogArgs) -> ExitCode {
    let dir = match dir() {
        Ok(d) => d,
        Err(e) => return err(e),
    };
    if args.verify {
        return verify(&dir);
    }
    let limit = match (args.limit, args.export) {
        (Some(n), _) => Some(n),
        (None, Some(_)) => None,
        (None, None) => Some(DEFAULT_ROWS),
    };
    let query = match args.filters.query(limit) {
        Ok(q) => q,
        Err(e) => return err(e),
    };
    let records = match read_all(&dir) {
        Ok(r) => r,
        Err(e) => return err(e.to_string()),
    };
    let rows = query.run(&records);
    match args.export {
        Some(f) => export(&rows, f, args.out.as_deref()),
        None => {
            print_table(&rows, &dir, records.is_empty());
            ExitCode::SUCCESS
        }
    }
}

fn verify(dir: &Path) -> ExitCode {
    match ms_receipts::verify(dir, None) {
        Ok(r) if r.ok() => {
            println!("{}", terminal_safe(&r.to_string()));
            eprintln!(
                "note: record MACs need the receipts key, which only the daemon can read. \
                 This checked the hash chain: it catches removed, reordered, duplicated and \
                 edited records, but not a rewrite that also recomputes the chain."
            );
            ExitCode::SUCCESS
        }
        Ok(r) => {
            println!("{}", terminal_safe(&r.to_string()));
            ExitCode::FAILURE
        }
        Err(e) => err(e.to_string()),
    }
}

fn export(rows: &[StoredRecord], f: Format, out: Option<&Path>) -> ExitCode {
    let text = match f {
        Format::Json => {
            let mut s = export_json(rows);
            s.push('\n');
            s
        }
        Format::Csv => export_csv(rows),
    };
    match out {
        None => {
            let mut stdout = std::io::stdout().lock();
            match stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => err(format!("morsec: writing export: {e}")),
            }
        }
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path);
            let written =
                file.and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()));
            match written {
                Ok(()) => {
                    eprintln!(
                        "exported {} records to {}",
                        rows.len(),
                        terminal_safe(&path.display().to_string())
                    );
                    ExitCode::SUCCESS
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => err(format!(
                    "morsec: {} already exists. Choose a new file name; exports never overwrite",
                    path.display()
                )),
                Err(e) => err(format!("morsec: writing {}: {e}", path.display())),
            }
        }
    }
}

/// Cuts to `width` chars with an ellipsis.
fn fit(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(width.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn result_text(r: &ReceiptResult) -> String {
    match r {
        ReceiptResult::Allowed => "allowed".into(),
        ReceiptResult::Approved => "approved".into(),
        ReceiptResult::Denied => "denied".into(),
        ReceiptResult::Blocked(reason) => format!(
            "blocked:{}",
            serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        ),
        ReceiptResult::Failed(_) => "failed".into(),
    }
}

fn print_table(rows: &[StoredRecord], dir: &Path, empty_store: bool) {
    if rows.is_empty() {
        if empty_store {
            println!(
                "No receipts yet in {}.",
                terminal_safe(&dir.display().to_string())
            );
        } else {
            println!("No receipts match.");
        }
        return;
    }
    println!(
        "{:>6}  {:<20}  {:<12}  {:>7}  {:<16}  {:<5}  {:<26}  TARGET",
        "SEQ", "TIME (UTC)", "AGENT", "PID", "KEY", "MODE", "RESULT"
    );
    for r in rows {
        let time = format_utc(r.rec.time_unix_ms);
        // Every agent-supplied string goes through terminal_safe (INJ-3).
        let line = match &r.rec.entry {
            Entry::Receipt(x) => format!(
                "{:>6}  {:<20}  {:<12}  {:>7}  {:<16}  {:<5}  {:<26}  {}",
                r.seq,
                time,
                fit(&terminal_safe(&agent_label(&x.session.agent)), 12),
                x.session.pid,
                fit(x.key.as_str(), 16),
                match x.mechanism {
                    ms_core::Mode::Swap => "swap",
                    ms_core::Mode::Run => "run",
                    ms_core::Mode::Mint => "mint",
                },
                fit(&result_text(&x.result), 26),
                fit(&terminal_safe(&x.target), TARGET_WIDTH)
            ),
            Entry::Alert(a) => format!(
                "{:>6}  {:<20}  {:<12}  {:>7}  {:<16}  {:<5}  {:<26}  {} blocked in {}s (records {}-{}){}",
                r.seq,
                time,
                fit(&terminal_safe(&agent_label(&a.session.agent)), 12),
                a.session.pid,
                "-",
                "-",
                "ALERT",
                a.blocked_count,
                a.window_ms / 1000,
                a.first_seq,
                a.last_seq,
                match a.action {
                    ms_receipts::AlertAction::StopSession => "; session stopped",
                    ms_receipts::AlertAction::None => "",
                }
            ),
            Entry::Checkpoint(_) => continue,
        };
        println!("{line}");
    }
}
