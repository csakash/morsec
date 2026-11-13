//! `ms stats`: approval prompts per session, blocks per day, approvals (L02).

use std::process::ExitCode;

use clap::Args;
use ms_receipts::read_all;
use ms_receipts::time::format_utc;

use crate::log::{Filters, dir};
use crate::terminal_safe;

/// `ms stats` arguments.
#[derive(Debug, Args)]
pub struct StatsArgs {
    #[command(flatten)]
    filters: Filters,
    /// Print JSON instead of text.
    #[arg(long)]
    json: bool,
}

/// Runs `ms stats`.
pub fn run(args: &StatsArgs) -> ExitCode {
    let fail = |m: String| {
        eprintln!("{}", terminal_safe(&m));
        ExitCode::FAILURE
    };
    let dir = match dir() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let query = match args.filters.query(None) {
        Ok(q) => q,
        Err(e) => return fail(e),
    };
    let records = match read_all(&dir) {
        Ok(r) => r,
        Err(e) => return fail(e.to_string()),
    };
    let s = ms_receipts::stats(&query.run(&records));
    if args.json {
        // Agent names are agent-supplied: control and bidi characters become \uXXXX escapes.
        match serde_json::to_string_pretty(&s) {
            Ok(j) => println!("{}", ms_receipts::export::json_inert(&j)),
            Err(e) => return fail(format!("morsec: encoding stats: {e}")),
        }
        return ExitCode::SUCCESS;
    }
    println!(
        "{} receipts: {} allowed, {} approved, {} denied, {} blocked, {} failed; {} alerts",
        s.receipts, s.allowed, s.approved, s.denied, s.blocked, s.failed, s.alerts
    );
    println!("approval prompts: {}", s.prompts);
    if !s.sessions.is_empty() {
        println!("\nper session:");
        println!(
            "  {:<14} {:>7}  {:<20}  {:>7} {:>8} {:>6} {:>7} {:>7} {:>6}",
            "AGENT",
            "PID",
            "STARTED (UTC)",
            "PROMPTS",
            "APPROVED",
            "DENIED",
            "BLOCKED",
            "ALLOWED",
            "ALERTS"
        );
        for x in &s.sessions {
            let agent: String = terminal_safe(&x.agent).chars().take(14).collect();
            println!(
                "  {:<14} {:>7}  {:<20}  {:>7} {:>8} {:>6} {:>7} {:>7} {:>6}",
                agent,
                x.pid,
                format_utc(x.started_unix_ms),
                x.prompts,
                x.approved,
                x.denied,
                x.blocked,
                x.allowed,
                x.alerts
            );
        }
    }
    if !s.blocks_per_day.is_empty() {
        println!("\nblocks per day (UTC):");
        for (day, n) in &s.blocks_per_day {
            println!("  {day}  {n}");
        }
    }
    ExitCode::SUCCESS
}
