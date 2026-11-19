//! `ms`, also installed as `mors`: the morsec command line.
//!
//! L00 ships the skeleton: `--version`, a working `status`, and every other PRD command as a stub
//! that names the loop that builds it and exits 69 (EX_UNAVAILABLE).

// A CLI prints to its terminal.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod add;
mod approve;
mod brew;
mod connect;
mod connect_codex;
mod dashboard;
mod doctor;
mod import;
mod init_project;
mod log;
mod mcp;
mod projects;
mod run;
mod service;
mod stats;
mod tty;

use std::path::Path;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

mod rules;
mod scan;

/// Exit code for "planned but not built yet" (sysexits EX_UNAVAILABLE).
const EXIT_NOT_BUILT: u8 = 69;
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("MS_GIT_SHA"), ")");

#[derive(Debug, Parser)]
#[command(
    about = "morsec: coding agents use your secrets without ever seeing them",
    disable_version_flag = true
)]
struct Cli {
    /// Print the version.
    #[arg(short = 'V', long)]
    version: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

// Parsed once per process; the size difference between variants doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Set up morsec: this Mac, and the project you run it in (secrets moved, agents connected).
    Init(service::InitArgs),
    /// Add a secret (hidden input, or --stdin from a pipe).
    Add(add::AddArgs),
    /// Move a .env into the vault and rewrite it with references.
    Import(import::ImportArgs),
    /// Set up a coding agent (claude-code, codex, cursor, gemini).
    Connect(connect::ConnectArgs),
    /// Remove a coding agent's morsec settings.
    Disconnect(connect::DisconnectArgs),
    /// Run a command with references resolved by the broker.
    Run(run::RunArgs),
    /// Show or change a key's hosts, commands, tier and session length.
    Rules(rules::RulesArgs),
    /// Show receipts; --verify checks the chain; --export for a security review.
    Log(log::LogArgs),
    /// Revoke every grant now (kill switch).
    Stop,
    /// Resume after ms stop (needs Touch ID).
    Start,
    /// Review and answer the request waiting for your approval (Touch ID).
    Approve(approve::ApproveArgs),
    /// Show whether morsec is on; --open also opens the dashboard.
    Status(service::StatusArgs),
    /// Check that every connected agent routes through morsec.
    Doctor(doctor::DoctorArgs),
    /// Run the MCP server for an agent: your run commands as typed tools.
    Mcp(mcp::McpArgs),
    /// Scan agent transcripts for leaked secret values.
    Scan(scan::ScanArgs),
    /// Prompts per session, blocks and approvals.
    Stats(stats::StatsArgs),
    /// The projects ms init set up; with a name, that project in full.
    Projects(projects::ProjectsArgs),
    /// Open the local dashboard in your browser (read-only).
    Dashboard(dashboard::DashboardArgs),
}

/// The name this binary was invoked as: `ms` or `mors` (or whatever the symlink is called).
pub(crate) fn invoked_name() -> String {
    std::env::args_os()
        .next()
        .as_deref()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("ms")
        .to_owned()
}

/// Text from the daemon goes to a terminal: drop control characters (escape sequences,
/// carriage returns, bidi overrides) so it can't rewrite what the user sees.
pub(crate) fn terminal_safe(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// Runs a blocking command on a plain thread. These commands drive their own IPC runtime, which
/// can't start inside this one.
fn on_own_thread(f: impl FnOnce() -> ExitCode + Send + 'static) -> ExitCode {
    std::thread::spawn(f).join().unwrap_or(ExitCode::FAILURE)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let name = invoked_name();
    let matches = Cli::command()
        .name(name.clone())
        .bin_name(name.clone())
        .get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    if cli.version {
        println!("morsec {VERSION}");
        return ExitCode::SUCCESS;
    }
    let Some(command) = cli.command else {
        let _ = Cli::command()
            .name(name.clone())
            .bin_name(name)
            .print_help();
        return ExitCode::from(2);
    };
    match command {
        Command::Status(a) => service::status(&a).await,
        Command::Init(a) => on_own_thread(move || service::init(&a)),
        Command::Stop => service::stop().await,
        Command::Start => service::start().await,
        Command::Add(a) => on_own_thread(move || add::run(&a)),
        Command::Import(a) => on_own_thread(move || import::run(&a)),
        Command::Rules(a) => on_own_thread(move || rules::run(a)),
        Command::Log(args) => log::run(&args),
        Command::Stats(args) => stats::run(&args),
        Command::Connect(a) => on_own_thread(move || connect::connect(&a)),
        Command::Disconnect(a) => on_own_thread(move || connect::disconnect(&a)),
        Command::Scan(a) => scan::run(&a).await,
        Command::Run(a) => on_own_thread(move || run::run(&a)),
        Command::Mcp(a) => mcp::run(&a, VERSION).await,
        Command::Approve(a) => on_own_thread(move || approve::run(&a)),
        Command::Doctor(a) => on_own_thread(move || doctor::run(&a)),
        Command::Projects(a) => on_own_thread(move || projects::run(&a)),
        Command::Dashboard(a) => on_own_thread(move || dashboard::run(&a)),
    }
}

#[cfg(test)]
mod tests {
    use super::terminal_safe;

    // protects=escape sequences, CR/LF and bidi overrides from the daemon never reach the
    // terminal; fails_when=any survives; no_claim=other output paths (each must use terminal_safe)
    #[test]
    fn strips_terminal_controls() {
        let evil = "0.0.0\u{1b}[2J\u{1b}]0;pwned\u{7}\r\nfake line\u{202e}txt";
        let safe = terminal_safe(evil);
        assert!(!safe.chars().any(|c| c.is_control()), "{safe:?}");
        assert!(!safe.contains('\u{202e}'));
        assert!(safe.starts_with("0.0.0"));
    }

    // protects=design §6.5 CLI parity: every ms subcommand has a dashboard screen or an exemption
    // with its reason (L33-owned actions exempt as L33 until it lands); fails_when=a subcommand is
    // added with neither; no_claim=that a screen shows everything its command does (browser pass)
    #[test]
    fn dash_parity_covers_every_subcommand() {
        use clap::CommandFactory;
        let cmd = super::Cli::command();
        let mut names: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        assert!(names.len() >= 18, "{names:?}");
        names.push("help".into());
        for n in &names {
            match ms_dash::parity::lookup(n) {
                Some(ms_dash::parity::Parity::Screen(s)) => {
                    assert!(ms_dash::parity::SCREENS.contains(&s), "{n}: {s}");
                }
                Some(ms_dash::parity::Parity::Exempt(why)) => {
                    assert!(!why.trim().is_empty(), "{n}: empty reason");
                }
                None => panic!(
                    "ms {n} has no dashboard screen and no exemption: add it to ms_dash::parity::PARITY"
                ),
            }
        }
    }
}
