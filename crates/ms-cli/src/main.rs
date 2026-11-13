//! `ms`, also installed as `mors`: the morsec command line.
//!
//! L00 ships the skeleton: `--version`, a working `status`, and every other PRD command as a stub
//! that names the loop that builds it and exits 69 (EX_UNAVAILABLE).

// A CLI prints to its terminal.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use ms_core::Error;
use ms_ipc::{Client, RequestBody, ResponseBody};

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

/// Arguments of a command that is not built yet; accepted and ignored.
#[derive(Debug, Args)]
struct Rest {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    args: Vec<OsString>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the vault and start the daemon.
    Init(Rest),
    /// Add a secret (hidden input, or from 1Password/Bitwarden).
    Add(Rest),
    /// Move a .env into the vault and rewrite it with references.
    Import(Rest),
    /// Set up a coding agent (claude-code, codex, cursor, gemini).
    Connect(Rest),
    /// Remove a coding agent's morsec settings.
    Disconnect(Rest),
    /// Run a command with references resolved by the broker.
    Run(Rest),
    /// Show or change a key's hosts, commands, tier and session length.
    Rules(Rest),
    /// Show receipts; --export for a security review.
    Log(Rest),
    /// Revoke every grant now (kill switch).
    Stop(Rest),
    /// Resume after ms stop.
    Start(Rest),
    /// Show whether morsec is on.
    Status,
    /// Check that every connected agent routes through morsec.
    Doctor(Rest),
    /// Run the MCP server for an agent.
    Mcp(Rest),
    /// Scan agent transcripts for leaked secret values.
    Scan(Rest),
    /// Prompts per session, blocks and approvals.
    Stats(Rest),
}

impl Command {
    /// (subcommand name, loop that builds it) for stubs; None when implemented.
    fn stub(&self) -> Option<(&'static str, &'static str)> {
        Some(match self {
            Command::Init(_) => ("init", "L07 daemon"),
            Command::Add(_) => ("add", "L04 import-env"),
            Command::Import(_) => ("import", "L04 import-env"),
            Command::Connect(_) => ("connect", "L08 connect-claude"),
            Command::Disconnect(_) => ("disconnect", "L08 connect-claude"),
            Command::Run(_) => ("run", "L12 run-core"),
            Command::Rules(_) => ("rules", "L03 rules-policy"),
            Command::Log(_) => ("log", "L02 receipts"),
            Command::Stop(_) => ("stop", "L07 daemon"),
            Command::Start(_) => ("start", "L07 daemon"),
            Command::Doctor(_) => ("doctor", "L17 doctor"),
            Command::Mcp(_) => ("mcp", "L14 mcp-server"),
            Command::Scan(_) => ("scan", "L09 e2e-canary"),
            Command::Stats(_) => ("stats", "L02 receipts"),
            Command::Status => return None,
        })
    }
}

/// The name this binary was invoked as: `ms` or `mors` (or whatever the symlink is called).
fn invoked_name() -> String {
    std::env::args_os()
        .next()
        .as_deref()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("ms")
        .to_owned()
}

async fn status() -> ExitCode {
    let result = async {
        let path = ms_ipc::default_socket_path()?;
        let mut client = Client::connect(&path).await?;
        client.request(RequestBody::Status).await
    }
    .await;
    match result {
        Ok(ResponseBody::Status { version, .. }) => {
            println!("morsec on · daemon {version}");
            ExitCode::SUCCESS
        }
        Ok(ResponseBody::Error { message, .. }) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
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
    if let Some((sub, loop_id)) = command.stub() {
        eprintln!(
            "{}",
            Error::NotImplemented {
                command: format!("{name} {sub}"),
                loop_id
            }
        );
        return ExitCode::from(EXIT_NOT_BUILT);
    }
    match command {
        Command::Status => status().await,
        _ => unreachable!("every other command is a stub"),
    }
}
