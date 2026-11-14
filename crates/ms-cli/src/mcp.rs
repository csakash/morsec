//! `ms mcp`: the stdio MCP server an agent connects to (L14). See `ms-mcp` and SPEC.md.
//!
//! It fetches the rules once, serves the catalog built from that version for its whole life
//! (SPEC D2), and forwards every tool call to msd as `McpCall`. msd identifies the caller from
//! this process (a child of the agent), validates, decides, runs and records.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use ms_ipc::{Client, RequestBody, ResponseBody};
use ms_mcp::Catalog;
use ms_mcp::server::{Backend, BoxFuture};
use ms_rules::Rules;
use serde_json::Value;

/// How long one tool call may take: a production key waits for a person, then the command runs.
pub(crate) const CALL_WAIT: Duration = Duration::from_secs(15 * 60);

/// `ms mcp`.
#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    /// Print the tool catalog this server would serve (rules version, tools, SHA-256) as JSON
    /// and exit. `ms doctor` compares that hash with a running server's.
    #[arg(long)]
    pub(crate) catalog: bool,
}

/// Runs `ms mcp`.
pub(crate) async fn run(a: &McpArgs, version: &str) -> ExitCode {
    let socket = match ms_ipc::default_socket_path() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", crate::terminal_safe(&e.to_string()));
            return ExitCode::from(69);
        }
    };
    let loaded = load(&socket).await;
    if a.catalog {
        return match loaded {
            Ok(c) => match serde_json::to_string_pretty(&c.to_json()) {
                Ok(s) => {
                    println!("{s}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("morsec: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("{}", crate::terminal_safe(&e));
                ExitCode::from(69)
            }
        };
    }
    // Still serve (no tools) when msd is down, so the agent shows "no tools" instead of a
    // crashed server; restarting the server after `ms start` loads them (SPEC D9).
    let catalog = loaded.unwrap_or_else(|e| {
        eprintln!(
            "{} (serving no tools; restart the MCP server once morsec is running)",
            crate::terminal_safe(&e)
        );
        Catalog::empty()
    });
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let backend = Arc::new(Msd { socket, cwd });
    let input = tokio::io::BufReader::new(tokio::io::stdin());
    match ms_mcp::server::serve(
        input,
        tokio::io::stdout(),
        Arc::new(catalog),
        backend,
        version,
    )
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("morsec: the MCP connection failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The catalog for the rules msd has in force now.
async fn load(socket: &std::path::Path) -> Result<Catalog, String> {
    let mut client = Client::connect(socket).await.map_err(|e| e.to_string())?;
    match client
        .request(RequestBody::RulesGet { key: None })
        .await
        .map_err(|e| e.to_string())?
    {
        ResponseBody::Rules { version, toml, .. } => {
            let rules = Rules::from_toml(&toml, "rules from msd").map_err(|e| e.to_string())?;
            if rules.version != version {
                return Err("morsec: msd sent inconsistent rules".into());
            }
            Ok(Catalog::from_rules(&rules))
        }
        ResponseBody::Error { message, .. } => Err(message),
        other => Err(format!("morsec: unexpected answer from msd: {other:?}")),
    }
}

/// msd as the backend: one connection per call.
#[derive(Debug)]
struct Msd {
    socket: PathBuf,
    cwd: PathBuf,
}

impl Backend for Msd {
    fn call(
        &self,
        tool: String,
        rules_version: u64,
        arguments: Value,
    ) -> BoxFuture<'_, Result<ResponseBody, String>> {
        Box::pin(async move {
            let mut client = Client::connect(&self.socket)
                .await
                .map_err(|e| e.to_string())?;
            client
                .request_within(
                    RequestBody::McpCall {
                        tool,
                        rules_version,
                        cwd: self.cwd.clone(),
                        arguments,
                    },
                    CALL_WAIT,
                )
                .await
                .map_err(|e| e.to_string())
        })
    }
}
