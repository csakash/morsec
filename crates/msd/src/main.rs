//! `msd`, the morsec broker daemon.
//!
//! L00: a dev stub. It binds the IPC socket, answers `Status`, and answers every other request
//! with `not_implemented` naming the loop that builds it. L07 turns this into the real daemon.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use ms_core::SecretBytes;
use ms_ipc::{ErrorCode, Handler, PeerInfo, RequestBody, ResponseBody, SameUid, Server};

#[derive(Debug, Parser)]
#[command(name = "msd", version, about = "morsec broker daemon (dev stub)")]
struct Args {
    /// Run in the foreground, logging to stderr. Required until L07 adds the LaunchAgent.
    #[arg(long)]
    foreground: bool,
    /// Proxy port. Recorded only until L05 adds the proxy. Also picks a per-port dev socket.
    #[arg(long)]
    port: Option<u16>,
    /// Socket path. Without it: a per-port dev socket when --port is given, else $MORSEC_SOCKET,
    /// else the platform path.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Debug)]
struct StubHandler;

impl Handler for StubHandler {
    async fn handle(
        &self,
        _peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        // Nothing is stored in L00; wipe any value now.
        drop(value);
        match request {
            RequestBody::Status => ResponseBody::Status {
                daemon: "msd".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                mode: "dev-stub".into(),
            },
            other => ResponseBody::error(
                ErrorCode::NotImplemented,
                format!(
                    "morsec: this request is not built yet (planned in loop {})",
                    other.owner_loop()
                ),
            ),
        }
    }
}

fn socket_path(args: &Args) -> ms_core::Result<PathBuf> {
    if let Some(p) = &args.socket {
        return Ok(p.clone());
    }
    // --port before $MORSEC_SOCKET: parallel loops each pass their own port, and must not all
    // land on one exported socket.
    if let Some(port) = args.port {
        return Ok(dev_socket(port));
    }
    ms_ipc::default_socket_path()
}

/// The per-port dev socket: `$TMPDIR/morsec-dev-<port>/msd.sock`.
fn dev_socket(port: u16) -> PathBuf {
    std::env::temp_dir()
        .join(format!("morsec-dev-{port}"))
        .join("msd.sock")
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen for SIGTERM");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MORSEC_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    if !args.foreground {
        tracing::error!(
            "morsec: msd only runs with --foreground until loop L07 adds the LaunchAgent"
        );
        return std::process::ExitCode::from(64);
    }
    let path = match socket_path(&args) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("{e}");
            return std::process::ExitCode::from(1);
        }
    };
    let server = match Server::bind(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            return std::process::ExitCode::from(1);
        }
    };
    let check = SameUid {
        uid: server.owner_uid(),
    };
    tracing::info!(socket = %path.display(), port = ?args.port, "msd listening (dev stub)");
    server
        .serve(Arc::new(StubHandler), Arc::new(check), shutdown_signal())
        .await;
    std::process::ExitCode::SUCCESS
}
