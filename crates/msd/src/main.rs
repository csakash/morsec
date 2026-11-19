//! `msd`, the morsec broker daemon (L07).
//!
//! One process owns the vault, the rules, the receipts, the swap proxy and the socket. It
//! identifies every caller from the kernel (L06), fails closed, and has a kill switch (`ms stop`)
//! that survives a restart and can't be starved by a same-user process holding connections.
//!
//! - `msd --foreground [--vault keychain|memory] [--port N | --socket P] [--state-dir D]` serves.
//! - `msd --init [--force]` creates the internal keys, the empty rules file and the receipts
//!   store. `ms init` runs it, so the keychain items are created by msd's own signature.

// The daemon reports startup failures on stderr before logging is set up.
#![allow(clippy::print_stderr)]

mod approve;
mod backend;
mod daemon;
mod dash;
mod doctor;
mod drift;
mod open;
mod pasteboard;
mod paths;
mod proxy;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use ms_core::{AgentKind, KeyName, Mode, ReceiptEvent, ReceiptResult, SecretBytes, SessionId};
use ms_ipc::Server;
use ms_receipts::{ReceiptSink, ReceiptStore, StoreConfig};
use ms_rules::{Rules, RulesStore};
use ms_session::SessionPeerCheck;
use ms_vault::VaultExt;
use ms_vault::memory::MemoryVault;
use tokio::sync::watch;

use crate::backend::{Backend, DAEMON_STATE_KEY, RULES_HMAC_KEY};
use crate::daemon::{DAEMON_KEY, Daemon, IpcHandler, OpenError};
use crate::paths::{DEV_MARKER, Paths, dev_dir, platform_state_dir, prepare_private_dir};

/// Default swap proxy port.
pub const DEFAULT_PROXY_PORT: u16 = 7277;

/// Exit code: usage error (sysexits EX_USAGE).
const EXIT_USAGE: u8 = 64;
/// Exit code: not set up / bad configuration (EX_CONFIG).
const EXIT_CONFIG: u8 = 78;
/// `--init` exit code when morsec is already set up (not an error for `ms init`).
const EXIT_ALREADY: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VaultKind {
    /// The macOS login keychain (default on macOS).
    Keychain,
    /// In memory, for dev loops and tests: everything is lost on exit.
    Memory,
}

#[derive(Debug, Parser)]
#[command(name = "msd", version, about = "morsec broker daemon")]
struct Args {
    /// Run in the foreground, logging to stderr (launchd runs it this way too).
    #[arg(long)]
    foreground: bool,
    /// Dev port: selects the per-port dev socket and state directory, and puts the proxy on
    /// port+1.
    #[arg(long)]
    port: Option<u16>,
    /// Socket path. Without it: the dev socket when --port is given, else $MORSEC_SOCKET, else
    /// the platform path.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// State directory (rules, receipts, CA certificate).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Swap proxy port on 127.0.0.1.
    #[arg(long)]
    proxy_port: Option<u16>,
    /// First port the dashboard tries on 127.0.0.1 (it tries ten). Default 7311; with --port P,
    /// P+2 (L32).
    #[arg(long)]
    dash_port: Option<u16>,
    /// Vault backend.
    #[arg(long, value_enum)]
    vault: Option<VaultKind>,
    /// Set morsec up (internal keys, empty rules, receipts store) and exit.
    #[arg(long)]
    init: bool,
    /// With --init: start over even if morsec is already set up. Old receipts and stored keys
    /// stop verifying.
    #[arg(long, requires = "init")]
    force: bool,
    /// Tests only (debug builds, with --vault memory): stand in for Touch ID.
    #[arg(long, value_enum, hide = true)]
    test_touch_id: Option<approve::TestTouchId>,
    /// Tests only (debug builds, with --vault memory): the proxy reaches HOST at this loopback
    /// address (HOST=127.0.0.1:PORT, repeatable). Needs --test-upstream-ca.
    #[arg(long, value_name = "HOST=ADDR", hide = true)]
    test_upstream: Vec<String>,
    /// Tests only (debug builds, with --vault memory): append the dashboard's sign-in URL to
    /// FILE instead of opening a browser.
    #[arg(long, value_name = "FILE", hide = true)]
    test_open_to: Option<PathBuf>,
    /// Tests only (debug builds, with --vault memory): the dashboard's Copy writes a line per
    /// copy and clear to FILE (length, short hash, markers; never the value) instead of the
    /// pasteboard.
    #[arg(long, value_name = "FILE", hide = true)]
    test_pasteboard_to: Option<PathBuf>,
    /// Tests only: the CA (PEM) that verifies the test upstreams.
    #[arg(long, value_name = "FILE", hide = true)]
    test_upstream_ca: Option<PathBuf>,
}

/// The pasteboard the dashboard's Copy writes: the system one, or with `--test-pasteboard-to`
/// (a debug build with the memory vault only) a file that records each copy without the value.
fn clipboard_for(
    test_to: Option<PathBuf>,
    memory_vault: bool,
) -> Result<Option<std::sync::Arc<dyn pasteboard::Clipboard>>, String> {
    match test_to {
        None => Ok(None),
        Some(_) if !cfg!(debug_assertions) => {
            Err("morsec: --test-pasteboard-to exists only in debug builds".into())
        }
        Some(_) if !memory_vault => Err(
            "morsec: --test-pasteboard-to only works with --vault memory (an ephemeral dev vault)"
                .into(),
        ),
        Some(file) => {
            tracing::warn!("TEST BUILD: the dashboard's Copy goes to --test-pasteboard-to");
            Ok(Some(std::sync::Arc::new(pasteboard::Marked(
                pasteboard::FilePasteboard::new(file),
            ))))
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
        return Ok(dev_dir(port).join("msd.sock"));
    }
    ms_ipc::default_socket_path()
}

fn state_dir(args: &Args) -> ms_core::Result<PathBuf> {
    if let Some(d) = &args.state_dir {
        return Ok(d.clone());
    }
    if let Some(port) = args.port {
        return Ok(dev_dir(port));
    }
    platform_state_dir()
}

fn vault_kind(args: &Args) -> VaultKind {
    args.vault.unwrap_or(if cfg!(target_os = "macos") {
        VaultKind::Keychain
    } else {
        VaultKind::Memory
    })
}

fn backend(kind: VaultKind) -> Result<Backend, String> {
    match kind {
        #[cfg(target_os = "macos")]
        VaultKind::Keychain => Ok(Backend::Keychain(Arc::new(
            ms_vault::macos::KeychainVault::new(),
        ))),
        #[cfg(not(target_os = "macos"))]
        VaultKind::Keychain => {
            Err("morsec: the keychain vault is macOS only; the Linux vault arrives in loop L21. For dev use --vault memory".into())
        }
        VaultKind::Memory => Ok(Backend::Memory(Arc::new(MemoryVault::new()))),
    }
}

/// An ephemeral (memory-vault) daemon starts from a clean state directory: rules MAC'd with the
/// last run's random key would fail to load. msd only wipes a directory it marked as a dev
/// directory, or one with no morsec files in it.
fn prepare_memory_state(paths: &Paths) -> Result<(), String> {
    if let Ok(platform) = platform_state_dir()
        && paths.state == platform
    {
        return Err(format!(
            "morsec: --vault memory can't use the real state directory {}; pass --state-dir or --port",
            platform.display()
        ));
    }
    let marker = paths.state.join(DEV_MARKER);
    let projects = paths.state.join(daemon::PROJECTS_FILE);
    let ours = [
        paths.rules.clone(),
        ms_rules::store::mac_path(&paths.rules),
        paths.ca_pem.clone(),
        ms_rules::store::mac_path(&projects),
        projects,
    ];
    if !marker.exists() {
        if ours.iter().any(|p| p.exists()) || paths.receipts.exists() {
            return Err(format!(
                "morsec: {} holds morsec files that are not from a dev daemon; refusing to wipe them for --vault memory",
                paths.state.display()
            ));
        }
        std::fs::write(&marker, b"msd --vault memory state; wiped at every start\n")
            .map_err(|e| format!("morsec: writing {}: {e}", marker.display()))?;
    }
    for p in &ours {
        match std::fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("morsec: removing {}: {e}", p.display())),
        }
    }
    match std::fs::remove_dir_all(&paths.receipts) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "morsec: removing {}: {e}",
            paths.receipts.display()
        )),
    }
}

fn now_ms() -> u64 {
    ms_session::peer::now_unix_ms()
}

/// Refuses when this process runs inside an agent's process tree (security review S2): setting
/// morsec up resets its keys, which only the person may do.
fn refuse_inside_agent() -> Result<(), String> {
    let r = ms_session::Resolver::new(ms_session::OsProcessTable);
    match r.resolve(std::process::id()) {
        Ok(ms_session::Caller::Unattributed { .. }) => Ok(()),
        Ok(ms_session::Caller::Agent(_)) => Err(
            "morsec: msd --init can't run inside an agent session. Run ms init from your own terminal".into(),
        ),
        Err(e) => Err(format!(
            "morsec: can't check who is running msd --init ({e}); refusing"
        )),
    }
}

/// Asks the person on `/dev/tty` (never stdin, so a pipe can't answer).
fn confirm_on_tty(question: &str) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Read, Write};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("morsec: msd --init must be confirmed at your own terminal ({e})"))?;
    write!(tty, "{question} Type yes to confirm: ")
        .and_then(|()| tty.flush())
        .map_err(|e| format!("morsec: writing to the terminal: {e}"))?;
    let mut line = String::new();
    BufReader::new((&tty).take(64))
        .read_line(&mut line)
        .map_err(|e| format!("morsec: reading the terminal: {e}"))?;
    if line.trim() == "yes" {
        Ok(())
    } else {
        Err("Cancelled. Nothing was changed.".into())
    }
}

/// `msd --init`.
fn init(args: &Args) -> ExitCode {
    let kind = vault_kind(args);
    if kind == VaultKind::Memory {
        eprintln!(
            "morsec: a memory vault sets itself up at every start; --init is for the keychain"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    if args.state_dir.is_some() || args.port.is_some() {
        // The keychain items are global: initialising them for another directory would reset
        // the real vault's keys behind the real state (security review S2).
        eprintln!(
            "morsec: msd --init with the keychain always uses the real state directory; drop --state-dir and --port"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    if let Err(e) = refuse_inside_agent() {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let result = (|| -> Result<bool, String> {
        let paths = Paths::under(state_dir(args).map_err(|e| e.to_string())?);
        prepare_private_dir(&paths.state).map_err(|e| e.to_string())?;
        let b = backend(kind)?;
        let mac = ms_rules::store::mac_path(&paths.rules);
        let receipts_key = KeyName::new(backend::RECEIPTS_HMAC_KEY).map_err(|e| e.to_string())?;
        let keys_exist = b.vault().with_secret(&receipts_key, &mut |_| {}).is_ok();
        let existing =
            paths.rules.exists() || mac.exists() || paths.receipts.exists() || keys_exist;
        if existing && !args.force {
            return Ok(false);
        }
        confirm_on_tty(if existing {
            "Start morsec over? New internal keys, empty rules, a new receipts file; stored keys and old receipts stop verifying."
        } else {
            "Set morsec up (internal keys in your login keychain, empty rules, receipts)?"
        })?;
        // A reset never clears `ms stop`: resuming is its own, separate step.
        let state_key = KeyName::new(DAEMON_STATE_KEY).map_err(|e| e.to_string())?;
        let was_stopped = match b.vault().read_with(&state_key, <[u8]>::to_vec) {
            Ok(v) => daemon::parse_state(&v).is_none_or(|(stopped, _)| stopped),
            Err(_) => existing,
        };
        if existing {
            // Keep the old files for inspection; they no longer verify after the reset.
            let tag = format!("old-{}", now_ms());
            for p in [&paths.rules, &mac, &paths.receipts] {
                if p.exists() {
                    let mut to = p.as_os_str().to_owned();
                    to.push(format!(".{tag}"));
                    std::fs::rename(p, PathBuf::from(&to))
                        .map_err(|e| format!("morsec: moving {} aside: {e}", p.display()))?;
                }
            }
            let _ = std::fs::remove_file(&paths.ca_pem);
        }
        b.reset().map_err(|e| e.to_string())?;
        // The reset replaced the projects MAC key: set any old records aside and reset their
        // floor (review R2), even when nothing else was there.
        daemon::reset_project_records(&paths.state, &b, &format!("old-{}", now_ms()))?;
        b.put_internal(
            &state_key,
            SecretBytes::new(daemon::encode_state(was_stopped, 1)),
        )
        .map_err(|e| e.to_string())?;
        let vault = b.vault();
        let mac_key = KeyName::new(RULES_HMAC_KEY).map_err(|e| e.to_string())?;
        let rules = RulesStore::new(&paths.rules, &*vault, mac_key)
            .create(&Rules::default())
            .map_err(|e| e.to_string())?;
        let receipts = ReceiptStore::open(&paths.receipts, vault, StoreConfig::default())
            .map_err(|e| e.to_string())?;
        receipts
            .append(ReceiptEvent {
                time_unix_ms: now_ms(),
                session: SessionId {
                    agent: AgentKind::Other("terminal".into()),
                    pid: std::process::id(),
                    started_unix_ms: 0,
                },
                key: KeyName::new(DAEMON_KEY).map_err(|e| e.to_string())?,
                mode: Mode::Run,
                target: "ms init".into(),
                argv_hash: None,
                rule_version: rules.version,
                approval_id: None,
                result: ReceiptResult::Allowed,
            })
            .map_err(|e| e.to_string())?;
        Ok(true)
    })();
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_ALREADY),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
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

async fn serve(args: Args) -> ExitCode {
    // L05 must-do: upstream TLS uses the system roots; an agent-writable bundle must not replace
    // them.
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if std::env::var_os(var).is_some() {
            tracing::error!(
                "morsec: msd refuses to start with {var} set: the proxy verifies upstream servers with the system trust store only. Unset it"
            );
            return ExitCode::from(EXIT_CONFIG);
        }
    }
    let kind = vault_kind(&args);
    let b = match backend(kind) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let (socket, state) = match (socket_path(&args), state_dir(&args)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let paths = Paths::under(state);
    if let Err(e) = prepare_private_dir(&paths.state) {
        tracing::error!("{e}");
        return ExitCode::FAILURE;
    }
    // Bind first: if another msd is running on this socket, its dev state must not be wiped.
    let server = match Server::bind(&socket) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if b.is_memory()
        && let Err(e) = prepare_memory_state(&paths)
    {
        tracing::error!("{e}");
        return ExitCode::FAILURE;
    }
    let proxy_port = args
        .proxy_port
        .or_else(|| args.port.and_then(|p| p.checked_add(1)))
        .unwrap_or(DEFAULT_PROXY_PORT);
    let opener = match open::opener(args.test_open_to.clone(), b.is_memory()) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let clipboard = match clipboard_for(args.test_pasteboard_to.clone(), b.is_memory()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let approvals = match approve::approver(args.test_touch_id, b.is_memory()) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let test_hook = match proxy::TestHook::new(
        &args.test_upstream,
        args.test_upstream_ca.as_deref(),
        b.is_memory(),
    ) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let uid = server.owner_uid();
    let opened = {
        let paths = paths.clone();
        tokio::task::spawn_blocking(move || {
            Daemon::open(
                b,
                paths,
                proxy_port,
                approvals,
                daemon::identify_by_session(uid),
            )
        })
        .await
    };
    let d = match opened {
        Ok(Ok(d)) => d,
        Ok(Err(OpenError::NotInitialized(m))) => {
            tracing::error!("{m}");
            return ExitCode::from(EXIT_CONFIG);
        }
        Ok(Err(e)) => {
            tracing::error!("morsec: msd could not start: {e}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            tracing::error!("morsec: msd could not start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dash_port = args
        .dash_port
        .or_else(|| args.port.and_then(|p| p.checked_add(2)))
        .unwrap_or(ms_dash::DEFAULT_PORT);
    if let Some(c) = clipboard {
        d.set_clipboard(c);
    }
    d.set_socket_path(socket.clone(), uid);
    // Not listening until the first DashOpen (design §6.1).
    dash::install(&d, ms_dash::DashConfig::new(dash_port), uid, opener);
    let (stop_tx, stop_rx) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy::supervise(d.clone(), stop_rx.clone(), test_hook));
    tokio::spawn(reap_dev_sessions(d.clone(), stop_rx.clone()));
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        tokio::spawn(drift::watch_loop(d.clone(), PathBuf::from(home), stop_rx));
    }
    tracing::info!(
        socket = %socket.display(),
        state = %paths.state.display(),
        proxy_port,
        vault = d.backend().label(),
        stopped = d.is_stopped(),
        "msd listening"
    );
    server
        .serve(
            Arc::new(IpcHandler(d.clone())),
            Arc::new(SessionPeerCheck::new(uid)),
            shutdown_signal(),
        )
        .await;
    // A copy still within its 30 s leaves the pasteboard with msd (review N4).
    pasteboard::clear_pending_now();
    if let Some(dash) = d.dash() {
        dash.shutdown();
    }
    let _ = stop_tx.send(true);
    let _ = proxy_task.await;
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MORSEC_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    if args.init {
        return init(&args);
    }
    if !args.foreground {
        tracing::error!(
            "morsec: run msd with --foreground (launchd does); to set morsec up, run: ms init"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("morsec: msd could not start its runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(serve(args))
}

/// Drops `ms dev` sessions whose `ms dev` process is gone (L34 SPEC D-6), every 2 s, so a
/// session ends with its child even when `ms dev` was killed before it could say so.
async fn reap_dev_sessions(d: std::sync::Arc<daemon::Daemon>, mut stop: watch::Receiver<bool>) {
    use ms_session::ProcessTable;
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
        }
        let dd = d.clone();
        let _ = tokio::task::spawn_blocking(move || {
            dd.reap_dev(|pid, started| {
                ms_session::OsProcessTable
                    .info(pid)
                    .is_ok_and(|i| i.started_unix_ms == started)
            })
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D-20: the file pasteboard (a test stand-in) is refused with the keychain
    // vault, so a real msd always writes the system pasteboard; fails_when=--test-pasteboard-to
    // is accepted with the keychain vault; no_claim=the release-build branch (tests run debug)
    #[test]
    fn test_pasteboard_to_needs_the_memory_vault() {
        let f = PathBuf::from("/tmp/x");
        assert!(clipboard_for(Some(f.clone()), false).is_err());
        assert!(clipboard_for(Some(f), true).unwrap().is_some());
        assert!(clipboard_for(None, false).unwrap().is_none());
    }
}
