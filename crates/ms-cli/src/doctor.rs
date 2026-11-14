//! `ms doctor` (L17): does every connected agent really route through morsec, and is direct
//! internet blocked inside its sandbox?
//!
//! - `ms doctor`: static, read-only checks (msd, its signature, the vault, the CA, each
//!   connector's settings, `ms mcp`).
//! - `ms doctor --live`: also runs each connected agent headless with a fixed prompt that makes it
//!   run `ms doctor --probe` inside its own sandbox, then asks msd what it saw. Opt-in only: it
//!   spends tokens. Refused inside an agent session.
//! - `ms doctor --probe --nonce <hex>`: runs inside the agent. Sends a canary CONNECT through the
//!   proxy (msd's proxy records the sighting), tries direct connections (which must fail) and
//!   reports to msd.
//!
//! What decides a live verdict is what msd itself saw (INJ-4: verify from inside the runtime).
//! The agent's own text never makes a check pass; it can only make the direct-egress check fail.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use clap::Args;
use ms_connect::Connector;
use ms_core::{AgentKind, Error};
use ms_ipc::{Client, ProbeReport, ProbeSighting, RequestBody, ResponseBody};

use crate::terminal_safe;

/// `ms doctor [--live | --probe]`
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Also run each connected agent headless and check from inside its sandbox (spends tokens).
    #[arg(long, conflicts_with = "probe")]
    live: bool,
    /// Run the in-sandbox probe (used by --live; agents run this, people rarely do).
    #[arg(long)]
    probe: bool,
    /// The probe's nonce (32 lowercase hex characters, made by --live).
    #[arg(long, requires = "probe")]
    nonce: Option<String>,
    /// Test hook: probe this host:port for direct egress instead of the built-in list.
    #[arg(long = "direct-target", requires = "probe", hide = true)]
    direct_target: Vec<String>,
}

/// Where the probe tries a direct connection. Nothing is sent; only the connect is attempted.
const DIRECT_TARGETS: &[&str] = &["1.1.1.1:443", "8.8.8.8:443", "example.com:443"];
/// The canary host suffix; msd records refusals for `<nonce>` + this. Never resolves.
const CANARY_SUFFIX: &str = ".doctor.morsec.invalid";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one live agent run may take.
const AGENT_TIMEOUT: Duration = Duration::from_secs(180);
/// Most output kept from an agent.
const MAX_AGENT_OUTPUT: usize = 64 * 1024;
/// A session counts as started by this live run if it started no earlier than this before it
/// (process start times are read at millisecond resolution from a different clock source).
const START_SLACK_MS: u64 = 2_000;

pub(crate) fn run(a: &DoctorArgs) -> ExitCode {
    if a.probe {
        return probe(a.nonce.as_deref(), &a.direct_target);
    }
    if a.live
        && let Some(found) = crate::connect::inside_agent()
    {
        eprintln!(
            "{}",
            terminal_safe(&format!(
                "morsec: ms doctor --live starts agents and spends tokens, so it runs only from your own terminal, not inside an agent session (found: {found})"
            ))
        );
        return ExitCode::FAILURE;
    }
    let mut report = Report::default();
    let daemon = daemon_section(&mut report);
    let port = daemon.as_ref().and_then(|d| d.proxy_port);
    agent_section(&mut report, &claude_target(), port);
    agent_section(&mut report, &codex_target(), port);
    report.section("mcp", mcp_checks());
    if a.live {
        if daemon.is_none() {
            report.section(
                "live",
                vec![Item::fail(
                    "skipped: msd is not running, so nothing can be checked from inside the agents",
                )],
            );
        } else if daemon.as_ref().is_some_and(|d| d.stopped) {
            // While stopped the proxy serves no session, so no canary could ever arrive.
            report.section(
                "live",
                vec![Item::fail(
                    "skipped: morsec is stopped (ms stop), so agents can't reach it · resume with: ms start",
                )],
            );
        } else {
            live(&mut report);
        }
    }
    print!("{}", report.render());
    if report.direct_open {
        eprintln!("{}", loud_banner());
    }
    if report.count(Mark::Fail) > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

// ---------------------------------------------------------------------------------------------
// Report

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    mark: Mark,
    text: String,
}

impl Item {
    fn new(mark: Mark, text: impl Into<String>) -> Self {
        Self {
            mark,
            text: text.into(),
        }
    }
    fn pass(t: impl Into<String>) -> Self {
        Self::new(Mark::Pass, t)
    }
    fn warn(t: impl Into<String>) -> Self {
        Self::new(Mark::Warn, t)
    }
    fn fail(t: impl Into<String>) -> Self {
        Self::new(Mark::Fail, t)
    }
    fn info(t: impl Into<String>) -> Self {
        Self::new(Mark::Info, t)
    }
}

#[derive(Debug, Default)]
struct Report {
    sections: Vec<(String, Vec<Item>)>,
    /// Some agent's sandbox has direct internet: shout.
    direct_open: bool,
}

impl Report {
    fn section(&mut self, title: &str, items: Vec<Item>) {
        self.sections.push((title.to_owned(), items));
    }

    fn count(&self, m: Mark) -> usize {
        self.sections
            .iter()
            .flat_map(|(_, i)| i)
            .filter(|i| i.mark == m)
            .count()
    }

    /// The output: every line passed through `terminal_safe`, since much of it came from files,
    /// msd or an agent.
    fn render(&self) -> String {
        let mut out = String::from("morsec doctor\n");
        for (title, items) in &self.sections {
            out.push('\n');
            out.push_str(&terminal_safe(title));
            out.push('\n');
            for i in items {
                let m = match i.mark {
                    Mark::Pass => '✓',
                    Mark::Warn => '!',
                    Mark::Fail => '✗',
                    Mark::Info => '-',
                };
                out.push_str(&format!("  {m} {}\n", terminal_safe(&i.text)));
            }
        }
        let (p, w) = (self.count(Mark::Fail), self.count(Mark::Warn));
        out.push('\n');
        out.push_str(&match (p, w) {
            (0, 0) => "No problems.\n".to_owned(),
            (0, w) => format!("No problems, {w} {}.\n", plural(w, "warning")),
            (p, 0) => format!(
                "{p} {}. Fix {}, then run: ms doctor\n",
                plural(p, "problem"),
                if p == 1 { "it" } else { "them" }
            ),
            (p, w) => format!(
                "{p} {}, {w} {}. Fix them, then run: ms doctor\n",
                plural(p, "problem"),
                plural(w, "warning")
            ),
        });
        out
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

fn loud_banner() -> String {
    "\n!!! DIRECT INTERNET IS OPEN inside an agent's sandbox. Commands there can reach any host \
     without going through morsec. See the live section above. !!!\n"
        .to_owned()
}

// ---------------------------------------------------------------------------------------------
// IPC

fn block_on<T>(f: impl std::future::Future<Output = ms_core::Result<T>>) -> ms_core::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Protocol(format!("starting the IPC client: {e}")))?
        .block_on(f)
}

fn ask(body: RequestBody) -> ms_core::Result<ResponseBody> {
    block_on(async {
        let path = ms_ipc::default_socket_path()?;
        Client::connect(&path).await?.request(body).await
    })
}

/// The PID of the process serving the socket, from the kernel (and only if it runs as us).
fn daemon_pid() -> ms_core::Result<u32> {
    block_on(async {
        let path = ms_ipc::default_socket_path()?;
        let s = tokio::net::UnixStream::connect(&path)
            .await
            .map_err(|e| Error::Protocol(format!("{}: {e}", path.display())))?;
        let cred = s
            .peer_cred()
            .map_err(|e| Error::Protocol(format!("peer credentials: {e}")))?;
        if cred.uid() != rustix::process::getuid().as_raw() {
            return Err(Error::Protocol(
                "the socket is served by another user".into(),
            ));
        }
        cred.pid()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| Error::Protocol("the kernel gave no PID for the socket".into()))
    })
}

// ---------------------------------------------------------------------------------------------
// Static checks: morsec itself

struct DaemonInfo {
    proxy_port: Option<u16>,
    stopped: bool,
}

fn daemon_section(report: &mut Report) -> Option<DaemonInfo> {
    let mut items = Vec::new();
    let status = ask(RequestBody::Status);
    let (mode, running, proxy_port, alerts, ca_pem) = match status {
        Ok(ResponseBody::Status {
            mode,
            running,
            proxy_port,
            alerts,
            ca_pem,
            ..
        }) => (mode, running, proxy_port, alerts, ca_pem),
        Ok(ResponseBody::Error { message, .. }) => {
            items.push(Item::fail(format!(
                "msd answered with an error · {message}"
            )));
            report.section("morsec", items);
            return None;
        }
        Ok(_) => {
            items.push(Item::fail(
                "msd gave an unexpected answer · make sure ms and msd are the same version (ms --version)",
            ));
            report.section("morsec", items);
            return None;
        }
        Err(e) => {
            items.push(Item::fail(format!(
                "msd not running · {e} · start it with: ms init (or launchctl kickstart gui/$UID/{})",
                crate::service::LABEL
            )));
            report.section("morsec", items);
            return None;
        }
    };
    let port = proxy_port.map_or_else(|| "no proxy".to_owned(), |p| format!("proxy 127.0.0.1:{p}"));
    if running == Some(false) {
        items.push(Item::fail(format!(
            "morsec is stopped (ms stop) · {mode} vault · {port} · resume with: ms start"
        )));
    } else {
        items.push(Item::pass(format!("msd running · {mode} vault · {port}")));
    }
    if mode == "dev-memory" {
        items.push(Item::warn(
            "this is a dev daemon with a memory vault: keys are gone when it stops",
        ));
    }
    items.push(signature_item());
    items.push(match ask(RequestBody::ListKeys) {
        Ok(ResponseBody::Keys { keys }) => Item::pass(format!(
            "vault reachable · {} {}",
            keys.len(),
            if keys.len() == 1 { "secret" } else { "secrets" }
        )),
        Ok(ResponseBody::Error { message, .. }) => {
            Item::fail(format!("vault not reachable · {message}"))
        }
        Ok(_) => Item::fail("vault not reachable · unexpected answer from msd"),
        Err(e) => Item::fail(format!("vault not reachable · {e}")),
    });
    items.push(ca_item(ca_pem.as_deref()));
    for a in alerts {
        items.push(Item::fail(format!("msd alert: {a}")));
    }
    report.section("morsec", items);
    Some(DaemonInfo {
        proxy_port,
        stopped: running == Some(false),
    })
}

fn signature_item() -> Item {
    let path = match daemon_pid().and_then(|pid| {
        ms_session::exe_path(pid).map_err(|e| Error::Protocol(format!("msd's executable: {e}")))
    }) {
        Ok(p) => p,
        Err(e) => return Item::fail(format!("msd signature not checked · {e}")),
    };
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let details = Command::new("/usr/bin/codesign")
        .arg("-dvv")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match (verify, details) {
        (Ok(v), Ok(d)) => classify_signature(
            &path,
            v.status.success(),
            &String::from_utf8_lossy(&d.stderr),
        ),
        (Err(e), _) | (_, Err(e)) => {
            Item::fail(format!("msd signature not checked · codesign: {e}"))
        }
    }
}

/// The verdict for msd's code signature, from `codesign --verify --strict` and `codesign -dvv`.
fn classify_signature(path: &Path, verified: bool, details: &str) -> Item {
    let field = |k: &str| {
        details
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "not set")
    };
    let p = path.display();
    if !verified {
        return Item::fail(format!(
            "msd's signature does not verify ({p}) · reinstall morsec (brew reinstall morsec)"
        ));
    }
    if field("Signature=") == Some("adhoc") {
        return Item::warn(format!(
            "msd is ad-hoc signed ({p}): a dev build, not a release"
        ));
    }
    match (field("TeamIdentifier="), field("Authority=")) {
        (Some(team), _) => Item::pass(format!("msd signed · team {team}")),
        (None, Some(auth)) => Item::warn(format!(
            "msd signed by {auth}, but without a Team ID: not a morsec release"
        )),
        (None, None) => Item::fail(format!(
            "msd has no signing identity ({p}) · reinstall morsec (brew reinstall morsec)"
        )),
    }
}

/// Is the CA msd uses trusted by macOS? Checked from the PEM msd sent (never `ca.pem` on disk),
/// through a private temp file, with `security verify-cert -L` (local only, no network).
fn ca_item(pem: Option<&str>) -> Item {
    let Some(pem) = pem else {
        return Item::info("no morsec CA yet (it is made when a key is first allowed a host)");
    };
    let dir = std::env::temp_dir().join(format!(
        "morsec-doctor-{}-{}",
        std::process::id(),
        crate::import::now_unix_ms()
    ));
    let made = {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .and_then(|()| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dir.join("ca.pem"))?
                    .write_all(pem.as_bytes())
            })
    };
    let item = match made {
        Err(e) => Item::warn(format!("CA trust not checked · writing a temp copy: {e}")),
        Ok(()) => match Command::new("/usr/bin/security")
            .args(["verify-cert", "-q", "-L", "-c"])
            .arg(dir.join("ca.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(s) if s.success() => Item::pass("morsec CA trusted by macOS"),
            Ok(_) => Item::warn(
                "morsec CA not trusted by macOS (agents trust it through their connector; other tools won't) · fix: ms init --trust",
            ),
            Err(e) => Item::warn(format!("CA trust not checked · security: {e}")),
        },
    };
    let _ = std::fs::remove_dir_all(&dir);
    item
}

// ---------------------------------------------------------------------------------------------
// Static checks: connectors

/// One agent doctor knows how to check and run.
struct Target {
    /// `claude-code`, `codex`.
    id: &'static str,
    /// Session kind msd reports for it.
    kind: AgentKind,
    /// Its command on PATH.
    bin: &'static str,
    /// The connector, or why it couldn't be made.
    connector: Result<Box<dyn Connector>, String>,
    connected: bool,
    recorded_port: Result<Option<u16>, String>,
}

fn claude_target() -> Target {
    let c = crate::connect::connector(ms_connect::claude::Options::default());
    let (connected, recorded_port) = match &c {
        Ok(c) => (
            c.is_connected(),
            c.recorded_proxy_port().map_err(|e| e.to_string()),
        ),
        Err(_) => (false, Ok(None)),
    };
    Target {
        id: "claude-code",
        kind: AgentKind::ClaudeCode,
        bin: "claude",
        connector: c.map(|c| Box::new(c) as Box<dyn Connector>),
        connected,
        recorded_port,
    }
}

fn codex_target() -> Target {
    let c = crate::connect_codex::connector(ms_connect::codex::Options::default());
    let (connected, recorded_port) = match &c {
        Ok(c) => (
            c.is_connected(),
            c.recorded_proxy_port().map_err(|e| e.to_string()),
        ),
        Err(_) => (false, Ok(None)),
    };
    Target {
        id: "codex",
        kind: AgentKind::Codex,
        bin: "codex",
        connector: c.map(|c| Box::new(c) as Box<dyn Connector>),
        connected,
        recorded_port,
    }
}

fn agent_section(report: &mut Report, t: &Target, daemon_port: Option<u16>) {
    let items = match &t.connector {
        Err(e) => vec![Item::fail(format!("settings not checked · {e}"))],
        Ok(c) => agent_items(
            t.id,
            c.detect().installed,
            t.connected,
            || c.verify(),
            &t.recorded_port,
            daemon_port,
        ),
    };
    report.section(t.id, items);
}

/// The items for one agent's settings. `verify` runs only when connected.
fn agent_items(
    id: &str,
    installed: bool,
    connected: bool,
    verify: impl FnOnce() -> Vec<ms_connect::Check>,
    recorded_port: &Result<Option<u16>, String>,
    daemon_port: Option<u16>,
) -> Vec<Item> {
    if !connected {
        return vec![if installed {
            Item::warn(format!(
                "installed but not connected to morsec · run: ms connect {id}"
            ))
        } else {
            Item::info("not installed")
        }];
    }
    let mut items: Vec<Item> = verify()
        .into_iter()
        .map(|c| {
            if c.ok {
                Item::pass(c.name)
            } else {
                Item::fail(format!("{} · {}", c.name, c.detail))
            }
        })
        .collect();
    match (recorded_port, daemon_port) {
        (Ok(Some(rec)), Some(now)) if *rec != now => items.push(Item::fail(format!(
            "connected to proxy port {rec}, but msd's proxy is on {now} · run: ms connect {id}"
        ))),
        (Ok(Some(_)), Some(_)) => items.push(Item::pass("proxy port matches msd")),
        (Err(e), _) => items.push(Item::fail(format!("connector state unreadable · {e}"))),
        _ => {}
    }
    items
}

/// `ms mcp` tool hashes (MCP-2). L14 (`ms mcp`) is not built yet, so there is nothing to hash;
/// this is the hook L14 fills in: compare each tool description's hash with the one shipped.
fn mcp_checks() -> Vec<Item> {
    vec![Item::info(
        "ms mcp not installed (tool hashes are checked once it ships, L14)",
    )]
}

// ---------------------------------------------------------------------------------------------
// --live

fn random_nonce() -> Result<String, String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn valid_nonce(n: &str) -> bool {
    n.len() == 32
        && n.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The fixed prompt. It holds only the `ms` path (quoted) and the nonce; no file, page or tool
/// output ever goes into it.
fn prompt(ms_quoted: &str, nonce: &str) -> String {
    format!(
        "This is a morsec connectivity check. Run exactly this shell command once, with your normal shell tool and sandbox, and then reply with its output and nothing else:\n\n{ms_quoted} doctor --probe --nonce {nonce}\n"
    )
}

/// The argv for one agent. Nothing here loosens the user's sandbox or permission settings.
fn agent_argv(t: &Target, bin: &Path, ms_quoted: &str, nonce: &str) -> Vec<String> {
    let bin = bin.display().to_string();
    let p = prompt(ms_quoted, nonce);
    match t.kind {
        AgentKind::ClaudeCode => vec![
            bin,
            "-p".into(),
            p,
            "--allowedTools".into(),
            format!("Bash({ms_quoted} doctor --probe:*)"),
        ],
        _ => vec![bin, "exec".into(), "--skip-git-repo-check".into(), p],
    }
}

fn on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(bin))
        .find(|p| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

fn live(report: &mut Report) {
    let ms = match crate::connect::ms_path() {
        Ok(m) => m,
        Err(e) => {
            report.section("live", vec![Item::fail(e)]);
            return;
        }
    };
    let ms_quoted = ms_connect::claude::sh_quote(&ms);
    for t in [claude_target(), codex_target()] {
        let title = format!("live: {} (inside its sandbox)", t.id);
        if !t.connected {
            report.section(&title, vec![Item::info("skipped: not connected")]);
            continue;
        }
        let Some(bin) = on_path(t.bin) else {
            report.section(
                &title,
                vec![Item::info(format!("skipped: {} not found on PATH", t.bin))],
            );
            continue;
        };
        let nonce = match random_nonce() {
            Ok(n) => n,
            Err(e) => {
                report.section(&title, vec![Item::fail(e)]);
                continue;
            }
        };
        let started = crate::import::now_unix_ms();
        let argv = agent_argv(&t, &bin, &ms_quoted, &nonce);
        let (outcome, output) = run_agent(&argv);
        let held = match ask(RequestBody::DoctorProbe {
            nonce: Some(nonce.clone()),
            report: None,
        }) {
            Ok(ResponseBody::Probe { canary, report }) => Ok((canary, report)),
            Ok(ResponseBody::Error { message, .. }) => Err(message),
            Ok(_) => Err("unexpected answer from msd".into()),
            Err(e) => Err(e.to_string()),
        };
        let mut items = vec![Item::info(format!("{} ran: {outcome}", t.bin))];
        if outcome != "exit 0" {
            // Why it failed (not signed in, a bad flag...): its last lines, as inert text.
            items.extend(
                output_tail(&output, 3)
                    .into_iter()
                    .map(|l| Item::info(format!("{} said: {l}", t.bin))),
            );
        }
        match held {
            Err(e) => {
                items.push(Item::fail(format!("could not ask msd what it saw · {e}")));
                // msd can't vouch for anything, but an "open" in the agent's output still counts.
                if output_says_open(&output, &nonce) {
                    report.direct_open = true;
                    items.push(Item::fail(format!(
                        "DIRECT INTERNET IS OPEN in {}'s sandbox (the probe said so in the agent's output)",
                        t.id
                    )));
                }
            }
            Ok((canary, rep)) => {
                let v = judge(
                    t.id,
                    &t.kind,
                    started,
                    &nonce,
                    canary.as_ref(),
                    rep.as_ref(),
                    &output,
                );
                report.direct_open |= v.direct_open;
                items.extend(v.items);
            }
        }
        report.section(&title, items);
    }
}

/// Runs an agent with stdin closed, in a fresh private directory, in its own process group so a
/// timeout kills everything it started. Returns (how it ended, its output, capped).
fn run_agent(argv: &[String]) -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "morsec-doctor-live-{}-{}",
        std::process::id(),
        crate::import::now_unix_ms()
    ));
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            return (format!("not started: {e}"), String::new());
        }
    }
    let result = run_agent_in(argv, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_agent_in(argv: &[String], dir: &Path) -> (String, String) {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (format!("not started: {e}"), String::new()),
    };
    // Keep the first MAX_AGENT_OUTPUT bytes and discard the rest, so a chatty agent never
    // blocks on a full pipe. Bytes land in a shared buffer as they arrive, so if something that
    // left the group still holds the pipe, doctor stops waiting after READ_TIMEOUT and keeps
    // everything captured so far (review R6).
    let reader = |r: Option<Box<dyn Read + Send>>| {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(r.is_none()));
        if let Some(mut r) = r {
            let (b, d) = (buf.clone(), done.clone());
            std::thread::spawn(move || {
                let mut chunk = [0u8; 8192];
                loop {
                    match r.read(&mut chunk) {
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut g = b.lock().unwrap_or_else(|e| e.into_inner());
                            let room = MAX_AGENT_OUTPUT.saturating_sub(g.len());
                            g.extend_from_slice(&chunk[..n.min(room)]);
                        }
                    }
                }
                d.store(true, std::sync::atomic::Ordering::Release);
            });
        }
        (buf, done)
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + AGENT_TIMEOUT;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(st)) => break format!("exit {}", st.code().unwrap_or(-1)),
            Ok(None) if Instant::now() >= deadline => {
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break format!("killed after {}s", AGENT_TIMEOUT.as_secs());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => break format!("wait failed: {e}"),
        }
    };
    // Children left holding the pipes would keep the readers open: end the group either way.
    kill_group(child.id());
    // One deadline for both pipes (review R7).
    let drained = Instant::now() + READ_TIMEOUT;
    while !(out.1.load(std::sync::atomic::Ordering::Acquire)
        && err.1.load(std::sync::atomic::Ordering::Acquire))
        && Instant::now() < drained
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let take = |b: &std::sync::Mutex<Vec<u8>>| {
        String::from_utf8_lossy(&b.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    };
    let mut text = take(&out.0);
    text.push_str(&take(&err.0));
    (outcome, text)
}

fn kill_group(pid: u32) {
    if let Some(p) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(p, rustix::process::Signal::KILL);
    }
}

/// The agent's output carries the probe's machine line for this nonce saying direct egress is
/// open. Believed on its own: a claim of "open" is never what an attacker wants doctor to see.
fn output_says_open(output: &str, nonce: &str) -> bool {
    output
        .lines()
        .any(|l| l.contains(&format!("morsec-probe nonce={nonce} ")) && l.contains("direct=OPEN"))
}

/// The last `n` non-empty lines of an agent's output, each cut to 200 characters.
fn output_tail(output: &str, n: usize) -> Vec<String> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| l.chars().take(200).collect())
        .collect()
}

struct Verdict {
    items: Vec<Item>,
    direct_open: bool,
}

/// Does a sighting come from a session of `kind` that started during this live run?
fn from_this_run(s: &ProbeSighting, kind: &AgentKind, started_ms: u64) -> bool {
    s.session.as_ref().is_some_and(|sess| {
        sess.agent == *kind && sess.started_unix_ms + START_SLACK_MS >= started_ms
    })
}

/// The live verdict for one agent. Passes come only from what msd saw; an "open" claim is
/// believed from any source (msd's report, or the agent's output carrying the probe's machine
/// line for this nonce).
fn judge(
    id: &str,
    kind: &AgentKind,
    started_ms: u64,
    nonce: &str,
    canary: Option<&ProbeSighting>,
    report: Option<&(ProbeReport, ProbeSighting)>,
    agent_output: &str,
) -> Verdict {
    let mut items = Vec::new();
    items.push(match canary {
        Some(c) if from_this_run(c, kind, started_ms) => {
            Item::pass("canary reached morsec's proxy from this agent's sandbox")
        }
        Some(_) => Item::fail(
            "a canary reached morsec's proxy, but not from this agent's session; commands may not route through morsec",
        ),
        None => Item::fail(format!(
            "commands in {id}'s sandbox did not reach morsec's proxy (the canary never arrived) · check: ms doctor, and that the sandbox allows the proxy"
        )),
    });
    let said_open = output_says_open(agent_output, nonce);
    let direct_open = report.is_some_and(|(r, _)| r.direct_open) || said_open;
    if direct_open {
        items.push(Item::fail(format!(
            "DIRECT INTERNET IS OPEN in {id}'s sandbox: commands there can reach the internet without morsec"
        )));
    } else {
        items.push(match report {
            Some((r, by)) if from_this_run(by, kind, started_ms) => {
                if r.detail.is_empty() {
                    Item::pass(format!("direct internet blocked in {id}'s sandbox"))
                } else {
                    Item::pass(format!(
                        "direct internet blocked in {id}'s sandbox ({})",
                        r.detail
                    ))
                }
            }
            Some(_) => Item::fail(
                "a probe report arrived, but not from this agent's session; not trusted",
            ),
            None => Item::fail(format!(
                "the probe did not report to msd: {id} did not run it, or its sandbox blocks the msd socket"
            )),
        });
    }
    Verdict { items, direct_open }
}

// ---------------------------------------------------------------------------------------------
// --probe (inside the agent's sandbox)

/// What the canary CONNECT got.
#[derive(Debug, PartialEq, Eq)]
enum ProxyResult {
    /// morsec's proxy answered with its own refusal: the request reached msd.
    Reached(String),
    /// No proxy variable is set.
    NoProxy,
    /// The proxy couldn't be reached, or something else answered.
    Failed(String),
}

/// The proxy from the usual variables: `http://[user[:pass]@]host:port[/]` only.
fn proxy_from_env(get: impl Fn(&str) -> Option<String>) -> Option<Result<String, String>> {
    let v = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .find_map(|n| get(n).filter(|v| !v.is_empty()))?;
    Some(parse_proxy(&v))
}

fn parse_proxy(v: &str) -> Result<String, String> {
    let rest = v
        .strip_prefix("http://")
        .ok_or_else(|| "the proxy variable is not an http:// URL".to_owned())?;
    let rest = rest.trim_end_matches('/');
    let hostport = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    if hostport.is_empty() || hostport.contains('/') || !hostport.contains(':') {
        return Err("the proxy variable has no host:port".into());
    }
    Ok(hostport.to_owned())
}

fn connect_any(hostport: &str) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = resolve(hostport)?;
    let mut last = String::from("no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

/// Resolves with a time limit (a sandbox without network can make lookups hang).
fn resolve(hostport: &str) -> Result<Vec<SocketAddr>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let hp = hostport.to_owned();
    std::thread::spawn(move || {
        let _ = tx.send(hp.to_socket_addrs().map(Iterator::collect::<Vec<_>>));
    });
    match rx.recv_timeout(READ_TIMEOUT) {
        Ok(Ok(a)) if !a.is_empty() => Ok(a),
        Ok(Ok(_)) => Err(format!("{hostport}: no address")),
        Ok(Err(e)) => Err(format!("{hostport}: lookup failed: {e}")),
        Err(_) => Err(format!("{hostport}: lookup timed out")),
    }
}

fn canary(proxy: &str, nonce: &str) -> ProxyResult {
    let mut s = match connect_any(proxy) {
        Ok(s) => s,
        Err(e) => return ProxyResult::Failed(format!("proxy {proxy} unreachable: {e}")),
    };
    let _ = s.set_read_timeout(Some(READ_TIMEOUT));
    let _ = s.set_write_timeout(Some(READ_TIMEOUT));
    let host = format!("{nonce}{CANARY_SUFFIX}:443");
    if let Err(e) = write!(s, "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n") {
        return ProxyResult::Failed(format!("proxy {proxy}: {e}"));
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < 4096 {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains("morsec:") {
                    break;
                }
            }
        }
    }
    classify_canary(proxy, &String::from_utf8_lossy(&buf))
}

/// Reached only when the answer is a 403 carrying morsec's own refusal text.
fn classify_canary(proxy: &str, answer: &str) -> ProxyResult {
    let status = answer.lines().next().unwrap_or("").trim();
    let body = answer.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    if status.starts_with("HTTP/1.") && status.contains(" 403") && body.contains("morsec:") {
        ProxyResult::Reached(proxy.to_owned())
    } else if status.is_empty() {
        ProxyResult::Failed(format!("proxy {proxy} closed without answering"))
    } else {
        ProxyResult::Failed(format!(
            "proxy {proxy} answered \"{}\", not morsec",
            status.chars().take(80).collect::<String>()
        ))
    }
}

/// Tries each target without a proxy; any connection = open. Nothing is sent.
fn direct(targets: &[String]) -> (bool, Vec<String>) {
    let mut notes = Vec::new();
    for t in targets {
        match connect_any(t) {
            Ok(_) => return (true, vec![format!("{t} connected")]),
            Err(e) => notes.push(e),
        }
    }
    (false, notes)
}

/// `host:port` with a non-empty host and a port from 1 to 65535.
fn valid_target(t: &str) -> bool {
    t.rsplit_once(':').is_some_and(|(h, p)| {
        !h.is_empty() && !h.contains(['/', ' ']) && p.parse::<u16>().is_ok_and(|p| p > 0)
    })
}

fn probe(nonce: Option<&str>, targets: &[String]) -> ExitCode {
    if let Some(n) = nonce
        && !valid_nonce(n)
    {
        eprintln!("morsec: --nonce must be 32 lowercase hex characters");
        return ExitCode::from(2);
    }
    // A target that can't even be parsed must not count as "blocked".
    if let Some(bad) = targets.iter().find(|t| !valid_target(t)) {
        eprintln!(
            "{}",
            terminal_safe(&format!("morsec: --direct-target {bad:?} is not host:port"))
        );
        return ExitCode::from(2);
    }
    let canary_nonce = match nonce {
        Some(n) => n.to_owned(),
        None => random_nonce().unwrap_or_else(|_| "0".repeat(32)),
    };
    let proxy = match proxy_from_env(|n| std::env::var(n).ok()) {
        None => ProxyResult::NoProxy,
        Some(Err(e)) => ProxyResult::Failed(e),
        Some(Ok(p)) => canary(&p, &canary_nonce),
    };
    let targets: Vec<String> = if targets.is_empty() {
        DIRECT_TARGETS.iter().map(|s| (*s).to_owned()).collect()
    } else {
        targets.to_vec()
    };
    let (open, notes) = direct(&targets);
    let reached = matches!(proxy, ProxyResult::Reached(_));
    let mut detail: String = notes.join("; ");
    detail = detail
        .chars()
        .take(ProbeReport::MAX_DETAIL - 3)
        .collect::<String>();
    let mut lines = vec![match &proxy {
        ProxyResult::Reached(p) => format!("  ✓ canary reached morsec through the proxy ({p})"),
        ProxyResult::NoProxy => {
            "  ✗ no proxy variable (HTTPS_PROXY / HTTP_PROXY) is set in this sandbox".to_owned()
        }
        ProxyResult::Failed(e) => format!("  ✗ canary did not reach morsec: {e}"),
    }];
    lines.push(if open {
        format!("  ✗ DIRECT INTERNET IS OPEN: {detail}")
    } else {
        format!("  ✓ direct internet blocked ({detail})")
    });
    if let Some(n) = nonce {
        let sent = ask(RequestBody::DoctorProbe {
            nonce: Some(n.to_owned()),
            report: Some(ProbeReport {
                proxy_reached: reached,
                direct_open: open,
                detail: detail.clone(),
            }),
        });
        lines.push(match sent {
            Ok(ResponseBody::Ok { .. }) => "  ✓ reported to msd".to_owned(),
            Ok(ResponseBody::Error { message, .. }) => {
                format!("  ✗ msd refused the report: {message}")
            }
            Ok(_) => "  ✗ msd gave an unexpected answer".to_owned(),
            Err(e) => format!("  ✗ could not report to msd: {e}"),
        });
    }
    println!("morsec probe");
    for l in &lines {
        println!("{}", terminal_safe(l));
    }
    println!(
        "morsec-probe nonce={canary_nonce} proxy={} direct={}",
        if reached { "reached" } else { "no" },
        if open { "OPEN" } else { "blocked" }
    );
    if open {
        eprintln!("{}", loud_banner());
    }
    if reached && !open {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::SessionId;

    const N: &str = "0123456789abcdef0123456789abcdef";

    fn sighting(kind: AgentKind, started: u64) -> ProbeSighting {
        ProbeSighting {
            session: Some(SessionId {
                agent: kind,
                pid: 10,
                started_unix_ms: started,
            }),
            seen_unix_ms: started + 1,
        }
    }

    fn rep(open: bool, by: ProbeSighting) -> (ProbeReport, ProbeSighting) {
        (
            ProbeReport {
                proxy_reached: true,
                direct_open: open,
                detail: String::new(),
            },
            by,
        )
    }

    fn marks(v: &Verdict) -> Vec<Mark> {
        v.items.iter().map(|i| i.mark).collect()
    }

    // protects=INJ-4 live verdict: both checks pass only on msd's own evidence from a session of
    // the agent under test that started in this run; fails_when=a pass is given without that
    // evidence; no_claim=running a real agent
    #[test]
    fn live_pass_needs_msds_evidence_from_this_agent() {
        let k = AgentKind::ClaudeCode;
        let ok = sighting(k.clone(), 100_000);
        let v = judge(
            "claude-code",
            &k,
            100_000,
            N,
            Some(&ok),
            Some(&rep(false, ok.clone())),
            "",
        );
        assert_eq!(marks(&v), [Mark::Pass, Mark::Pass]);
        assert!(!v.direct_open);

        // The agent claims success in text but msd saw nothing.
        let claim = format!("morsec-probe nonce={N} proxy=reached direct=blocked");
        let v = judge("claude-code", &k, 100_000, N, None, None, &claim);
        assert_eq!(marks(&v), [Mark::Fail, Mark::Fail]);

        // Evidence from another agent kind, from an older session, or from no session.
        for wrong in [
            sighting(AgentKind::Codex, 100_000),
            sighting(k.clone(), 1_000),
            ProbeSighting {
                session: None,
                seen_unix_ms: 100_001,
            },
        ] {
            let v = judge(
                "claude-code",
                &k,
                100_000,
                N,
                Some(&wrong),
                Some(&rep(false, wrong.clone())),
                "",
            );
            assert_eq!(marks(&v), [Mark::Fail, Mark::Fail], "{wrong:?}");
        }
    }

    // protects=SPEC: when direct egress is open, doctor fails loudly, whether msd's report or only
    // the agent's own output (the probe's machine line for this nonce) says so, even if a later
    // report says blocked; fails_when=an open sandbox is not a failure or not flagged loud;
    // no_claim=what the probe measures
    #[test]
    fn open_egress_fails_loudly_from_any_source() {
        let k = AgentKind::Codex;
        let ok = sighting(k.clone(), 5_000);
        let v = judge(
            "codex",
            &k,
            5_000,
            N,
            Some(&ok),
            Some(&rep(true, ok.clone())),
            "",
        );
        assert!(v.direct_open);
        assert!(v.items[1].text.contains("DIRECT INTERNET IS OPEN"));
        assert_eq!(v.items[1].mark, Mark::Fail);

        let line = format!("morsec-probe nonce={N} proxy=no direct=OPEN");
        let v = judge(
            "codex",
            &k,
            5_000,
            N,
            Some(&ok),
            Some(&rep(false, ok.clone())),
            &line,
        );
        assert!(v.direct_open);
        // Another nonce's line (e.g. echoed from elsewhere) is not this run's.
        let other = "morsec-probe nonce=ffffffffffffffffffffffffffffffff proxy=no direct=OPEN";
        let v = judge(
            "codex",
            &k,
            5_000,
            N,
            Some(&ok),
            Some(&rep(false, ok.clone())),
            other,
        );
        assert!(!v.direct_open);

        assert!(loud_banner().contains("DIRECT INTERNET IS OPEN"));
    }

    // protects=SPEC acceptance 2: a connector check that failed (e.g. the proxy variable removed)
    // is a problem with its fix; a port that no longer matches msd is a problem; not connected is
    // info or a warning, never a pass; fails_when=a failed check shows as anything but ✗;
    // no_claim=the connector's own checks (ms-connect tests)
    #[test]
    fn connector_failures_are_problems() {
        let broken = || {
            vec![
                ms_connect::Check {
                    name: "Codex connected".into(),
                    ok: true,
                    detail: String::new(),
                },
                ms_connect::Check {
                    name: "Codex commands use the morsec proxy".into(),
                    ok: false,
                    detail: "HTTPS_PROXY is missing; run: ms connect codex".into(),
                },
            ]
        };
        let items = agent_items("codex", true, true, broken, &Ok(Some(7000)), Some(7000));
        assert_eq!(
            items.iter().map(|i| i.mark).collect::<Vec<_>>(),
            [Mark::Pass, Mark::Fail, Mark::Pass]
        );
        assert!(items[1].text.contains("HTTPS_PROXY is missing"));
        let items = agent_items("codex", true, true, Vec::new, &Ok(Some(7000)), Some(7001));
        assert_eq!(items[0].mark, Mark::Fail);
        let items = agent_items(
            "codex",
            true,
            false,
            || panic!("verify ran"),
            &Ok(None),
            None,
        );
        assert_eq!(items[0].mark, Mark::Warn);
        let items = agent_items(
            "codex",
            false,
            false,
            || panic!("verify ran"),
            &Ok(None),
            None,
        );
        assert_eq!(items[0].mark, Mark::Info);
    }

    // protects=MCP hook: until L14 ships, ms mcp is reported as not installed, as info that never
    // fails doctor; fails_when=it is a problem or a pass; no_claim=tool hashes (L14)
    #[test]
    fn mcp_not_installed_is_info() {
        let m = mcp_checks();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].mark, Mark::Info);
        assert!(m[0].text.contains("not installed"));
    }

    #[test]
    fn signature_verdicts() {
        let p = Path::new("/x/msd");
        assert_eq!(classify_signature(p, false, "").mark, Mark::Fail);
        assert_eq!(
            classify_signature(p, true, "Signature=adhoc\nTeamIdentifier=not set\n").mark,
            Mark::Warn
        );
        let i = classify_signature(
            p,
            true,
            "Authority=Developer ID Application: X\nTeamIdentifier=ABCDE12345\n",
        );
        assert_eq!(i.mark, Mark::Pass);
        assert!(i.text.contains("ABCDE12345"));
        assert_eq!(
            classify_signature(p, true, "TeamIdentifier=not set\n").mark,
            Mark::Fail
        );
        assert_eq!(
            classify_signature(p, true, "Authority=My Own Cert\nTeamIdentifier=not set\n").mark,
            Mark::Warn
        );
    }

    #[test]
    fn proxy_parsing_and_canary_answer() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |n: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(proxy_from_env(env(&[])), None);
        assert_eq!(
            proxy_from_env(env(&[("http_proxy", "http://claude-code@127.0.0.1:7777/")])),
            Some(Ok("127.0.0.1:7777".into()))
        );
        assert!(matches!(
            proxy_from_env(env(&[("HTTPS_PROXY", "socks5://127.0.0.1:1")])),
            Some(Err(_))
        ));
        assert!(parse_proxy("http://").is_err());
        assert_eq!(
            classify_canary(
                "p",
                "HTTP/1.1 403 Forbidden\r\ncontent-length: 9\r\n\r\nmorsec: no"
            ),
            ProxyResult::Reached("p".into())
        );
        // Another proxy's 403, or a 200, is not morsec.
        assert!(matches!(
            classify_canary("p", "HTTP/1.1 403 Forbidden\r\n\r\nsquid says no"),
            ProxyResult::Failed(_)
        ));
        assert!(matches!(
            classify_canary("p", "HTTP/1.1 200 OK\r\n\r\nmorsec:"),
            ProxyResult::Failed(_)
        ));
    }

    // protects=INJ-4 / prompt hygiene: the live prompt carries only the ms path and the nonce,
    // and the argv adds no permission bypass or sandbox loosening for either agent;
    // fails_when=a bypass, full-access or network flag appears; no_claim=the agents' own defaults
    #[test]
    fn live_argv_never_loosens() {
        let t = |kind, id, bin| Target {
            id,
            kind,
            bin,
            connector: Err(String::new()),
            connected: true,
            recorded_port: Ok(None),
        };
        for target in [
            t(AgentKind::ClaudeCode, "claude-code", "claude"),
            t(AgentKind::Codex, "codex", "codex"),
        ] {
            let argv = agent_argv(&target, Path::new("/bin/agent"), "'/opt/ms'", N);
            let joined = argv.join(" ").to_lowercase();
            for bad in [
                "dangerously",
                concat!("bypass", "permissions"),
                "--permission-mode",
                concat!("danger-", "full-access"),
                "--full-auto",
                "network_access",
                "--sandbox",
                "-c",
            ] {
                assert!(!argv.iter().any(|a| a.to_lowercase() == bad), "{bad}");
                assert!(
                    !joined.contains(&format!(" {bad} ")) || bad == "-c",
                    "{bad}"
                );
            }
            assert!(!joined.contains("dangerously"));
            assert!(
                argv.iter()
                    .any(|a| a.contains(&format!("doctor --probe --nonce {N}")))
            );
        }
        assert_eq!(
            prompt("'/opt/ms'", N)
                .lines()
                .filter(|l| !l.is_empty())
                .count(),
            2
        );
    }

    // protects=R1: the agent's own "direct=OPEN" line for this nonce is recognised on its own (used
    // even when msd can't be asked); fails_when=it is missed or another nonce's line counts;
    // no_claim=msd's evidence
    #[test]
    fn output_open_claim_needs_this_nonce() {
        assert!(output_says_open(
            &format!("x\nmorsec-probe nonce={N} proxy=no direct=OPEN\n"),
            N
        ));
        assert!(!output_says_open(
            &format!("morsec-probe nonce={N} proxy=reached direct=blocked"),
            N
        ));
        assert!(!output_says_open(
            "morsec-probe nonce=ffffffffffffffffffffffffffffffff proxy=no direct=OPEN",
            N
        ));
    }

    // protects=R6: output already printed is kept when something that left the agent's process
    // group still holds the pipe, and doctor stops waiting soon after the agent exits;
    // fails_when=the captured line is lost or run_agent_in waits for the orphan;
    // no_claim=real agents
    #[test]
    fn output_kept_when_an_orphan_holds_the_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let argv: Vec<String> = [
            "/bin/sh",
            "-c",
            "echo morsec-probe-line; /usr/bin/perl -e 'use POSIX; exit if fork; POSIX::setsid(); sleep 8'",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let t = Instant::now();
        let (outcome, text) = run_agent_in(&argv, dir.path());
        assert_eq!(outcome, "exit 0");
        assert!(text.contains("morsec-probe-line"), "{text:?}");
        assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    }

    #[test]
    fn output_tail_is_short() {
        let long = "x".repeat(500);
        let out = format!("a\n\n b \nc\n{long}\n\n");
        let t = output_tail(&out, 3);
        assert_eq!(t[..2], ["b".to_owned(), "c".to_owned()]);
        assert_eq!(t[2].len(), 200);
        assert!(output_tail("", 3).is_empty());
    }

    #[test]
    fn render_counts_and_sanitises() {
        let mut r = Report::default();
        r.section(
            "x",
            vec![
                Item::pass("ok"),
                Item::warn("w"),
                Item::fail("bad\u{1b}[2Jthing"),
                Item::info("i"),
            ],
        );
        let out = r.render();
        assert!(!out.contains('\u{1b}'));
        assert!(out.contains("  ✗ bad[2Jthing"));
        assert!(out.ends_with("1 problem, 1 warning. Fix them, then run: ms doctor\n"));
    }
}
