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
/// How often `--live` asks msd what it has seen while an agent runs.
const TICK: Duration = Duration::from_millis(200);

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
    let (mut report, daemon) = static_report();
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

/// The static checks (no agent is started).
fn static_report() -> (Report, Option<DaemonInfo>) {
    let mut report = Report::default();
    let daemon = daemon_section(&mut report);
    // Shown even when msd is down: a LaunchAgent left pointing at a deleted version is a
    // common reason it is.
    report.section("launchagent", launch_agent_items());
    let port = daemon.as_ref().and_then(|d| d.proxy_port);
    if daemon.is_some() {
        report.section("run shims", shim_items());
    }
    agent_section(&mut report, &claude_target(), port);
    agent_section(&mut report, &codex_target(), port);
    report.section("mcp", mcp_checks());
    (report, daemon)
}

/// `ms init` machine step 4 (L31): the static checks' failures, one line each (`section: text`),
/// for the summary. Nothing is printed here.
pub(crate) fn static_problems() -> Vec<String> {
    let (report, _) = static_report();
    report
        .sections
        .iter()
        .flat_map(|(title, items)| {
            items
                .iter()
                .filter(|i| i.mark == Mark::Fail)
                .map(move |i| format!("{title}: {}", i.text))
        })
        .collect()
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
        Err(Error::DaemonNotVerified { detail }) => {
            // T-03: nothing was sent. Say whether this ms can't verify anything (a dev build,
            // the fix is on this side) or the process on the socket failed the check.
            let advice = if matches!(
                ms_ipc::peer_verify::current_trust(),
                ms_ipc::peer_verify::Trust::Refuse(_)
            ) {
                "this ms can't verify msd; nothing was sent".to_owned()
            } else {
                format!(
                    "nothing was sent to it; check what serves {}, then restart msd: launchctl kickstart -k gui/$UID/{}",
                    ms_ipc::default_socket_path()
                        .map_or_else(|_| "the socket".to_owned(), |p| p.display().to_string()),
                    crate::service::LABEL
                )
            };
            items.push(Item::fail(format!(
                "msd identity not verified · {detail} · {advice}"
            )));
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
    items.push(identity_item());
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

/// T-03: what `Client::connect` established about the process serving the socket.
fn identity_item() -> Item {
    let identity = block_on(async {
        let path = ms_ipc::default_socket_path()?;
        Ok(Client::connect(&path).await?.peer_identity().clone())
    });
    identity_verdict(identity.map_err(|e| match e {
        Error::DaemonNotVerified { detail } => detail,
        other => other.to_string(),
    }))
}

/// The doctor line for a peer identity, or for the reason it wasn't verified.
fn identity_verdict(
    identity: std::result::Result<ms_ipc::peer_verify::PeerIdentity, String>,
) -> Item {
    use ms_ipc::peer_verify::{DEV_OPT_OUT_ENV, MSD_IDENTIFIER, PeerIdentity};
    match identity {
        Ok(PeerIdentity::Verified { team }) => Item::pass(format!(
            "msd identity verified · {MSD_IDENTIFIER} · team {team}"
        )),
        Ok(PeerIdentity::DevUnverified) => Item::warn(format!(
            "msd identity NOT verified · dev opt-out {DEV_OPT_OUT_ENV}=1 with an unsigned ms (never use with real secrets)"
        )),
        Err(e) => Item::fail(format!("msd identity not verified · {e}")),
    }
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
/// `Err` when it could not be checked.
fn ca_trust(pem: &str) -> std::result::Result<bool, String> {
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
    let out = match made {
        Err(e) => Err(format!("writing a temp copy: {e}")),
        Ok(()) => Command::new("/usr/bin/security")
            .args(["verify-cert", "-q", "-L", "-c"])
            .arg(dir.join("ca.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .map_err(|e| format!("security: {e}")),
    };
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// `ms init` machine step 2 (L31): `Some(trusted)`, or `None` when it could not be checked.
pub(crate) fn ca_trusted(pem: &str) -> Option<bool> {
    ca_trust(pem).ok()
}

fn ca_item(pem: Option<&str>) -> Item {
    let Some(pem) = pem else {
        return Item::info("no morsec CA yet (it is made when a key is first allowed a host)");
    };
    match ca_trust(pem) {
        Ok(true) => Item::pass("morsec CA trusted by macOS"),
        Ok(false) => Item::warn(
            "morsec CA not trusted by macOS (agents trust it through their connector; other tools won't) · fix: ms init --trust",
        ),
        Err(e) if e.starts_with("security") => Item::warn(format!("CA trust not checked · {e}")),
        Err(e) => Item::warn(format!("CA trust not checked · {e}")),
    }
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

/// msd's LaunchAgent (launchagent-opt-path): does the program it starts still exist, and will it
/// survive `brew upgrade`?
fn launch_agent_items() -> Vec<Item> {
    match crate::service::plist_path() {
        // msd as installed next to this ms (canonical), to spot a LaunchAgent from another install.
        Ok(p) => vec![launch_agent_check(
            &p,
            crate::brew::sibling("msd")
                .ok()
                .map(|(real, _)| real)
                .filter(|m| m.is_file())
                .as_deref(),
        )],
        Err(e) => vec![Item::fail(format!("LaunchAgent not checked · {e}"))],
    }
}

/// `this_msd`: the canonical path of the msd installed next to this `ms`, when known.
fn launch_agent_check(plist: &Path, this_msd: Option<&Path>) -> Item {
    let text = match std::fs::read_to_string(plist) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Item::info(format!(
                "no LaunchAgent at {} (ms init installs it; skip this if you start msd yourself)",
                plist.display()
            ));
        }
        Err(e) => {
            return Item::fail(format!(
                "LaunchAgent unreadable ({}) · {e} · run: ms init",
                plist.display()
            ));
        }
    };
    let Some(program) = crate::service::plist_program(&text).map(PathBuf::from) else {
        return Item::fail(format!(
            "LaunchAgent {} names no program in the form ms init writes, so it may start nothing · run: ms init",
            plist.display()
        ));
    };
    let p = program.display();
    let keg = crate::brew::keg_of(&program).map(|(prefix, v)| (prefix.to_path_buf(), v.to_owned()));
    if !std::fs::metadata(&program).is_ok_and(|m| m.is_file()) {
        return Item::fail(match keg {
            Some((_, v)) => format!(
                "LaunchAgent starts msd from morsec {v}, which is no longer installed (brew upgrade removes old versions), so msd can't start ({p}) · run: ms init"
            ),
            None if crate::brew::is_npm(&program) => format!(
                "LaunchAgent starts msd from an npm install that is gone ({p}): npm uninstall, or a switch to another Node.js version (nvm, fnm, volta) removes it · run: ms init from the morsec you use now"
            ),
            None => format!("LaunchAgent starts {p}, which does not exist · run: ms init"),
        });
    }
    if program.file_name().is_none_or(|n| n != "msd") {
        return Item::warn(format!(
            "LaunchAgent {} starts {p}, which is not msd · run: ms init",
            plist.display()
        ));
    }
    if let Some((prefix, v)) = keg {
        let opt = prefix.join("opt/morsec/bin/msd");
        let real = std::fs::canonicalize(&program).ok();
        if let Ok(opt_real) = std::fs::canonicalize(&opt) {
            if real.as_ref() != Some(&opt_real) {
                let now = crate::brew::keg_of(&opt_real).map_or_else(
                    || "another version".to_owned(),
                    |(_, w)| format!("morsec {w}"),
                );
                return Item::warn(format!(
                    "LaunchAgent is pinned to morsec {v} ({p}), but {now} is installed: msd runs the old version and stops starting when brew cleans it up · run: ms init"
                ));
            }
            if real.as_deref().and_then(crate::brew::stable_path).is_some() {
                return Item::warn(format!(
                    "LaunchAgent is pinned to morsec {v} ({p}); the next brew upgrade will stop msd from starting · run: ms init"
                ));
            }
            return Item::warn(format!(
                "LaunchAgent is pinned to morsec {v} ({p}): ms init can't use {} because it or {}/opt is not owned by you or root, or is writable by others; the next brew upgrade will stop msd from starting",
                opt.display(),
                prefix.display()
            ));
        }
    }
    // Two installs (say npm and Homebrew, or two Node.js versions): msd and this ms may be
    // different versions, and the next upgrade of this one won't reach msd.
    if let Some(mine) = this_msd {
        let theirs = std::fs::canonicalize(&program).ok();
        if theirs.as_deref() != Some(mine) {
            return Item::warn(format!(
                "LaunchAgent starts {p}, but this ms is another install (its msd is {}): msd may run another version · run: ms init from the install you want to use",
                mine.display()
            ));
        }
    }
    Item::pass(format!("LaunchAgent starts {p}"))
}

/// Run-mode shims (L12): when a run key allows programs, `ms-shim` must sit next to `ms` and
/// `~/.morsec/shims/<program>` must be it: a symlink to the stable `opt` path in a Homebrew
/// install, else a hard link (or a byte-identical copy).
fn shim_items() -> Vec<Item> {
    let rules = match crate::run::fetch_rules() {
        Ok(r) => r,
        Err(e) => return vec![Item::fail(format!("run rules not readable · {e}"))],
    };
    let want = crate::run::wanted(&rules);
    if want.is_empty() {
        return vec![Item::info(
            "no run-mode key allows a program, so no shims are needed",
        )];
    }
    let shim = crate::brew::sibling("ms-shim")
        .and_then(|(real, _)| crate::brew::Shim::open(&real, crate::brew::link_target(&real)))
        .ok();
    let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        return vec![Item::fail(
            "HOME is not set, so ~/.morsec/shims can't be checked",
        )];
    };
    let dir = home.join(".morsec/shims");
    let on_path =
        std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d == dir));
    shim_check(shim.as_ref(), &dir, &want, on_path)
}

fn shim_check(
    shim: Option<&crate::brew::Shim>,
    dir: &Path,
    want: &std::collections::BTreeSet<String>,
    on_path: bool,
) -> Vec<Item> {
    use crate::brew::Entry;
    let Some(shim) = shim else {
        return vec![Item::fail(
            "ms-shim is not installed next to ms · reinstall morsec (brew reinstall morsec)",
        )];
    };
    let mut bad = Vec::new();
    let mut pinned = Vec::new();
    for n in want {
        match shim.classify(&dir.join(n)) {
            Entry::Linked => {}
            Entry::Pinned => pinned.push(n.as_str()),
            Entry::Stale | Entry::Foreign | Entry::Missing => bad.push(n.as_str()),
        }
    }
    let mut items = vec![if bad.is_empty() {
        Item::pass(format!(
            "{} shim{} linked in {}",
            want.len(),
            if want.len() == 1 { "" } else { "s" },
            dir.display()
        ))
    } else {
        Item::fail(format!(
            "shims missing or stale: {} · run: ms run --link-shims",
            bad.join(", ")
        ))
    }];
    if !pinned.is_empty() {
        items.push(Item::warn(if shim.stable.is_some() {
            format!(
                "shims pinned to this morsec version: {} · the next upgrade (brew upgrade, npm install -g) leaves them stale · run: ms run --link-shims",
                pinned.join(", ")
            )
        } else {
            format!(
                "shims linked another way than ms run --link-shims makes them: {} · run: ms run --link-shims",
                pinned.join(", ")
            )
        }));
    }
    if !on_path {
        items.push(Item::warn(format!(
            "{} is not on this terminal's PATH (agents get it from their connector); add it to run these programs through morsec here too",
            dir.display()
        )));
    }
    items
}

/// `ms mcp` tool hashes (MCP-2). `ms mcp` (L14) is built, but doctor does not compare a running
/// server's catalog hash (`tools/list` `_meta["dev.morsec/catalog"]`) with
/// `ms_mcp::Catalog::from_rules` on the live rules yet; until it does, say so as info.
fn mcp_checks() -> Vec<Item> {
    vec![Item::info(
        "ms mcp tool catalog hash not checked yet (MCP-2; `ms mcp --catalog` prints it)",
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
        let argv = agent_argv(&t, &bin, &ms_quoted, &nonce);
        // While the agent runs, ask msd what it has seen and decide for each session there
        // whether it is the agent doctor started (or below it): its parent chain, read live,
        // must reach the spawned process. A session that can't be checked while it runs is not
        // trusted (security review S1).
        let mut bound: Vec<(ms_core::SessionId, bool)> = Vec::new();
        let mut last: Result<Lookup, String> = Err("msd was not asked".into());
        let (outcome, output) = run_agent(&argv, &mut |child| {
            last = lookup(&nonce);
            if let Ok(l) = &last {
                for sess in l.sessions() {
                    if !bound.iter().any(|(s, _)| s == sess) {
                        let ok = descends(&ms_session::OsProcessTable, sess, child);
                        bound.push((sess.clone(), ok));
                    }
                }
            }
        });
        let held = lookup(&nonce).or(last);
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
            Ok(l) => {
                let is_ours = |sess: &ms_core::SessionId| {
                    sess.agent == t.kind && bound.iter().any(|(s, ok)| s == sess && *ok)
                };
                let v = judge(t.id, &nonce, &l, &output, &is_ours);
                report.direct_open |= v.direct_open;
                items.extend(v.items);
            }
        }
        report.section(&title, items);
    }
}

/// Runs an agent with stdin closed, in a fresh private directory, in its own process group so a
/// timeout kills everything it started. Returns (how it ended, its output, capped).
fn run_agent(argv: &[String], tick: &mut dyn FnMut(Child)) -> (String, String) {
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
    let result = run_agent_in(argv, &dir, tick);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_agent_in(argv: &[String], dir: &Path, tick: &mut dyn FnMut(Child)) -> (String, String) {
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
    // The spawned process, with its start time so a reused PID can't stand in for it.
    let me = Child {
        pid: child.id(),
        started_unix_ms: ms_session::ProcessTable::info(&ms_session::OsProcessTable, child.id())
            .map(|i| i.started_unix_ms)
            .ok(),
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
    let mut next_tick = Instant::now();
    let outcome = loop {
        if Instant::now() >= next_tick {
            tick(me);
            next_tick = Instant::now() + TICK;
        }
        match child.try_wait() {
            Ok(Some(st)) => break format!("exit {}", st.code().unwrap_or(-1)),
            Ok(None) if Instant::now() >= deadline => {
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break format!("killed after {}s", AGENT_TIMEOUT.as_secs());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
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

/// The process doctor spawned for a live run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Child {
    pid: u32,
    /// `None` if it could not be read right after spawning: then nothing is bound to it.
    started_unix_ms: Option<u64>,
}

/// What msd held for a nonce.
struct Lookup {
    canaries: Vec<ProbeSighting>,
    reports: Vec<(ProbeReport, ProbeSighting)>,
    any_open: bool,
}

impl Lookup {
    fn sessions(&self) -> impl Iterator<Item = &ms_core::SessionId> {
        self.canaries
            .iter()
            .chain(self.reports.iter().map(|(_, by)| by))
            .filter_map(|s| s.session.as_ref())
    }
}

fn lookup(nonce: &str) -> Result<Lookup, String> {
    match ask(RequestBody::DoctorProbe {
        nonce: Some(nonce.to_owned()),
        report: None,
    }) {
        Ok(ResponseBody::Probe {
            canaries,
            reports,
            any_open,
        }) => Ok(Lookup {
            canaries,
            reports,
            any_open,
        }),
        Ok(ResponseBody::Error { message, .. }) => Err(message),
        Ok(_) => Err("unexpected answer from msd".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Is `session`'s root process, alive now with the same start time, `child` or below it? Read
/// from the process table while the agent runs; anything unreadable is "no" (fail closed).
fn descends<T: ms_session::ProcessTable>(
    table: &T,
    session: &ms_core::SessionId,
    child: Child,
) -> bool {
    let Some(child_started) = child.started_unix_ms else {
        return false;
    };
    let Ok(mut cur) = table.info(session.pid) else {
        return false;
    };
    if cur.started_unix_ms != session.started_unix_ms {
        return false;
    }
    for _ in 0..ms_session::MAX_DEPTH {
        if cur.pid == child.pid {
            return cur.started_unix_ms == child_started;
        }
        if cur.ppid <= 1 || cur.ppid == cur.pid {
            return false;
        }
        match table.info(cur.ppid) {
            // A parent can't start after its child; if it did, the PID was reused.
            Ok(p) if p.started_unix_ms <= cur.started_unix_ms => cur = p,
            _ => return false,
        }
    }
    false
}

/// The live verdict for one agent. Passes come only from what msd saw, from a session that
/// `is_ours` (the agent doctor started); an "open" claim is believed from any source (any report,
/// or the agent's output carrying the probe's machine line for this nonce).
fn judge(
    id: &str,
    nonce: &str,
    held: &Lookup,
    agent_output: &str,
    is_ours: &dyn Fn(&ms_core::SessionId) -> bool,
) -> Verdict {
    let ours = |s: &ProbeSighting| s.session.as_ref().is_some_and(is_ours);
    let mut items = Vec::new();
    items.push(if held.canaries.iter().any(ours) {
        Item::pass("canary reached morsec's proxy from the agent doctor started")
    } else if held.canaries.is_empty() {
        Item::fail(format!(
            "commands in {id}'s sandbox did not reach morsec's proxy (the canary never arrived) · check: ms doctor, and that the sandbox allows the proxy"
        ))
    } else {
        Item::fail(
            "a canary reached morsec's proxy, but not from the agent doctor started; not trusted",
        )
    });
    let said_open = output_says_open(agent_output, nonce);
    let direct_open = held.any_open || held.reports.iter().any(|(r, _)| r.direct_open) || said_open;
    if direct_open {
        items.push(Item::fail(format!(
            "DIRECT INTERNET IS OPEN in {id}'s sandbox: commands there can reach the internet without morsec"
        )));
    } else {
        items.push(match held.reports.iter().find(|(_, by)| ours(by)) {
            Some((r, _)) if r.detail.is_empty() => {
                Item::pass(format!("direct internet blocked in {id}'s sandbox"))
            }
            Some((r, _)) => Item::pass(format!(
                "direct internet blocked in {id}'s sandbox ({})",
                r.detail
            )),
            None if held.reports.is_empty() => Item::fail(format!(
                "the probe did not report to msd: {id} did not run it, or its sandbox blocks the msd socket"
            )),
            None => Item::fail(
                "a probe report arrived, but not from the agent doctor started; not trusted",
            ),
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

    fn sess(kind: AgentKind, pid: u32) -> SessionId {
        SessionId {
            agent: kind,
            pid,
            started_unix_ms: 100,
        }
    }

    fn by(s: SessionId) -> ProbeSighting {
        ProbeSighting {
            session: Some(s),
            seen_unix_ms: 1,
        }
    }

    fn held(canaries: Vec<ProbeSighting>, reports: Vec<(bool, ProbeSighting)>) -> Lookup {
        Lookup {
            any_open: false,
            canaries,
            reports: reports
                .into_iter()
                .map(|(open, b)| {
                    (
                        ProbeReport {
                            proxy_reached: true,
                            direct_open: open,
                            detail: String::new(),
                        },
                        b,
                    )
                })
                .collect(),
        }
    }

    fn marks(v: &Verdict) -> Vec<Mark> {
        v.items.iter().map(|i| i.mark).collect()
    }

    // protects=INJ-4 live verdict and security review S1: both checks pass only on msd's own
    // evidence from a session that is the agent doctor started; the same evidence from any other
    // session (another process that forged a canary and a "blocked" report first) passes
    // nothing, and the agent's text claiming success passes nothing; fails_when=a pass is given
    // without evidence from our session; no_claim=how "ours" is decided (descends test)
    #[test]
    fn live_pass_needs_msds_evidence_from_this_agent() {
        let ours = sess(AgentKind::ClaudeCode, 10);
        let forger = sess(AgentKind::ClaudeCode, 99);
        let is_ours = |s: &SessionId| *s == ours;
        let v = judge(
            "claude-code",
            N,
            &held(vec![by(ours.clone())], vec![(false, by(ours.clone()))]),
            "",
            &is_ours,
        );
        assert_eq!(marks(&v), [Mark::Pass, Mark::Pass]);
        assert!(!v.direct_open);

        // A forger's canary and report, even first and alongside nothing of ours.
        let v = judge(
            "claude-code",
            N,
            &held(vec![by(forger.clone())], vec![(false, by(forger.clone()))]),
            "",
            &is_ours,
        );
        assert_eq!(marks(&v), [Mark::Fail, Mark::Fail]);
        assert!(
            v.items[0]
                .text
                .contains("not from the agent doctor started")
        );

        // The agent claims success in text but msd saw nothing.
        let claim = format!("morsec-probe nonce={N} proxy=reached direct=blocked");
        let v = judge("claude-code", N, &held(vec![], vec![]), &claim, &is_ours);
        assert_eq!(marks(&v), [Mark::Fail, Mark::Fail]);

        // No session at all.
        let none = ProbeSighting {
            session: None,
            seen_unix_ms: 1,
        };
        let v = judge(
            "claude-code",
            N,
            &held(vec![none.clone()], vec![(false, none)]),
            "",
            &is_ours,
        );
        assert_eq!(marks(&v), [Mark::Fail, Mark::Fail]);
    }

    // protects=SPEC: when direct egress is open, doctor fails loudly, whether a report from any
    // session or only the agent's own output (the probe's machine line for this nonce) says so,
    // even if our own report says blocked; fails_when=an open sandbox is not a failure or not
    // flagged loud; no_claim=what the probe measures
    #[test]
    fn open_egress_fails_loudly_from_any_source() {
        let ours = sess(AgentKind::Codex, 10);
        let other = sess(AgentKind::Codex, 11);
        let is_ours = |s: &SessionId| *s == ours;
        let v = judge(
            "codex",
            N,
            &held(
                vec![by(ours.clone())],
                vec![(false, by(ours.clone())), (true, by(other))],
            ),
            "",
            &is_ours,
        );
        assert!(v.direct_open);
        assert!(v.items[1].text.contains("DIRECT INTERNET IS OPEN"));
        assert_eq!(v.items[1].mark, Mark::Fail);

        let ok = held(vec![by(ours.clone())], vec![(false, by(ours.clone()))]);
        // S3: msd's any_open flag counts even when no kept report says open.
        let flagged = Lookup {
            any_open: true,
            ..held(vec![by(ours.clone())], vec![(false, by(ours.clone()))])
        };
        assert!(judge("codex", N, &flagged, "", &is_ours).direct_open);
        let line = format!("morsec-probe nonce={N} proxy=no direct=OPEN");
        assert!(judge("codex", N, &ok, &line, &is_ours).direct_open);
        let other_nonce =
            "morsec-probe nonce=ffffffffffffffffffffffffffffffff proxy=no direct=OPEN";
        assert!(!judge("codex", N, &ok, other_nonce, &is_ours).direct_open);
        assert!(loud_banner().contains("DIRECT INTERNET IS OPEN"));
    }

    struct Table(Vec<ms_session::ProcInfo>);
    impl ms_session::ProcessTable for Table {
        fn info(&self, pid: u32) -> std::io::Result<ms_session::ProcInfo> {
            self.0
                .iter()
                .find(|p| p.pid == pid)
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn proc(pid: u32, ppid: u32, started: u64, name: &str) -> ms_session::ProcInfo {
        ms_session::ProcInfo {
            pid,
            ppid,
            uid: 501,
            started_unix_ms: started,
            name: name.into(),
        }
    }

    // protects=security review S1: a session is ours only if its root process is the spawned
    // child or below it (e.g. Codex's node shim → native codex), alive with the start time msd
    // recorded; a detached process with the same name, a reused PID, an exited process or an
    // unreadable child start are not; fails_when=any of those is accepted; no_claim=the OS
    // process table itself (ms-session tests)
    #[test]
    fn descends_binds_to_the_spawned_child() {
        let t = Table(vec![
            proc(1, 0, 0, "launchd"),
            proc(50, 1, 10, "zsh"),
            proc(60, 50, 20, "ms"),
            proc(70, 60, 30, "node"),   // spawned child (Codex's npm shim)
            proc(71, 70, 31, "codex"),  // the real agent below it
            proc(80, 1, 40, "claude"),  // detached forger, reparented to launchd
            proc(90, 70, 25, "claude"), // claims a parent that started after it: reused PID
        ]);
        let child = Child {
            pid: 70,
            started_unix_ms: Some(30),
        };
        let s = |pid, started| SessionId {
            agent: AgentKind::Codex,
            pid,
            started_unix_ms: started,
        };
        assert!(descends(&t, &s(71, 31), child));
        assert!(descends(&t, &s(70, 30), child));
        assert!(!descends(&t, &s(80, 40), child), "detached forger");
        assert!(
            !descends(&t, &s(71, 999), child),
            "start time differs from msd's"
        );
        assert!(
            !descends(&t, &s(90, 25), child),
            "parent started after child"
        );
        assert!(!descends(&t, &s(12345, 1), child), "exited");
        let wrong_child = Child {
            pid: 70,
            started_unix_ms: Some(29),
        };
        assert!(!descends(&t, &s(71, 31), wrong_child), "child PID reused");
        let unread = Child {
            pid: 70,
            started_unix_ms: None,
        };
        assert!(!descends(&t, &s(71, 31), unread));
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

    // protects=MCP hook: until doctor compares the catalog hash, ms mcp is reported as not
    // checked, as info that never fails doctor; fails_when=it is a problem or a pass, or claims
    // ms mcp is not installed; no_claim=the hash comparison (MCP-2)
    #[test]
    fn mcp_hash_not_checked_is_info() {
        let m = mcp_checks();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].mark, Mark::Info);
        assert!(m[0].text.contains("not checked yet"));
        assert!(!m[0].text.contains("not installed"));
    }

    // protects=T-03 ms doctor reports the peer verdict: verified is a pass naming the team, the
    // dev opt-out is a loud warning, a failed check is a failure carrying the reason;
    // fails_when=an unverified or impostor peer shows as a pass; no_claim=the live connect (msd's
    // tests/peer_verify.rs drives that)
    #[test]
    fn identity_verdicts() {
        use ms_ipc::peer_verify::PeerIdentity;
        let v = identity_verdict(Ok(PeerIdentity::Verified {
            team: "ABCDE12345".into(),
        }));
        assert_eq!(v.mark, Mark::Pass);
        assert!(v.text.contains("cc.morsec.msd") && v.text.contains("ABCDE12345"));
        let d = identity_verdict(Ok(PeerIdentity::DevUnverified));
        assert_eq!(d.mark, Mark::Warn);
        assert!(d.text.contains("NOT verified") && d.text.contains("MORSEC_DEV_UNVERIFIED_DAEMON"));
        let f = identity_verdict(Err("it does not carry msd's signature".into()));
        assert_eq!(f.mark, Mark::Fail);
        assert!(f.text.contains("does not carry msd's signature"));
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
        let mut ticks = 0;
        let (outcome, text) = run_agent_in(&argv, dir.path(), &mut |_| ticks += 1);
        assert!(ticks >= 1);
        assert_eq!(outcome, "exit 0");
        assert!(text.contains("morsec-probe-line"), "{text:?}");
        assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    }

    // protects=L12 shims: a run program without a linked ms-shim in ~/.morsec/shims is a problem
    // with its fix; a linked one passes; a missing ms-shim is a problem; shims not on PATH is a
    // warning; fails_when=a missing or foreign file passes as a shim; no_claim=ms run itself
    #[test]
    fn shim_check_verdicts() {
        let d = tempfile::tempdir().unwrap();
        let shim_path = d.path().join("ms-shim");
        std::fs::write(&shim_path, b"shim-bytes").unwrap();
        let shim = crate::brew::Shim::open(&shim_path, None).unwrap();
        let dir = d.path().join("shims");
        std::fs::create_dir(&dir).unwrap();
        std::fs::hard_link(&shim_path, dir.join("psql")).unwrap();
        std::fs::write(dir.join("deploy"), b"something else").unwrap();
        let want = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect();
        let items = shim_check(Some(&shim), &dir, &want(&["psql"]), true);
        assert_eq!(
            items.iter().map(|i| i.mark).collect::<Vec<_>>(),
            [Mark::Pass]
        );
        let items = shim_check(Some(&shim), &dir, &want(&["psql", "deploy", "git"]), false);
        assert_eq!(items[0].mark, Mark::Fail);
        assert!(items[0].text.contains("deploy, git"), "{}", items[0].text);
        assert!(items[0].text.contains("ms run --link-shims"));
        assert_eq!(items[1].mark, Mark::Warn);
        let items = shim_check(None, &dir, &want(&["psql"]), true);
        assert_eq!(items[0].mark, Mark::Fail);
    }

    // protects=in a Homebrew install, opt symlinks pass and hard links into the keg warn (they
    // go stale on upgrade); fails_when=a keg-pinned shim passes silently; no_claim=-
    #[test]
    fn shim_check_brew() {
        use crate::brew::tests::{FakeBrew, shim_bytes};
        let b = FakeBrew::new();
        let v1 = b.install("1.0.0", &shim_bytes("1"));
        b.point_opt("1.0.0");
        let real = v1.join("ms-shim");
        let shim = crate::brew::Shim::open(&real, crate::brew::link_target(&real)).unwrap();
        let dir = b.prefix.join("shims");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink(b.opt_bin("ms-shim"), dir.join("psql")).unwrap();
        std::fs::hard_link(&real, dir.join("stripe")).unwrap();
        let want = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect();
        let items = shim_check(Some(&shim), &dir, &want(&["psql"]), true);
        assert_eq!(
            items.iter().map(|i| i.mark).collect::<Vec<_>>(),
            [Mark::Pass]
        );
        let items = shim_check(Some(&shim), &dir, &want(&["psql", "stripe"]), true);
        assert_eq!(
            items.iter().map(|i| i.mark).collect::<Vec<_>>(),
            [Mark::Pass, Mark::Warn]
        );
        assert!(items[1].text.contains("stripe") && items[1].text.contains("brew upgrade"));
    }

    // protects=doctor flags a LaunchAgent whose program is in a deleted Cellar version (fail,
    // names the version), warns on a keg-pinned one, passes the opt path, treats a missing plist
    // as info; fails_when=a LaunchAgent into a removed keg passes; no_claim=launchctl's state
    #[test]
    fn launch_agent_verdicts() {
        use crate::brew::tests::{FakeBrew, shim_bytes};
        let b = FakeBrew::new();
        let v1 = b.install("1.0.0", &shim_bytes("1"));
        b.point_opt("1.0.0");
        let plist = b.prefix.join("LaunchAgents/cc.morsec.msd.plist");
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        let write = |msd: &Path| {
            std::fs::write(
                &plist,
                crate::service::render_plist(msd, Path::new("/tmp/msd.log")),
            )
            .unwrap();
        };
        assert_eq!(launch_agent_check(&plist, None).mark, Mark::Info);

        write(&b.opt_bin("msd"));
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Pass, "{}", it.text);

        write(&v1.join("msd"));
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Warn, "{}", it.text);
        assert!(
            it.text.contains("1.0.0") && it.text.contains("ms init"),
            "{}",
            it.text
        );

        // brew upgrade with cleanup deferred: 1.1.0 is current, 1.0.0 still on disk.
        b.install("1.1.0", &shim_bytes("2"));
        b.point_opt("1.1.0");
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Warn, "{}", it.text);
        assert!(
            it.text.contains("pinned to morsec 1.0.0")
                && it.text.contains("morsec 1.1.0 is installed"),
            "{}",
            it.text
        );

        // A group-writable opt: ms init can't use it, and doctor says why.
        {
            use std::os::unix::fs::PermissionsExt;
            let opt = b.prefix.join("opt");
            write(&b.keg_bin("1.1.0").join("msd"));
            std::fs::set_permissions(&opt, std::fs::Permissions::from_mode(0o775)).unwrap();
            let it = launch_agent_check(&plist, None);
            assert_eq!(it.mark, Mark::Warn, "{}", it.text);
            assert!(it.text.contains("not owned by you or root"), "{}", it.text);
            std::fs::set_permissions(&opt, std::fs::Permissions::from_mode(0o755)).unwrap();
            write(&v1.join("msd"));
        }

        // brew cleanup: 1.0.0 is gone.
        b.uninstall("1.0.0");
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Fail, "{}", it.text);
        assert!(
            it.text.contains("morsec 1.0.0") && it.text.contains("no longer installed"),
            "{}",
            it.text
        );
        assert!(it.text.contains("run: ms init"));
        // ...while one written with the opt path keeps working.
        write(&b.opt_bin("msd"));
        assert_eq!(launch_agent_check(&plist, None).mark, Mark::Pass);

        // A program that is not msd.
        write(Path::new("/bin/sh"));
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Warn, "{}", it.text);
        assert!(it.text.contains("not msd"), "{}", it.text);

        // A non-Homebrew program that is gone, and one that exists.
        write(&b.prefix.join("dev/msd"));
        let it = launch_agent_check(&plist, None);
        assert_eq!(it.mark, Mark::Fail);
        assert!(it.text.contains("does not exist"), "{}", it.text);
        std::fs::create_dir_all(b.prefix.join("dev")).unwrap();
        std::fs::write(b.prefix.join("dev/msd"), "dev").unwrap();
        assert_eq!(launch_agent_check(&plist, None).mark, Mark::Pass);

        std::fs::write(&plist, "<plist><dict></dict></plist>").unwrap();
        assert_eq!(launch_agent_check(&plist, None).mark, Mark::Fail);
    }

    // protects=an npm install: the LaunchAgent into node_modules passes while it is there, and
    // when it is gone (npm uninstall, another Node.js version) doctor fails naming npm and ms
    // init; a LaunchAgent that starts another install's msd warns; fails_when=a vanished npm
    // install gets the generic message, or two installs pass silently; no_claim=npm, launchctl
    #[test]
    fn launch_agent_npm_and_two_installs() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let npm_bin = |node: &str| {
            root.join(format!(
                "nvm/{node}/lib/node_modules/morsec/node_modules/morsec-darwin-arm64/bin"
            ))
        };
        let v22 = npm_bin("v22");
        std::fs::create_dir_all(&v22).unwrap();
        std::fs::write(v22.join("msd"), "msd").unwrap();
        let plist = root.join("cc.morsec.msd.plist");
        std::fs::write(
            &plist,
            crate::service::render_plist(&v22.join("msd"), Path::new("/tmp/msd.log")),
        )
        .unwrap();
        // Run from that same install: pass.
        let it = launch_agent_check(&plist, Some(&v22.join("msd")));
        assert_eq!(it.mark, Mark::Pass, "{}", it.text);
        // ms now comes from another Node.js version's install: warn, name both, say ms init.
        let v24 = npm_bin("v24");
        std::fs::create_dir_all(&v24).unwrap();
        std::fs::write(v24.join("msd"), "msd").unwrap();
        let it = launch_agent_check(&plist, Some(&v24.join("msd")));
        assert_eq!(it.mark, Mark::Warn, "{}", it.text);
        assert!(
            it.text.contains("another install")
                && it.text.contains(&v24.display().to_string())
                && it.text.contains("ms init"),
            "{}",
            it.text
        );
        // The old Node.js version is removed: fail, naming npm and Node versions.
        std::fs::remove_dir_all(root.join("nvm/v22")).unwrap();
        let it = launch_agent_check(&plist, Some(&v24.join("msd")));
        assert_eq!(it.mark, Mark::Fail, "{}", it.text);
        assert!(
            it.text.contains("npm install that is gone")
                && it.text.contains("Node.js")
                && it.text.contains("run: ms init"),
            "{}",
            it.text
        );
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
