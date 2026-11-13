//! `ms connect` and `ms disconnect` (L08: Claude Code). See `SPEC.md`.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use ms_connect::claude::diff::{Line, changed_lines, redact, significant};
use ms_connect::claude::{ClaudeConnector, Options, Paths, session_env_line};
use ms_connect::{ConnectCfg, Connector};
use ms_core::Error;
use ms_ipc::{Client, RequestBody, ResponseBody};
use ms_rules::Rules;

use crate::terminal_safe;

/// `ms connect [agent] [options]`
#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// claude-code (codex, cursor and gemini come later). Without it, lists the agents.
    agent: Option<String>,
    /// Show the changes and stop.
    #[arg(long)]
    dry_run: bool,
    /// Apply without asking.
    #[arg(long, short = 'y')]
    yes: bool,
    /// Give the agent an environment variable holding a reference, e.g.
    /// --env STRIPE_API_KEY=ms://stripe/test. Only ms:// references are accepted.
    #[arg(long = "env", value_name = "NAME=ms://REF")]
    env: Vec<String>,
    /// Also add the `ms mcp` server (off until ms mcp ships, L14).
    #[arg(long)]
    with_mcp: bool,
    /// Also run your hooks and local MCP servers through `ms run --` (off until ms run ships, L12).
    #[arg(long)]
    wrap: bool,
    /// Add a status line showing `ms status` (only when you have none).
    #[arg(long)]
    statusline: bool,
    /// Replace a sandbox proxy port or an "ms" MCP server you set yourself.
    #[arg(long)]
    force: bool,
    /// Read rules from this file instead of msd (tests; the MAC is not checked). Debug builds
    /// only: a release `ms` takes the hosts only from msd's MAC-verified rules (review R2).
    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    rules: Option<PathBuf>,
    /// Used by the Claude Code SessionStart hook: put the shims first on PATH.
    #[arg(long, hide = true)]
    session_env: bool,
}

/// `ms disconnect <agent>`
#[derive(Debug, Args)]
pub struct DisconnectArgs {
    /// claude-code.
    agent: String,
    /// Show the changes and stop.
    #[arg(long)]
    dry_run: bool,
    /// Remove without asking.
    #[arg(long, short = 'y')]
    yes: bool,
}

fn say(s: &str) {
    for line in s.lines() {
        println!("{}", terminal_safe(line));
    }
}

fn fail(s: &str) -> ExitCode {
    for line in s.lines() {
        eprintln!("{}", terminal_safe(line));
    }
    ExitCode::FAILURE
}

/// The agent a user typed, as a connector id.
fn agent_id(name: &str) -> Result<&'static str, ExitCode> {
    match name {
        "claude-code" | "claude" => Ok(ms_connect::claude::ID),
        "codex" => Err(not_built("codex", "L13 connect-codex")),
        "cursor" | "gemini" => Err(not_built(name, "L22 connect-cursor-gemini")),
        other => {
            eprintln!(
                "{}",
                terminal_safe(&format!(
                    "morsec: unknown agent \"{other}\". Agents: claude-code, codex, cursor, gemini"
                ))
            );
            Err(ExitCode::from(EXIT_USAGE))
        }
    }
}

/// Usage error, as clap reports one.
const EXIT_USAGE: u8 = 2;

fn not_built(agent: &str, loop_id: &'static str) -> ExitCode {
    eprintln!(
        "{}",
        Error::NotImplemented {
            command: format!("{} connect {agent}", crate::invoked_name()),
            loop_id
        }
    );
    ExitCode::from(crate::EXIT_NOT_BUILT)
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "morsec: HOME is not set".to_owned())
}

/// The `ms` path to write into settings: the first `ms` on PATH that is this binary (a stable
/// Homebrew link survives upgrades), else this binary (SPEC D12). A PATH entry counts only in a
/// directory outside HOME and the current directory that no other user can write (security
/// review S4): the link is run outside the sandbox at every session start, so it must not live
/// where a repo checkout or a temp dir could repoint it.
fn ms_path() -> Result<String, String> {
    let me = std::env::current_exe().map_err(|e| format!("morsec: finding ms: {e}"))?;
    let real = std::fs::canonicalize(&me).unwrap_or_else(|_| me.clone());
    let home = home().ok().and_then(|h| std::fs::canonicalize(h).ok());
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|d| std::fs::canonicalize(d).ok());
    let stable_dir = |d: &Path| {
        use std::os::unix::fs::MetadataExt;
        let Ok(cd) = std::fs::canonicalize(d) else {
            return false;
        };
        let under = |base: &Option<PathBuf>| base.as_ref().is_some_and(|b| cd.starts_with(b));
        let uid = rustix::process::getuid().as_raw();
        !under(&home)
            && !under(&cwd)
            && std::fs::metadata(&cd)
                .is_ok_and(|m| m.mode() & 0o022 == 0 && (m.uid() == uid || m.uid() == 0))
    };
    let on_path = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .filter(|d| d.is_absolute() && stable_dir(d))
            .map(|d| d.join("ms"))
            .find(|c| std::fs::canonicalize(c).is_ok_and(|r| r == real))
    });
    let p = on_path.unwrap_or(real);
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("morsec: the path of ms ({}) is not UTF-8", p.display()))
}

fn connector(opts: Options) -> Result<ClaudeConnector, String> {
    let home = home()?;
    let config_dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    if config_dir.as_ref().is_some_and(|d| !d.is_absolute()) {
        return Err("morsec: CLAUDE_CONFIG_DIR must be an absolute path".into());
    }
    let paths = Paths::for_home(&home, config_dir.as_deref());
    let socket = ms_ipc::default_socket_path().map_err(|e| e.to_string())?;
    let socket = socket
        .to_str()
        .ok_or("morsec: the socket path is not UTF-8")?
        .to_owned();
    let mut c = ClaudeConnector::new(paths, ms_path()?, socket);
    c.socket_env = std::env::var(ms_ipc::paths::SOCKET_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    c.opts = opts;
    Ok(c)
}

/// True when this process runs inside an agent session (or that can't be told). An agent must
/// not loosen its own sandbox (SPEC D10, SDLC-4).
fn inside_agent() -> Option<String> {
    use ms_session::{Caller, OsProcessTable, Resolver};
    match Resolver::new(OsProcessTable).resolve(std::process::id()) {
        Ok(Caller::Agent(s)) => Some(format!("{:?} session {}", s.agent, s.pid)),
        Ok(_) => None,
        Err(e) => Some(format!("unknown ({e})")),
    }
}

fn ask(body: RequestBody) -> ms_core::Result<ResponseBody> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Protocol(format!("starting the IPC client: {e}")))?;
    rt.block_on(async {
        let path = ms_ipc::default_socket_path()?;
        Client::connect(&path).await?.request(body).await
    })
}

const UNEXPECTED: &str = "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)";

/// (proxy port, CA PEM) from msd. Fails closed when msd is down.
fn daemon_status() -> Result<(u16, Option<String>, bool), String> {
    match ask(RequestBody::Status) {
        Ok(ResponseBody::Status {
            proxy_port,
            ca_pem,
            running,
            ..
        }) => {
            let port = proxy_port.ok_or(
                "morsec: this daemon has no swap proxy. Update ms and msd to the same version (ms --version)",
            )?;
            Ok((port, ca_pem, running != Some(false)))
        }
        Ok(ResponseBody::Error { message, .. }) => Err(message),
        Ok(_) => Err(UNEXPECTED.into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Every host in the user rules, as Claude Code `allowedDomains` entries.
fn rule_hosts(file: Option<&Path>) -> Result<Vec<String>, String> {
    let rules = match file {
        Some(p) => {
            let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            Rules::from_toml(&t, &p.display().to_string()).map_err(|e| e.to_string())?
        }
        None => match ask(RequestBody::RulesGet { key: None }) {
            Ok(ResponseBody::Rules { toml, .. }) => {
                Rules::from_toml(&toml, "the rules from msd").map_err(|e| e.to_string())?
            }
            Ok(ResponseBody::Error { message, .. }) => return Err(message),
            Ok(_) => return Err(UNEXPECTED.into()),
            Err(e) => return Err(e.to_string()),
        },
    };
    let mut hosts: Vec<String> = Vec::new();
    for rule in rules.keys.values() {
        for h in &rule.hosts {
            let s = h.to_string();
            if !hosts.contains(&s) {
                hosts.push(s);
            }
        }
    }
    hosts.sort();
    Ok(hosts)
}

/// Prints the changed lines of one file. Lines that only gained a comma are skipped, and string
/// values morsec didn't write are shown as "…", so a value of the user's own (a token in an env
/// entry or hook) never reaches the terminal or an agent's transcript.
fn show_file(path: &Path, before: Option<&str>, after: Option<&str>, safe: &[String]) {
    let safe = |s: &str| safe.iter().any(|x| x == s);
    let verb = match (before, after) {
        (None, Some(_)) => "create",
        (Some(_), None) => "remove",
        _ => "change",
    };
    say(&format!("{verb} {}:", path.display()));
    match changed_lines(before.unwrap_or(""), after.unwrap_or("")) {
        Some(lines) => {
            for l in significant(lines) {
                match l {
                    Line::Removed(n, t) => say(&format!("  -{n:>4} {}", redact(t, &safe))),
                    Line::Added(n, t) => say(&format!("  +{n:>4} {}", redact(t, &safe))),
                }
            }
        }
        None => say("  (too large to show line by line)"),
    }
}

/// Asks to go ahead. `--yes` skips; without a terminal nothing is changed.
fn confirm(yes: bool, what: &str) -> Result<bool, ExitCode> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(fail(&format!(
            "morsec: nothing changed. Re-run with --yes to {what} without a terminal"
        )));
    }
    print!("{}? [y/N] ", what[..1].to_uppercase() + &what[1..]);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| fail(&format!("morsec: {e}")))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

fn session_env(c: &ClaudeConnector) -> ExitCode {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(f) = std::env::var_os("CLAUDE_ENV_FILE").filter(|f| !f.is_empty()) else {
        return ExitCode::SUCCESS;
    };
    let line = session_env_line(&c.paths.shims);
    let res = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&f)
        .and_then(|mut file| file.write_all(line.as_bytes()));
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!(
            "morsec: could not add the shims to PATH ({}): {e}",
            Path::new(&f).display()
        )),
    }
}

fn list() -> ExitCode {
    let claude = match connector(Options::default()) {
        Ok(c) if c.is_partly_disconnected() => {
            "partly disconnected (run: ms disconnect claude-code)"
        }
        Ok(c) if c.is_connected() => "connected",
        Ok(_) => "not connected",
        Err(_) => "unknown (HOME is not set)",
    };
    say(&format!("claude-code  {claude}"));
    say("codex        not built yet (L13)");
    say("cursor       not built yet (L22)");
    say("gemini       not built yet (L22)");
    say("Connect one with: ms connect claude-code");
    ExitCode::SUCCESS
}

pub(crate) fn connect(a: &ConnectArgs) -> ExitCode {
    let Some(agent) = &a.agent else {
        return list();
    };
    if let Err(code) = agent_id(agent) {
        return code;
    }
    let opts = Options {
        with_mcp: a.with_mcp,
        wrap: a.wrap,
        statusline: a.statusline,
        force: a.force,
    };
    let mut c = match connector(opts) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    // A plain re-run keeps the opt-in parts the last connect used (security review S2);
    // dropping one is a partial disconnect, which is `ms disconnect`'s job.
    match c.previous_options() {
        Ok(p) => {
            c.opts.with_mcp |= p.with_mcp;
            c.opts.wrap |= p.wrap;
            c.opts.statusline |= p.statusline;
        }
        Err(e) if !a.session_env => return fail(&e.to_string()),
        Err(_) => {}
    }
    if a.session_env {
        return session_env(&c);
    }
    // Options that can loosen what the user set up are for the user, not an agent (SPEC D10).
    // --force replaces the user's own proxy or server; --wrap changes how every hook runs, and
    // while `ms run` is a stub a blocking hook would stop blocking (review R2).
    if (a.force || a.wrap)
        && let Some(who) = inside_agent()
    {
        let flag = if a.force { "--force" } else { "--wrap" };
        return fail(&format!(
            "morsec: {flag} changes settings you made yourself, so it can't run inside an agent session ({who}). Run it from your own terminal"
        ));
    }
    if a.wrap {
        eprintln!(
            "warning: --wrap runs your hooks and MCP servers through `ms run`, which is not built yet (L12): until it is, they fail, and a hook that blocks a tool stops blocking. Undo with: ms disconnect claude-code"
        );
    }
    let mut env = match c.ca_env() {
        Ok(e) => e,
        Err(e) => return fail(&e.to_string()),
    };
    // Keep the references an earlier connect wrote, unless this run names the same variable.
    let previous = match c.previous_env_refs() {
        Ok(p) => p,
        Err(e) => return fail(&e.to_string()),
    };
    let mut refs: Vec<(String, String)> = Vec::new();
    for pair in &a.env {
        let Some((name, value)) = pair.split_once('=') else {
            return fail(&format!(
                "morsec: --env takes NAME=ms://ref, e.g. --env STRIPE_API_KEY=ms://stripe/test (got {pair:?})"
            ));
        };
        if let Err(e) = ms_connect::claude::check_ref_env(name, value) {
            return fail(&format!("morsec: {e}"));
        }
        refs.retain(|(n, _)| n != name);
        refs.push((name.to_owned(), value.to_owned()));
    }
    env.extend(
        previous
            .into_iter()
            .filter(|(n, _)| !refs.iter().any(|(m, _)| m == n)),
    );
    env.extend(refs);
    let (port, ca_pem, running) = match daemon_status() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    c.ca_pem = ca_pem;
    #[cfg(debug_assertions)]
    let rules_file = a.rules.as_deref();
    #[cfg(not(debug_assertions))]
    let rules_file: Option<&Path> = None;
    let hosts = match rule_hosts(rules_file) {
        Ok(h) => h,
        Err(e) => return fail(&e),
    };
    let cfg = ConnectCfg {
        proxy_port: port,
        allowed_domains: hosts,
        env,
        shim_dir: Some(c.paths.shims.clone()),
    };
    let planned = match c.try_plan(&cfg) {
        Ok(p) => p,
        Err(e) => return fail(&e.to_string()),
    };
    for w in &planned.warnings {
        eprintln!("note: {}", terminal_safe(w));
    }
    if !running {
        eprintln!("note: morsec is stopped (ms stop); agents can't use keys until you resume");
    }
    if planned.diff.changes.is_empty() {
        say("Claude Code is already connected; nothing to change.");
        return ExitCode::SUCCESS;
    }
    let safe = c.display_safe(Some(&cfg));
    for ch in &planned.diff.changes {
        if ch.path == c.paths.settings || ch.path == c.paths.claude_json {
            show_file(&ch.path, ch.before.as_deref(), Some(&ch.after), &safe);
        } else {
            say(&format!("write {}", ch.path.display()));
        }
    }
    if a.dry_run {
        say("(dry run: nothing changed)");
        return ExitCode::SUCCESS;
    }
    match confirm(a.yes, "apply these changes") {
        Ok(true) => {}
        Ok(false) => {
            say("Nothing changed.");
            return ExitCode::FAILURE;
        }
        Err(code) => return code,
    }
    if let Err(e) = c.apply(&planned.diff) {
        return fail(&e.to_string());
    }
    say("Connected Claude Code. Restart open Claude Code sessions so every part picks it up.");
    say("Undo with: ms disconnect claude-code");
    ExitCode::SUCCESS
}

pub(crate) fn disconnect(a: &DisconnectArgs) -> ExitCode {
    if let Err(code) = agent_id(&a.agent) {
        return code;
    }
    if let Some(who) = inside_agent() {
        return fail(&format!(
            "morsec: an agent can't remove its own sandbox, so ms disconnect doesn't run inside an agent session ({who}). Run it from your own terminal"
        ));
    }
    let c = match connector(Options::default()) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let plan = match c.plan_remove() {
        Ok(Some(p)) => p,
        Ok(None) => {
            say("Claude Code is not connected; nothing to do.");
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e.to_string()),
    };
    let safe = c.display_safe(None);
    for f in &plan.files {
        show_file(&f.path, f.before.as_deref(), f.after.as_deref(), &safe);
    }
    if plan.state_after.is_some() {
        say(&format!(
            "keep {} (records what is left to undo)",
            c.paths.state.display()
        ));
    } else {
        say(&format!("remove {}", c.paths.state.display()));
    }
    for n in &plan.notes {
        eprintln!("note: {}", terminal_safe(n));
    }
    if a.dry_run {
        say("(dry run: nothing changed)");
        return ExitCode::SUCCESS;
    }
    match confirm(a.yes, "remove morsec from Claude Code") {
        Ok(true) => {}
        Ok(false) => {
            say("Nothing changed.");
            return ExitCode::FAILURE;
        }
        Err(code) => return code,
    }
    if let Err(e) = c.apply_remove(&plan) {
        return fail(&e.to_string());
    }
    if plan.state_after.is_some() {
        // Review R10: a partial disconnect is not a success.
        return fail(&format!(
            "morsec: partly disconnected. Your Claude Code settings are restored, but morsec's changes in {} are still there (see the note above). Fix that file, then run: ms disconnect claude-code",
            c.paths.claude_json.display()
        ));
    }
    say("Disconnected Claude Code; its settings are back as they were.");
    ExitCode::SUCCESS
}
