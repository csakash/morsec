//! `ms connect codex` and `ms disconnect codex` (L13). See `SPEC.md`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ms_connect::codex::{self, CodexConnector, McpRef, Options, Paths};
use ms_connect::{ConnectCfg, Connector};

use crate::connect::{
    ConnectArgs, DisconnectArgs, confirm, daemon_status, fail, home, inside_agent, ms_path, say,
};
use crate::terminal_safe;

pub(crate) fn connector(opts: Options) -> Result<CodexConnector, String> {
    let home = home()?;
    let codex_home = std::env::var_os("CODEX_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    if codex_home.as_ref().is_some_and(|d| !d.is_absolute()) {
        return Err("morsec: CODEX_HOME must be an absolute path".into());
    }
    let paths = Paths::for_home(&home, codex_home.as_deref());
    let mut c = CodexConnector::new(paths, ms_path()?);
    c.socket_env = std::env::var(ms_ipc::paths::SOCKET_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    c.opts = opts;
    Ok(c)
}

/// The `ms connect` list entry.
pub(crate) fn list_status() -> &'static str {
    match connector(Options::default()) {
        Ok(c) if c.is_connected() => "connected",
        Ok(_) => "not connected",
        Err(_) => "unknown (HOME is not set)",
    }
}

/// Prints the changed lines of `config.toml`, with values morsec didn't write shown as "…"
/// (SPEC D9).
fn show_config(path: &Path, before: Option<&str>, after: Option<&str>, safe: &[String]) {
    let f =
        ms_connect::view::settings_file(path, before, after, ms_connect::view::Syntax::Toml, safe);
    for l in ms_connect::view::terminal_lines(&f) {
        say(&l);
    }
}

pub(crate) fn connect(a: &ConnectArgs) -> ExitCode {
    if a.wrap || a.statusline || a.session_env {
        return fail(
            "morsec: --wrap and --statusline are for claude-code; Codex gets references through --env and --mcp-env",
        );
    }
    let mut c = match connector(Options {
        with_mcp: a.with_mcp,
        force: a.force,
    }) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    // A plain re-run keeps what the last connect set up (SPEC D11).
    match c.previous_options() {
        Ok(p) => c.opts.with_mcp |= p.with_mcp,
        Err(e) => return fail(&e.to_string()),
    }
    // --force replaces settings the user made; that is for the user, not an agent (SPEC D10).
    if a.force
        && let Some(who) = inside_agent()
    {
        return fail(&format!(
            "morsec: --force changes settings you made yourself, so it can't run inside an agent session ({who}). Run it from your own terminal"
        ));
    }
    let mut refs: Vec<(String, String)> = Vec::new();
    for pair in &a.env {
        let Some((name, value)) = pair.split_once('=') else {
            return fail(&format!(
                "morsec: --env takes NAME=ms://ref, e.g. --env STRIPE_API_KEY=ms://stripe/test (got {pair:?})"
            ));
        };
        if let Err(e) = codex::check_ref_env(name, value) {
            return fail(&format!("morsec: {e}"));
        }
        refs.retain(|(n, _)| n != name);
        refs.push((name.to_owned(), value.to_owned()));
    }
    let mut mcp: Vec<McpRef> = Vec::new();
    for s in &a.mcp_env {
        match McpRef::parse(s) {
            Ok(r) => {
                mcp.retain(|x| !(x.server == r.server && x.name == r.name));
                mcp.push(r);
            }
            Err(e) => return fail(&format!("morsec: {e}")),
        }
    }
    // Keep the references an earlier connect wrote, unless this run names the same variable.
    let (prev_env, prev_mcp) = match (c.previous_env_refs(), c.previous_mcp_refs()) {
        (Ok(e), Ok(m)) => (e, m),
        (Err(e), _) | (_, Err(e)) => return fail(&e.to_string()),
    };
    let mut env: Vec<(String, String)> = prev_env
        .into_iter()
        .filter(|(n, _)| !refs.iter().any(|(m, _)| m == n))
        .collect();
    env.extend(refs);
    c.mcp_refs = prev_mcp
        .into_iter()
        .filter(|p| !mcp.iter().any(|r| r.server == p.server && r.name == p.name))
        .collect();
    c.mcp_refs.extend(mcp);

    let (port, ca_pem, running) = match daemon_status() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    c.ca_pem = ca_pem;
    let cfg = ConnectCfg {
        proxy_port: port,
        allowed_domains: Vec::new(),
        env,
        shim_dir: None,
    };
    let planned = match c.try_plan(&cfg) {
        Ok(p) => p,
        Err(e) => return fail(&e.to_string()),
    };
    for w in &planned.warnings {
        eprintln!("note: {}", terminal_safe(w));
    }
    if std::env::var_os("CODEX_HOME").is_some_and(|d| !d.is_empty()) {
        eprintln!(
            "note: CODEX_HOME is set, so morsec edits {}. The Codex app may still read ~/.codex/config.toml",
            terminal_safe(&c.paths.config.display().to_string())
        );
    }
    if !running {
        eprintln!("note: morsec is stopped (ms stop); agents can't use keys until you resume");
    }
    if planned.diff.changes.is_empty() {
        say("Codex is already connected; nothing to change.");
        return ExitCode::SUCCESS;
    }
    let safe = c.display_safe(Some(&cfg));
    for ch in &planned.diff.changes {
        if ch.path == c.paths.config {
            show_config(&ch.path, ch.before.as_deref(), Some(&ch.after), &safe);
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
    say("Connected Codex (CLI, app and IDE). Restart open Codex sessions to pick it up.");
    say("Undo with: ms disconnect codex");
    ExitCode::SUCCESS
}

pub(crate) fn disconnect(a: &DisconnectArgs) -> ExitCode {
    if let Some(who) = inside_agent() {
        return fail(&format!(
            "morsec: an agent can't remove morsec from its own setup, so ms disconnect doesn't run inside an agent session ({who}). Run it from your own terminal"
        ));
    }
    let c = match connector(Options::default()) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let plan = match c.plan_remove() {
        Ok(Some(p)) => p,
        Ok(None) => {
            say("Codex is not connected; nothing to do.");
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e.to_string()),
    };
    let safe = c.display_safe(None);
    if let Some((before, after)) = &plan.config {
        show_config(&c.paths.config, before.as_deref(), after.as_deref(), &safe);
    }
    say(&format!("remove {}", c.paths.state.display()));
    for n in &plan.notes {
        eprintln!("note: {}", terminal_safe(n));
    }
    if a.dry_run {
        say("(dry run: nothing changed)");
        return ExitCode::SUCCESS;
    }
    match confirm(a.yes, "remove morsec from Codex") {
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
    if plan.notes.is_empty() {
        say("Disconnected Codex; its config is back as it was.");
    } else {
        say("Disconnected Codex; morsec's settings are removed (see the notes above).");
    }
    ExitCode::SUCCESS
}
