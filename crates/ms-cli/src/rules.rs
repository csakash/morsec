//! `ms rules`: show a key's effective rule, check a project file, and change a rule.
//!
//! The user rules come from msd (`RulesGet`), which verified their MAC; the project
//! `.morsec.toml` is merged here, so msd never reads a path a client names. Changes go to msd as a
//! proposed rule (`RulesProposeLoosen`, L07): msd classifies them, saves tightening at once, and
//! needs an approval to loosen (until L11, `--at-terminal` from your own terminal). With msd down,
//! or with `--rules <path>`, the file is read locally and labelled unverified; nothing is written.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use ms_core::{KeyName, Tier};
use ms_rules::store::read_limited;
use ms_rules::{
    Change, CommandPattern, HostPattern, KeyRule, PROJECT_FILE, ProjectRules, Rules, classify_rule,
};

use ms_ipc::{Client, ErrorCode, RequestBody, ResponseBody};

use crate::terminal_safe;

/// Largest rules file read by the CLI, bytes.
const MAX_FILE: u64 = 1 << 20;

/// `ms rules [<name>] [options]`
#[derive(Debug, Args)]
pub struct RulesArgs {
    /// Key to show or change, e.g. stripe/test. Without it, every key is listed.
    name: Option<String>,
    /// Rules file to read (default: the morsec data directory).
    #[arg(long, value_name = "PATH")]
    rules: Option<PathBuf>,
    /// Project file to merge (default: .morsec.toml from here up to the git root).
    #[arg(long, value_name = "PATH", conflicts_with = "no_project")]
    project: Option<PathBuf>,
    /// Ignore project files.
    #[arg(long)]
    no_project: bool,
    /// Validate a project .morsec.toml and exit.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["name", "rules", "project", "no_project"])]
    check: Option<PathBuf>,
    /// Propose adding a host (api.example.com or *.example.com).
    #[arg(long, value_name = "HOST")]
    add_host: Vec<String>,
    /// Propose removing a host.
    #[arg(long, value_name = "HOST")]
    remove_host: Vec<String>,
    /// Propose adding a command, as a JSON array: '["psql", "-c", "*"]'.
    #[arg(long, value_name = "JSON")]
    add_command: Vec<String>,
    /// Propose removing a command, as a JSON array.
    #[arg(long, value_name = "JSON")]
    remove_command: Vec<String>,
    /// Propose adding a project root a run key's commands may run in (an absolute directory).
    #[arg(long, value_name = "DIR")]
    add_root: Vec<PathBuf>,
    /// Propose removing a project root.
    #[arg(long, value_name = "DIR")]
    remove_root: Vec<PathBuf>,
    /// Propose letting a run key's value go into this environment variable (the command is
    /// then called with NAME=ms://<key>).
    #[arg(long, value_name = "NAME")]
    add_env: Vec<String>,
    /// Propose removing an environment variable name.
    #[arg(long, value_name = "NAME")]
    remove_env: Vec<String>,
    /// Propose a tier: test or production.
    #[arg(long, value_name = "TIER")]
    tier: Option<String>,
    /// Propose a session TTL in seconds.
    #[arg(long, value_name = "SECS")]
    ttl: Option<u64>,
    /// Propose read-only access.
    #[arg(long, conflicts_with = "writable")]
    read_only: bool,
    /// Propose read-write access.
    #[arg(long)]
    writable: bool,
    /// Loosening without Touch ID (until loop L11): confirm at your own terminal, outside any
    /// agent session.
    #[arg(long)]
    at_terminal: bool,
}

impl RulesArgs {
    fn has_changes(&self) -> bool {
        !self.add_host.is_empty()
            || !self.remove_host.is_empty()
            || !self.add_command.is_empty()
            || !self.remove_command.is_empty()
            || !self.add_root.is_empty()
            || !self.remove_root.is_empty()
            || !self.add_env.is_empty()
            || !self.remove_env.is_empty()
            || self.tier.is_some()
            || self.ttl.is_some()
            || self.read_only
            || self.writable
    }
}

/// Prints each line through the terminal filter, so file content can't inject escapes.
fn out(s: &str) {
    if s.is_empty() {
        println!();
    }
    for line in s.lines() {
        println!("{}", terminal_safe(line));
    }
}

fn err(s: &str) -> ExitCode {
    eprintln!("{}", terminal_safe(s));
    ExitCode::FAILURE
}

/// The default rules file: `~/Library/Application Support/morsec/rules.toml` on macOS,
/// `/var/lib/morsec/rules.toml` on Linux (docs/PLAN.md §3.5).
fn default_rules_path() -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or(
            "morsec: HOME is not set, so the rules file can't be found. Pass --rules <path>",
        )?;
        Ok(PathBuf::from(home).join("Library/Application Support/morsec/rules.toml"))
    } else {
        Ok(PathBuf::from("/var/lib/morsec/rules.toml"))
    }
}

/// `.morsec.toml` in `start` or a parent, up to and including the directory holding `.git`.
/// Outside a git repository nothing is found: a stray file in a parent directory (another user's
/// `/tmp`, the home directory) must not apply.
fn find_project_file(start: &Path) -> Option<PathBuf> {
    let mut found = None;
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(PROJECT_FILE);
        if found.is_none() && candidate.is_file() {
            found = Some(candidate);
        }
        if d.join(".git").exists() {
            return found;
        }
        dir = d.parent();
    }
    None
}

fn read_text(path: &Path) -> Result<String, String> {
    let bytes = read_limited(path, MAX_FILE).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidInput {
            return format!(
                "morsec: {} is a pipe or device, not a file. Save it to a regular file and pass that",
                path.display()
            );
        }
        format!(
            "morsec: can't read {}: {e}. Check the path and its permissions",
            path.display()
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        format!(
            "morsec: {} is not UTF-8. Save it as UTF-8 text",
            path.display()
        )
    })
}

/// Exit code for a change that can't be sent (sysexits EX_USAGE).
const EXIT_USAGE: u8 = 64;

/// Where the user rules came from.
enum Source {
    /// msd, which checked the MAC.
    Daemon,
    /// A local file read by `ms`, unverified.
    Local(PathBuf, &'static str),
}

impl Source {
    fn label(&self) -> String {
        match self {
            Source::Daemon => "verified by msd".into(),
            Source::Local(p, why) => format!("{} ({why}; MAC not checked by ms)", p.display()),
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: starting the IPC client: {e}"))
}

fn ask(body: RequestBody) -> ms_core::Result<ResponseBody> {
    let rt = runtime().map_err(ms_core::Error::Protocol)?;
    rt.block_on(async {
        let path = ms_ipc::default_socket_path()?;
        Client::connect(&path).await?.request(body).await
    })
}

/// The user rules: from msd, or (with `--rules`, or msd down) from a local file, unverified.
fn load_user_rules(a: &RulesArgs) -> Result<(Rules, Source), ExitCode> {
    let local = |path: PathBuf, why: &'static str| -> Result<(Rules, Source), ExitCode> {
        match read_text(&path) {
            Ok(t) => match Rules::from_toml(&t, &path.display().to_string()) {
                Ok(r) => Ok((r, Source::Local(path, why))),
                Err(e) => Err(err(&e.to_string())),
            },
            Err(_) if !path.exists() => Err(err(&format!(
                "morsec: no rules file at {}. Create it with: ms init",
                path.display()
            ))),
            Err(e) => Err(err(&e)),
        }
    };
    if let Some(p) = &a.rules {
        return local(p.clone(), "--rules");
    }
    match ask(RequestBody::RulesGet { key: None }) {
        Ok(ResponseBody::Rules { toml, notes, .. }) => {
            let r =
                Rules::from_toml(&toml, "the rules from msd").map_err(|e| err(&e.to_string()))?;
            for n in notes {
                out(&format!("note: {n}"));
            }
            Ok((r, Source::Daemon))
        }
        Ok(ResponseBody::Error { message, .. }) => Err(err(&message)),
        Ok(_) => Err(err(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)",
        )),
        Err(ms_core::Error::DaemonUnavailable { .. }) => {
            let path = default_rules_path().map_err(|e| err(&e))?;
            local(path, "msd is not running")
        }
        Err(e) => Err(err(&e.to_string())),
    }
}

/// Sends a proposed rule to msd.
fn propose(name: &KeyName, user: &Rules, proposed: KeyRule, at_terminal: bool) -> ExitCode {
    if at_terminal {
        match crate::tty::confirm_at_terminal(&format!(
            "Apply this change to {name} without Touch ID (until loop L11)?"
        )) {
            Ok(true) => {}
            Ok(false) => return err("Cancelled. Nothing was changed."),
            Err(e) => {
                return err(&format!(
                    "morsec: --at-terminal must be confirmed at your own terminal ({e})"
                ));
            }
        }
    }
    let mut one = Rules {
        version: user.version,
        ..Rules::default()
    };
    one.keys.insert(name.clone(), proposed);
    match ask(RequestBody::RulesProposeLoosen {
        key: name.clone(),
        rule: Some(one.to_toml()),
        at_terminal,
    }) {
        Ok(ResponseBody::Ok { message }) => {
            out(&message);
            ExitCode::SUCCESS
        }
        Ok(ResponseBody::Error { code, message }) => {
            if code == ErrorCode::NeedsApproval {
                eprintln!("{}", terminal_safe(&message));
                return ExitCode::FAILURE;
            }
            err(&message)
        }
        Ok(_) => err(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)",
        ),
        Err(e) => err(&e.to_string()),
    }
}

pub fn run(a: RulesArgs) -> ExitCode {
    if let Some(file) = &a.check {
        return check(file);
    }
    let name = match a.name.as_deref().map(KeyName::new).transpose() {
        Ok(n) => n,
        Err(e) => return err(&e.to_string()),
    };
    if a.has_changes() && name.is_none() {
        return err(
            "morsec: say which key to change, e.g. ms rules stripe/test --add-host api.stripe.com",
        );
    }

    let (user, verified) = match load_user_rules(&a) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let project_path = if a.no_project {
        None
    } else if let Some(p) = &a.project {
        Some(p.clone())
    } else {
        std::env::current_dir()
            .ok()
            .and_then(|d| find_project_file(&d))
    };
    let (effective, project_err) = match &project_path {
        Some(p) => {
            let file = p.display().to_string();
            match read_text(p) {
                Ok(t) => {
                    let (r, e) = ms_rules::effective(&user, Some(&t), &file);
                    (r, e.map(|e| e.to_string()))
                }
                // An unreadable project file is treated like an invalid one: fail closed.
                Err(e) => (ms_rules::project::disable_all(&user, &file), Some(e)),
            }
        }
        None => (user.clone(), None),
    };

    out(&format!(
        "rules version {} · {}",
        user.version,
        verified.label()
    ));
    match &project_path {
        Some(p) => out(&format!("project rules: {}", p.display())),
        None => out("project rules: none"),
    }
    if let Some(e) = &project_err {
        eprintln!("{}", terminal_safe(e));
    }
    for n in &effective.notes {
        out(&format!("note: {n}"));
    }

    let Some(name) = name else {
        list(&effective);
        return ExitCode::SUCCESS;
    };
    let Some(rule) = effective.keys.get(&name) else {
        return err(&format!(
            "morsec: no key named {name}. List keys with: ms rules"
        ));
    };
    out("");
    show(&name, rule);

    if a.has_changes() {
        // Changes apply to your rules, not to the project-merged view.
        let current = &user.keys[&name];
        let proposed = match apply_edits(&name, current, &a) {
            Ok(r) => r,
            Err(e) => return err(&e),
        };
        let change = classify_rule(Some(current), Some(&proposed));
        out("");
        out("proposed:");
        show(&name, &proposed);
        out("");
        match change {
            Change::Same => {
                out("no change.");
                return ExitCode::SUCCESS;
            }
            Change::Tighten => out("this change tightens the rule."),
            Change::Loosen => out("this change loosens the rule, so it needs an approval."),
        }
        if !matches!(verified, Source::Daemon) {
            eprintln!(
                "morsec: changes are applied by msd, and these rules were read locally ({}). Start msd (ms start) and run this again without --rules",
                verified.label()
            );
            return ExitCode::from(EXIT_USAGE);
        }
        return propose(&name, &user, proposed, a.at_terminal);
    }
    ExitCode::SUCCESS
}

fn check(file: &Path) -> ExitCode {
    let text = match read_text(file) {
        Ok(t) => t,
        Err(e) => return err(&e),
    };
    match ProjectRules::from_toml(&text, &file.display().to_string()) {
        Ok(p) => {
            out(&format!(
                "{} is valid: restricts {} key(s). Project rules can only tighten your rules.",
                file.display(),
                p.keys.len()
            ));
            ExitCode::SUCCESS
        }
        Err(e) => err(&e.to_string()),
    }
}

fn mode_str(r: &KeyRule) -> &'static str {
    match r.mode {
        ms_core::Mode::Swap => "swap",
        ms_core::Mode::Run => "run",
        ms_core::Mode::Mint => "mint",
    }
}

fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Test => "test",
        Tier::Production => "production",
    }
}

fn targets(r: &KeyRule) -> String {
    if r.allows_nothing() {
        return "nothing allowed".into();
    }
    match r.mode {
        ms_core::Mode::Swap => format!("{} host(s)", r.hosts.len()),
        ms_core::Mode::Run => format!("{} command(s)", r.commands.len()),
        ms_core::Mode::Mint => format!("{} scope(s)", r.mint_scopes.len()),
    }
}

fn list(rules: &Rules) {
    if rules.keys.is_empty() {
        out("no keys. Add one with: ms add <name>");
        return;
    }
    out("");
    out(&format!(
        "{:<32} {:<5} {:<11} {}",
        "KEY", "MODE", "TIER", "ALLOWS"
    ));
    for (name, r) in &rules.keys {
        out(&format!(
            "{:<32} {:<5} {:<11} {}",
            name.as_str(),
            mode_str(r),
            tier_str(r.tier),
            targets(r)
        ));
    }
}

fn show(name: &KeyName, r: &KeyRule) {
    out(name.as_str());
    out(&format!("  mode       {}", mode_str(r)));
    let tier_note = match r.tier {
        Tier::Test => "never prompts",
        Tier::Production => "every use needs an approval",
    };
    out(&format!("  tier       {} ({tier_note})", tier_str(r.tier)));
    let list = |label: &str, items: Vec<String>| {
        if items.is_empty() {
            out(&format!("  {label:<10} none"));
        }
        for (i, it) in items.iter().enumerate() {
            let l = if i == 0 { label } else { "" };
            out(&format!("  {l:<10} {it}"));
        }
    };
    match r.mode {
        ms_core::Mode::Swap => {}
        ms_core::Mode::Run => {
            list(
                "commands",
                r.commands.iter().map(ToString::to_string).collect(),
            );
            list(
                "roots",
                r.roots.iter().map(|p| p.display().to_string()).collect(),
            );
            list("env", r.env.clone());
        }
        ms_core::Mode::Mint => list("scopes", r.mint_scopes.clone()),
    }
    if r.mode == ms_core::Mode::Swap || !r.hosts.is_empty() {
        list("hosts", r.hosts.iter().map(ToString::to_string).collect());
    }
    out(&format!("  ttl        {} s", r.session_ttl_secs));
    out(&format!(
        "  read-only  {}",
        if r.read_only { "yes" } else { "no" }
    ));
    if r.allows_nothing() {
        out("  (this key allows nothing until you add a target)");
    }
}

fn parse_command(json: &str) -> Result<CommandPattern, String> {
    let argv: Vec<String> = serde_json::from_str(json).map_err(|_| {
        format!(
            "morsec: --add-command/--remove-command takes a JSON array of strings, e.g. '[\"psql\", \"-c\", \"*\"]', not {json:?}"
        )
    })?;
    CommandPattern::parse(&argv).map_err(|e| format!("morsec: {e}"))
}

/// A root as given on the command line: made absolute against the current directory and
/// resolved (symlinks, `..`) when it exists, so the rule names the real directory.
fn root_arg(d: &Path) -> Result<PathBuf, String> {
    let abs = if d.is_absolute() {
        d.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("morsec: can't read the current directory: {e}"))?
            .join(d)
    };
    let p = std::fs::canonicalize(&abs).unwrap_or(abs);
    ms_rules::validate_root(&p).map_err(|e| format!("morsec: {e}"))?;
    Ok(p)
}

fn apply_edits(name: &KeyName, current: &KeyRule, a: &RulesArgs) -> Result<KeyRule, String> {
    let mut r = current.clone();
    for h in &a.add_host {
        r.hosts
            .push(HostPattern::parse(h).map_err(|e| format!("morsec: {e}"))?);
    }
    for h in &a.remove_host {
        let p = HostPattern::parse(h).map_err(|e| format!("morsec: {e}"))?;
        r.hosts.retain(|x| *x != p);
    }
    for c in &a.add_command {
        r.commands.push(parse_command(c)?);
    }
    for c in &a.remove_command {
        let p = parse_command(c)?;
        r.commands.retain(|x| *x != p);
    }
    for d in &a.add_root {
        r.roots.push(root_arg(d)?);
    }
    for d in &a.remove_root {
        let p = root_arg(d)?;
        r.roots.retain(|x| *x != p);
    }
    for n in &a.add_env {
        ms_rules::validate_env_name(n).map_err(|e| format!("morsec: {e}"))?;
        r.env.push(n.clone());
    }
    for n in &a.remove_env {
        r.env.retain(|x| x != n);
    }
    if let Some(t) = &a.tier {
        r.tier = match t.as_str() {
            "test" => Tier::Test,
            "production" => Tier::Production,
            _ => return Err("morsec: --tier is test or production".into()),
        };
    }
    if let Some(ttl) = a.ttl {
        r.session_ttl_secs = ttl;
    }
    if a.read_only {
        r.read_only = true;
    }
    if a.writable {
        r.read_only = false;
    }
    // Same limits and per-mode checks as the file.
    r.normalise("your proposed change", name)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=project discovery stops at the git root, so a .morsec.toml above the repository
    // (someone else's directory) is never picked up; fails_when=it walks past .git;
    // no_claim=symlinked directories
    #[test]
    fn project_lookup_stops_at_git_root() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        let sub = repo.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(d.path().join(PROJECT_FILE), "").unwrap();
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(find_project_file(&sub), None);
        std::fs::write(repo.join(PROJECT_FILE), "").unwrap();
        assert_eq!(find_project_file(&sub), Some(repo.join(PROJECT_FILE)));
        // Outside any repository nothing is picked up, even with a file right here.
        let loose = d.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::write(loose.join(PROJECT_FILE), "").unwrap();
        assert_eq!(find_project_file(&loose), None);
    }
}
