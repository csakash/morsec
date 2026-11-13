//! `ms rules`: show a key's effective rule, check a project file, and preview changes.
//!
//! IPC v1 has no rules response and `RulesProposeLoosen` carries no rule, so this command reads
//! the local files and never writes them: writing needs the vault MAC key, which only `msd` holds.
//! It says so in its output, and the daemon verifies the MAC on every load (L07).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use ms_core::{KeyName, Tier};
use ms_rules::store::read_limited;
use ms_rules::{
    Change, CommandPattern, HostPattern, KeyRule, PROJECT_FILE, ProjectRules, Rules, classify_rule,
};

use crate::{EXIT_NOT_BUILT, terminal_safe};

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
}

impl RulesArgs {
    fn has_changes(&self) -> bool {
        !self.add_host.is_empty()
            || !self.remove_host.is_empty()
            || !self.add_command.is_empty()
            || !self.remove_command.is_empty()
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

    let rules_path = match a.rules.clone().map(Ok).unwrap_or_else(default_rules_path) {
        Ok(p) => p,
        Err(e) => return err(&e),
    };
    let user = match read_text(&rules_path) {
        Ok(t) => match Rules::from_toml(&t, &rules_path.display().to_string()) {
            Ok(r) => r,
            Err(e) => return err(&e.to_string()),
        },
        Err(_) if !rules_path.exists() => {
            return err(&format!(
                "morsec: no rules file at {}. Create it with: ms init",
                rules_path.display()
            ));
        }
        Err(e) => return err(&e),
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
        "rules version {} · {} (MAC not checked by ms; msd verifies it)",
        user.version,
        rules_path.display()
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
            Change::Loosen => {
                out("this change loosens the rule; applying it will need an approval (Touch ID).")
            }
        }
        eprintln!(
            "morsec: changes are applied by msd, which is not built yet (planned in loop L07 daemon)."
        );
        return ExitCode::from(EXIT_NOT_BUILT);
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
        ms_core::Mode::Run => list(
            "commands",
            r.commands.iter().map(ToString::to_string).collect(),
        ),
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
