//! The rules model and its TOML file format.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ms_core::{KeyName, Mode, Tier};
use serde::{Deserialize, Serialize};

use crate::error::{Result, RulesError};
use crate::pattern::{CommandPattern, HostPattern, MAX_COMMANDS, MAX_HOSTS};

/// Default approval/grant lifetime within a session, seconds.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600;
/// Longest allowed session TTL, seconds (one day).
pub const MAX_SESSION_TTL_SECS: u64 = 86_400;
/// Most mint scopes in one rule.
pub const MAX_MINT_SCOPES: usize = 64;
/// Longest mint scope, bytes.
pub const MAX_SCOPE_LEN: usize = 128;
/// Most keys in one rules file.
pub const MAX_KEYS: usize = 4096;
/// Most project roots in one rule.
pub const MAX_ROOTS: usize = 64;
/// Longest project root, bytes.
pub const MAX_ROOT_LEN: usize = 1024;
/// Most environment variable names in one rule.
pub const MAX_ENV_NAMES: usize = 32;

/// What one key may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRule {
    /// How the key is used. A request for another mechanism is denied.
    pub mode: Mode,
    /// Production keys need an approval for every use.
    pub tier: Tier,
    /// Hosts the key may be sent to (swap; run adapters may also bind a host). Empty means no
    /// host is allowed, never "any host": adapters that read this (L15, L16) must keep that.
    pub hosts: Vec<HostPattern>,
    /// Commands the key may be used with (run only).
    pub commands: Vec<CommandPattern>,
    /// Scopes a credential may be minted with (mint only).
    pub mint_scopes: Vec<String>,
    /// How long an approval or grant lasts within a session, seconds. Used by the approver and
    /// token expiry (L11); `decide` has no clock.
    pub session_ttl_secs: u64,
    /// Run adapters must use read-only access (for example `default_transaction_read_only`).
    pub read_only: bool,
    /// Project directories the key's commands may run in (run only, L12). Absolute and
    /// normalised. Empty means nowhere: a run key without roots can't run anything.
    pub roots: Vec<PathBuf>,
    /// Environment variables the key's value may be put in for its commands (run only, L12):
    /// a call may set one of these to exactly `ms://<this key>`. Empty means none.
    pub env: Vec<String>,
}

impl KeyRule {
    /// A rule for `mode` and `tier` that allows nothing yet (fail closed until targets are added).
    pub fn new(mode: Mode, tier: Tier) -> Self {
        Self {
            mode,
            tier,
            hosts: Vec::new(),
            commands: Vec::new(),
            mint_scopes: Vec::new(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            read_only: false,
            roots: Vec::new(),
            env: Vec::new(),
        }
    }

    /// True when the rule can never allow a request.
    pub fn allows_nothing(&self) -> bool {
        match self.mode {
            Mode::Swap => self.hosts.is_empty(),
            Mode::Run => self.commands.is_empty(),
            Mode::Mint => self.mint_scopes.is_empty(),
        }
    }

    /// Checks limits and per-mode fields. Sorts and deduplicates the sets so equal rules compare
    /// equal.
    pub fn normalise(mut self, file: &str, key: &KeyName) -> Result<Self> {
        let bad = |why: String| RulesError::invalid(file, format!("key {key}: {why}"));
        if is_reserved(key) {
            return Err(bad(
                "names under morsec/ are morsec's own keys (rules and receipts MACs) and can't have rules"
                    .into(),
            ));
        }
        if self.hosts.len() > MAX_HOSTS {
            return Err(bad(format!("more than {MAX_HOSTS} hosts")));
        }
        if self.commands.len() > MAX_COMMANDS {
            return Err(bad(format!("more than {MAX_COMMANDS} commands")));
        }
        if self.mint_scopes.len() > MAX_MINT_SCOPES {
            return Err(bad(format!("more than {MAX_MINT_SCOPES} mint scopes")));
        }
        if self.mode != Mode::Run && !self.commands.is_empty() {
            return Err(bad("commands are only allowed on a run-mode key".into()));
        }
        if self.roots.len() > MAX_ROOTS {
            return Err(bad(format!("more than {MAX_ROOTS} roots")));
        }
        if self.mode != Mode::Run && !self.roots.is_empty() {
            return Err(bad("roots are only allowed on a run-mode key".into()));
        }
        for r in &self.roots {
            validate_root(r).map_err(&bad)?;
        }
        if self.env.len() > MAX_ENV_NAMES {
            return Err(bad(format!("more than {MAX_ENV_NAMES} env names")));
        }
        if self.mode != Mode::Run && !self.env.is_empty() {
            return Err(bad("env names are only allowed on a run-mode key".into()));
        }
        for n in &self.env {
            validate_env_name(n).map_err(&bad)?;
        }
        if self.mode != Mode::Mint && !self.mint_scopes.is_empty() {
            return Err(bad("mint_scopes are only allowed on a mint-mode key".into()));
        }
        for s in &self.mint_scopes {
            validate_scope(s).map_err(&bad)?;
        }
        if !(1..=MAX_SESSION_TTL_SECS).contains(&self.session_ttl_secs) {
            return Err(bad(format!(
                "session_ttl_secs must be 1 to {MAX_SESSION_TTL_SECS}"
            )));
        }
        self.hosts.sort();
        self.hosts.dedup();
        self.commands.sort();
        self.commands.dedup();
        self.mint_scopes.sort();
        self.mint_scopes.dedup();
        self.roots.sort();
        self.roots.dedup();
        self.env.sort();
        self.env.dedup();
        Ok(self)
    }
}

/// Keys under `morsec/` (the rules and receipts MAC keys) are morsec's own. No rule may name them,
/// so no approval can ever send one to a host or a command.
pub fn is_reserved(key: &KeyName) -> bool {
    key.as_str() == "morsec" || key.as_str().starts_with("morsec/")
}

/// A project root must be an absolute, normalised UTF-8 path (no `.`, `..`, `//` or trailing
/// `/`), not `/` itself, without control characters.
pub fn validate_root(p: &Path) -> std::result::Result<(), String> {
    let Some(s) = p.to_str() else {
        return Err("a root must be valid UTF-8".into());
    };
    if s.is_empty() || s.len() > MAX_ROOT_LEN || s.chars().any(char::is_control) {
        return Err(format!(
            "root {s:?} must be 1 to {MAX_ROOT_LEN} bytes without control characters"
        ));
    }
    if !s.starts_with('/') {
        return Err(format!("root {s:?} must be an absolute path"));
    }
    if s == "/" {
        return Err("root \"/\" would allow every directory; name a project directory".into());
    }
    if s.ends_with('/')
        || s[1..]
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!(
            "root {s:?} must be normalised (no '.', '..', '//' or trailing '/')"
        ));
    }
    Ok(())
}

/// An environment variable name: `[A-Za-z_][A-Za-z0-9_]{0,127}`. (`ms-run` refuses names that
/// change how programs load code on top of this.)
pub fn validate_env_name(n: &str) -> std::result::Result<(), String> {
    let b = n.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "env name {n:?} must be letters, digits and '_', not starting with a digit"
        ))
    }
}

/// True when `path` is `root` or inside it, comparing whole components.
pub fn within_root(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

pub(crate) fn validate_scope(s: &str) -> std::result::Result<(), String> {
    if s.is_empty() || s.len() > MAX_SCOPE_LEN || !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "mint scope {s:?} must be 1 to {MAX_SCOPE_LEN} printable ASCII characters without spaces"
        ));
    }
    Ok(())
}

/// The effective rules the policy function reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// Monotonic version, recorded in every receipt. Increases on every saved change.
    pub version: u64,
    /// Per-key rules. A key with no entry is denied.
    pub keys: BTreeMap<KeyName, KeyRule>,
    /// `ms stop` is in effect (runtime state, never stored in the file).
    pub stopped: bool,
    /// The rules file failed its integrity check (runtime state): everything is denied.
    pub tampered: bool,
    /// Human-readable notes from the project merge, for `ms rules` (runtime state).
    pub notes: Vec<String>,
}

impl Rules {
    /// Rules that deny every request with `RulesTampered`. The daemon uses this when loading
    /// fails, so a broken or forged file never falls back to anything permissive.
    pub fn tampered() -> Self {
        Self {
            tampered: true,
            ..Self::default()
        }
    }

    /// Parses the user rules file format. `file` names the file in errors.
    pub fn from_toml(text: &str, file: &str) -> Result<Self> {
        let raw: RulesFile =
            toml::from_str(text).map_err(|e| RulesError::invalid(file, e.to_string()))?;
        if raw.version == 0 {
            return Err(RulesError::invalid(file, "version must be 1 or more"));
        }
        if raw.keys.len() > MAX_KEYS {
            return Err(RulesError::invalid(
                file,
                format!("more than {MAX_KEYS} keys"),
            ));
        }
        let mut keys = BTreeMap::new();
        for (name, r) in raw.keys {
            let rule = r.into_rule(file, &name)?;
            keys.insert(name, rule);
        }
        Ok(Self {
            version: raw.version,
            keys,
            ..Self::default()
        })
    }

    /// The file format. Runtime state (`stopped`, `tampered`, `notes`) is not written.
    pub fn to_toml(&self) -> String {
        let raw = RulesFile {
            version: self.version,
            keys: self
                .keys
                .iter()
                .map(|(k, r)| (k.clone(), KeyRuleFile::from_rule(r)))
                .collect(),
        };
        // Serializing plain strings, integers, bools and enums into TOML cannot fail.
        toml::to_string(&raw).unwrap_or_else(|e| unreachable!("rules serialize: {e}"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    version: u64,
    #[serde(default)]
    keys: BTreeMap<KeyName, KeyRuleFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyRuleFile {
    mode: Mode,
    tier: Tier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    commands: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mint_scopes: Vec<String>,
    #[serde(default = "default_ttl")]
    session_ttl_secs: u64,
    #[serde(default)]
    read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    env: Vec<String>,
}

fn default_ttl() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}

pub(crate) fn parse_hosts(raw: &[String], file: &str, key: &KeyName) -> Result<Vec<HostPattern>> {
    if raw.len() > MAX_HOSTS {
        return Err(RulesError::invalid(
            file,
            format!("key {key}: more than {MAX_HOSTS} hosts"),
        ));
    }
    raw.iter()
        .map(|h| {
            HostPattern::parse(h).map_err(|e| RulesError::invalid(file, format!("key {key}: {e}")))
        })
        .collect()
}

pub(crate) fn parse_commands(
    raw: &[Vec<String>],
    file: &str,
    key: &KeyName,
) -> Result<Vec<CommandPattern>> {
    if raw.len() > MAX_COMMANDS {
        return Err(RulesError::invalid(
            file,
            format!("key {key}: more than {MAX_COMMANDS} commands"),
        ));
    }
    raw.iter()
        .map(|c| {
            CommandPattern::parse(c)
                .map_err(|e| RulesError::invalid(file, format!("key {key}: {e}")))
        })
        .collect()
}

impl KeyRuleFile {
    fn into_rule(self, file: &str, key: &KeyName) -> Result<KeyRule> {
        KeyRule {
            mode: self.mode,
            tier: self.tier,
            hosts: parse_hosts(&self.hosts, file, key)?,
            commands: parse_commands(&self.commands, file, key)?,
            mint_scopes: self.mint_scopes,
            session_ttl_secs: self.session_ttl_secs,
            read_only: self.read_only,
            roots: self.roots.into_iter().map(PathBuf::from).collect(),
            env: self.env,
        }
        .normalise(file, key)
    }

    fn from_rule(r: &KeyRule) -> Self {
        Self {
            mode: r.mode,
            tier: r.tier,
            hosts: r.hosts.iter().map(ToString::to_string).collect(),
            commands: r.commands.iter().map(CommandPattern::to_strings).collect(),
            mint_scopes: r.mint_scopes.clone(),
            session_ttl_secs: r.session_ttl_secs,
            read_only: r.read_only,
            roots: r
                .roots
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            env: r.env.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 3

[keys."stripe/test"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com", "*.stripe.com"]

[keys."pg/production"]
mode = "run"
tier = "production"
commands = [["psql", "-c", "*"], ["pg_dump", "**"]]
session_ttl_secs = 600
read_only = true
roots = ["/Users/me/code/app", "/Users/me/code/api"]
env = ["PGPASSWORD", "DATABASE_URL"]

[keys."aws/dev"]
mode = "mint"
tier = "test"
mint_scopes = ["s3:read"]
"#;

    // protects=the documented file format parses into the model and writes back unchanged;
    // fails_when=a field is lost, reordered sets compare unequal, or runtime state is written;
    // no_claim=the MAC (store tests)
    #[test]
    fn parse_and_roundtrip() {
        let r = Rules::from_toml(SAMPLE, "rules.toml").unwrap();
        assert_eq!(r.version, 3);
        let pg = &r.keys[&KeyName::new("pg/production").unwrap()];
        assert_eq!(pg.mode, Mode::Run);
        assert_eq!(pg.tier, Tier::Production);
        assert_eq!(pg.session_ttl_secs, 600);
        assert!(pg.read_only);
        assert_eq!(pg.commands.len(), 2);
        assert_eq!(
            pg.roots,
            [
                PathBuf::from("/Users/me/code/api"),
                PathBuf::from("/Users/me/code/app")
            ]
        );
        assert_eq!(pg.env, ["DATABASE_URL", "PGPASSWORD"]);
        let stripe = &r.keys[&KeyName::new("stripe/test").unwrap()];
        assert_eq!(stripe.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
        let mut with_state = r.clone();
        with_state.stopped = true;
        with_state.notes.push("x".into());
        let text = with_state.to_toml();
        assert!(
            !text.contains("stopped") && !text.contains("notes"),
            "{text}"
        );
        assert_eq!(Rules::from_toml(&text, "rules.toml").unwrap(), r);
    }

    // protects=malformed or over-broad rule files are rejected, never half-loaded;
    // fails_when=any of these parses; no_claim=every possible malformed file
    #[test]
    fn rejects_bad_files() {
        let cases = [
            "version = 0",
            "keys = {}",
            "version = 1\nextra = 1",
            "version = 1\n[keys.\"Bad\"]\nmode = \"swap\"\ntier = \"test\"",
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\nhost = [\"a.com\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\nhosts = [\"*\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\ncommands = [[\"x\"]]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nmint_scopes = [\"x\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nsession_ttl_secs = 0",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nsession_ttl_secs = 86401",
            "version = 1\n[keys.\"a\"]\nmode = \"mint\"\ntier = \"test\"\nmint_scopes = [\"a b\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"staging\"",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\ncommands = [[]]",
            "version = 1\n[keys.\"morsec/rules-mac\"]\nmode = \"run\"\ntier = \"production\"\ncommands = [[\"printenv\"]]",
            "version = 1\n[keys.\"morsec\"]\nmode = \"swap\"\ntier = \"test\"",
            // Roots: run keys only, absolute, normalised, never "/".
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\nroots = [\"/x\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"rel/dir\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/a/../b\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/a/./b\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/a//b\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/a/\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nroots = [\"/a\\nb\"]",
            // Env names: run keys only, valid names.
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\nenv = [\"X\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nenv = [\"1X\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nenv = [\"A-B\"]",
            "version = 1\n[keys.\"a\"]\nmode = \"run\"\ntier = \"test\"\nenv = [\"\"]",
        ];
        for c in cases {
            assert!(Rules::from_toml(c, "rules.toml").is_err(), "accepted {c:?}");
        }
    }

    // protects=error text from a hostile file can't carry terminal escapes; fails_when=a raw ESC
    // or newline reaches the message; no_claim=CLI output (cli tests)
    #[test]
    fn error_text_is_escaped() {
        let evil =
            "version = 1\n[keys.\"a\"]\nmode = \"swap\"\ntier = \"test\"\nhosts = [\"\u{1b}[2J\"]";
        let msg = Rules::from_toml(evil, "rules.toml")
            .unwrap_err()
            .to_string();
        assert!(!msg.contains('\u{1b}') && !msg.contains('\n'), "{msg}");
    }
}
