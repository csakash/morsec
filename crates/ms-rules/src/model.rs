//! The rules model and its TOML file format.

use std::collections::BTreeMap;

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

/// What one key may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRule {
    /// How the key is used. A request for another mechanism is denied.
    pub mode: Mode,
    /// Production keys need an approval for every use.
    pub tier: Tier,
    /// Hosts the key may be sent to (swap; run adapters may also bind a host).
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
        Ok(self)
    }
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
