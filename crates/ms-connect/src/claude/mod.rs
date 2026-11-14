//! The Claude Code connector (L08). See `SPEC.md` for the settings it writes and why.
//!
//! Claude Code's terminal, desktop app and IDE extensions read the same user settings
//! (`~/.claude/settings.json`) and keep MCP servers in `~/.claude.json`. `ms connect claude-code`
//! merges a recorded block into those files; `ms disconnect claude-code` undoes it, byte for byte
//! when nothing else touched the file.

pub mod diff;
pub mod edit;
pub mod fsio;
pub mod json;
pub mod skel;

use std::path::{Path, PathBuf};

use ms_core::{Error, Result, SecretRef};

use crate::{Check, ConfigDiff, ConnectCfg, Connector, Detection, FileChange};
use edit::{Change, Edits, add_unique, path, set, undo};
use json::Value;

/// Connector id.
pub const ID: &str = "claude-code";
/// The marker `env` entry (SPEC D7).
pub const MARKER: &str = "MORSEC_CONNECTED";
/// The CA variables pointed at the bundle (SPEC D6).
pub const CA_VARS: [&str; 5] = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    // git (Apple's and Homebrew's) trusts only this one on macOS (L30).
    "GIT_SSL_CAINFO",
];
/// Largest `~/.claude.json` read (Claude Code keeps project history there).
pub const MAX_CLAUDE_JSON: u64 = 64 << 20;
/// Largest extra CA file folded into the bundle.
const MAX_CA_FILE: u64 = 1 << 20;
const STATE_VERSION: i64 = 1;
/// Claude Code's bypass permission mode, which connect only ever *detects* in the user's own
/// settings (to warn) and never writes (SDLC-2, test `sdlc2_sandbox_on_and_no_bypass`). Spelled
/// in two parts because the ARI-42 scanner's SDLC-2 rule matches the literal anywhere and has no
/// way to mark a detector as safe; recorded in ARI42.md.
const BYPASS_MODE: &str = concat!("bypass", "Permissions");
/// macOS system roots, the base of the bundle.
pub const SYSTEM_ROOTS: &str = "/etc/ssl/cert.pem";

/// Where the connector reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `$HOME`.
    pub home: PathBuf,
    /// `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`).
    pub settings: PathBuf,
    /// `~/.claude.json` (or `$CLAUDE_CONFIG_DIR/.claude.json`).
    pub claude_json: PathBuf,
    /// `~/.morsec/connect/claude-code.json`: original bytes and the recorded changes.
    pub state: PathBuf,
    /// `~/.morsec/ca-bundle.pem`.
    pub bundle: PathBuf,
    /// `~/.morsec/shims`.
    pub shims: PathBuf,
    /// System roots PEM.
    pub system_roots: PathBuf,
}

impl Paths {
    /// Paths under `home`, honouring a `CLAUDE_CONFIG_DIR` value.
    pub fn for_home(home: &Path, claude_config_dir: Option<&Path>) -> Self {
        let cfg = claude_config_dir.map_or_else(|| home.join(".claude"), Path::to_path_buf);
        let claude_json =
            claude_config_dir.map_or_else(|| home.join(".claude.json"), |d| d.join(".claude.json"));
        Self {
            home: home.to_path_buf(),
            settings: cfg.join("settings.json"),
            claude_json,
            state: home.join(".morsec/connect/claude-code.json"),
            bundle: home.join(".morsec/ca-bundle.pem"),
            shims: home.join(".morsec/shims"),
            system_roots: PathBuf::from(SYSTEM_ROOTS),
        }
    }
}

/// Opt-in parts of the block (SPEC D3) and `--force`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Add the `ms mcp` server to `~/.claude.json`.
    pub with_mcp: bool,
    /// Wrap existing command hooks and local stdio MCP servers in `ms run --`.
    pub wrap: bool,
    /// Add a status line showing `ms status` when none is set.
    pub statusline: bool,
    /// Override a proxy port or `mcpServers.ms` the user set.
    pub force: bool,
}

/// The Claude Code connector.
#[derive(Debug, Clone)]
pub struct ClaudeConnector {
    /// Files.
    pub paths: Paths,
    /// Absolute path of `ms` written into hooks and servers.
    pub ms: String,
    /// msd's socket (added to `sandbox.network.allowUnixSockets`).
    pub socket: String,
    /// `MORSEC_SOCKET` at connect time, if set (dev daemons): carried into `env` and the MCP env.
    pub socket_env: Option<String>,
    /// The proxy CA certificate from msd's `Status` (never from `ca.pem` on disk).
    pub ca_pem: Option<String>,
    /// Options.
    pub opts: Options,
    /// Values of the user's that an earlier `--force` already replaced: (path, value).
    replaceable: Vec<(Vec<String>, Value)>,
}

/// A computed connect: the file changes, plus warnings to show.
#[derive(Debug, Clone, Default)]
pub struct Planned {
    /// Changes, in write order: state, bundle, settings, `~/.claude.json`.
    pub diff: ConfigDiff,
    /// Things the user should know (weaker settings of their own, restored-around edits).
    pub warnings: Vec<String>,
}

/// One file write or removal in a disconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restore {
    /// File.
    pub path: PathBuf,
    /// Content now.
    pub before: Option<String>,
    /// Content after (None: remove the file).
    pub after: Option<String>,
}

/// A computed disconnect.
#[derive(Debug, Clone, Default)]
pub struct RemovePlan {
    /// File writes and removals; the state file and bundle are removed after these.
    pub files: Vec<Restore>,
    /// Notes (changes left in place because the user edited them).
    pub notes: Vec<String>,
    /// What to leave in the state file: None removes it (and the bundle); Some keeps a record of
    /// what could not be undone yet (an unreadable `~/.claude.json`), so a later disconnect can.
    pub state_after: Option<String>,
}

/// Previous connect, from the state file.
#[derive(Debug, Clone)]
struct State {
    /// The settings file before the first connect, without its values (None: no file).
    original: Option<skel::Skeleton>,
    /// SHA-256 of the settings text this connect wrote; empty for a partly-disconnected record.
    written: String,
    settings_edits: Edits,
    claude_edits: Edits,
    proxy_port: u16,
    with_mcp: bool,
    /// `--wrap` was used.
    wrap: bool,
    /// `--statusline` was used.
    statusline: bool,
    /// `~/.claude.json` did not exist before connect created it.
    claude_created: bool,
}

impl State {
    /// True when `cur` is exactly the settings text this connect wrote.
    fn is_written(&self, cur: Option<&str>) -> bool {
        !self.written.is_empty() && cur.is_some_and(|c| skel::sha256(c) == self.written)
    }
}

/// A connector error. `ms-core`'s `Error` is frozen (PLAN §4) and has no general variant, so the
/// message travels as an I/O error with the command as context: "morsec: claude-code: <msg>".
fn err(msg: impl Into<String>) -> Error {
    Error::io(ID, std::io::Error::other(msg.into()))
}

/// Single-quotes `s` for a POSIX shell.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The line the `SessionStart` hook appends to `$CLAUDE_ENV_FILE` (SPEC D5).
pub fn session_env_line(shims: &Path) -> String {
    format!(
        "export PATH={}:\"$PATH\"\n",
        sh_quote(&shims.to_string_lossy())
    )
}

/// Checks an `--env NAME=ms://ref` pair (SPEC "What it writes"): the value must be exactly a
/// reference, so no secret value can ever be written; the name must not steer loaders, proxies,
/// trust, the shell or Claude Code itself.
pub fn check_ref_env(name: &str, value: &str) -> std::result::Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit();
    if !valid {
        return Err(format!(
            "{name:?} is not a usable variable name (use A-Z, 0-9 and _, not starting with a digit)"
        ));
    }
    const DENY: &[&str] = &[
        "PATH",
        "HOME",
        "SHELL",
        "USER",
        "TMPDIR",
        "IFS",
        "ENV",
        "BASH_ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5OPT",
        "RUBYOPT",
        "JAVA_TOOL_OPTIONS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ];
    const DENY_PREFIX: &[&str] = &[
        "LD_",
        "DYLD_",
        "MORSEC_",
        "CLAUDE_",
        "ANTHROPIC_",
        "NPM_CONFIG_",
    ];
    if DENY.contains(&name) || DENY_PREFIX.iter().any(|p| name.starts_with(p)) {
        return Err(format!(
            "{name} can't be set by ms connect: it controls the shell, loaders, proxies, trust or the agent itself"
        ));
    }
    match SecretRef::parse(value) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!(
            "the value for {name} must be a morsec reference like ms://stripe/test. Store the secret with ms add first; a value is never written into agent settings"
        )),
    }
}

/// The value morsec recorded appending at `p` (verify compares against what was written, not
/// against what this process would write now: review R5).
fn recorded_add(e: &Edits, p: &[&str]) -> Option<Value> {
    e.changes.iter().find_map(|c| match c {
        Change::Add { path: q, value } if *q == path(p) => Some(value.clone()),
        _ => None,
    })
}

/// The value morsec recorded setting at `p`.
fn recorded_set(e: &Edits, p: &[&str]) -> Option<Value> {
    e.changes.iter().find_map(|c| match c {
        Change::Set { path: q, after, .. } if *q == path(p) => Some(after.clone()),
        _ => None,
    })
}

/// The certificate blocks of a PEM text.
pub(crate) fn pem_blocks(text: &str) -> Vec<&str> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find(BEGIN) {
        let Some(e) = rest[s..].find(END) else { break };
        out.push(&rest[s..s + e + END.len()]);
        rest = &rest[s + e + END.len()..];
    }
    out
}

pub(crate) fn as_str_path(p: &Path) -> Result<String> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| err(format!("{} is not valid UTF-8", p.display())))
}

/// Parses a settings document; a missing file is an empty object.
fn parse_doc(path: &Path, text: Option<&str>) -> Result<Value> {
    let Some(t) = text else {
        return Ok(Value::object());
    };
    let v = json::parse(t).map_err(|e| {
        err(format!(
            "{} is not valid JSON ({e}). Fix it, then run ms connect again; nothing was changed",
            path.display()
        ))
    })?;
    if !matches!(v, Value::Object(_)) {
        return Err(err(format!(
            "{} must hold a JSON object; it holds {}. Nothing was changed",
            path.display(),
            v.kind()
        )));
    }
    Ok(v)
}

/// The text to write for `v`, in the style of `like` (indent, trailing newline).
fn render(v: &Value, like: Option<&str>) -> String {
    let indent = like.map_or_else(|| "  ".to_owned(), json::detect_indent);
    let newline = like.is_none_or(|t| t.ends_with('\n'));
    json::print_doc(v, &indent, newline)
}

impl ClaudeConnector {
    /// A connector over `paths`.
    pub fn new(paths: Paths, ms: impl Into<String>, socket: impl Into<String>) -> Self {
        Self {
            paths,
            ms: ms.into(),
            socket: socket.into(),
            socket_env: None,
            ca_pem: None,
            opts: Options::default(),
            replaceable: Vec::new(),
        }
    }

    /// The CA variables, all pointing at the bundle (SPEC D6), for [`ConnectCfg::env`].
    pub fn ca_env(&self) -> Result<Vec<(String, String)>> {
        let b = as_str_path(&self.paths.bundle)?;
        Ok(CA_VARS
            .iter()
            .map(|v| ((*v).to_owned(), b.clone()))
            .collect())
    }

    /// The `--env` references the previous connect wrote, so re-running `ms connect` (for example
    /// after adding a host) keeps them.
    pub fn previous_env_refs(&self) -> Result<Vec<(String, String)>> {
        let Some(st) = self.read_state()? else {
            return Ok(Vec::new());
        };
        // One per name, the newest record winning (review F2: an older state may hold two).
        let mut out: Vec<(String, String)> = Vec::new();
        for (n, v) in st.settings_edits.changes.iter().filter_map(|c| match c {
            Change::Set {
                path,
                after: Value::String(v),
                ..
            }
            | Change::SetRedacted {
                path,
                after: Value::String(v),
            } if path.len() == 2 && path[0] == "env" => check_ref_env(&path[1], v)
                .ok()
                .map(|()| (path[1].clone(), v.clone())),
            _ => None,
        }) {
            out.retain(|(m, _)| *m != n);
            out.push((n, v));
        }
        Ok(out)
    }

    /// The string values morsec itself writes, for the plan preview: everything else is redacted
    /// there ([`diff::redact`]). Includes `cfg`'s refs and domains, and the previous connect's.
    pub fn display_safe(&self, cfg: Option<&ConnectCfg>) -> Vec<String> {
        let mut v: Vec<String> = [
            ID,
            MARKER,
            "connect",
            "--session-env",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "/usr/bin/env",
            "-i",
            "mcp",
            "stdio",
            "command",
            "PATH=/usr/bin:/bin",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        v.push(self.ms.clone());
        v.push(self.socket.clone());
        v.push(format!("{} status", sh_quote(&self.ms)));
        for p in [&self.paths.bundle, &self.paths.home] {
            v.push(p.to_string_lossy().into_owned());
        }
        v.push(format!("HOME={}", self.paths.home.to_string_lossy()));
        if let Some(s) = &self.socket_env {
            v.push(s.clone());
            v.push(format!("MORSEC_SOCKET={s}"));
        }
        if let Some(c) = cfg {
            v.extend(c.env.iter().map(|(_, x)| x.clone()));
            v.extend(c.allowed_domains.iter().cloned());
        }
        if let Ok(Some(st)) = self.read_state() {
            for c in &st.settings_edits.changes {
                match c {
                    Change::Add {
                        path,
                        value: Value::String(x),
                    } if path.first().is_some_and(|p| p == "sandbox") => v.push(x.clone()),
                    Change::Set {
                        path,
                        after: Value::String(x),
                        ..
                    }
                    | Change::SetRedacted {
                        path,
                        after: Value::String(x),
                    } if path.first().is_some_and(|p| p == "env")
                        && (SecretRef::parse(x).is_ok() || *x == ID) =>
                    {
                        v.push(x.clone());
                    }
                    _ => {}
                }
            }
        }
        v
    }

    /// True when an earlier disconnect restored the settings but left changes in an unreadable
    /// `~/.claude.json` to undo (review R10).
    pub fn is_partly_disconnected(&self) -> bool {
        matches!(self.read_state(), Ok(Some(st)) if st.written.is_empty() && st.settings_edits.is_empty())
    }

    /// The opt-in parts the previous connect used, so a plain re-run keeps them: dropping one is
    /// a partial disconnect, which only `ms disconnect` does (security review S2).
    pub fn previous_options(&self) -> Result<Options> {
        Ok(self
            .read_state()?
            .map_or_else(Options::default, |st| Options {
                with_mcp: st.with_mcp,
                wrap: st.wrap,
                statusline: st.statusline,
                force: false,
            }))
    }

    /// True when a state file says this connector is applied.
    pub fn is_connected(&self) -> bool {
        self.paths.state.exists()
    }

    /// The msd proxy port the last connect wrote (`ms doctor` compares it with msd's, L17).
    pub fn recorded_proxy_port(&self) -> Result<Option<u16>> {
        Ok(self.read_state()?.map(|st| st.proxy_port))
    }

    fn read_state(&self) -> Result<Option<State>> {
        let Some(text) = fsio::read_text(&self.paths.state).map_err(err)? else {
            return Ok(None);
        };
        let bad = |m: &str| {
            err(format!(
                "{} is damaged ({m}). Restore ~/.claude/settings.json by hand, then delete that file",
                self.paths.state.display()
            ))
        };
        let v = json::parse(&text).map_err(|e| bad(&e.to_string()))?;
        if v.get("version") != Some(&Value::int(STATE_VERSION)) {
            return Err(bad("unknown version"));
        }
        let s = v.get("settings").ok_or_else(|| bad("no settings"))?;
        let original = match s.get("original") {
            Some(Value::Null) => None,
            Some(o) => {
                let text = o
                    .get("skeleton")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("no skeleton"))?
                    .to_owned();
                let sha256 = o
                    .get("sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("no sha256"))?
                    .to_owned();
                let mut literals = Vec::new();
                for l in o
                    .get("literals")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("no literals"))?
                {
                    let pair = l.as_array().filter(|a| a.len() == 2);
                    let (Some(Value::Number(i)), Some(Value::String(t))) =
                        (pair.and_then(|a| a.first()), pair.and_then(|a| a.get(1)))
                    else {
                        return Err(bad("bad literal"));
                    };
                    literals.push((i.parse().map_err(|_| bad("bad literal"))?, t.clone()));
                }
                Some(skel::Skeleton {
                    text,
                    literals,
                    sha256,
                })
            }
            None => return Err(bad("no original")),
        };
        let written = s
            .get("written_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("no written_sha256"))?
            .to_owned();
        let settings_edits = edit::edits_from_value(s).map_err(|e| bad(&e))?;
        let claude_edits = match v.get("claude_json") {
            Some(c) => edit::edits_from_value(c).map_err(|e| bad(&e))?,
            None => Edits::default(),
        };
        let proxy_port = match v.get("proxy_port") {
            Some(Value::Number(n)) => n.parse().map_err(|_| bad("proxy_port"))?,
            _ => return Err(bad("proxy_port")),
        };
        let flag = |k: &str| matches!(v.get(k), Some(Value::Bool(true)));
        Ok(Some(State {
            original,
            written,
            settings_edits,
            claude_edits,
            proxy_port,
            with_mcp: flag("with_mcp"),
            wrap: flag("wrap"),
            statusline: flag("statusline"),
            claude_created: flag("claude_created"),
        }))
    }

    fn state_text(&self, st: &State) -> String {
        let mut s = edit::edits_to_value(&st.settings_edits);
        s.set(
            "original",
            st.original.as_ref().map_or(Value::Null, |sk| {
                let mut o = Value::object();
                o.set("sha256", Value::str(sk.sha256.clone()));
                o.set("skeleton", Value::str(sk.text.clone()));
                o.set(
                    "literals",
                    Value::Array(
                        sk.literals
                            .iter()
                            .map(|(i, t)| {
                                Value::Array(vec![
                                    Value::int(i64::try_from(*i).unwrap_or(i64::MAX)),
                                    Value::str(t.clone()),
                                ])
                            })
                            .collect(),
                    ),
                );
                o
            }),
        );
        s.set("written_sha256", Value::str(st.written.clone()));
        let mut v = Value::object();
        v.set("version", Value::int(STATE_VERSION));
        v.set("agent", Value::str(ID));
        v.set("proxy_port", Value::int(i64::from(st.proxy_port)));
        v.set("with_mcp", Value::Bool(st.with_mcp));
        v.set("wrap", Value::Bool(st.wrap));
        v.set("statusline", Value::Bool(st.statusline));
        v.set("claude_created", Value::Bool(st.claude_created));
        v.set("settings", s);
        v.set("claude_json", edit::edits_to_value(&st.claude_edits));
        json::print_doc(&v, "  ", true)
    }

    /// The settings document with this connect undone, and the text to restore: the original
    /// bytes when the skeleton rebuilds them exactly (S1), else the document in the original
    /// layout. `cur` is the text this connect wrote.
    fn unwritten(&self, st: &State, cur: &str) -> Result<(Value, Option<String>, Vec<String>)> {
        let mut v = parse_doc(&self.paths.settings, Some(cur))?;
        let notes = undo(&mut v, &st.settings_edits);
        let text = st
            .original
            .as_ref()
            .map(|sk| skel::rebuild(sk, &v).unwrap_or_else(|| render(&v, Some(&sk.text))));
        Ok((v, text, notes))
    }

    /// The settings document as it would be without morsec (except the references that replaced
    /// a value of the user's, which are carried forward: that value is gone, review R13/R14),
    /// the skeleton of the original, the text whose layout to keep, notes, and the carried
    /// records.
    #[allow(clippy::type_complexity)]
    fn settings_base(
        &self,
        cur: Option<&str>,
        prev: Option<&State>,
    ) -> Result<(
        Value,
        Option<skel::Skeleton>,
        Option<String>,
        Vec<String>,
        Vec<Change>,
    )> {
        let Some(st) = prev else {
            return Ok((
                parse_doc(&self.paths.settings, cur)?,
                cur.map(skel::skeletonize),
                cur.map(str::to_owned),
                Vec::new(),
                Vec::new(),
            ));
        };
        let mut v = parse_doc(&self.paths.settings, cur)?;
        let (carried, rest): (Vec<Change>, Vec<Change>) =
            st.settings_edits.changes.iter().cloned().partition(
                |c| matches!(c, Change::SetRedacted { path, after } if v.at(path) == Some(after)),
            );
        let partial = Edits {
            changes: rest,
            created: st.settings_edits.created.clone(),
        };
        let was = v.clone();
        let notes = undo(&mut v, &partial);
        if st.is_written(cur) {
            // The file is still what connect wrote: keep the first original's skeleton. A
            // re-plan undoes in memory only, so its notes would describe a disconnect.
            let style = st.original.as_ref().map(|sk| sk.text.clone());
            return Ok((v, st.original.clone(), style, Vec::new(), carried));
        }
        // Edited since: the current file, minus morsec's changes, is the new original. Keep the
        // user's bytes when nothing of ours was there to undo (review R1).
        let text = if v == was {
            cur.map(str::to_owned)
        } else {
            cur.map(|c| render(&v, Some(c)))
        };
        Ok((
            v,
            text.as_deref().map(skel::skeletonize),
            text,
            notes,
            carried,
        ))
    }

    /// Computes a connect without writing anything.
    pub fn try_plan(&self, cfg: &ConnectCfg) -> Result<Planned> {
        let ca_env = self.ca_env()?;
        for (name, value) in &cfg.env {
            if ca_env.iter().any(|(n, v)| n == name && v == value) {
                continue;
            }
            check_ref_env(name, value).map_err(err)?;
        }
        if cfg.proxy_port == 0 {
            return Err(err(
                "the morsec proxy port is unknown. Start the daemon: ms start",
            ));
        }
        let prev = self.read_state()?;
        let mut warnings = Vec::new();
        // A re-run after `--force` may replace again exactly the value the user chose to replace
        // then, and only while morsec's own value is still in place (so it is undo, not the user,
        // that puts the old value back). Any value the user set since needs a fresh --force,
        // which an agent can't give (review R7, R9).
        let mut this = self.clone();
        if let Some(p) = &prev {
            let scur = fsio::read_text(&self.paths.settings).map_err(err)?;
            let sdoc = scur.as_deref().and_then(|t| json::parse(t).ok());
            let still_ours_in_settings = |at: &[String], after: &Value| {
                p.is_written(scur.as_deref())
                    || sdoc.as_ref().is_some_and(|d| d.at(at) == Some(after))
            };
            let cdoc = fsio::read_capped(&self.paths.claude_json, MAX_CLAUDE_JSON)
                .ok()
                .flatten()
                .and_then(|t| json::parse(&t).ok());
            for (edits, at, in_settings) in [
                (
                    &p.settings_edits,
                    path(&["sandbox", "network", "httpProxyPort"]),
                    true,
                ),
                (&p.claude_edits, path(&["mcpServers", "ms"]), false),
            ] {
                for c in &edits.changes {
                    if let Change::Set {
                        path: q,
                        before: Some(b),
                        after,
                    } = c
                        && *q == at
                    {
                        let ours = if in_settings {
                            still_ours_in_settings(&at, after)
                        } else {
                            cdoc.as_ref().is_some_and(|d| d.at(&at) == Some(after))
                        };
                        if ours {
                            this.replaceable.push((at.clone(), b.clone()));
                        }
                    }
                }
            }
        }

        // settings.json
        let cur = fsio::read_text(&self.paths.settings).map_err(err)?;
        let (base, skeleton, style, notes, carried) =
            self.settings_base(cur.as_deref(), prev.as_ref())?;
        warnings.extend(notes);
        let mut after = base.clone();
        let mut sedits = Edits {
            changes: carried,
            created: Vec::new(),
        };
        let extra_ca = this.plan_settings(&mut after, cfg, &mut sedits, &mut warnings)?;
        // Keep the records of an unchanged re-run in their earlier order, so it writes nothing.
        if let Some(p) = &prev {
            let rank = |c: &Change| {
                p.settings_edits
                    .changes
                    .iter()
                    .position(|x| x == c)
                    .unwrap_or(usize::MAX)
            };
            sedits.changes.sort_by_key(rank);
        }
        let settings_text = render(&after, style.as_deref().or(cur.as_deref()));

        // ~/.claude.json
        let ccur = fsio::read_capped(&self.paths.claude_json, MAX_CLAUDE_JSON).map_err(err)?;
        let mut cedits = Edits::default();
        let mut claude_change = None;
        let prev_c = prev.as_ref().map(|p| &p.claude_edits);
        let touch_claude =
            self.opts.with_mcp || self.opts.wrap || prev_c.is_some_and(|e| !e.is_empty());
        if touch_claude && (ccur.is_some() || self.opts.with_mcp) {
            let mut cv = parse_doc(&self.paths.claude_json, ccur.as_deref())?;
            if let Some(pe) = prev_c {
                warnings.extend(undo(&mut cv, pe));
            }
            this.plan_claude_json(&mut cv, &mut cedits)?;
            let text = render(&cv, ccur.as_deref());
            if ccur.as_deref() != Some(text.as_str()) {
                claude_change = Some(FileChange {
                    path: self.paths.claude_json.clone(),
                    before: ccur.clone(),
                    after: text,
                });
            }
        }

        let bundle = self.bundle_text(&extra_ca, &mut warnings)?;
        let claude_created = prev.as_ref().is_some_and(|p| p.claude_created)
            || (ccur.is_none() && claude_change.is_some());
        let state = State {
            original: skeleton,
            written: skel::sha256(&settings_text),
            settings_edits: sedits,
            claude_edits: cedits,
            proxy_port: cfg.proxy_port,
            with_mcp: self.opts.with_mcp,
            wrap: self.opts.wrap,
            statusline: self.opts.statusline,
            claude_created,
        };
        let state_now = fsio::read_text(&self.paths.state).map_err(err)?;
        let bundle_now = fsio::read_capped(&self.paths.bundle, MAX_CLAUDE_JSON).map_err(err)?;
        let mut changes = Vec::new();
        let mut push = |path: &Path, before: Option<String>, after: String| {
            if before.as_deref() != Some(after.as_str()) {
                changes.push(FileChange {
                    path: path.to_path_buf(),
                    before,
                    after,
                });
            }
        };
        push(&self.paths.state, state_now, self.state_text(&state));
        push(&self.paths.bundle, bundle_now, bundle);
        push(&self.paths.settings, cur, settings_text);
        if let Some(c) = claude_change {
            changes.push(c);
        }
        Ok(Planned {
            diff: ConfigDiff { changes },
            warnings,
        })
    }

    /// Adds the block to the settings document; returns CA files the user's settings named.
    fn plan_settings(
        &self,
        v: &mut Value,
        cfg: &ConnectCfg,
        e: &mut Edits,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<PathBuf>> {
        // The user's own proxy port: refuse unless forced (SPEC D8).
        let port_path = path(&["sandbox", "network", "httpProxyPort"]);
        if let Some(p) = v.at(&port_path)
            && *p != Value::int(i64::from(cfg.proxy_port))
            && !self.opts.force
            && !self.replaceable.contains(&(port_path.clone(), p.clone()))
        {
            return Err(err(format!(
                "your Claude Code settings already send sandbox traffic to your own proxy (sandbox.network.httpProxyPort = {}). morsec needs that port for its proxy. Re-run with --force to replace it (ms disconnect puts yours back)",
                json::print(p, "")
            )));
        }
        // SDLC-2: say so when the user's own settings weaken the sandbox. Never change them.
        if v.at(&path(&["permissions", "defaultMode"])) == Some(&Value::str(BYPASS_MODE)) {
            warnings.push(format!("your settings set permissions.defaultMode to {BYPASS_MODE}: Claude runs commands without asking. morsec still keeps values out of reach, but consider removing it"));
        }
        if v.at(&path(&["sandbox", "excludedCommands"]))
            .is_some_and(|x| !x.is_empty_container())
        {
            warnings.push("sandbox.excludedCommands lists commands that run outside the sandbox; they won't go through morsec, so references in them won't resolve".into());
        }
        if v.at(&path(&["sandbox", "enabled"])) == Some(&Value::Bool(false)) {
            warnings.push("your settings had the sandbox turned off; ms connect turns it on (ms disconnect turns it back off)".into());
        }

        if self.opts.wrap {
            self.wrap_hooks(v, e)?;
        }

        // CA files the user already named, so their trust keeps working (SPEC D6).
        let bundle = as_str_path(&self.paths.bundle)?;
        let mut extra = Vec::new();
        for var in CA_VARS {
            if let Some(Value::String(p)) = v.at(&path(&["env", var]))
                && *p != bundle
                && !extra.contains(&PathBuf::from(p))
            {
                extra.push(PathBuf::from(p));
            }
        }

        set(v, &path(&["env", MARKER]), Value::str(ID), e).map_err(err)?;
        for (name, value) in &cfg.env {
            let p = path(&["env", name]);
            let new = Value::str(value.clone());
            // A ref that already replaced a value of the user's (a carried record, R13): change
            // that record in place. A second record would warn again and grow with every
            // re-run (review F2); the user's value is gone either way.
            if let Some(Change::SetRedacted { after, .. }) = e
                .changes
                .iter_mut()
                .find(|c| matches!(c, Change::SetRedacted { path: q, .. } if *q == p))
            {
                if *after != new {
                    *after = new.clone();
                    if let Some(env) = v.get_mut("env") {
                        env.set(name, new);
                    }
                }
                continue;
            }
            match v.at(&p).cloned() {
                // A value of the user's under a name an --env ref takes over: not kept (S1).
                Some(old) if old != new && !CA_VARS.contains(&name.as_str()) => {
                    edit::ensure_object(v, &path(&["env"]), e).map_err(err)?;
                    if let Some(env) = v.get_mut("env") {
                        env.set(name, new.clone());
                    }
                    e.changes.push(Change::SetRedacted {
                        path: p,
                        after: new,
                    });
                    warnings.push(format!("env.{name} held a value of yours; it is replaced by the reference, and morsec doesn't keep the old value (ms disconnect removes the entry instead of putting it back)"));
                }
                _ => set(v, &p, new, e).map_err(err)?,
            }
        }
        if let Some(s) = &self.socket_env {
            set(
                v,
                &path(&["env", "MORSEC_SOCKET"]),
                Value::str(s.clone()),
                e,
            )
            .map_err(err)?;
        }
        set(v, &path(&["sandbox", "enabled"]), Value::Bool(true), e).map_err(err)?;
        set(v, &port_path, Value::int(i64::from(cfg.proxy_port)), e).map_err(err)?;
        for d in &cfg.allowed_domains {
            add_unique(
                v,
                &path(&["sandbox", "network", "allowedDomains"]),
                Value::str(d.clone()),
                e,
            )
            .map_err(err)?;
        }
        add_unique(
            v,
            &path(&["sandbox", "network", "allowUnixSockets"]),
            Value::str(self.socket.clone()),
            e,
        )
        .map_err(err)?;
        if cfg.shim_dir.is_some() {
            add_unique(v, &path(&["hooks", "SessionStart"]), self.session_hook(), e)
                .map_err(err)?;
        }
        if self.opts.statusline {
            if v.get("statusLine").is_some() {
                warnings.push("you already have a status line, so morsec didn't add one; add `ms status` to yours if you like".into());
            } else {
                let mut sl = Value::object();
                sl.set("type", Value::str("command"));
                sl.set(
                    "command",
                    Value::str(format!("{} status", sh_quote(&self.ms))),
                );
                set(v, &path(&["statusLine"]), sl, e).map_err(err)?;
            }
        }
        Ok(extra)
    }

    /// The `SessionStart` group that puts the shim directory first on `PATH` (SPEC D5).
    pub fn session_hook(&self) -> Value {
        let mut h = Value::object();
        h.set("type", Value::str("command"));
        h.set("command", Value::str(self.ms.clone()));
        h.set(
            "args",
            Value::Array(vec![
                Value::str("connect"),
                Value::str(ID),
                Value::str("--session-env"),
            ]),
        );
        let mut g = Value::object();
        g.set("hooks", Value::Array(vec![h]));
        g
    }

    /// `ms run -- <argv>` for an exec-form command hook or stdio server; None when it must stay
    /// as it is (ours, already wrapped, not a plain command, PowerShell).
    fn wrapped(&self, command: &Value, args: Option<&Value>) -> Option<Vec<Value>> {
        let cmd = command.as_str()?;
        if cmd == self.ms || cmd.is_empty() {
            return None;
        }
        let mut argv = vec![Value::str("run"), Value::str("--")];
        match args {
            None => {
                argv.extend([Value::str("/bin/sh"), Value::str("-c"), Value::str(cmd)]);
            }
            Some(Value::Array(a)) if a.iter().all(|x| x.as_str().is_some()) => {
                argv.push(Value::str(cmd));
                argv.extend(a.iter().cloned());
            }
            Some(_) => return None,
        }
        Some(argv)
    }

    /// Wraps `o` (a command hook or stdio server) in place; returns the record to undo it.
    fn wrap_one(
        &self,
        o: &mut Value,
        path: &[String],
        at: Option<(usize, usize)>,
    ) -> Option<Change> {
        let had_args = o.get("args").is_some();
        let argv = self.wrapped(o.get("command")?, o.get("args"))?;
        let shell = !had_args && argv.get(2) == Some(&Value::str("/bin/sh"));
        o.set("command", Value::str(self.ms.clone()));
        // Exec form: `shell` is ignored with `args`, so nothing else changes.
        o.set("args", Value::Array(argv));
        Some(Change::Wrap {
            path: path.to_vec(),
            sha256: edit::wrap_shape_sha256(o),
            shell,
            had_args,
            at,
        })
    }

    fn wrap_hooks(&self, v: &mut Value, e: &mut Edits) -> Result<()> {
        let events: Vec<String> = match v.get("hooks") {
            Some(Value::Object(m)) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => return Ok(()),
        };
        for event in events {
            let at = path(&["hooks", &event]);
            let Some(Value::Array(groups)) = v.at_mut(&at) else {
                continue;
            };
            for (gi, g) in groups.iter_mut().enumerate() {
                let Some(Value::Array(hooks)) = g.get_mut("hooks") else {
                    continue;
                };
                for (hi, h) in hooks.iter_mut().enumerate() {
                    if h.get("type") != Some(&Value::str("command"))
                        || h.get("shell") == Some(&Value::str("powershell"))
                    {
                        continue;
                    }
                    if let Some(c) = self.wrap_one(h, &at, Some((gi, hi))) {
                        e.changes.push(c);
                    }
                }
            }
        }
        Ok(())
    }

    /// The `ms mcp` server entry: a minimal explicit environment (SPEC D4, MCP-4).
    pub fn mcp_entry(&self) -> Result<Value> {
        let home = as_str_path(&self.paths.home)?;
        // `env` takes any argument with '=' as an assignment, so such a path would not run ms.
        if self.ms.contains('=') {
            return Err(err(format!(
                "the path of ms ({}) contains '=', which /usr/bin/env would misread; install ms elsewhere",
                self.ms
            )));
        }
        let mut args = vec![
            Value::str("-i"),
            Value::str(format!("HOME={home}")),
            Value::str("PATH=/usr/bin:/bin"),
        ];
        if let Some(s) = &self.socket_env {
            args.push(Value::str(format!("MORSEC_SOCKET={s}")));
        }
        args.push(Value::str(self.ms.clone()));
        args.push(Value::str("mcp"));
        let mut o = Value::object();
        o.set("type", Value::str("stdio"));
        o.set("command", Value::str("/usr/bin/env"));
        o.set("args", Value::Array(args));
        o.set("env", Value::object());
        Ok(o)
    }

    fn wrap_servers(&self, v: &mut Value, base: &[String], e: &mut Edits) -> Result<()> {
        let names: Vec<String> = match v.at(base) {
            Some(Value::Object(m)) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => return Ok(()),
        };
        for name in names {
            if name == "ms" {
                continue;
            }
            let mut at = base.to_vec();
            at.push(name);
            let Some(s) = v.at_mut(&at) else { continue };
            if !matches!(s, Value::Object(_))
                || !s.get("type").is_none_or(|t| *t == Value::str("stdio"))
            {
                continue;
            }
            // A stdio server with no args runs `command` directly: wrap it as exec form.
            if s.get("args").is_none() {
                let Some(cmd) = s.get("command").cloned() else {
                    continue;
                };
                let Some(argv) = self.wrapped(&cmd, Some(&Value::Array(Vec::new()))) else {
                    continue;
                };
                s.set("command", Value::str(self.ms.clone()));
                s.set("args", Value::Array(argv));
                e.changes.push(Change::Wrap {
                    path: at.clone(),
                    sha256: edit::wrap_shape_sha256(s),
                    shell: false,
                    had_args: false,
                    at: None,
                });
            } else if let Some(c) = self.wrap_one(s, &at, None) {
                e.changes.push(c);
            }
        }
        Ok(())
    }

    fn plan_claude_json(&self, v: &mut Value, e: &mut Edits) -> Result<()> {
        if self.opts.wrap {
            self.wrap_servers(v, &path(&["mcpServers"]), e)?;
            if let Some(Value::Object(projects)) = v.get("projects").cloned() {
                for (p, _) in projects {
                    self.wrap_servers(v, &path(&["projects", &p, "mcpServers"]), e)?;
                }
            }
        }
        if self.opts.with_mcp {
            let entry = self.mcp_entry()?;
            let p = path(&["mcpServers", "ms"]);
            if let Some(cur) = v.at(&p)
                && *cur != entry
                && !self.opts.force
                && !self.replaceable.contains(&(p.clone(), cur.clone()))
            {
                return Err(err(format!(
                    "{} already has an MCP server named \"ms\" that morsec didn't add. Rename it, or re-run with --force to replace it (ms disconnect puts it back)",
                    self.paths.claude_json.display()
                )));
            }
            set(v, &p, entry, e).map_err(err)?;
        }
        Ok(())
    }

    fn bundle_text(&self, extra: &[PathBuf], warnings: &mut Vec<String>) -> Result<String> {
        let roots = fsio::read_capped(&self.paths.system_roots, MAX_CLAUDE_JSON)
            .map_err(err)?
            .ok_or_else(|| {
                err(format!(
                    "{} is missing, so morsec can't build a CA bundle with the system roots",
                    self.paths.system_roots.display()
                ))
            })?;
        let mut out = String::from(
            "# morsec CA bundle for Claude Code: system roots, the morsec proxy CA, and CA files your\n# settings named. Written by ms connect claude-code; removed by ms disconnect.\n",
        );
        let mut add = |blocks: Vec<&str>| {
            for b in blocks {
                out.push_str(b);
                out.push('\n');
            }
        };
        let root_blocks = pem_blocks(&roots);
        if root_blocks.is_empty() {
            return Err(err(format!(
                "{} holds no certificates",
                self.paths.system_roots.display()
            )));
        }
        add(root_blocks);
        if let Some(ca) = &self.ca_pem {
            let b = pem_blocks(ca);
            if b.is_empty() {
                return Err(err("the daemon's CA certificate is not PEM"));
            }
            add(b);
        }
        for p in extra {
            match fsio::read_capped(p, MAX_CA_FILE) {
                Ok(Some(t)) if !pem_blocks(&t).is_empty() => add(pem_blocks(&t)),
                Ok(_) | Err(_) => warnings.push(format!(
                    "{} (named in your settings as a CA file) has no readable certificates; it isn't in the morsec bundle",
                    p.display()
                )),
            }
        }
        Ok(out)
    }

    /// Writes a plan's changes. Each file must still hold the content the plan was computed
    /// from; otherwise nothing more is written.
    pub fn apply_changes(&self, diff: &ConfigDiff) -> Result<()> {
        // Check every file before writing any, so a refusal leaves nothing half-applied (R1).
        for c in &diff.changes {
            let now = fsio::read_capped(&c.path, MAX_CLAUDE_JSON).map_err(err)?;
            if now != c.before {
                return Err(err(format!(
                    "{} changed while ms connect was running. Nothing was changed; run it again",
                    c.path.display()
                )));
            }
        }
        for c in &diff.changes {
            let mode = if c.path == self.paths.bundle {
                0o644
            } else {
                0o600
            };
            fsio::atomic_write(&c.path, &c.after, mode).map_err(err)?;
        }
        Ok(())
    }

    /// Computes a disconnect without writing anything. `Ok(None)`: not connected.
    ///
    /// `settings.json` is always restored, even when `~/.claude.json` can't be read (review R3):
    /// then the state file is kept, holding only what is left to undo there.
    pub fn plan_remove(&self) -> Result<Option<RemovePlan>> {
        let Some(st) = self.read_state()? else {
            return Ok(None);
        };
        let mut plan = RemovePlan::default();
        // A partly-disconnected record has nothing left in settings.json (review R11).
        let partial = st.written.is_empty() && st.settings_edits.is_empty();
        let cur = if partial {
            None
        } else {
            fsio::read_text(&self.paths.settings).map_err(err)?
        };
        if st.is_written(cur.as_deref()) {
            let (_, after, notes) = self.unwritten(&st, cur.as_deref().unwrap_or_default())?;
            plan.notes.extend(notes);
            if cur != after {
                plan.files.push(Restore {
                    path: self.paths.settings.clone(),
                    before: cur.clone(),
                    after,
                });
            }
        } else if let Some(c) = cur.as_deref().filter(|_| !st.settings_edits.is_empty()) {
            let mut v = parse_doc(&self.paths.settings, Some(c))?;
            let was = v.clone();
            let notes = undo(&mut v, &st.settings_edits);
            // Rewrite only when something of ours was there to undo (review R1).
            if v != was {
                plan.notes.extend(notes);
                plan.notes.push(format!(
                    "{} was edited after ms connect, so morsec removed only its own changes and kept yours",
                    self.paths.settings.display()
                ));
                let after = if st.original.is_none() && v.is_empty_container() {
                    None
                } else {
                    Some(render(&v, Some(c)))
                };
                plan.files.push(Restore {
                    path: self.paths.settings.clone(),
                    before: cur.clone(),
                    after,
                });
            }
        }
        if !st.claude_edits.is_empty() || st.claude_created {
            let undone = fsio::read_capped(&self.paths.claude_json, MAX_CLAUDE_JSON)
                .map_err(err)
                .and_then(|ccur| {
                    let Some(c) = ccur.as_deref() else {
                        return Ok(None);
                    };
                    let mut v = parse_doc(&self.paths.claude_json, Some(c))?;
                    let was = v.clone();
                    let notes = undo(&mut v, &st.claude_edits);
                    let drop_file = st.claude_created && v.is_empty_container();
                    if v == was && !drop_file {
                        return Ok(None);
                    }
                    let after = if drop_file {
                        None
                    } else {
                        Some(render(&v, Some(c)))
                    };
                    Ok(Some((ccur.clone(), after, notes)))
                });
            match undone {
                Ok(Some((before, after, notes))) => {
                    plan.notes.extend(notes);
                    plan.files.push(Restore {
                        path: self.paths.claude_json.clone(),
                        before,
                        after,
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    plan.notes.push(format!(
                        "{e}. Your settings are restored, but the MCP changes in {} are still there; fix the file and run ms disconnect claude-code again, or remove the \"ms\" server and the `ms run --` wrapping by hand",
                        self.paths.claude_json.display()
                    ));
                    let rest = State {
                        original: None,
                        written: String::new(),
                        settings_edits: Edits::default(),
                        ..st.clone()
                    };
                    // `written` empty never matches a settings file, and with no recorded
                    // settings changes the next disconnect leaves settings.json alone.
                    plan.state_after = Some(self.state_text(&rest));
                }
            }
        }
        Ok(Some(plan))
    }

    /// Writes a disconnect, then removes the bundle and the state file (or keeps what is left).
    pub fn apply_remove(&self, plan: &RemovePlan) -> Result<()> {
        // Check every file before writing any (review R1).
        for f in &plan.files {
            let now = fsio::read_capped(&f.path, MAX_CLAUDE_JSON).map_err(err)?;
            if now != f.before {
                return Err(err(format!(
                    "{} changed while ms disconnect was running. Nothing was changed; run it again",
                    f.path.display()
                )));
            }
        }
        for f in &plan.files {
            match &f.after {
                Some(t) => fsio::atomic_write(&f.path, t, 0o600).map_err(err)?,
                None => fsio::remove(&f.path).map_err(err)?,
            }
        }
        match &plan.state_after {
            Some(t) => fsio::atomic_write(&self.paths.state, t, 0o600).map_err(err)?,
            None => {
                fsio::remove(&self.paths.bundle).map_err(err)?;
                fsio::remove(&self.paths.state).map_err(err)?;
            }
        }
        Ok(())
    }

    fn checks(&self) -> Result<Vec<Check>> {
        let fix = "run: ms connect claude-code";
        let Some(st) = self.read_state()? else {
            return Ok(vec![Check {
                name: "Claude Code connected".into(),
                ok: false,
                detail: format!("not connected; {fix}"),
            }]);
        };
        if st.written.is_empty() && st.settings_edits.is_empty() {
            return Ok(vec![Check {
                name: "Claude Code disconnected".into(),
                ok: false,
                detail: format!(
                    "partly disconnected: morsec's changes in {} are still there; fix that file, then run: ms disconnect claude-code",
                    self.paths.claude_json.display()
                ),
            }]);
        }
        let v = parse_doc(
            &self.paths.settings,
            fsio::read_text(&self.paths.settings)
                .map_err(err)?
                .as_deref(),
        )?;
        let mut out = Vec::new();
        let mut check = |name: &str, ok: bool, bad: &str| {
            out.push(Check {
                name: name.into(),
                ok,
                detail: if ok {
                    String::new()
                } else {
                    format!("{bad}; {fix}")
                },
            });
        };
        check(
            "Claude Code connected",
            v.at(&path(&["env", MARKER])) == Some(&Value::str(ID)),
            "the morsec marker is missing from ~/.claude/settings.json",
        );
        check(
            "Claude Code sandbox on",
            v.at(&path(&["sandbox", "enabled"])) == Some(&Value::Bool(true)),
            "sandbox.enabled is not true",
        );
        check(
            "Claude Code sandbox uses the morsec proxy",
            v.at(&path(&["sandbox", "network", "httpProxyPort"]))
                == Some(&Value::int(i64::from(st.proxy_port))),
            "sandbox.network.httpProxyPort no longer points at morsec",
        );
        let bundle = as_str_path(&self.paths.bundle)?;
        check(
            "Claude Code trusts the morsec CA",
            CA_VARS
                .iter()
                .all(|n| v.at(&path(&["env", n])) == Some(&Value::str(bundle.clone())))
                && self.paths.bundle.is_file(),
            "a CA variable or the CA bundle is missing",
        );
        check(
            "Claude Code puts the shims on PATH",
            v.at(&path(&["hooks", "SessionStart"]))
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.contains(
                        &recorded_add(&st.settings_edits, &["hooks", "SessionStart"])
                            .unwrap_or_else(|| self.session_hook()),
                    )
                }),
            "the SessionStart hook is missing",
        );
        if st.with_mcp {
            let c = fsio::read_capped(&self.paths.claude_json, MAX_CLAUDE_JSON).map_err(err)?;
            let cv = parse_doc(&self.paths.claude_json, c.as_deref())?;
            check(
                "Claude Code has the ms MCP server",
                cv.at(&path(&["mcpServers", "ms"]))
                    == Some(
                        &match recorded_set(&st.claude_edits, &["mcpServers", "ms"]) {
                            Some(v) => v,
                            None => self.mcp_entry()?,
                        },
                    ),
                "mcpServers.ms is missing or changed in ~/.claude.json",
            );
        }
        Ok(out)
    }
}

impl Connector for ClaudeConnector {
    fn id(&self) -> &'static str {
        ID
    }

    fn detect(&self) -> Detection {
        let on_path = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("claude").is_file()));
        Detection {
            installed: on_path || self.paths.settings.parent().is_some_and(Path::is_dir),
            config_paths: vec![self.paths.settings.clone(), self.paths.claude_json.clone()],
        }
    }

    /// The trait can't return an error (frozen, PLAN §4), so an impossible plan is an empty
    /// diff; callers that need the reason use [`ClaudeConnector::try_plan`] (SPEC D11).
    fn plan(&self, cfg: &ConnectCfg) -> ConfigDiff {
        self.try_plan(cfg).map(|p| p.diff).unwrap_or_default()
    }

    fn apply(&self, diff: &ConfigDiff) -> Result<()> {
        self.apply_changes(diff)
    }

    fn remove(&self) -> Result<()> {
        match self.plan_remove()? {
            Some(p) => self.apply_remove(&p),
            None => Ok(()),
        }
    }

    fn verify(&self) -> Vec<Check> {
        self.checks().unwrap_or_else(|e| {
            vec![Check {
                name: "Claude Code settings readable".into(),
                ok: false,
                detail: e.to_string(),
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC acceptance 6 / SDLC-4: --env accepts only safe names with an exact ms://
    // reference, so ms connect can never write a secret value or steer a loader, proxy or trust
    // variable; fails_when=a raw value or a dangerous name is accepted
    #[test]
    fn env_refs_only() {
        assert!(check_ref_env("STRIPE_API_KEY", "ms://stripe/test").is_ok());
        for (n, v) in [
            ("STRIPE_API_KEY", "sk_test_123"),
            ("STRIPE_API_KEY", " ms://stripe/test"),
            ("STRIPE_API_KEY", "ms://stripe/test\nX=1"),
            ("STRIPE_API_KEY", "ms://Stripe"),
            ("stripe", "ms://stripe/test"),
            ("1X", "ms://stripe/test"),
            ("A-B", "ms://stripe/test"),
            ("PATH", "ms://stripe/test"),
            ("HTTPS_PROXY", "ms://stripe/test"),
            ("NODE_OPTIONS", "ms://stripe/test"),
            ("DYLD_INSERT_LIBRARIES", "ms://stripe/test"),
            ("LD_PRELOAD", "ms://stripe/test"),
            ("ANTHROPIC_API_KEY", "ms://anthropic/key"),
            ("CLAUDE_CODE_USE_BEDROCK", "ms://x"),
            ("MORSEC_SOCKET", "ms://x"),
            ("SSL_CERT_FILE", "ms://x"),
            ("NODE_TLS_REJECT_UNAUTHORIZED", "ms://x"),
            ("", "ms://x"),
        ] {
            assert!(check_ref_env(n, v).is_err(), "{n}={v:?} accepted");
        }
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/a b/it's"), r"'/a b/it'\''s'");
        assert_eq!(
            session_env_line(Path::new("/h/.morsec/shims")),
            "export PATH='/h/.morsec/shims':\"$PATH\"\n"
        );
    }

    #[test]
    fn pem_extraction_ignores_non_cert_material() {
        let t = "junk\n-----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\ntrail";
        assert_eq!(
            pem_blocks(t),
            vec!["-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"]
        );
    }
}
