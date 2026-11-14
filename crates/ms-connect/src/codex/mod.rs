//! The Codex connector (L13). See `SPEC.md` for what it writes and why, and
//! `docs/evidence/codex-config-spike.md` for the key names.
//!
//! The Codex CLI, desktop app and IDE extension share `~/.codex/config.toml` (or
//! `$CODEX_HOME/config.toml`). `ms connect codex` merges recorded keys into it with `toml_edit`
//! ([`tedit`]); `ms disconnect codex` takes them out again, byte for byte when nothing else
//! touched the file.

pub mod tedit;

use std::path::{Path, PathBuf};

use ms_core::{Error, Result};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::claude::{self, fsio, json, skel::sha256};
use crate::{Check, ConfigDiff, ConnectCfg, Connector, Detection, FileChange};
use tedit::{Edits, Kind, OnConflict, Record, path, show_path};

/// Connector id.
pub const ID: &str = "codex";
/// The marker variable (SPEC "What it writes" 1).
pub const MARKER: &str = "MORSEC_CONNECTED";
/// The proxy variables pointed at msd (SPEC D1).
pub const PROXY_VARS: [&str; 4] = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"];
/// The CA variables pointed at the bundle.
pub const CA_VARS: [&str; 4] = claude::CA_VARS;
/// The MCP server morsec adds with `--with-mcp`.
pub const MCP_ID: &str = "ms";
const STATE_VERSION: i64 = 1;
/// Largest extra CA file folded into the bundle.
const MAX_CA_FILE: u64 = 1 << 20;
/// Settings that weaken Codex's sandbox. Connect only *detects* them (to warn) and never writes
/// them (SDLC-2). Spelled in parts because the ARI-42 scanner matches the literals anywhere.
const FULL_ACCESS: &str = concat!("danger-", "full-access");
const NEVER_ASK: &str = "never";

/// Where the connector reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `$HOME`.
    pub home: PathBuf,
    /// `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`).
    pub config: PathBuf,
    /// `~/.morsec/connect/codex.json`: hashes and the recorded changes.
    pub state: PathBuf,
    /// `~/.morsec/codex-ca-bundle.pem`.
    pub bundle: PathBuf,
    /// System roots PEM.
    pub system_roots: PathBuf,
}

impl Paths {
    /// Paths under `home`, honouring a `CODEX_HOME` value.
    pub fn for_home(home: &Path, codex_home: Option<&Path>) -> Self {
        let dir = codex_home.map_or_else(|| home.join(".codex"), Path::to_path_buf);
        Self {
            home: home.to_path_buf(),
            config: dir.join("config.toml"),
            state: home.join(".morsec/connect/codex.json"),
            bundle: home.join(".morsec/codex-ca-bundle.pem"),
            system_roots: PathBuf::from(claude::SYSTEM_ROOTS),
        }
    }
}

/// Opt-in parts and `--force`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Add the `ms mcp` server.
    pub with_mcp: bool,
    /// Replace a proxy variable or an `ms` MCP server the user set.
    pub force: bool,
}

/// Checks an `--env` / `--mcp-env` pair: [`claude::check_ref_env`], and the name must not steer
/// Codex itself.
pub fn check_ref_env(name: &str, value: &str) -> std::result::Result<(), String> {
    if name.starts_with("CODEX_") {
        return Err(format!(
            "{name} can't be set by ms connect: it controls Codex itself"
        ));
    }
    claude::check_ref_env(name, value)
}

/// `--mcp-env <server>:NAME=ms://ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRef {
    /// The `mcp_servers` id.
    pub server: String,
    /// Variable name.
    pub name: String,
    /// The reference.
    pub value: String,
    /// Carried from the previous connect, not given on this run: a server removed since is
    /// skipped with a note instead of failing the re-run (review R2).
    pub carried: bool,
}

impl McpRef {
    /// Parses `server:NAME=ms://ref` and checks it like `--env` ([`claude::check_ref_env`]).
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let usage = || {
            format!(
                "--mcp-env takes SERVER:NAME=ms://ref, e.g. --mcp-env github:GITHUB_TOKEN=ms://github/token (got {s:?})"
            )
        };
        let (server, rest) = s.split_once(':').ok_or_else(usage)?;
        let (name, value) = rest.split_once('=').ok_or_else(usage)?;
        if server.is_empty() || server.len() > 128 || server.chars().any(char::is_control) {
            return Err(usage());
        }
        if server == MCP_ID {
            return Err("the \"ms\" server is morsec's own; it needs no references".into());
        }
        check_ref_env(name, value)?;
        Ok(Self {
            server: server.to_owned(),
            name: name.to_owned(),
            value: value.to_owned(),
            carried: false,
        })
    }
}

/// The Codex connector.
#[derive(Debug, Clone)]
pub struct CodexConnector {
    /// Files.
    pub paths: Paths,
    /// Absolute path of `ms`, written into the `ms` MCP server.
    pub ms: String,
    /// `MORSEC_SOCKET` at connect time, if set (dev daemons).
    pub socket_env: Option<String>,
    /// The proxy CA certificate from msd's `Status`.
    pub ca_pem: Option<String>,
    /// Options.
    pub opts: Options,
    /// `--mcp-env` references.
    pub mcp_refs: Vec<McpRef>,
}

/// A computed connect.
#[derive(Debug, Clone, Default)]
pub struct Planned {
    /// Changes, in write order: state, bundle, `config.toml`.
    pub diff: ConfigDiff,
    /// Things the user should know.
    pub warnings: Vec<String>,
}

/// A computed disconnect.
#[derive(Debug, Clone, Default)]
pub struct RemovePlan {
    /// `config.toml`: (content now, content after; None removes it). None: unchanged.
    pub config: Option<(Option<String>, Option<String>)>,
    /// Notes.
    pub notes: Vec<String>,
}

/// The previous connect, from the state file. It holds no value of the user's (SPEC D7).
#[derive(Debug, Clone)]
struct State {
    /// SHA-256 of `config.toml` before morsec; None when unknown (a reference replaced a value).
    original: Option<String>,
    /// morsec created `config.toml`.
    created_file: bool,
    /// SHA-256 of the text connect wrote.
    written: String,
    edits: Edits,
    proxy_port: u16,
    with_mcp: bool,
}

fn err(msg: impl Into<String>) -> Error {
    Error::io(ID, std::io::Error::other(msg.into()))
}

fn str_item(s: &str) -> Item {
    Item::Value(Value::from(s))
}

fn parse_doc(p: &Path, text: &str) -> Result<DocumentMut> {
    text.parse::<DocumentMut>().map_err(|e| {
        err(format!(
            "{} is not valid TOML ({}). Fix it, then run ms again; nothing was changed",
            p.display(),
            e.to_string().lines().next().unwrap_or("parse error")
        ))
    })
}

/// True when `v` looks like it holds credentials (`user:pass@host`), so it is never kept.
fn has_userinfo(v: &str) -> bool {
    v.split_once("://")
        .map_or(v, |(_, r)| r)
        .split('/')
        .next()
        .is_some_and(|auth| auth.contains('@'))
}

impl CodexConnector {
    /// A connector over `paths`.
    pub fn new(paths: Paths, ms: impl Into<String>) -> Self {
        Self {
            paths,
            ms: ms.into(),
            socket_env: None,
            ca_pem: None,
            opts: Options::default(),
            mcp_refs: Vec::new(),
        }
    }

    /// msd's proxy as a URL.
    pub fn proxy_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}")
    }

    /// True when a state file says this connector is applied.
    pub fn is_connected(&self) -> bool {
        self.paths.state.exists()
    }

    /// The opt-in parts the previous connect used (a plain re-run keeps them: SPEC D11).
    pub fn previous_options(&self) -> Result<Options> {
        Ok(self
            .read_state()?
            .map_or_else(Options::default, |st| Options {
                with_mcp: st.with_mcp,
                force: false,
            }))
    }

    /// The `--env` references the previous connect wrote.
    pub fn previous_env_refs(&self) -> Result<Vec<(String, String)>> {
        let Some(st) = self.read_state()? else {
            return Ok(Vec::new());
        };
        Ok(st
            .edits
            .records
            .iter()
            .filter_map(|r| match r.path.as_slice() {
                [a, b, name] if a == "shell_environment_policy" && b == "set" => {
                    let v = tedit::parse_value(&r.after).ok()?;
                    let v = v.as_str()?;
                    check_ref_env(name, v)
                        .ok()
                        .map(|()| (name.clone(), v.to_owned()))
                }
                _ => None,
            })
            .collect())
    }

    /// The `--mcp-env` references the previous connect wrote.
    pub fn previous_mcp_refs(&self) -> Result<Vec<McpRef>> {
        let Some(st) = self.read_state()? else {
            return Ok(Vec::new());
        };
        Ok(st
            .edits
            .records
            .iter()
            .filter_map(|r| match r.path.as_slice() {
                [a, server, e, name] if a == "mcp_servers" && e == "env" => {
                    let v = tedit::parse_value(&r.after).ok()?;
                    let v = v.as_str()?;
                    check_ref_env(name, v).ok().map(|()| McpRef {
                        server: server.clone(),
                        name: name.clone(),
                        value: v.to_owned(),
                        carried: true,
                    })
                }
                _ => None,
            })
            .collect())
    }

    /// The string values morsec writes, for the plan preview: everything else is redacted.
    pub fn display_safe(&self, cfg: Option<&ConnectCfg>) -> Vec<String> {
        let mut v: Vec<String> = [ID, "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "mcp"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        v.push(self.ms.clone());
        v.push(self.paths.bundle.to_string_lossy().into_owned());
        v.push(format!("HOME={}", self.paths.home.to_string_lossy()));
        if let Some(s) = &self.socket_env {
            v.push(s.clone());
            v.push(format!("MORSEC_SOCKET={s}"));
        }
        if let Some(c) = cfg {
            v.push(Self::proxy_url(c.proxy_port));
            v.extend(c.env.iter().map(|(_, x)| x.clone()));
        }
        v.extend(self.mcp_refs.iter().map(|r| r.value.clone()));
        if let Ok(Some(st)) = self.read_state() {
            v.push(Self::proxy_url(st.proxy_port));
            for r in &st.edits.records {
                if let Ok(x) = tedit::parse_value(&r.after)
                    && let Some(s) = x.as_str()
                    && (s.starts_with("ms://") || s == ID)
                {
                    v.push(s.to_owned());
                }
            }
        }
        v
    }

    fn read_state(&self) -> Result<Option<State>> {
        let Some(text) = fsio::read_text(&self.paths.state).map_err(err)? else {
            return Ok(None);
        };
        let bad = |m: &str| {
            err(format!(
                "{} is damaged ({m}). Remove morsec's MORSEC_CONNECTED, proxy and CA entries from {} by hand, then delete that file",
                self.paths.state.display(),
                self.paths.config.display()
            ))
        };
        let v = json::parse(&text).map_err(|e| bad(&e.to_string()))?;
        if v.get("version") != Some(&json::Value::int(STATE_VERSION))
            || v.get("agent") != Some(&json::Value::str(ID))
        {
            return Err(bad("unknown version"));
        }
        let s = |k: &str| v.get(k).and_then(json::Value::as_str).map(str::to_owned);
        let flag = |k: &str| matches!(v.get(k), Some(json::Value::Bool(true)));
        let strs = |x: &json::Value| -> std::result::Result<Vec<String>, String> {
            x.as_array()
                .ok_or("not a list")?
                .iter()
                .map(|e| e.as_str().map(str::to_owned).ok_or("not a string".into()))
                .collect()
        };
        let mut edits = Edits {
            no_final_newline: flag("no_final_newline"),
            ..Edits::default()
        };
        for r in v
            .get("records")
            .and_then(json::Value::as_array)
            .ok_or_else(|| bad("no records"))?
        {
            let p = strs(r.get("path").ok_or_else(|| bad("record path"))?).map_err(|e| bad(&e))?;
            let after = r
                .get("after")
                .and_then(json::Value::as_str)
                .ok_or_else(|| bad("record value"))?
                .to_owned();
            tedit::parse_value(&after).map_err(|e| bad(&e))?;
            let kind = match r.get("kind").and_then(json::Value::as_str) {
                Some("added") => Kind::Added,
                Some("redacted") => Kind::Redacted { before: None },
                Some("replaced") => Kind::Replaced {
                    before: r
                        .get("before")
                        .and_then(json::Value::as_str)
                        .ok_or_else(|| bad("record before"))?
                        .to_owned(),
                },
                _ => return Err(bad("record kind")),
            };
            if p.is_empty() {
                return Err(bad("record path"));
            }
            edits.push(Record {
                path: p,
                after,
                kind,
            });
        }
        for c in v
            .get("created")
            .and_then(json::Value::as_array)
            .ok_or_else(|| bad("no created"))?
        {
            edits.created.push(strs(c).map_err(|e| bad(&e))?);
        }
        let proxy_port = match v.get("proxy_port") {
            Some(json::Value::Number(n)) => n.parse().map_err(|_| bad("proxy_port"))?,
            _ => return Err(bad("proxy_port")),
        };
        Ok(Some(State {
            original: s("original_sha256"),
            created_file: flag("created_file"),
            written: s("written_sha256").ok_or_else(|| bad("no written_sha256"))?,
            edits,
            proxy_port,
            with_mcp: flag("with_mcp"),
        }))
    }

    fn state_text(st: &State) -> String {
        use json::Value as J;
        let strs = |p: &[String]| J::Array(p.iter().map(|k| J::str(k.clone())).collect());
        let mut v = J::object();
        v.set("version", J::int(STATE_VERSION));
        v.set("agent", J::str(ID));
        v.set("proxy_port", J::int(i64::from(st.proxy_port)));
        v.set("with_mcp", J::Bool(st.with_mcp));
        v.set("created_file", J::Bool(st.created_file));
        v.set(
            "original_sha256",
            st.original.clone().map_or(J::Null, J::str),
        );
        v.set("written_sha256", J::str(st.written.clone()));
        v.set("no_final_newline", J::Bool(st.edits.no_final_newline));
        v.set(
            "records",
            J::Array(
                st.edits
                    .records
                    .iter()
                    .map(|r| {
                        let mut o = J::object();
                        o.set("path", strs(&r.path));
                        o.set("after", J::str(r.after.clone()));
                        match &r.kind {
                            Kind::Added => {
                                o.set("kind", J::str("added"));
                            }
                            Kind::Replaced { before } => {
                                o.set("kind", J::str("replaced"));
                                o.set("before", J::str(before.clone()));
                            }
                            // The old value is never written (SPEC D7).
                            Kind::Redacted { .. } => {
                                o.set("kind", J::str("redacted"));
                            }
                        }
                        o
                    })
                    .collect(),
            ),
        );
        v.set(
            "created",
            J::Array(st.edits.created.iter().map(|c| strs(c)).collect()),
        );
        json::print_doc(&v, "  ", true)
    }

    /// The `ms mcp` server entry: an explicit minimal environment (SPEC 3, MCP-4).
    pub fn mcp_entry(&self) -> Result<Table> {
        let home = claude::as_str_path(&self.paths.home)?;
        if self.ms.contains('=') {
            return Err(err(format!(
                "the path of ms ({}) contains '=', which /usr/bin/env would misread; install ms elsewhere",
                self.ms
            )));
        }
        let mut args = Array::new();
        args.push("-i");
        args.push(format!("HOME={home}"));
        args.push("PATH=/usr/bin:/bin");
        if let Some(s) = &self.socket_env {
            args.push(format!("MORSEC_SOCKET={s}"));
        }
        args.push(self.ms.clone());
        args.push("mcp");
        let mut t = Table::new();
        t.insert("command", str_item("/usr/bin/env"));
        t.insert("args", Item::Value(Value::Array(args)));
        Ok(t)
    }

    /// The variables every morsec environment gets: proxy, CA bundle, socket.
    fn base_env(&self, port: u16) -> Result<Vec<(&'static str, String)>> {
        let bundle = claude::as_str_path(&self.paths.bundle)?;
        let mut out: Vec<(&'static str, String)> = PROXY_VARS
            .iter()
            .map(|n| (*n, Self::proxy_url(port)))
            .collect();
        out.extend(CA_VARS.iter().map(|n| (*n, bundle.clone())));
        if let Some(s) = &self.socket_env {
            out.push(("MORSEC_SOCKET", s.clone()));
        }
        Ok(out)
    }

    /// Computes a connect without writing anything.
    pub fn try_plan(&self, cfg: &ConnectCfg) -> Result<Planned> {
        for (name, value) in &cfg.env {
            check_ref_env(name, value).map_err(err)?;
        }
        if cfg.proxy_port == 0 {
            return Err(err(
                "the morsec proxy port is unknown. Start the daemon: ms start",
            ));
        }
        let prev = self.read_state()?;
        let cur = fsio::read_text(&self.paths.config).map_err(err)?;
        let cur_text = cur.as_deref().unwrap_or("");
        if cur_text.contains('\r') {
            return Err(err(format!(
                "{} uses Windows (CRLF) line endings, which morsec can't edit and restore exactly. Convert it to LF line endings first; nothing was changed",
                self.paths.config.display()
            )));
        }
        parse_doc(&self.paths.config, cur_text)?;
        let mut warnings = Vec::new();

        // The text without the previous connect. A reference that replaced a value of the
        // user's stays (that value is gone) and its record is carried (SPEC D6).
        // `ours`: the previous records whose key still holds what morsec wrote, judged on the
        // file as it is now. Only these may be replaced again without --force (review R1: once
        // undo puts the user's old value back, "ours" can't be told apart on the base text).
        let (base_text, original, created_file, carried, ours) = match &prev {
            None => (
                cur_text.to_owned(),
                cur.as_deref().map(sha256),
                cur.is_none(),
                Edits::default(),
                None,
            ),
            Some(p) => {
                let doc = parse_doc(&self.paths.config, cur_text)?;
                let still = |r: &Record| {
                    tedit::parse_value(&r.after).is_ok_and(|a| {
                        tedit::get(&doc, &r.path).and_then(tedit::canon_item)
                            == Some(tedit::canon_value(&a))
                    })
                };
                let (keep, rest): (Vec<Record>, Vec<Record>) = p
                    .edits
                    .records
                    .iter()
                    .cloned()
                    .partition(|r| matches!(r.kind, Kind::Redacted { .. }) && still(r));
                let unchanged = cur.as_deref().map(sha256).as_deref() == Some(p.written.as_str());
                // Take the final newline back off only when the file is exactly what connect
                // wrote: after an edit (Codex appends trust entries) the newline may be theirs.
                let partial = Edits {
                    records: rest,
                    created: p.edits.created.clone(),
                    no_final_newline: p.edits.no_final_newline && unchanged,
                };
                let (text, notes) = tedit::undo_text(cur_text, &partial, false).map_err(err)?;
                if !unchanged {
                    // A re-plan only undoes in memory; notes about keys the user changed matter.
                    warnings.extend(notes);
                }
                let text_doc = parse_doc(&self.paths.config, &text)?;
                let carried = Edits {
                    records: keep.clone(),
                    created: p
                        .edits
                        .created
                        .iter()
                        .filter(|c| tedit::get(&text_doc, c).is_some())
                        .cloned()
                        .collect(),
                    no_final_newline: false,
                };
                let ours = State {
                    edits: Edits {
                        records: p
                            .edits
                            .records
                            .iter()
                            .filter(|r| still(r))
                            .cloned()
                            .collect(),
                        ..Edits::default()
                    },
                    ..p.clone()
                };
                let original = if unchanged {
                    p.original.clone()
                } else if !keep.is_empty() || cur.is_none() {
                    None
                } else {
                    Some(sha256(&text))
                };
                // A config the user deleted since is one morsec creates again (review R4).
                let created = p.created_file || cur.is_none();
                (text, original, created, carried, Some(ours))
            }
        };

        let mut doc = parse_doc(&self.paths.config, &base_text)?;
        let mut e = Edits::starting_from(&base_text);
        e.records = carried.records;
        e.created = carried.created;
        let extra_ca = self.plan_doc(&mut doc, cfg, ours.as_ref(), &mut e, &mut warnings)?;
        // Keep an unchanged re-run's records in their earlier order, so it writes nothing.
        if let Some(p) = &prev {
            let rank = |r: &Record| {
                p.edits
                    .records
                    .iter()
                    .position(|x| x.path == r.path)
                    .unwrap_or(usize::MAX)
            };
            e.records.sort_by_key(rank);
            // Created tables too (review R7).
            let crank = |c: &Vec<String>| {
                p.edits
                    .created
                    .iter()
                    .position(|x| x == c)
                    .unwrap_or(usize::MAX)
            };
            e.created.sort_by_key(crank);
        }
        let after = doc.to_string();
        // SPEC D4: prove the change undoes to the exact bytes before writing anything.
        let (back, _) = tedit::undo_text(&after, &e, true).map_err(err)?;
        if back != base_text {
            return Err(err(format!(
                "morsec can't add its settings to {} in a way it can undo exactly, so nothing was changed. Please report this with the layout of your file (not its values)",
                self.paths.config.display()
            )));
        }

        let bundle = self.bundle_text(&extra_ca, &mut warnings)?;
        let state = State {
            original,
            created_file,
            written: sha256(&after),
            edits: e,
            proxy_port: cfg.proxy_port,
            with_mcp: self.opts.with_mcp,
        };
        let state_now = fsio::read_text(&self.paths.state).map_err(err)?;
        let bundle_now = fsio::read_capped(&self.paths.bundle, fsio::MAX_BYTES).map_err(err)?;
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
        push(&self.paths.state, state_now, Self::state_text(&state));
        push(&self.paths.bundle, bundle_now, bundle);
        push(&self.paths.config, cur, after);
        Ok(Planned {
            diff: ConfigDiff { changes },
            warnings,
        })
    }

    /// How an earlier `--force` replaced `p`, when `cur` is the value it left there: a re-run
    /// may replace it again without `--force` (L08 review R7). `ours` holds only the records
    /// whose key still held morsec's value in the file (review R1); a carried redacted record's
    /// value is morsec's own (review R3).
    fn forced_before(ours: Option<&State>, p: &[String], cur: &Item) -> Option<OnConflict> {
        ours.and_then(|s| s.edits.get(p))
            .and_then(|r| match &r.kind {
                Kind::Replaced { before } => tedit::parse_value(before)
                    .is_ok_and(|b| Some(tedit::canon_value(&b)) == tedit::canon_item(cur))
                    .then_some(OnConflict::Keep),
                Kind::Redacted { .. } => Some(OnConflict::Drop),
                Kind::Added => None,
            })
    }

    /// Sets a proxy-like value the user may have set themselves: refused unless `--force` (or
    /// an earlier `--force` replaced exactly this value). The old value is kept unless it holds
    /// credentials (SPEC D6).
    fn set_guarded(
        &self,
        doc: &mut DocumentMut,
        p: &[String],
        item: Item,
        prev: Option<&State>,
        e: &mut Edits,
        what: &str,
    ) -> Result<()> {
        let cur = tedit::get(doc, p).cloned();
        let again = cur.as_ref().and_then(|c| Self::forced_before(prev, p, c));
        let on = match &cur {
            Some(_) if again == Some(OnConflict::Drop) => OnConflict::Drop,
            Some(c) if self.opts.force || again.is_some() => {
                let secretish = match c {
                    Item::Value(v) => v.as_str().is_none_or(has_userinfo),
                    _ => true,
                };
                if secretish || p.first().is_some_and(|k| k == "mcp_servers") && p.len() == 2 {
                    OnConflict::Drop
                } else {
                    OnConflict::Keep
                }
            }
            _ => OnConflict::Refuse,
        };
        if tedit::set(doc, p, item, e, on).map_err(err)?.is_some() {
            return Err(err(format!(
                "{} already sets {} ({what}). morsec needs it. Re-run with --force to replace it{}",
                self.paths.config.display(),
                show_path(p),
                if p.len() == 2 {
                    "; your entry is not kept"
                } else {
                    " (ms disconnect puts yours back)"
                }
            )));
        }
        Ok(())
    }

    /// Sets the morsec variables in the env table at `base`; returns CA files it replaced.
    fn set_env_table(
        &self,
        doc: &mut DocumentMut,
        base: &[String],
        port: u16,
        prev: Option<&State>,
        e: &mut Edits,
    ) -> Result<Vec<PathBuf>> {
        let at = |n: &str| {
            let mut p = base.to_vec();
            p.push(n.to_owned());
            p
        };
        let mut extra = Vec::new();
        let bundle = claude::as_str_path(&self.paths.bundle)?;
        for (name, value) in self.base_env(port)? {
            let p = at(name);
            if CA_VARS.contains(&name) {
                // A CA file the user already named stays trusted: it goes into the bundle.
                if let Some(Item::Value(Value::String(s))) = tedit::get(doc, &p)
                    && *s.value() != bundle
                {
                    let f = PathBuf::from(s.value());
                    if !extra.contains(&f) {
                        extra.push(f);
                    }
                }
                tedit::set(doc, &p, str_item(&value), e, OnConflict::Keep).map_err(err)?;
            } else if PROXY_VARS.contains(&name) {
                self.set_guarded(doc, &p, str_item(&value), prev, e, "a proxy")?;
            } else {
                tedit::set(doc, &p, str_item(&value), e, OnConflict::Keep).map_err(err)?;
            }
        }
        Ok(extra)
    }

    /// A reference at `p`. A value of the user's there is replaced and not kept (SPEC D6).
    fn set_ref(
        doc: &mut DocumentMut,
        p: &[String],
        value: &str,
        e: &mut Edits,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let had_other = tedit::get(doc, p)
            .is_some_and(|c| tedit::canon_item(c) != Some(tedit::Canon::Str(value.to_owned())));
        let was_ours = e
            .get(p)
            .is_some_and(|r| matches!(r.kind, Kind::Redacted { .. }));
        tedit::set(doc, p, str_item(value), e, OnConflict::Drop).map_err(err)?;
        if had_other && !was_ours {
            warnings.push(format!(
                "{} held a value of yours; it is replaced by the reference, and morsec doesn't keep the old value (ms disconnect removes the entry instead of putting it back)",
                show_path(p)
            ));
        }
        Ok(())
    }

    fn plan_doc(
        &self,
        doc: &mut DocumentMut,
        cfg: &ConnectCfg,
        prev: Option<&State>,
        e: &mut Edits,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<PathBuf>> {
        self.warn_weaker(doc, warnings);
        let set_base = path(&["shell_environment_policy", "set"]);
        let mut at = set_base.clone();
        at.push(MARKER.to_owned());
        tedit::set(doc, &at, str_item(ID), e, OnConflict::Keep).map_err(err)?;
        let mut extra = self.set_env_table(doc, &set_base, cfg.proxy_port, prev, e)?;
        for (name, value) in &cfg.env {
            let mut p = set_base.clone();
            p.push(name.clone());
            Self::set_ref(doc, &p, value, e, warnings)?;
        }

        // References for other local MCP servers (SPEC 2).
        let mut servers: Vec<&str> = Vec::new();
        for r in &self.mcp_refs {
            let sp = path(&["mcp_servers", &r.server]);
            let Some(s) = tedit::get(doc, &sp).and_then(Item::as_table_like) else {
                if r.carried {
                    warnings.push(format!(
                        "the MCP server \"{}\" is gone from your Codex config, so morsec dropped its reference {}",
                        r.server, r.name
                    ));
                    continue;
                }
                return Err(err(format!(
                    "{} has no MCP server \"{}\" (mcp_servers.{}). Add it to Codex first (codex mcp add), then connect",
                    self.paths.config.display(),
                    r.server,
                    r.server
                )));
            };
            if s.get("command").is_none() {
                return Err(err(format!(
                    "the MCP server \"{}\" has no command (a remote server, or not set up yet); morsec can only give references to local servers Codex starts",
                    r.server
                )));
            }
            if !servers.contains(&r.server.as_str()) {
                servers.push(&r.server);
            }
            let mut p = sp.clone();
            p.extend(["env".to_owned(), r.name.clone()]);
            Self::set_ref(doc, &p, &r.value, e, warnings)?;
        }
        for s in servers {
            let base = path(&["mcp_servers", s, "env"]);
            for f in self.set_env_table(doc, &base, cfg.proxy_port, prev, e)? {
                if !extra.contains(&f) {
                    extra.push(f);
                }
            }
        }

        if self.opts.with_mcp {
            let entry = self.mcp_entry()?;
            self.set_guarded(
                doc,
                &path(&["mcp_servers", MCP_ID]),
                Item::Table(entry),
                prev,
                e,
                "an MCP server named \"ms\" that morsec didn't add",
            )?;
        }
        Ok(extra)
    }

    /// SDLC-2 / SPEC D1, D12: say so when the user's settings weaken the sandbox or would stop
    /// morsec's variables from arriving. Never changes them.
    fn warn_weaker(&self, doc: &DocumentMut, w: &mut Vec<String>) {
        let s = |p: &[&str]| {
            tedit::get(doc, &path(p))
                .and_then(Item::as_str)
                .map(str::to_owned)
        };
        let truthy = |p: &[&str]| {
            tedit::get(doc, &path(p)).is_some_and(|i| {
                i.as_bool() == Some(true)
                    || i.as_table_like()
                        .and_then(|t| t.get("enabled"))
                        .and_then(Item::as_bool)
                        == Some(true)
            })
        };
        let mode = s(&["sandbox_mode"]);
        if mode.as_deref() == Some(FULL_ACCESS) {
            w.push(format!("your config sets sandbox_mode = \"{FULL_ACCESS}\": Codex runs commands with no sandbox. morsec still keeps values out of reach, but consider workspace-write"));
        }
        if s(&["approval_policy"]).as_deref() == Some(NEVER_ASK) {
            w.push(format!("your config sets approval_policy = \"{NEVER_ASK}\": Codex never asks before running a command"));
        }
        let net = tedit::get(doc, &path(&["sandbox_workspace_write", "network_access"]))
            .and_then(Item::as_bool)
            == Some(true);
        if mode.as_deref() != Some(FULL_ACCESS) && !net {
            w.push("Codex's sandbox has network turned off (the default), so commands Codex runs can't reach morsec either: references in commands resolve only once you allow network (sandbox_workspace_write.network_access = true). MCP servers are not affected. morsec doesn't change this for you".into());
        }
        if truthy(&["features", "network_proxy"])
            || tedit::get(doc, &path(&["permissions"]))
                .and_then(Item::as_table_like)
                .is_some_and(|t| {
                    t.iter().any(|(_, p)| {
                        p.as_table_like()
                            .and_then(|p| p.get("network"))
                            .and_then(Item::as_table_like)
                            .and_then(|n| n.get("enabled"))
                            .and_then(Item::as_bool)
                            == Some(true)
                    })
                })
        {
            w.push("Codex's own network proxy is on; it replaces HTTPS_PROXY in commands, so their traffic won't reach morsec".into());
        }
        let pol =
            tedit::get(doc, &path(&["shell_environment_policy"])).and_then(Item::as_table_like);
        if pol.is_some_and(|p| p.contains_key("include_only") || p.contains_key("filters")) {
            w.push("shell_environment_policy has include_only or filters; check they keep MORSEC_CONNECTED, the proxy and CA variables and your references, or Codex drops them".into());
        }
        if let Some(profiles) = tedit::get(doc, &path(&["profiles"])).and_then(Item::as_table_like)
        {
            for (name, p) in profiles.iter() {
                if p.as_table_like()
                    .is_some_and(|t| t.contains_key("shell_environment_policy"))
                {
                    w.push(format!("profile \"{name}\" sets its own shell_environment_policy; with -p {name}, morsec's variables may not apply"));
                }
            }
        }
    }

    fn bundle_text(&self, extra: &[PathBuf], warnings: &mut Vec<String>) -> Result<String> {
        let roots = fsio::read_capped(&self.paths.system_roots, fsio::MAX_BYTES)
            .map_err(err)?
            .ok_or_else(|| {
                err(format!(
                    "{} is missing, so morsec can't build a CA bundle with the system roots",
                    self.paths.system_roots.display()
                ))
            })?;
        let mut out = String::from(
            "# morsec CA bundle for Codex: system roots, the morsec proxy CA, and CA files your\n# config named. Written by ms connect codex; removed by ms disconnect codex.\n",
        );
        let root_blocks = claude::pem_blocks(&roots);
        if root_blocks.is_empty() {
            return Err(err(format!(
                "{} holds no certificates",
                self.paths.system_roots.display()
            )));
        }
        let mut add = |blocks: Vec<&str>| {
            for b in blocks {
                out.push_str(b);
                out.push('\n');
            }
        };
        add(root_blocks);
        if let Some(ca) = &self.ca_pem {
            let b = claude::pem_blocks(ca);
            if b.is_empty() {
                return Err(err("the daemon's CA certificate is not PEM"));
            }
            add(b);
        }
        for p in extra {
            match fsio::read_capped(p, MAX_CA_FILE) {
                Ok(Some(t)) if !claude::pem_blocks(&t).is_empty() => add(claude::pem_blocks(&t)),
                Ok(_) | Err(_) => warnings.push(format!(
                    "{} (named in your config as a CA file) has no readable certificates; it isn't in the morsec bundle",
                    p.display()
                )),
            }
        }
        Ok(out)
    }

    /// Writes a plan's changes. Each file must still hold what the plan was computed from.
    pub fn apply_changes(&self, diff: &ConfigDiff) -> Result<()> {
        for c in &diff.changes {
            let now = fsio::read_text(&c.path).map_err(err)?;
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
    pub fn plan_remove(&self) -> Result<Option<RemovePlan>> {
        let Some(st) = self.read_state()? else {
            return Ok(None);
        };
        let mut plan = RemovePlan::default();
        let Some(cur) = fsio::read_text(&self.paths.config).map_err(err)? else {
            return Ok(Some(plan));
        };
        parse_doc(&self.paths.config, &cur)?;
        let written = sha256(&cur) == st.written;
        // As in a re-plan: the final newline is morsec's to take off only in the file it wrote.
        let edits = Edits {
            no_final_newline: st.edits.no_final_newline && written,
            ..st.edits.clone()
        };
        let (text, notes) = tedit::undo_text(&cur, &edits, false).map_err(err)?;
        plan.notes.extend(notes);
        if !written && text != cur {
            plan.notes.push(format!(
                "{} was edited after ms connect (by you or Codex), so morsec removed only its own settings and kept the rest",
                self.paths.config.display()
            ));
        }
        if written
            && let Some(o) = &st.original
            && sha256(&text) != *o
        {
            plan.notes.push(format!(
                "{} could not be put back exactly as it was; morsec removed its own settings",
                self.paths.config.display()
            ));
        }
        if text != cur {
            let after = (!(st.created_file && text.is_empty())).then_some(text);
            plan.config = Some((Some(cur), after));
        } else if st.created_file && cur.is_empty() {
            plan.config = Some((Some(cur), None));
        }
        Ok(Some(plan))
    }

    /// Writes a disconnect, then removes the bundle and the state file.
    pub fn apply_remove(&self, plan: &RemovePlan) -> Result<()> {
        if let Some((before, after)) = &plan.config {
            let now = fsio::read_text(&self.paths.config).map_err(err)?;
            if now != *before {
                return Err(err(format!(
                    "{} changed while ms disconnect was running. Nothing was changed; run it again",
                    self.paths.config.display()
                )));
            }
            match after {
                Some(t) => fsio::atomic_write(&self.paths.config, t, 0o600).map_err(err)?,
                None => fsio::remove(&self.paths.config).map_err(err)?,
            }
        }
        fsio::remove(&self.paths.bundle).map_err(err)?;
        fsio::remove(&self.paths.state).map_err(err)?;
        Ok(())
    }

    fn checks(&self) -> Result<Vec<Check>> {
        let fix = "run: ms connect codex";
        let Some(st) = self.read_state()? else {
            return Ok(vec![Check {
                name: "Codex connected".into(),
                ok: false,
                detail: format!("not connected; {fix}"),
            }]);
        };
        let text = fsio::read_text(&self.paths.config)
            .map_err(err)?
            .unwrap_or_default();
        let doc = parse_doc(&self.paths.config, &text)?;
        let is = |p: &[&str], v: &str| tedit::get(&doc, &path(p)).and_then(Item::as_str) == Some(v);
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
        let set = ["shell_environment_policy", "set"];
        check(
            "Codex connected",
            is(&[set[0], set[1], MARKER], ID),
            "the morsec marker is missing from config.toml",
        );
        let url = Self::proxy_url(st.proxy_port);
        check(
            "Codex commands use the morsec proxy",
            PROXY_VARS.iter().all(|n| is(&[set[0], set[1], n], &url)),
            "a proxy variable in shell_environment_policy.set no longer points at morsec",
        );
        let bundle = claude::as_str_path(&self.paths.bundle)?;
        check(
            "Codex trusts the morsec CA",
            CA_VARS.iter().all(|n| is(&[set[0], set[1], n], &bundle))
                && self.paths.bundle.is_file(),
            "a CA variable or the CA bundle is missing",
        );
        for r in &st.edits.records {
            if let [a, server, e, _] = r.path.as_slice()
                && a == "mcp_servers"
                && e == "env"
            {
                let ok = tedit::parse_value(&r.after).is_ok_and(|v| {
                    tedit::get(&doc, &r.path).and_then(tedit::canon_item)
                        == Some(tedit::canon_value(&v))
                });
                check(
                    &format!("Codex MCP server {server} has its morsec reference"),
                    ok,
                    &format!("{} is missing or changed", show_path(&r.path)),
                );
            }
        }
        if st.with_mcp {
            let want = st
                .edits
                .get(&path(&["mcp_servers", MCP_ID]))
                .and_then(|r| tedit::parse_value(&r.after).ok())
                .map(|v| tedit::canon_value(&v));
            let have =
                tedit::get(&doc, &path(&["mcp_servers", MCP_ID])).and_then(tedit::canon_item);
            let ok = match want {
                Some(w) => have == Some(w),
                None => have == tedit::canon_item(&Item::Table(self.mcp_entry()?)),
            };
            check(
                "Codex has the ms MCP server",
                ok,
                "mcp_servers.ms is missing or changed in config.toml",
            );
        }
        Ok(out)
    }
}

impl Connector for CodexConnector {
    fn id(&self) -> &'static str {
        ID
    }

    fn detect(&self) -> Detection {
        let on_path = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("codex").is_file()));
        Detection {
            installed: on_path || self.paths.config.parent().is_some_and(Path::is_dir),
            config_paths: vec![self.paths.config.clone()],
        }
    }

    /// The trait can't return an error (frozen, PLAN §4), so an impossible plan is an empty
    /// diff; callers that need the reason use [`CodexConnector::try_plan`].
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
                name: "Codex config readable".into(),
                ok: false,
                detail: e.to_string(),
            }]
        })
    }
}

#[cfg(test)]
mod tests;
