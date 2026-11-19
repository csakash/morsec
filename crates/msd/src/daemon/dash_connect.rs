//! Connect, Disconnect and Add project from the dashboard (L35 dash-connect).
//!
//! Each is two calls. The preview plans exactly what `ms connect <agent>`, `ms disconnect
//! <agent>` or `ms init` would do, changes nothing, and answers the redacted changes with a plan
//! digest. The apply plans again, refuses when the digest moved, raises Touch ID through the
//! confirm path with a reason that names the agent or folder, every file and every host, plans a
//! third time after the sheet (connect and disconnect: a file edited while the sheet was up is
//! not overwritten), and only then writes. Every apply, done or refused, leaves a receipt;
//! previews leave none (they change nothing). No value reaches a preview or an answer.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ms_connect::view::{self, Syntax, ViewFile};
use ms_connect::{ConnectCfg, Connector};
use ms_core::{KeyMeta, KeyName, Mode, ReceiptResult, SecretBytes, SessionId, Tier};
use ms_dash::actions::{
    ActionCode, ActionError, ActionOk, ActionResult, Actor, AgentPlanView, PlanFileView,
    PlanLineView, ProjectAddView, ProjectFileView, ProjectKeyView, ProjectPreviewView,
};
use ms_import::KeyStore;
use ms_import::catalog::Catalog;
use ms_ipc::{ErrorCode, ResponseBody};
use ms_projects::record::ProjectRecord;
use ms_projects::setup::{self, Host, Prepared, SaveError};
use ms_rules::Rules;

use super::projects::SaveAuth;
use super::{Daemon, admin_request, daemon_key, lock, now_ms};

/// The dashboard connect's own state.
#[derive(Debug, Default)]
pub struct ConnectState {
    /// msd's socket, as `main` bound it.
    socket: OnceLock<PathBuf>,
    /// The user msd serves (the socket's owner).
    uid: OnceLock<u32>,
    /// Watched agent settings files msd itself just wrote, with the fingerprint it left: the
    /// drift watcher skips exactly that one change (SPEC D-8, T-111).
    own_writes: Mutex<Vec<(PathBuf, Option<String>)>>,
    /// Tests: the home the connectors use (never the real one).
    #[cfg(test)]
    pub(crate) home: Mutex<Option<PathBuf>>,
    /// Tests: the `ms` path written into settings.
    #[cfg(test)]
    pub(crate) ms: Mutex<Option<String>>,
    /// Tests: the proxy port (the test daemon runs none).
    #[cfg(test)]
    pub(crate) port: Mutex<Option<u16>>,
}

fn err(code: ActionCode, m: impl Into<String>) -> ActionError {
    ActionError::new(code, m)
}

/// The two agents, by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Agent {
    Claude,
    Codex,
}

impl Agent {
    fn parse(id: &str) -> Result<Self, ActionError> {
        match id {
            "claude-code" => Ok(Agent::Claude),
            "codex" => Ok(Agent::Codex),
            _ => Err(err(
                ActionCode::Invalid,
                "morsec: the dashboard connects claude-code or codex",
            )),
        }
    }
    fn id(self) -> &'static str {
        match self {
            Agent::Claude => ms_connect::claude::ID,
            Agent::Codex => ms_connect::codex::ID,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
        }
    }
}

/// A computed connect or disconnect, ready to apply.
enum Plan {
    ClaudeConnect(
        ms_connect::claude::ClaudeConnector,
        ms_connect::claude::Planned,
    ),
    CodexConnect(
        ms_connect::codex::CodexConnector,
        ms_connect::codex::Planned,
    ),
    ClaudeRemove(
        ms_connect::claude::ClaudeConnector,
        Option<ms_connect::claude::RemovePlan>,
    ),
    CodexRemove(
        ms_connect::codex::CodexConnector,
        Option<ms_connect::codex::RemovePlan>,
    ),
}

/// A plan as people see it, with its digest.
struct Shown {
    plan: Plan,
    files: Vec<ViewFile>,
    notes: Vec<String>,
    digest: String,
    nothing: bool,
}

/// `/Users/me/x` as `~/x`.
fn tilde(p: &Path, home: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

impl Daemon {
    /// Records msd's socket path (for the connectors' sandbox socket and `MORSEC_SOCKET`) and
    /// the user it serves.
    pub fn set_socket_path(&self, p: PathBuf, uid: u32) {
        let _ = self.dash_acts.conn.socket.set(p);
        let _ = self.dash_acts.conn.uid.set(uid);
    }

    /// Whether the drift watcher should skip this change: msd wrote exactly this (once).
    pub(crate) fn take_own_write(&self, path: &Path, fp: &Option<String>) -> bool {
        crate::drift::skip_own(&mut lock(&self.dash_acts.conn.own_writes), path, fp)
    }

    fn connect_home(&self) -> Result<PathBuf, ActionError> {
        #[cfg(test)]
        if let Some(h) = lock(&self.dash_acts.conn.home).clone() {
            return Ok(h);
        }
        std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| err(ActionCode::Unavailable, "morsec: msd has no HOME"))
    }

    /// The `ms` written into agent settings (SPEC D-6): the one next to msd, in msd's own
    /// canonical directory, in a directory only its owner can write and (release builds) outside
    /// HOME. `None` with the reason otherwise.
    fn connect_ms_path(&self, home: &Path) -> Result<String, ActionError> {
        #[cfg(test)]
        if let Some(m) = lock(&self.dash_acts.conn.ms).clone() {
            return Ok(m);
        }
        let no = |why: &str| {
            err(
                ActionCode::Unavailable,
                format!(
                    "morsec can't use the ms command next to msd ({why}), so it can't connect agents from here. Connect from a terminal"
                ),
            )
        };
        let me = std::env::current_exe().map_err(|_| no("msd's own path is unknown"))?;
        let uid = *self
            .dash_acts
            .conn
            .uid
            .get()
            .ok_or_else(|| no("msd's user is not known"))?;
        sibling_ms(&me, home, uid).map_err(|w| no(&w))
    }

    fn connect_socket(&self) -> Result<(String, Option<String>), ActionError> {
        let s = self
            .dash_acts
            .conn
            .socket
            .get()
            .cloned()
            .ok_or_else(|| err(ActionCode::Unavailable, "morsec: msd's socket is not known"))?;
        let text = s
            .to_str()
            .ok_or_else(|| {
                err(
                    ActionCode::Unavailable,
                    "morsec: the socket path is not UTF-8",
                )
            })?
            .to_owned();
        let default = ms_ipc::default_socket_path().ok();
        let env = (default.as_deref() != Some(s.as_path())).then(|| text.clone());
        Ok((text, env))
    }

    /// Every host in the rules in force, as the CLI's `rule_hosts` gives them.
    fn connect_hosts(&self) -> Result<Vec<String>, ActionError> {
        let l = self.read_live();
        if l.rules.tampered {
            return Err(err(
                ActionCode::Refused,
                "morsec: the rules failed their integrity check. Run ms doctor",
            ));
        }
        let mut hosts: Vec<String> = Vec::new();
        for r in l.rules.keys.values() {
            for h in &r.hosts {
                let s = h.to_string();
                if !hosts.contains(&s) {
                    hosts.push(s);
                }
            }
        }
        hosts.sort();
        Ok(hosts)
    }

    fn connect_port_ca(&self) -> Result<(u16, Option<String>), ActionError> {
        #[cfg(test)]
        if let Some(p) = *lock(&self.dash_acts.conn.port) {
            return Ok((p, lock(&self.ca).as_ref().map(|(pem, _)| pem.clone())));
        }
        if self.proxy_port == 0 {
            return Err(err(
                ActionCode::Unavailable,
                "morsec: this msd has no swap proxy, so agents can't be connected to it",
            ));
        }
        Ok((
            self.proxy_port,
            lock(&self.ca).as_ref().map(|(pem, _)| pem.clone()),
        ))
    }

    /// Plans connect or disconnect for `agent`, as `ms connect <agent>` / `ms disconnect <agent>`
    /// with no flags would (SPEC D-1 to D-7).
    fn plan_agent(&self, agent: Agent, disconnect: bool) -> Result<Shown, ActionError> {
        let home = self.connect_home()?;
        let fail = |e: ms_core::Error| err(ActionCode::Internal, e.to_string());
        let mut notes = Vec::new();
        let mut files = Vec::new();
        let terminal = |what: &str| {
            format!(
                "morsec: {what}. Use a terminal: ms {} {}",
                if disconnect { "disconnect" } else { "connect" },
                agent.id()
            )
        };
        match agent {
            Agent::Claude => {
                let paths = ms_connect::claude::Paths::for_home(&home, None);
                let (socket, socket_env) = self.connect_socket()?;
                // Disconnect writes no ms path, but the lines it removes show it: the real one
                // when it resolves, so the page matches the terminal (review R4).
                let ms = if disconnect {
                    self.connect_ms_path(&home)
                        .unwrap_or_else(|_| String::from("ms"))
                } else {
                    self.connect_ms_path(&home)?
                };
                let mut c = ms_connect::claude::ClaudeConnector::new(paths, ms, socket);
                c.socket_env = socket_env;
                if let Some(p) = c.recorded_settings_path().map_err(fail)?
                    && p != c.paths.settings
                {
                    return Err(err(
                        ActionCode::Refused,
                        terminal(&format!(
                            "Claude Code was connected from a terminal with CLAUDE_CONFIG_DIR set ({}), which msd can't see",
                            tilde(&p, &home)
                        )),
                    ));
                }
                if disconnect {
                    let plan = c.plan_remove().map_err(fail)?;
                    let safe = c.display_safe(None);
                    let mut changes = Vec::new();
                    if let Some(p) = &plan {
                        for f in &p.files {
                            files.push(view::settings_file(
                                &f.path,
                                f.before.as_deref(),
                                f.after.as_deref(),
                                Syntax::Json,
                                &safe,
                            ));
                            changes.push((f.path.clone(), f.before.clone(), f.after.clone()));
                        }
                        let state_now = ms_connect::claude::fsio::read_text(&c.paths.state)
                            .ok()
                            .flatten();
                        changes.push((c.paths.state.clone(), state_now, p.state_after.clone()));
                        files.push(view::own_file(
                            &c.paths.state,
                            if p.state_after.is_some() {
                                "keep"
                            } else {
                                "drop"
                            },
                        ));
                        notes.extend(p.notes.iter().cloned());
                    }
                    let digest = view::digest(
                        agent.id(),
                        "disconnect",
                        changes.iter().map(|(p, b, a)| view::Change {
                            path: p,
                            before: b.as_deref(),
                            after: a.as_deref(),
                        }),
                    );
                    let nothing = plan.is_none();
                    return Ok(Shown {
                        plan: Plan::ClaudeRemove(c, plan),
                        files,
                        notes,
                        digest,
                        nothing,
                    });
                }
                let prev = c.previous_options().map_err(fail)?;
                if prev.wrap {
                    return Err(err(
                        ActionCode::Refused,
                        terminal(
                            "Claude Code was connected with --wrap, which changes how every hook runs, so only a terminal re-runs it",
                        ),
                    ));
                }
                c.opts.with_mcp = prev.with_mcp;
                c.opts.statusline = prev.statusline;
                let mut env = c.ca_env().map_err(fail)?;
                env.extend(c.previous_env_refs().map_err(fail)?);
                let (port, ca) = self.connect_port_ca()?;
                c.ca_pem = ca;
                let cfg = ConnectCfg {
                    proxy_port: port,
                    allowed_domains: self.connect_hosts()?,
                    env,
                    shim_dir: Some(c.paths.shims.clone()),
                };
                let planned = c.try_plan(&cfg).map_err(fail)?;
                let safe = c.display_safe(Some(&cfg));
                for ch in &planned.diff.changes {
                    files.push(
                        if ch.path == c.paths.settings || ch.path == c.paths.claude_json {
                            view::settings_file(
                                &ch.path,
                                ch.before.as_deref(),
                                Some(&ch.after),
                                Syntax::Json,
                                &safe,
                            )
                        } else {
                            view::own_file(&ch.path, "write")
                        },
                    );
                }
                notes.extend(planned.warnings.iter().cloned());
                let digest = view::connect_digest(agent.id(), &planned.diff);
                let nothing = planned.diff.changes.is_empty();
                Ok(Shown {
                    plan: Plan::ClaudeConnect(c, planned),
                    files,
                    notes,
                    digest,
                    nothing,
                })
            }
            Agent::Codex => {
                let paths = ms_connect::codex::Paths::for_home(&home, None);
                let ms = if disconnect {
                    self.connect_ms_path(&home)
                        .unwrap_or_else(|_| String::from("ms"))
                } else {
                    self.connect_ms_path(&home)?
                };
                let mut c = ms_connect::codex::CodexConnector::new(paths, ms);
                c.socket_env = self.connect_socket()?.1;
                if let Some(p) = c.recorded_config_path().map_err(fail)?
                    && p != c.paths.config
                {
                    return Err(err(
                        ActionCode::Refused,
                        terminal(&format!(
                            "Codex was connected from a terminal with CODEX_HOME set ({}), which msd can't see",
                            tilde(&p, &home)
                        )),
                    ));
                }
                if disconnect {
                    let plan = c.plan_remove().map_err(fail)?;
                    let safe = c.display_safe(None);
                    let mut changes = Vec::new();
                    if let Some(p) = &plan {
                        if let Some((before, after)) = &p.config {
                            files.push(view::settings_file(
                                &c.paths.config,
                                before.as_deref(),
                                after.as_deref(),
                                Syntax::Toml,
                                &safe,
                            ));
                            changes.push((c.paths.config.clone(), before.clone(), after.clone()));
                        }
                        let state_now = ms_connect::claude::fsio::read_text(&c.paths.state)
                            .ok()
                            .flatten();
                        changes.push((c.paths.state.clone(), state_now, None));
                        files.push(view::own_file(&c.paths.state, "drop"));
                        notes.extend(p.notes.iter().cloned());
                    }
                    let digest = view::digest(
                        agent.id(),
                        "disconnect",
                        changes.iter().map(|(p, b, a)| view::Change {
                            path: p,
                            before: b.as_deref(),
                            after: a.as_deref(),
                        }),
                    );
                    let nothing = plan.is_none();
                    return Ok(Shown {
                        plan: Plan::CodexRemove(c, plan),
                        files,
                        notes,
                        digest,
                        nothing,
                    });
                }
                c.opts.with_mcp = c.previous_options().map_err(fail)?.with_mcp;
                let env = c.previous_env_refs().map_err(fail)?;
                c.mcp_refs = c.previous_mcp_refs().map_err(fail)?;
                let (port, ca) = self.connect_port_ca()?;
                c.ca_pem = ca;
                let cfg = ConnectCfg {
                    proxy_port: port,
                    allowed_domains: Vec::new(),
                    env,
                    shim_dir: None,
                };
                let planned = c.try_plan(&cfg).map_err(fail)?;
                let safe = c.display_safe(Some(&cfg));
                for ch in &planned.diff.changes {
                    files.push(if ch.path == c.paths.config {
                        view::settings_file(
                            &ch.path,
                            ch.before.as_deref(),
                            Some(&ch.after),
                            Syntax::Toml,
                            &safe,
                        )
                    } else {
                        view::own_file(&ch.path, "write")
                    });
                }
                notes.extend(planned.warnings.iter().cloned());
                let digest = view::connect_digest(agent.id(), &planned.diff);
                let nothing = planned.diff.changes.is_empty();
                Ok(Shown {
                    plan: Plan::CodexConnect(c, planned),
                    files,
                    notes,
                    digest,
                    nothing,
                })
            }
        }
    }

    /// Connect or disconnect preview (SPEC D-1): no mutation, no Touch ID, no receipt.
    pub(crate) fn dash_agent_preview(
        &self,
        agent: &str,
        disconnect: bool,
    ) -> Result<AgentPlanView, ActionError> {
        let agent = Agent::parse(agent)?;
        let home = self.connect_home()?;
        let s = self.plan_agent(agent, disconnect)?;
        let mut notes: Vec<String> = s.notes.iter().map(|n| setup::safe_text(n)).collect();
        if !disconnect && self.is_stopped() {
            notes.push("morsec is stopped: agents can't use keys until you start it".into());
        }
        Ok(AgentPlanView {
            agent: agent.id().into(),
            action: if disconnect { "disconnect" } else { "connect" }.into(),
            plan: s.digest,
            nothing_to_do: s.nothing,
            files: s
                .files
                .iter()
                .map(|f| PlanFileView {
                    path: setup::safe_text(&tilde(&f.path, &home)),
                    verb: f.verb.into(),
                    lines: f
                        .lines
                        .iter()
                        .map(|l| PlanLineView {
                            sign: l.sign.to_string(),
                            n: l.n,
                            text: setup::safe_text(&l.text),
                        })
                        .collect(),
                    too_large: f.too_large,
                })
                .collect(),
            notes,
        })
    }

    /// Connect or disconnect as previewed (SPEC D-1 to D-3): plan, digest, Touch ID, plan and
    /// digest again, write.
    pub(crate) fn dash_agent_apply(
        &self,
        a: &Actor,
        agent: &str,
        disconnect: bool,
        plan: &str,
    ) -> ActionResult {
        let key = daemon_key();
        let verb = if disconnect { "disconnect" } else { "connect" };
        let agent = Agent::parse(agent)?;
        let what = format!("{verb} {}", agent.id());
        let refuse = |e: ActionError| self.refuse(a, &key, &what, e);
        if disconnect && self.is_stopped() {
            return Err(refuse(err(
                ActionCode::Stopped,
                "morsec: morsec is stopped, so agents can't be disconnected from here. Start it first",
            )));
        }
        let home = self.connect_home().map_err(refuse)?;
        let first = self.plan_agent(agent, disconnect).map_err(refuse)?;
        if first.digest != plan {
            return Err(refuse(changed(agent)));
        }
        if first.nothing {
            return Ok(ActionOk::new(if disconnect {
                format!("{} is not connected; nothing to do", agent.name())
            } else {
                format!("{} is already connected; nothing to change", agent.name())
            }));
        }
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let req = admin_request(
            &a.session,
            key.clone(),
            Tier::Production,
            &["dashboard", verb, agent.id(), &format!("plan {plan}")],
        );
        let shown: Vec<String> = first
            .files
            .iter()
            .filter(|f| !matches!(f.verb, "write" | "keep" | "drop"))
            .map(|f| tilde(&f.path, &home))
            .collect();
        let reason = if disconnect {
            format!(
                "disconnect {} from morsec: restore {}; its requests stop going through morsec and its sandbox settings are removed",
                agent.name(),
                ms_approve::render::inert(&shown.join(", "))
            )
        } else {
            format!(
                "connect {} to morsec: change {} (sandbox on, its requests through morsec)",
                agent.name(),
                ms_approve::render::inert(&shown.join(", "))
            )
        };
        let token = self.dash_confirm(&req, &reason).map_err(refuse)?;
        if disconnect
            && (self.is_stopped()
                || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen)
        {
            return Err(refuse(err(
                ActionCode::Stopped,
                "morsec: morsec was stopped while Touch ID was up, so nothing changed",
            )));
        }
        // Planned again after the sheet: a file edited while it was up is not overwritten.
        let again = self.plan_agent(agent, disconnect).map_err(refuse)?;
        if again.digest != plan {
            return Err(refuse(changed(agent)));
        }
        // msd's own writes are not drift (SPEC D-8). The content it is about to write is
        // recorded before writing, so a poll between the write and the record can't alert on it
        // (review R8); afterwards only what is really on disk stays recorded.
        let watched = crate::drift::watched(&home);
        let expected: Vec<(PathBuf, Option<String>)> = planned_contents(&again.plan)
            .into_iter()
            .filter(|(p, _)| watched.contains(p))
            .map(|(p, after)| {
                let fp = after.map(|t| {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(t.as_bytes()))
                });
                (p, fp)
            })
            .collect();
        {
            let mut w = lock(&self.dash_acts.conn.own_writes);
            for (p, fp) in &expected {
                w.retain(|(q, _)| q != p);
                w.push((p.clone(), fp.clone()));
            }
        }
        let partly = match &again.plan {
            Plan::ClaudeConnect(c, p) => c.apply(&p.diff).map(|()| false),
            Plan::CodexConnect(c, p) => c.apply(&p.diff).map(|()| false),
            Plan::ClaudeRemove(c, Some(p)) => c.apply_remove(p).map(|()| p.state_after.is_some()),
            Plan::CodexRemove(c, Some(p)) => c.apply_remove(p).map(|()| false),
            Plan::ClaudeRemove(_, None) | Plan::CodexRemove(_, None) => Ok(false),
        };
        {
            let mut w = lock(&self.dash_acts.conn.own_writes);
            for (p, fp) in &expected {
                w.retain(|(q, _)| q != p);
                let now = crate::drift::fingerprint(p);
                if partly.is_ok() && now == *fp {
                    w.push((p.clone(), now));
                }
            }
        }
        match partly {
            Err(e) => Err(refuse(err(
                ActionCode::Internal,
                setup::safe_text(&e.to_string()),
            ))),
            Ok(true) => {
                self.dash_receipt(a, &key, &what, ReceiptResult::Approved, Some(&token));
                Err(err(
                    ActionCode::Internal,
                    "morsec: partly disconnected: Claude Code's settings are restored, but morsec's changes in ~/.claude.json are still there. Fix that file, then run: ms disconnect claude-code",
                ))
            }
            Ok(false) => {
                self.dash_receipt(a, &key, &what, ReceiptResult::Approved, Some(&token));
                Ok(ActionOk::new(if disconnect {
                    format!(
                        "Disconnected {}; its settings are back as they were",
                        agent.name()
                    )
                } else {
                    format!(
                        "Connected {}. Restart its open sessions so they pick it up",
                        agent.name()
                    )
                }))
            }
        }
    }

    // ---- Add project and re-scan (SPEC D-10 to D-14) --------------------------------------

    /// The folder check, then `prepare`. `Ok(Err(view))` when the folder is refused.
    fn project_prepare(
        &self,
        host: &MsdHost<'_>,
        path: &str,
    ) -> Result<Result<(Prepared, String), ProjectPreviewView>, ActionError> {
        let check = self.dash_check_path(path)?;
        if !check.ok {
            return Ok(Err(ProjectPreviewView {
                ok: false,
                reason: check.reason,
                ..ProjectPreviewView::default()
            }));
        }
        let Some(folder) = check.folder.clone() else {
            return Err(err(
                ActionCode::Internal,
                "morsec: the folder check gave no folder",
            ));
        };
        let command = check.command.unwrap_or_default();
        match setup::prepare(host, Catalog::builtin(), Path::new(&folder), None) {
            Ok(p) => Ok(Ok((p, command))),
            Err(e) => {
                let e = setup::safe_text(&e);
                let low = e.to_lowercase();
                let reason = if low.contains("operation not permitted")
                    || low.contains("permission denied")
                {
                    format!(
                        "macOS did not let morsec read this folder ({e}). Allow msd in System Settings → Privacy & Security → Files and Folders, or run the command below in a terminal"
                    )
                } else {
                    e
                };
                Ok(Err(ProjectPreviewView {
                    ok: false,
                    reason: Some(reason),
                    command: Some(command),
                    root: folder,
                    ..ProjectPreviewView::default()
                }))
            }
        }
    }

    /// Add project's preview (SPEC D-11): reads only.
    pub(crate) fn dash_project_preview(
        &self,
        a: &Actor,
        path: &str,
    ) -> Result<ProjectPreviewView, ActionError> {
        let host = MsdHost::new(self, &a.session);
        let (p, command) = match self.project_prepare(&host, path)? {
            Ok(x) => x,
            Err(v) => return Ok(v),
        };
        Ok(preview_view(&p, command))
    }

    /// Sets the folder up as previewed (SPEC D-11, D-12): refused while stopped or with the
    /// records unreadable; digest; Touch ID; `execute` on the digested `Prepared`.
    pub(crate) fn dash_project_add(
        &self,
        a: &Actor,
        path: &str,
        plan: &str,
    ) -> Result<ProjectAddView, ActionError> {
        let key = daemon_key();
        let what = "add project";
        let refuse = |e: ActionError| self.refuse(a, &key, what, e);
        if self.is_stopped() {
            return Err(refuse(err(
                ActionCode::Stopped,
                "morsec: morsec is stopped, so projects can't be set up. Start it first",
            )));
        }
        if let Err(e) = self.dash_projects() {
            return Err(refuse(err(ActionCode::Refused, e)));
        }
        let mut host = MsdHost::new(self, &a.session);
        let (p, _) = match self.project_prepare(&host, path).map_err(refuse)? {
            Ok(x) => x,
            Err(v) => {
                return Err(refuse(err(
                    ActionCode::Invalid,
                    v.reason
                        .unwrap_or_else(|| "morsec: that folder can't be set up".into()),
                )));
            }
        };
        if p.digest() != plan {
            return Err(refuse(err(
                ActionCode::Changed,
                "The folder changed since you looked (a file or a line moved). Review it again",
            )));
        }
        let what = format!("add project {}", p.slug);
        let refuse = |e: ActionError| self.refuse(a, &key, &what, e);
        // A key that already allows something joins a project only from a terminal `ms init`,
        // which names it in its own approval (L34 S2; SPEC D-12).
        if let Some(k) = self.loose_adoption(&p) {
            return Err(refuse(err(
                ActionCode::Refused,
                format!(
                    "morsec: {k} already allows something, so it joins project {} only from a terminal. Run the command below",
                    p.slug
                ),
            )));
        }
        if p.nothing_to_do() {
            return Ok(ProjectAddView {
                message: format!("Nothing new to protect in {}", p.display),
                slug: p.slug.clone(),
                rows: Vec::new(),
                partial: false,
            });
        }
        let home = self.connect_home().ok();
        let shown_root = home
            .as_deref()
            .map_or_else(|| p.root.display().to_string(), |h| tilde(&p.root, h));
        let req = admin_request(
            &a.session,
            key.clone(),
            Tier::Production,
            &[
                "dashboard",
                "add project",
                &p.slug,
                &p.root.display().to_string(),
                &format!("plan {plan}"),
            ],
        );
        let reason = approval_reason(&p, &shown_root);
        // A Stop (and Start) while the sheet is up voids it, as for every loosening (review R2).
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let token = self.dash_confirm(&req, &reason).map_err(refuse)?;
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return Err(refuse(err(
                ActionCode::Stopped,
                "morsec: morsec was stopped while Touch ID was up, so nothing was set up",
            )));
        }
        self.dash_receipt(a, &key, &what, ReceiptResult::Approved, Some(&token));
        host.confirmed = Some((token, p.proposed.clone()));
        let slug = p.slug.clone();
        let rep = setup::execute(&host, Catalog::builtin(), p, now_ms());
        let keys = rep
            .record
            .as_ref()
            .map(|r| self.key_statuses(r))
            .unwrap_or_default();
        Ok(add_view(&rep, &slug, &keys))
    }
}

impl Daemon {
    /// A ref in the folder to a key of this project that the earlier record doesn't list and
    /// whose rule already allows something.
    fn loose_adoption(&self, p: &Prepared) -> Option<KeyName> {
        let earlier: Vec<KeyName> = p
            .previous
            .as_ref()
            .map(ProjectRecord::keys)
            .unwrap_or_default();
        let l = self.read_live();
        p.adopted
            .iter()
            .flatten()
            .map(|s| &s.key)
            .find(|k| {
                !earlier.contains(k)
                    && l.rules
                        .keys
                        .get(*k)
                        .is_some_and(|r| !ms_projects::save::is_fresh(r))
            })
            .cloned()
    }
}

/// Each file a plan writes, with its content after (`None`: removed).
fn planned_contents(plan: &Plan) -> Vec<(PathBuf, Option<String>)> {
    match plan {
        Plan::ClaudeConnect(_, p) => p
            .diff
            .changes
            .iter()
            .map(|c| (c.path.clone(), Some(c.after.clone())))
            .collect(),
        Plan::CodexConnect(_, p) => p
            .diff
            .changes
            .iter()
            .map(|c| (c.path.clone(), Some(c.after.clone())))
            .collect(),
        Plan::ClaudeRemove(_, Some(p)) => p
            .files
            .iter()
            .map(|f| (f.path.clone(), f.after.clone()))
            .collect(),
        Plan::CodexRemove(c, Some(p)) => p
            .config
            .as_ref()
            .map(|(_, after)| vec![(c.paths.config.clone(), after.clone())])
            .unwrap_or_default(),
        Plan::ClaudeRemove(_, None) | Plan::CodexRemove(_, None) => Vec::new(),
    }
}

fn changed(agent: Agent) -> ActionError {
    err(
        ActionCode::Changed,
        format!(
            "{}'s settings changed since you looked. Review the changes again",
            agent.name()
        ),
    )
}

/// `ms` next to `me` (msd as launched), checked (SPEC D-6).
fn sibling_ms(me: &Path, home: &Path, uid: u32) -> Result<String, String> {
    let dir = me.parent().ok_or("msd has no directory")?;
    let ms = dir.join("ms");
    let real = std::fs::canonicalize(&ms).map_err(|_| "no ms next to msd".to_owned())?;
    if !std::fs::metadata(&real).is_ok_and(|m| m.is_file()) {
        return Err("ms next to msd is not a file".into());
    }
    let my_dir = std::fs::canonicalize(me)
        .ok()
        .and_then(|m| m.parent().map(Path::to_path_buf));
    if real.parent() != my_dir.as_deref() {
        return Err("ms next to msd is not from the same install".into());
    }
    let home = std::fs::canonicalize(home).ok();
    let skip_home = cfg!(debug_assertions);
    if !ms_connect::stable_dir(
        dir,
        if skip_home { None } else { home.as_deref() },
        None,
        uid,
    ) {
        return Err("its folder is writable by others, or inside your home folder".into());
    }
    ms.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "its path is not UTF-8".into())
}

/// The Touch ID reason for Add project: the folder, every file, every host (SPEC D-11).
fn approval_reason(p: &Prepared, shown_root: &str) -> String {
    let i = ms_approve::render::inert;
    let files: Vec<&str> = p
        .files
        .iter()
        .filter(|f| {
            f.plan
                .as_ref()
                .is_ok_and(|pl| pl.rows.iter().any(|r| r.action.rewrites()))
        })
        .map(|f| f.rel.as_str())
        .collect();
    let mut hosts: Vec<String> = Vec::new();
    let mut runs: Vec<String> = Vec::new();
    let mut swap = 0;
    let mut run = 0;
    for r in p.proposed.keys.values() {
        match r.mode {
            Mode::Run => {
                run += 1;
                for f in &r.roots {
                    let s = f.display().to_string();
                    if !runs.contains(&s) {
                        runs.push(s);
                    }
                }
            }
            _ => {
                swap += 1;
                for h in &r.hosts {
                    let s = h.to_string();
                    if !hosts.contains(&s) {
                        hosts.push(s);
                    }
                }
            }
        }
    }
    let mut out = format!(
        "set up project {} in {}: move {} secret{} from {} into morsec",
        i(&p.slug),
        i(shown_root),
        p.rewrites(),
        if p.rewrites() == 1 { "" } else { "s" },
        i(&files.join(", "))
    );
    if swap > 0 {
        out.push_str(&format!(
            "; {swap} key{} may reach {}",
            if swap == 1 { "" } else { "s" },
            i(&hosts.join(", "))
        ));
    }
    if run > 0 {
        out.push_str(&format!(
            "; {run} database key{} may run in {}",
            if run == 1 { "" } else { "s" },
            i(&runs.join(", "))
        ));
    }
    out
}

fn preview_view(p: &Prepared, command: String) -> ProjectPreviewView {
    let mut keys: Vec<ProjectKeyView> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut files = Vec::new();
    for (i, f) in p.files.iter().enumerate() {
        let mut v = ProjectFileView {
            path: setup::safe_text(&f.rel),
            ..ProjectFileView::default()
        };
        match &f.plan {
            Err(e) => v.error = Some(setup::safe_text(e)),
            Ok(plan) => {
                for r in plan.rows.iter().filter(|r| r.action.rewrites()) {
                    v.secrets += 1;
                    if r.action == ms_import::plan::Action::Import {
                        v.new_keys += 1;
                    } else {
                        v.reused += 1;
                    }
                    if let Some(k) = &r.key
                        && r.action == ms_import::plan::Action::Import
                        && seen.insert(k.clone())
                    {
                        keys.push(key_view(p, k, r.provider.clone(), r.mode));
                    }
                }
            }
        }
        for a in p.adopted.get(i).into_iter().flatten() {
            if seen.insert(a.key.clone()) {
                keys.push(key_view(p, &a.key, a.provider.clone(), None));
            }
        }
        if v.secrets > 0 || v.error.is_some() {
            files.push(v);
        }
    }
    // Keys an earlier run stored that get their first rule now (review R1).
    for k in p.proposed.keys.keys() {
        if seen.insert(k.clone()) {
            let provider = p
                .previous
                .as_ref()
                .and_then(|r| r.provider_of(k).map(str::to_owned));
            keys.push(key_view(p, k, provider, None));
        }
    }
    for (rel, why) in &p.failed {
        files.push(ProjectFileView {
            path: setup::safe_text(rel),
            error: Some(setup::safe_text(why)),
            ..ProjectFileView::default()
        });
    }
    ProjectPreviewView {
        ok: true,
        reason: None,
        command: Some(command),
        plan: p.digest(),
        slug: p.slug.clone(),
        display: setup::safe_text(&p.display),
        root: p.root.display().to_string(),
        existing: p.previous.is_some(),
        files,
        keys,
        findings: p.scan.findings.len(),
        stopped_early: p
            .scan
            .stopped_early
            .then(|| p.scan.stop_reason.clone().unwrap_or_default()),
        too_large: p
            .scan
            .too_large
            .iter()
            .map(|s| setup::safe_text(s))
            .collect(),
        nothing_to_do: p.nothing_to_do(),
    }
}

fn key_view(
    p: &Prepared,
    k: &KeyName,
    provider: Option<String>,
    mode: Option<Mode>,
) -> ProjectKeyView {
    let rule = p.proposed.keys.get(k);
    let reaches = rule
        .map(|r| r.hosts.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    let runs_in = rule
        .map(|r| r.roots.iter().map(|f| f.display().to_string()).collect())
        .unwrap_or_default();
    let needs = match rule {
        Some(_) => None,
        None if mode == Some(Mode::Run) => Some("command".to_owned()),
        None => Some("website".to_owned()),
    };
    ProjectKeyView {
        key: k.to_string(),
        provider,
        reaches,
        runs_in,
        needs,
    }
}

/// The `ms init` summary, as rows for the page.
fn add_view(r: &setup::Report, slug: &str, keys: &[ms_ipc::KeyStatus]) -> ProjectAddView {
    let mut rows: Vec<(String, String)> = Vec::new();
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    rows.push((
        "Project".into(),
        format!("{}  ({})", r.display, r.root.display()),
    ));
    // The rows `ms init` prints (its `summary_rows`), from the same report and key states
    // (review R6).
    let total = keys.len();
    let ready = keys.iter().filter(|k| k.ready).count();
    rows.push((
        "Found".into(),
        if r.found > 0 {
            format!(
                "{} in {}",
                plural(r.found, "secret", "secrets"),
                plural(r.files, "file", "files")
            )
        } else if total > 0 {
            let waiting = total - ready;
            if waiting == 0 {
                format!("nothing new; {ready} already protected")
            } else {
                format!(
                    "nothing new; {ready} already protected, {waiting} still {} you",
                    if waiting == 1 { "needs" } else { "need" }
                )
            }
        } else {
            "no secrets in this project".into()
        },
    ));
    if total > 0 {
        rows.push(("Protected".into(), format!("{ready}, ready to use")));
    }
    if let Some(first) = r.missing.first() {
        rows.push((
            "Missing".into(),
            format!(
                "{} no longer in the vault ({first}{}); its lines still hold the ref",
                plural(r.missing.len(), "key is", "keys are"),
                if r.missing.len() > 1 { " and more" } else { "" }
            ),
        ));
    }
    let unknown: Vec<&ms_ipc::KeyStatus> = keys
        .iter()
        .filter(|k| {
            !k.ready
                && k.mode != Some(Mode::Run)
                && r.record
                    .as_ref()
                    .is_some_and(|rec| rec.provider_of(&k.key).is_none())
        })
        .collect();
    if let Some(k) = unknown.first() {
        rows.push((
            "Needs you".into(),
            format!(
                "{} no known service yet: give {} its website on its page",
                plural(unknown.len(), "has", "have"),
                k.key
            ),
        ));
    }
    let run_keys: Vec<&ms_ipc::KeyStatus> = keys
        .iter()
        .filter(|k| !k.ready && k.mode == Some(Mode::Run))
        .collect();
    if let Some(k) = run_keys.first() {
        rows.push((
            "Needs you".into(),
            format!(
                "{} can run only in this folder and needs its commands: add them on {}'s page",
                plural(run_keys.len(), "database key", "database keys"),
                k.key
            ),
        ));
    }
    if r.recovered > 0 {
        rows.push((
            "Recovered".into(),
            format!(
                "{} an earlier run stored but never recorded",
                plural(r.recovered, "key", "keys")
            ),
        ));
    }
    if let Some(why) = &r.declined {
        rows.push((
            "Rules".into(),
            format!("not saved, so the new keys can't be used yet ({why})"),
        ));
    }
    if let Some(e) = &r.rules_error {
        rows.push(("Rules".into(), format!("not saved: {e}")));
    }
    if let Some(e) = &r.save_error {
        rows.push(("Record".into(), format!("not saved: {e}")));
    }
    if let Some(f) = r.findings.first() {
        rows.push((
            "In code".into(),
            format!(
                "{} written straight into {}:{}{} (move it into .env, then re-scan)",
                plural(r.findings.len(), "key", "keys"),
                f.path,
                f.line,
                if r.findings.len() > 1 {
                    " and more"
                } else {
                    ""
                }
            ),
        ));
    }
    if r.findings_skipped > 0 {
        rows.push((
            "In code".into(),
            format!(
                "{} more not recorded (too many, or a path morsec can't record)",
                r.findings_skipped
            ),
        ));
    }
    for (file, n) in &r.committed {
        rows.push((
            "Committed".into(),
            format!(
                "{file} is in {}: rotate those keys at each provider",
                plural(*n as usize, "git commit", "git commits")
            ),
        ));
    }
    for (file, why) in &r.failed {
        rows.push(("Skipped".into(), format!("{file}: {why}")));
    }
    for file in &r.too_large {
        rows.push((
            "Skipped".into(),
            format!("{file}: too large for a .env file"),
        ));
    }
    if let Some(why) = &r.stopped_early {
        rows.push(("Scan".into(), format!("stopped {why}")));
    }
    if !r.hints.is_empty() {
        rows.push((
            "Hint".into(),
            format!(
                "added to {}: agents keep the ms:// refs as they are",
                r.hints.join(", ")
            ),
        ));
    }
    let rows: Vec<(String, String)> = rows
        .into_iter()
        .map(|(a, b)| (a, setup::safe_text(&b)))
        .collect();
    let partial = r.declined.is_some()
        || r.rules_error.is_some()
        || r.save_error.is_some()
        || !r.failed.is_empty();
    ProjectAddView {
        message: if r.save_error.is_some() {
            format!("Project {slug} was not saved")
        } else if partial {
            format!("Project {slug} set up, with some things left to do")
        } else {
            format!("Project {slug} set up")
        },
        slug: slug.to_owned(),
        rows,
        partial,
    }
}

// ---- msd as the setup host -------------------------------------------------------------------

/// msd's side of `ms_projects::setup` (SPEC D-10): its records, its vault (through `put_key_as`,
/// so each new key gets a rule that allows nothing and a receipt), its rules, and
/// `project_save`'s core with the dashboard's token.
struct MsdHost<'a> {
    d: &'a Daemon,
    session: &'a SessionId,
    /// The token Touch ID gave and the rules the person saw.
    confirmed: Option<(ms_approve::ApprovalToken, Rules)>,
}

impl<'a> MsdHost<'a> {
    fn new(d: &'a Daemon, session: &'a SessionId) -> Self {
        Self {
            d,
            session,
            confirmed: None,
        }
    }
}

impl KeyStore for MsdHost<'_> {
    fn list(&self) -> Result<Vec<KeyMeta>, ms_import::Error> {
        self.d
            .scan_keys()
            .map(|l| l.keys)
            .map_err(|e| ms_import::Error::Store(e.to_string()))
    }

    fn put(
        &self,
        name: &KeyName,
        value: SecretBytes,
        meta: KeyMeta,
    ) -> Result<(), ms_import::Error> {
        match self.d.put_key_as(
            self.session,
            name.clone(),
            meta,
            value,
            "dashboard: add project",
        ) {
            ResponseBody::Ok { .. } => Ok(()),
            ResponseBody::Error { message, .. } => Err(ms_import::Error::Store(message)),
            _ => Err(ms_import::Error::Store("unexpected answer".into())),
        }
    }
}

impl Host for MsdHost<'_> {
    fn projects(&self) -> Result<Vec<(String, PathBuf)>, String> {
        Ok(self
            .d
            .dash_projects()?
            .projects
            .into_iter()
            .map(|p| (p.slug, PathBuf::from(p.root)))
            .collect())
    }

    fn record(&self, slug: &str) -> Result<ProjectRecord, String> {
        self.d
            .dash_projects()?
            .projects
            .into_iter()
            .find(|p| p.slug == slug)
            .ok_or_else(|| format!("morsec: no project named {slug}"))
    }

    fn store(&self) -> &dyn KeyStore {
        self
    }

    fn rules(&self) -> Result<Rules, String> {
        let l = self.d.read_live();
        if l.rules.tampered {
            return Err("morsec: the rules failed their integrity check. Run ms doctor".into());
        }
        Ok(l.rules.clone())
    }

    fn save(&self, record: &ProjectRecord, rules: &Rules) -> Result<(), SaveError> {
        // Only an add the person confirmed saves; a preview never gets here. Both saves go
        // through the confirmed path, so nothing here can raise a second approval.
        let Some((token, allowed)) = &self.confirmed else {
            return Err(SaveError::Declined("morsec: no approval was given".into()));
        };
        let auth = SaveAuth::Confirmed { token, allowed };
        match self
            .d
            .project_save_parsed(self.session, record, rules, auth)
        {
            ResponseBody::Ok { .. } => Ok(()),
            ResponseBody::Error {
                code: ErrorCode::NeedsApproval | ErrorCode::Busy | ErrorCode::Denied,
                message,
            } => Err(SaveError::Declined(message)),
            ResponseBody::Error { message, .. } => Err(SaveError::Failed(message)),
            _ => Err(SaveError::Failed("unexpected answer".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::tests::*;
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{AgentKind, SessionId};
    use std::sync::Arc;

    const TOKEN: &str = concat!("ghp_", "CONNECTcanaryxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    const OPENAI: &str = concat!("sk-", "proj-", "canaryxxxxxxxxxxxxxxxxxxxxxxxx");
    const STRIPE: &str = concat!("sk_", "test_", "51HcanaryADDPROJECTxxxxxxxxxxxxxxxxxxxxxx");

    fn actor() -> Actor {
        Actor {
            session: SessionId {
                agent: AgentKind::Other("dashboard".into()),
                pid: 7,
                started_unix_ms: 1,
            },
            peer: "127.0.0.1:50000".parse().unwrap(),
            local: "127.0.0.1:7311".parse().unwrap(),
        }
    }

    /// A test home with Claude Code and Codex settings, wired into `h`.
    fn wire(h: &H) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            format!("{{\n  \"env\": {{\n    \"MY_TOKEN\": \"{TOKEN}\"\n  }}\n}}\n"),
        )
        .unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::write(
            home.join(".codex/config.toml"),
            format!("model = \"o3\"\n\n[shell_environment_policy.set]\nMY_TOKEN = \"{TOKEN}\"\n"),
        )
        .unwrap();
        *lock(&h.d.dash_acts.conn.home) = Some(home.clone());
        *lock(&h.d.dash_acts.conn.ms) = Some("/opt/homebrew/bin/ms".into());
        *lock(&h.d.dash_acts.conn.port) = Some(4101);
        h.d.set_socket_path(home.join("msd.sock"), 501);
        *lock(&h.d.ca) = Some((
            "-----BEGIN CERTIFICATE-----\nTU9SU0VDLUNB\n-----END CERTIFICATE-----\n".into(),
            vec![],
        ));
        (d, home)
    }

    fn denying() -> H {
        let dir = tempfile::tempdir().unwrap();
        open_auth(
            crate::backend::Backend::Memory(Arc::new(ms_vault::memory::MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
            FakeAuthenticator::deny("cancelled"),
        )
    }

    fn files(home: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![home.to_owned()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    stack.push(e.path());
                } else if e.file_name() != "msd.sock" {
                    out.push((e.path(), std::fs::read(e.path()).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    // protects=SPEC D-1, criterion 1: a preview changes no file, raises no sheet and writes no
    // receipt, answers the same files the terminal would show and a 64-hex digest, and no value of
    // the user's own; fails_when=a preview writes, asks Touch ID, or leaks the user's token;
    // no_claim=the terminal's own output (ms-connect view tests)
    #[test]
    fn connect_preview_writes_nothing() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let before = files(&home);
        for (agent, off) in [
            ("claude-code", false),
            ("codex", false),
            ("claude-code", true),
        ] {
            let v = h.d.dash_agent_preview(agent, off).unwrap();
            assert_eq!(v.plan.len(), 64);
            let text = serde_json::to_string(&v).unwrap();
            assert!(!text.contains(TOKEN), "{text}");
            if !off {
                assert!(!v.nothing_to_do);
                assert!(v.files.iter().any(|f| f.verb == "change"), "{text}");
                assert!(v.files.iter().all(|f| f.path.starts_with("~/")), "{text}");
            } else {
                assert!(v.nothing_to_do, "not connected yet: {text}");
            }
        }
        assert_eq!(files(&home), before);
        assert!(h.auth.reasons().is_empty());
        assert!(!h.receipts_text().contains("dashboard: connect"));
    }

    // protects=SPEC D-2, criterion 2 / T-104: Connect needs Touch ID (denied: nothing written,
    // a denied receipt); approved, it writes exactly the previewed plan, the sheet names the agent
    // and the file, and a second preview has nothing left to do; fails_when=connect writes without
    // the sheet or writes something other than the plan; no_claim=the real sheet (manual)
    #[test]
    fn connect_needs_touch_id() {
        let h = denying();
        let (_d, home) = wire(&h);
        let before = files(&home);
        let v = h.d.dash_agent_preview("claude-code", false).unwrap();
        let e =
            h.d.dash_agent_apply(&actor(), "claude-code", false, &v.plan)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
        assert_eq!(files(&home), before);
        assert!(h.receipts_text().contains("dashboard: connect claude-code"));

        let h = fresh();
        let (_d, home) = wire(&h);
        let v = h.d.dash_agent_preview("claude-code", false).unwrap();
        let ok =
            h.d.dash_agent_apply(&actor(), "claude-code", false, &v.plan)
                .unwrap();
        assert!(
            ok.message.contains("Connected Claude Code"),
            "{}",
            ok.message
        );
        let reasons = h.auth.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].contains("connect Claude Code")
                && reasons[0].contains("~/.claude/settings.json"),
            "{}",
            reasons[0]
        );
        let settings = std::fs::read_to_string(home.join(".claude/settings.json")).unwrap();
        assert!(settings.contains("\"httpProxyPort\": 4101") && settings.contains(TOKEN));
        assert!(settings.contains("/opt/homebrew/bin/ms"));
        assert!(
            h.d.dash_agent_preview("claude-code", false)
                .unwrap()
                .nothing_to_do
        );
        // Codex the same way.
        let v = h.d.dash_agent_preview("codex", false).unwrap();
        h.d.dash_agent_apply(&actor(), "codex", false, &v.plan)
            .unwrap();
        let cfg = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(
            cfg.contains("127.0.0.1:4101") && cfg.contains(TOKEN),
            "{cfg}"
        );
    }

    // protects=T-105: a plan that changed since the preview (another digest, or the file edited
    // after the preview) is refused with `changed` before any sheet, and nothing is written;
    // fails_when=msd writes a plan the person did not see; no_claim=an edit during the sheet
    // (covered by the re-plan after it, same digest check)
    #[test]
    fn connect_refuses_changed_plan() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let v = h.d.dash_agent_preview("claude-code", false).unwrap();
        let e =
            h.d.dash_agent_apply(&actor(), "claude-code", false, &"0".repeat(64))
                .unwrap_err();
        assert_eq!(e.code, ActionCode::Changed);
        std::fs::write(
            home.join(".claude/settings.json"),
            "{\n  \"model\": \"opus\"\n}\n",
        )
        .unwrap();
        let before = files(&home);
        let e =
            h.d.dash_agent_apply(&actor(), "claude-code", false, &v.plan)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::Changed);
        assert_eq!(files(&home), before);
        assert!(h.auth.reasons().is_empty());
    }

    // protects=SPEC D-4: a Claude Code connect a terminal made with --wrap is not re-run from
    // the dashboard (it changes how every hook runs); the answer gives the terminal command;
    // fails_when=the dashboard re-applies --wrap; no_claim=--force (never offered)
    #[test]
    fn connect_refuses_carried_wrap() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let mut c = ms_connect::claude::ClaudeConnector::new(
            ms_connect::claude::Paths::for_home(&home, None),
            "/opt/homebrew/bin/ms",
            home.join("msd.sock").display().to_string(),
        );
        c.opts.wrap = true;
        c.ca_pem = lock(&h.d.ca).as_ref().map(|(p, _)| p.clone());
        let cfg = ConnectCfg {
            proxy_port: 4101,
            allowed_domains: vec![],
            env: c.ca_env().unwrap(),
            shim_dir: Some(c.paths.shims.clone()),
        };
        c.apply(&c.try_plan(&cfg).unwrap().diff).unwrap();
        let e = h.d.dash_agent_preview("claude-code", false).unwrap_err();
        assert_eq!(e.code, ActionCode::Refused);
        assert!(
            e.message.contains("ms connect claude-code"),
            "{}",
            e.message
        );
    }

    // protects=SPEC D-2, D-3, criterion 3 / T-104: Disconnect needs Touch ID and leaves the
    // settings byte-identical to before the connect; it is refused while stopped (before any
    // sheet); fails_when=disconnect runs without the sheet or while stopped, or the restore
    // differs; no_claim=partial disconnects (ms-connect's own tests)
    #[test]
    fn disconnect_needs_touch_id_and_restores() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let original = std::fs::read(home.join(".claude/settings.json")).unwrap();
        let v = h.d.dash_agent_preview("claude-code", false).unwrap();
        h.d.dash_agent_apply(&actor(), "claude-code", false, &v.plan)
            .unwrap();
        let v = h.d.dash_agent_preview("claude-code", true).unwrap();
        assert!(!v.nothing_to_do);
        assert!(v.files.iter().any(|f| f.verb == "drop"));
        h.d.dash_agent_apply(&actor(), "claude-code", true, &v.plan)
            .unwrap();
        assert_eq!(
            std::fs::read(home.join(".claude/settings.json")).unwrap(),
            original
        );
        assert!(!home.join(".morsec/connect/claude-code.json").exists());
        let reasons = h.auth.reasons();
        assert!(
            reasons[1].contains("disconnect Claude Code"),
            "{}",
            reasons[1]
        );
    }

    #[test]
    fn disconnect_refused_while_stopped() {
        let h = fresh();
        let (_d, _home) = wire(&h);
        let v = h.d.dash_agent_preview("codex", false).unwrap();
        h.d.dash_agent_apply(&actor(), "codex", false, &v.plan)
            .unwrap();
        let v = h.d.dash_agent_preview("codex", true).unwrap();
        h.d.dash_stop(&actor()).unwrap();
        let e =
            h.d.dash_agent_apply(&actor(), "codex", true, &v.plan)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::Stopped);
        assert_eq!(h.auth.reasons().len(), 1, "only the connect's sheet");
        // Connect stays allowed while stopped, and says so.
        assert!(
            h.d.dash_agent_preview("claude-code", false)
                .unwrap()
                .notes
                .iter()
                .any(|n| n.contains("stopped"))
        );
    }

    // protects=SPEC D-5, criterion 4: a state that says a terminal connected another settings
    // file (CLAUDE_CONFIG_DIR, CODEX_HOME) is refused with the terminal command, for both
    // agents and both actions; fails_when=msd edits or restores the default file for a connect
    // that went elsewhere; no_claim=older states without the field (read as the default)
    #[test]
    fn custom_config_dir_refused() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let custom = home.join("elsewhere");
        let mut c = ms_connect::claude::ClaudeConnector::new(
            ms_connect::claude::Paths::for_home(&home, Some(&custom)),
            "/opt/homebrew/bin/ms",
            "/s",
        );
        c.ca_pem = lock(&h.d.ca).as_ref().map(|(p, _)| p.clone());
        let cfg = ConnectCfg {
            proxy_port: 4101,
            allowed_domains: vec![],
            env: c.ca_env().unwrap(),
            shim_dir: Some(c.paths.shims.clone()),
        };
        c.apply(&c.try_plan(&cfg).unwrap().diff).unwrap();
        for off in [false, true] {
            let e = h.d.dash_agent_preview("claude-code", off).unwrap_err();
            assert!(e.message.contains("CLAUDE_CONFIG_DIR"), "{}", e.message);
        }
        let mut x = ms_connect::codex::CodexConnector::new(
            ms_connect::codex::Paths::for_home(&home, Some(&custom)),
            "/opt/homebrew/bin/ms",
        );
        x.ca_pem = c.ca_pem.clone();
        let cfg = ConnectCfg {
            proxy_port: 4101,
            ..ConnectCfg::default()
        };
        x.apply(&x.try_plan(&cfg).unwrap().diff).unwrap();
        let e = h.d.dash_agent_preview("codex", true).unwrap_err();
        assert!(e.message.contains("CODEX_HOME"), "{}", e.message);
    }

    // protects=SPEC D-6 / T-106: the ms written into agent settings is msd's own sibling only:
    // missing, from another install (a symlink elsewhere), or in a folder others can write, it is
    // refused; fails_when=msd would write a path an agent could plant; no_claim=the HOME part
    // (skipped in debug builds, where dev msd runs from target/debug)
    #[test]
    fn ms_path_is_checked_sibling() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let bin = base.join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = bin.join("msd");
        std::fs::write(&me, "").unwrap();
        let uid = std::fs::metadata(&bin)
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
            .unwrap();
        assert!(sibling_ms(&me, &base, uid).unwrap_err().contains("no ms"));
        let other = base.join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("ms"), "").unwrap();
        std::os::unix::fs::symlink(other.join("ms"), bin.join("ms")).unwrap();
        assert!(
            sibling_ms(&me, &base, uid)
                .unwrap_err()
                .contains("same install")
        );
        std::fs::remove_file(bin.join("ms")).unwrap();
        std::fs::write(bin.join("ms"), "").unwrap();
        assert_eq!(
            sibling_ms(&me, &base, uid).unwrap(),
            bin.join("ms").display().to_string()
        );
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            sibling_ms(&me, &base, uid)
                .unwrap_err()
                .contains("writable")
        );
        assert!(sibling_ms(&me, &base, uid + 1).is_err());
    }

    /// A project folder `shop` with a canary `.env`, not under the real home.
    fn project() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap().join("shop");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
        std::fs::write(
            root.join(".env"),
            format!("STRIPE_SECRET_KEY={STRIPE}\nPORT=3000\n"),
        )
        .unwrap();
        (d, root)
    }

    // protects=SPEC D-11, criterion 7 / T-107: Add project's preview names the project, the
    // file, the new key and the hosts it will reach, with no value and no masked value, and
    // writes nothing (file, vault, records, sheet, receipt); refused folders answer the L33
    // reason; fails_when=a preview writes or leaks the canary or its prefix;
    // no_claim=macOS folder prompts (manual)
    #[test]
    fn project_preview_has_no_values() {
        let h = fresh();
        let (_d, root) = project();
        let env_before = std::fs::read(root.join(".env")).unwrap();
        let v =
            h.d.dash_project_preview(&actor(), root.to_str().unwrap())
                .unwrap();
        assert!(v.ok, "{v:?}");
        assert_eq!(v.slug, "shop");
        assert_eq!(v.files.len(), 1);
        assert_eq!(v.files[0].new_keys, 1);
        let k = &v.keys[0];
        assert_eq!(k.key, "shop/stripe-secret-key");
        assert!(k.reaches.iter().any(|h| h == "api.stripe.com"), "{k:?}");
        let text = serde_json::to_string(&v).unwrap();
        assert!(
            !text.contains(STRIPE) && !text.contains("sk_test_51H"),
            "{text}"
        );
        assert_eq!(std::fs::read(root.join(".env")).unwrap(), env_before);
        assert!(h.d.dash_projects().unwrap().projects.is_empty());
        assert!(h.auth.reasons().is_empty());
        let home = std::env::var("HOME").unwrap();
        let refused = h.d.dash_project_preview(&actor(), &home).unwrap();
        assert!(!refused.ok && refused.reason.unwrap().contains("home folder"));
    }

    // protects=SPEC D-11, D-12, criterion 8 / T-108: Add project needs Touch ID (denied: no
    // file, key or record changes); approved, it imports exactly the preview, the `.env` holds
    // the ref, the key has the previewed first rule (approved receipt), the record is saved, and
    // the sheet names the folder, the file and the host; fails_when=a project is set up without the
    // sheet or with other rules than shown; no_claim=the real sheet (manual)
    #[test]
    fn add_project_needs_touch_id() {
        let h = denying();
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        let e = h.d.dash_project_add(&actor(), path, &v.plan).unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
        assert!(
            std::fs::read_to_string(root.join(".env"))
                .unwrap()
                .contains(STRIPE)
        );
        assert!(h.d.dash_projects().unwrap().projects.is_empty());

        let h = fresh();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        let done = h.d.dash_project_add(&actor(), path, &v.plan).unwrap();
        assert!(!done.partial, "{done:?}");
        let env = std::fs::read_to_string(root.join(".env")).unwrap();
        assert!(
            env.contains("STRIPE_SECRET_KEY=ms://shop/stripe-secret-key"),
            "{env}"
        );
        assert!(!env.contains(STRIPE));
        let key = KeyName::new("shop/stripe-secret-key").unwrap();
        let rule = h.d.read_live().rules.keys.get(&key).cloned().unwrap();
        assert_eq!(
            rule.hosts
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            v.keys[0].reaches
        );
        assert_eq!(h.d.dash_projects().unwrap().projects[0].slug, "shop");
        let reasons = h.auth.reasons();
        assert_eq!(
            reasons.len(),
            1,
            "one sheet for the import and the first rules"
        );
        assert!(
            reasons[0].contains("set up project shop")
                && reasons[0].contains(".env")
                && reasons[0].contains("api.stripe.com"),
            "{}",
            reasons[0]
        );
        let r = h.receipts_text();
        assert!(r.contains("dashboard: add project shop") && r.contains("ms init: first rules"));
    }

    // protects=T-109: a folder that changed after the preview (a new secret) is refused with
    // `changed` before any sheet, and nothing moves; fails_when=msd imports what the person did not
    // see; no_claim=a change during the sheet (envfile::commit refuses a file changed since read)
    #[test]
    fn add_project_refuses_changed_plan() {
        let h = fresh();
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        std::fs::write(
            root.join(".env"),
            format!("STRIPE_SECRET_KEY={STRIPE}\nOPENAI_API_KEY={OPENAI}\n"),
        )
        .unwrap();
        let e = h.d.dash_project_add(&actor(), path, &v.plan).unwrap_err();
        assert_eq!(e.code, ActionCode::Changed);
        assert!(h.auth.reasons().is_empty());
        assert!(
            std::fs::read_to_string(root.join(".env"))
                .unwrap()
                .contains(STRIPE)
        );
    }

    #[test]
    fn add_project_refused_while_stopped() {
        let h = fresh();
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        h.d.dash_stop(&actor()).unwrap();
        let e = h.d.dash_project_add(&actor(), path, &v.plan).unwrap_err();
        assert_eq!(e.code, ActionCode::Stopped);
        assert!(h.auth.reasons().is_empty());
        assert!(h.receipts_text().contains("dashboard: add project"));
    }

    // protects=SPEC D-12 / T-108 (review R3): with the dashboard's token, the first rules are
    // saved only when each is exactly one the person saw: run through the real execute with a
    // token whose approved set is empty, the catalog-valid rules are refused (Denied, keys stay
    // inert, the record is saved, denied receipts) by the Confirmed branch, not by the catalog
    // check; and a key that already allows something can't join through the token (the
    // adoption branch, bypassing the pre-sheet check); fails_when=either branch is removed;
    // no_claim=IPC ProjectSave (asks as before)
    #[test]
    fn add_project_rules_bound_to_preview() {
        let h = fresh();
        let (_d, root) = project();
        let session = actor().session;
        let token =
            h.d.dash_confirm(
                &admin_request(&session, daemon_key(), Tier::Production, &["x"]),
                "test",
            )
            .unwrap();
        let mut host = MsdHost::new(&h.d, &session);
        let p = setup::prepare(&host, Catalog::builtin(), &root, None).unwrap();
        assert!(!p.proposed.keys.is_empty());
        host.confirmed = Some((token.clone(), Rules::default()));
        let rep = setup::execute(&host, Catalog::builtin(), p, 1);
        let why = rep.declined.clone().unwrap_or_default();
        assert!(why.contains("not the one you approved"), "{rep:?}");
        assert!(
            rep.save_error.is_none(),
            "the record is saved first: {rep:?}"
        );
        let key = KeyName::new("shop/stripe-secret-key").unwrap();
        assert!(h.d.read_live().rules.keys[&key].allows_nothing());
        assert!(h.receipts_text().contains("ms init: first rules"));

        // Adoption through the token: a loose key of the project referenced in the folder.
        let (_d2, root2) = project();
        std::fs::rename(&root2, root2.with_file_name("shop2")).unwrap();
        let root2 = root2.with_file_name("shop2");
        assert!(matches!(
            h.put("shop2/loose", Tier::Test),
            ResponseBody::Ok { .. }
        ));
        let loose = KeyName::new("shop2/loose").unwrap();
        let mut r = ms_rules::KeyRule::new(Mode::Swap, Tier::Test);
        r.hosts = vec![ms_rules::HostPattern::parse("api.example.com").unwrap()];
        h.d.change_rule(&loose, Some(r), true).unwrap();
        std::fs::write(root2.join(".env"), "LOOSE=ms://shop2/loose\n").unwrap();
        let mut host = MsdHost::new(&h.d, &session);
        let p = setup::prepare(&host, Catalog::builtin(), &root2, None).unwrap();
        assert_eq!(p.slug, "shop2");
        host.confirmed = Some((token, p.proposed.clone()));
        let rep = setup::execute(&host, Catalog::builtin(), p, 1);
        let e = rep.save_error.clone().unwrap_or_default();
        assert!(
            e.contains("joins project shop2") && e.contains("terminal"),
            "{rep:?}"
        );
        assert!(
            h.d.dash_projects()
                .unwrap()
                .projects
                .iter()
                .all(|p| p.slug != "shop2")
        );
    }

    // protects=review R2: a Stop and Start while the Add project sheet is up void it: nothing is
    // imported and no rule loosens; fails_when=a sheet answered across a stop still applies;
    // no_claim=the real sheet timing
    #[test]
    fn add_project_void_after_stop_during_sheet() {
        let dir = tempfile::tempdir().unwrap();
        let h = open_auth(
            crate::backend::Backend::Memory(Arc::new(ms_vault::memory::MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
            FakeAuthenticator::approve().after(std::time::Duration::from_millis(400)),
        );
        h.d.set_approval_timeout(std::time::Duration::from_secs(5));
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        let e = std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(150));
                // A stop and start completed while the sheet was up (the count moved, morsec
                // is on again).
                h.d.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
            h.d.dash_project_add(&actor(), path, &v.plan).unwrap_err()
        });
        assert_eq!(e.code, ActionCode::Stopped, "{e:?}");
        assert!(
            std::fs::read_to_string(root.join(".env"))
                .unwrap()
                .contains(STRIPE)
        );
        assert!(h.d.dash_projects().unwrap().projects.is_empty());
    }

    // protects=review R1: keys an earlier run stored inert (rules declined) are not "nothing to
    // do": the re-scan preview lists them and the add gives them their first rules, as ms init
    // run again would; fails_when=the dashboard leaves them inert; no_claim=new secrets
    #[test]
    fn rescan_gives_inert_keys_their_rules() {
        let h = fresh();
        let (_d, root) = project();
        let session = actor().session;
        let token =
            h.d.dash_confirm(
                &admin_request(&session, daemon_key(), Tier::Production, &["x"]),
                "test",
            )
            .unwrap();
        let mut host = MsdHost::new(&h.d, &session);
        let p = setup::prepare(&host, Catalog::builtin(), &root, None).unwrap();
        host.confirmed = Some((token, Rules::default()));
        let rep = setup::execute(&host, Catalog::builtin(), p, 1);
        assert!(rep.declined.is_some());
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        assert!(!v.nothing_to_do, "{v:?}");
        assert!(
            v.keys
                .iter()
                .any(|k| k.key == "shop/stripe-secret-key" && !k.reaches.is_empty()),
            "{v:?}"
        );
        let done = h.d.dash_project_add(&actor(), path, &v.plan).unwrap();
        assert!(!done.partial, "{done:?}");
        let key = KeyName::new("shop/stripe-secret-key").unwrap();
        assert!(!h.d.read_live().rules.keys[&key].allows_nothing());
        assert!(
            h.d.dash_project_preview(&actor(), path)
                .unwrap()
                .nothing_to_do
        );
    }

    // protects=SPEC D-12 / L34 S2: a ref in the folder to a key of this project that already
    // allows something and that no record lists is refused before the sheet, with the terminal
    // command; fails_when=a loose key joins a project through the dashboard;
    // no_claim=keys that still allow nothing (they join, as with ms init)
    #[test]
    fn add_project_refuses_adoption() {
        let h = fresh();
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        assert!(matches!(
            h.put("shop/loose", Tier::Test),
            ResponseBody::Ok { .. }
        ));
        let key = KeyName::new("shop/loose").unwrap();
        let mut r = ms_rules::KeyRule::new(Mode::Swap, Tier::Test);
        r.hosts = vec![ms_rules::HostPattern::parse("api.example.com").unwrap()];
        h.d.change_rule(&key, Some(r), true).unwrap();
        std::fs::write(
            root.join(".env"),
            format!("STRIPE_SECRET_KEY={STRIPE}\nLOOSE=ms://shop/loose\n"),
        )
        .unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        let e = h.d.dash_project_add(&actor(), path, &v.plan).unwrap_err();
        assert_eq!(e.code, ActionCode::Refused);
        assert!(
            e.message.contains("shop/loose") && e.message.contains("terminal"),
            "{}",
            e.message
        );
        assert!(h.auth.reasons().is_empty());
    }

    // protects=SPEC criterion 9: a re-scan of a set-up project imports only the new line and keeps
    // the record's earlier entries; the preview says it is an existing project; fails_when=a
    // re-scan re-imports or drops earlier entries; no_claim=moved projects
    #[test]
    fn rescan_imports_only_new() {
        let h = fresh();
        let (_d, root) = project();
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        h.d.dash_project_add(&actor(), path, &v.plan).unwrap();
        let mut env = std::fs::read_to_string(root.join(".env")).unwrap();
        env.push_str(&format!("OPENAI_API_KEY={OPENAI}x\n"));
        std::fs::write(root.join(".env"), env).unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        assert!(v.existing);
        assert_eq!(v.files[0].new_keys, 1, "{v:?}");
        let done = h.d.dash_project_add(&actor(), path, &v.plan).unwrap();
        assert!(
            done.rows
                .iter()
                .any(|(l, t)| l == "Found" && t.starts_with("1 secret")),
            "{done:?}"
        );
        let rec = &h.d.dash_projects().unwrap().projects[0];
        assert_eq!(rec.keys().len(), 2);
        let nothing = h.d.dash_project_preview(&actor(), path).unwrap();
        assert!(nothing.nothing_to_do);
    }

    // protects=SPEC D-14, criterion 12: connect, disconnect and add project leave one receipt each
    // under the dashboard session (approved with the token, or denied), previews none;
    // fails_when=an action goes unrecorded or a preview writes one; no_claim=the per-key PutKey
    // receipts (put_key_as's own tests)
    #[test]
    fn connect_actions_write_receipts() {
        let h = fresh();
        let (_d, _home) = wire(&h);
        let (_p, root) = project();
        h.d.dash_agent_preview("codex", false).unwrap();
        h.d.dash_project_preview(&actor(), root.to_str().unwrap())
            .unwrap();
        assert!(!h.receipts_text().contains("dashboard:"));
        let v = h.d.dash_agent_preview("codex", false).unwrap();
        h.d.dash_agent_apply(&actor(), "codex", false, &v.plan)
            .unwrap();
        let v = h.d.dash_agent_preview("codex", true).unwrap();
        h.d.dash_agent_apply(&actor(), "codex", true, &v.plan)
            .unwrap();
        let v =
            h.d.dash_project_preview(&actor(), root.to_str().unwrap())
                .unwrap();
        h.d.dash_project_add(&actor(), root.to_str().unwrap(), &v.plan)
            .unwrap();
        let r = h.receipts_text();
        for want in [
            "dashboard: connect codex",
            "dashboard: disconnect codex",
            "dashboard: add project shop",
        ] {
            assert_eq!(r.matches(want).count(), 1, "{want}\n{r}");
        }
        assert!(r.contains("\"dashboard\""), "{r}");
    }

    // protects=SPEC criterion 13 / T-107: the canaries in the agent settings and the project's
    // .env appear in no preview, answer, sheet reason or receipt; fails_when=any of them leaks;
    // no_claim=msd's log (no value is ever logged by these paths; checked in QA)
    #[test]
    fn dash_connect_never_leaks_canary() {
        let h = fresh();
        let (_d, home) = wire(&h);
        let (_p, root) = project();
        let mut out = String::new();
        for agent in ["claude-code", "codex"] {
            let v = h.d.dash_agent_preview(agent, false).unwrap();
            out.push_str(&serde_json::to_string(&v).unwrap());
            out.push_str(
                &h.d.dash_agent_apply(&actor(), agent, false, &v.plan)
                    .unwrap()
                    .message,
            );
            let v = h.d.dash_agent_preview(agent, true).unwrap();
            out.push_str(&serde_json::to_string(&v).unwrap());
            out.push_str(
                &h.d.dash_agent_apply(&actor(), agent, true, &v.plan)
                    .unwrap()
                    .message,
            );
        }
        let path = root.to_str().unwrap();
        let v = h.d.dash_project_preview(&actor(), path).unwrap();
        out.push_str(&serde_json::to_string(&v).unwrap());
        out.push_str(
            &serde_json::to_string(&h.d.dash_project_add(&actor(), path, &v.plan).unwrap())
                .unwrap(),
        );
        out.push_str(&h.auth.reasons().join("\n"));
        out.push_str(&h.receipts_text());
        for c in [TOKEN, STRIPE] {
            assert!(!out.contains(c), "{c} leaked");
        }
        assert!(
            std::fs::read_to_string(home.join(".claude/settings.json"))
                .unwrap()
                .contains(TOKEN)
        );
    }
}
