//! The dashboard's actions (L33 dash-actions, SPEC D-9 to D-22): msd's [`DashActions`].
//!
//! The page asks; msd decides. Every action that loosens, starts, reads a value or changes one
//! raises Touch ID here, through [`HumanApprover::confirm`] (the confirm path, SPEC D-19): the
//! click in the page is the review, the sheet's reason is built here from the real action and
//! rendered inert, and the once token it issues is verified against the same binding right
//! before acting. Stop, Deny, tightening and Add need none (they only refuse or allow nothing).
//! Every action, done or refused, leaves one receipt under the dashboard session
//! (`other("dashboard")`, the browser's process) with the target `dashboard: <action>`; a value
//! never appears in one.
//!
//! msd's alerts are structured here too ([`AlertKind`]): `ms status` prints their text as
//! before, and the dashboard shows each in plain words with its fix (SPEC D-10).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ms_approve::{ApprovalToken, Binding, ConfirmError, DecideError, Scope};
use ms_core::{ApprovalRequest, KeyMeta, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, Tier};
use ms_dash::actions::{
    Action, ActionCode, ActionError, ActionOk, ActionResult, Actor, DashActions, NewKey, PathCheck,
    Revealed, RuleEdit, UndoView,
};
use ms_dash::api::{AgentsView, FixView, WarningView};
use ms_ipc::{ErrorCode, ResponseBody};
use ms_receipts::ReceiptDetail;
use ms_rules::{Change, KeyRule};
use ms_vault::VaultExt;
use sha2::{Digest, Sha256};

use super::{
    Daemon, DashSource, TOUCH_ID_METHOD, admin_request, daemon_key, lock, now_ms, tier_str,
};

pub use crate::pasteboard::Clipboard;

/// Show and Copy together, in all sessions, per [`REVEAL_WINDOW`] (SPEC D-12).
pub const REVEAL_LIMIT: usize = 10;
/// The window [`REVEAL_LIMIT`] counts in.
pub const REVEAL_WINDOW: Duration = Duration::from_secs(600);
/// How long a copied value stays on the pasteboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

// ---- alerts --------------------------------------------------------------------------------

/// What an alert is about (SPEC D-10). The text `ms status` prints is kept beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
    /// The proxy CA was issued again for `hosts` hosts.
    CaReissued {
        /// How many hosts it may sign for.
        hosts: usize,
    },
    /// A watched agent settings file changed.
    SettingsChanged {
        /// The file.
        path: PathBuf,
        /// Its fingerprint when the alert was raised (`drift::fingerprint`), so Re-check can tell
        /// whether it changed again since.
        fingerprint: Option<String>,
    },
    /// The swap proxy is not running.
    ProxyDown,
    /// The vault could not be listed.
    VaultUnlisted,
    /// The stop flag or a rollback floor could not be saved.
    FloorNotSaved,
    /// The project records failed their integrity check.
    ProjectsUnreadable,
    /// A key's binding was skipped when the proxy was built.
    BindingSkipped,
    /// Anything else.
    Other,
}

impl AlertKind {
    fn tag(&self) -> &'static str {
        match self {
            AlertKind::CaReissued { .. } => "ca-reissued",
            AlertKind::SettingsChanged { .. } => "settings-changed",
            AlertKind::ProxyDown => "proxy-down",
            AlertKind::VaultUnlisted => "vault-unlisted",
            AlertKind::FloorNotSaved => "floor-not-saved",
            AlertKind::ProjectsUnreadable => "projects-unreadable",
            AlertKind::BindingSkipped => "binding-skipped",
            AlertKind::Other => "other",
        }
    }

    /// Informational: the person may dismiss it (SPEC D-10).
    pub fn dismissable(&self) -> bool {
        matches!(
            self,
            AlertKind::CaReissued { .. } | AlertKind::SettingsChanged { .. }
        )
    }
}

/// One alert: its kind and the text `ms status` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEntry {
    /// What it is about.
    pub kind: AlertKind,
    /// The text, unchanged from before L33.
    pub text: String,
}

impl AlertEntry {
    /// An alert.
    pub fn new(kind: AlertKind, text: String) -> Self {
        Self { kind, text }
    }

    /// Stable for this alert: a hash of its kind and text.
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.kind.tag().as_bytes());
        h.update([0]);
        h.update(self.text.as_bytes());
        format!("w-{}", hex::encode(&h.finalize()[..8]))
    }
}

fn agent_of(path: &Path) -> &'static str {
    let s = path.to_string_lossy();
    if s.contains("/.claude/") {
        "Claude Code"
    } else if s.contains("/.codex/") {
        "Codex"
    } else {
        "An agent"
    }
}

fn command(c: &str) -> FixView {
    FixView {
        command: Some(c.into()),
        ..FixView::default()
    }
}

/// An alert in plain words with its fix (the SPEC D-10 table). Agent-influenced text (a path)
/// is rendered inert.
pub fn warning(e: &AlertEntry) -> WarningView {
    let inert = ms_approve::render::inert;
    let (title, detail, fix) = match &e.kind {
        AlertKind::CaReissued { hosts } => (
            "Some tools may not trust morsec yet".to_owned(),
            format!(
                "morsec made a new certificate for {hosts} website{}. Tools that check the macOS trust store (curl, Python, Git) will refuse morsec's connections until you trust it once. Run this in a terminal: it asks for your Mac password.",
                if *hosts == 1 { "" } else { "s" }
            ),
            vec![command("ms init --trust")],
        ),
        AlertKind::SettingsChanged { path, .. } => (
            format!("{}'s settings changed", agent_of(path)),
            format!(
                "{} changed while morsec was running. Check it still sends its requests through morsec.",
                inert(&path.display().to_string())
            ),
            vec![
                FixView {
                    action: Some("/api/agents/recheck".into()),
                    label: Some("Re-check".into()),
                    command: None,
                },
                command("ms doctor"),
            ],
        ),
        AlertKind::ProxyDown => (
            "morsec's proxy is not running".to_owned(),
            "Agents can't use keys that go to websites.".to_owned(),
            vec![command("ms doctor")],
        ),
        AlertKind::VaultUnlisted | AlertKind::FloorNotSaved => (
            "morsec couldn't read or save its state".to_owned(),
            inert(&e.text),
            vec![command("ms doctor")],
        ),
        AlertKind::ProjectsUnreadable => (
            "Project records failed their check".to_owned(),
            "Undo is off until they are fixed. Keys and rules keep working.".to_owned(),
            vec![command("ms doctor")],
        ),
        AlertKind::BindingSkipped | AlertKind::Other => {
            (inert(&e.text), String::new(), vec![command("ms doctor")])
        }
    };
    WarningView {
        id: e.id(),
        title,
        detail,
        fix,
        dismiss: e.kind.dismissable(),
    }
}

// ---- state ---------------------------------------------------------------------------------

/// The actions' own state.
#[derive(Default)]
pub struct ActState {
    /// A scan the dashboard started is running.
    scan_running: AtomicBool,
    /// Why the last one failed.
    scan_error: Mutex<Option<String>>,
    /// When each Show or Copy was counted (before Touch ID), newest last.
    reveals: Mutex<VecDeque<Instant>>,
    /// The pasteboard writer; the real one unless a test or `--test-pasteboard-to` set another.
    clipboard: OnceLock<Arc<dyn Clipboard>>,
    /// Tests: the next store fails (after deleting, as the keychain's replace would).
    #[cfg(test)]
    pub(crate) fail_next_put: AtomicBool,
    /// Tests: the transcript folders a scan reads (never the real home).
    #[cfg(test)]
    pub(crate) scan_roots: Mutex<Option<Vec<PathBuf>>>,
}

impl std::fmt::Debug for ActState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActState").finish_non_exhaustive()
    }
}

fn err(code: ActionCode, m: impl Into<String>) -> ActionError {
    ActionError::new(code, m)
}

/// An IPC-style error reply as an action error.
fn from_reply(r: ResponseBody) -> ActionResult {
    match r {
        ResponseBody::Ok { message } => Ok(ActionOk::new(message)),
        ResponseBody::Error { code, message } => Err(err(
            match code {
                ErrorCode::Denied => ActionCode::Refused,
                ErrorCode::NeedsApproval => ActionCode::TouchIdFailed,
                ErrorCode::Busy => ActionCode::Busy,
                ErrorCode::Invalid => ActionCode::Invalid,
                _ => ActionCode::Internal,
            },
            message,
        )),
        _ => Err(err(ActionCode::Internal, "morsec: unexpected answer")),
    }
}

impl Daemon {
    /// The transcript folders a scan reads.
    pub(crate) fn scan_roots(&self) -> Vec<PathBuf> {
        #[cfg(test)]
        if let Some(r) = lock(&self.dash_acts.scan_roots).clone() {
            return r;
        }
        crate::scan::roots()
    }

    /// The pasteboard writer.
    pub(crate) fn clipboard(&self) -> Arc<dyn Clipboard> {
        self.dash_acts
            .clipboard
            .get_or_init(crate::pasteboard::system)
            .clone()
    }

    /// Replaces the pasteboard writer (tests, `--test-pasteboard-to`). Only before first use.
    pub fn set_clipboard(&self, c: Arc<dyn Clipboard>) {
        let _ = self.dash_acts.clipboard.set(c);
    }

    /// The warnings for these alert texts (`ms status`'s list): structured where msd raised
    /// them, inert text for the computed ones (tampered rules, keys another build stored).
    pub(crate) fn warnings_for(&self, texts: &[String]) -> Vec<WarningView> {
        let entries = lock(&self.alerts).clone();
        texts
            .iter()
            .map(|t| {
                let e = entries
                    .iter()
                    .find(|e| &e.text == t)
                    .cloned()
                    .unwrap_or_else(|| AlertEntry::new(AlertKind::Other, t.clone()));
                warning(&e)
            })
            .collect()
    }

    /// Whether the dashboard's scan runs, and why the last one failed.
    pub(crate) fn dash_scan_state(&self) -> (bool, Option<String>) {
        (
            self.dash_acts.scan_running.load(Ordering::SeqCst),
            lock(&self.dash_acts.scan_error).clone(),
        )
    }

    /// One receipt for a dashboard action (SPEC D-22): the dashboard session, the key (or
    /// morsec's own), the key's mode (run for morsec's own), `dashboard: <what>`, the approval
    /// token when Touch ID confirmed.
    pub(crate) fn dash_receipt(
        &self,
        a: &Actor,
        key: &KeyName,
        what: &str,
        result: ReceiptResult,
        token: Option<&ApprovalToken>,
    ) {
        let mode = self
            .read_live()
            .rules
            .keys
            .get(key)
            .map_or(Mode::Run, |r| r.mode);
        let target = format!("dashboard: {what}");
        let r = self.receipts.append_detailed(
            ReceiptEvent {
                time_unix_ms: now_ms(),
                session: a.session.clone(),
                key: key.clone(),
                mode,
                target,
                argv_hash: None,
                rule_version: self.rules_version(),
                approval_id: token.map(|t| t.id.clone()),
                result,
            },
            ReceiptDetail {
                approval_method: token.map(|_| TOUCH_ID_METHOD.to_owned()),
                ..ReceiptDetail::default()
            },
        );
        if let Err(e) = r {
            tracing::error!(error = %e, "could not record a dashboard action");
        }
    }

    /// The receipt for an action msd refused, then the error.
    fn refuse(&self, a: &Actor, key: &KeyName, what: &str, e: ActionError) -> ActionError {
        let result = match e.code {
            ActionCode::TouchIdFailed => ReceiptResult::Denied,
            ActionCode::Stopped => ReceiptResult::Blocked(Reason::Stopped),
            ActionCode::Gone => ReceiptResult::Blocked(Reason::NoSuchKey),
            ActionCode::Refused | ActionCode::RateLimited => {
                ReceiptResult::Blocked(Reason::HostNotAllowed)
            }
            _ => ReceiptResult::Failed(match e.code {
                ActionCode::Busy => "busy".into(),
                ActionCode::Referenced => "still referenced".into(),
                ActionCode::NotText => "not text".into(),
                ActionCode::Invalid => "invalid".into(),
                ActionCode::Unavailable => "unavailable".into(),
                _ => "failed".into(),
            }),
        };
        self.dash_receipt(a, key, what, result, None);
        e
    }

    /// Touch ID for a dashboard action (SPEC D-19): the confirm path, then the token verified
    /// against the same binding (which uses it up).
    pub(crate) fn dash_confirm(
        &self,
        req: &ApprovalRequest,
        reason: &str,
    ) -> Result<ApprovalToken, ActionError> {
        let t = self
            .approvals
            .confirm(req, reason, self.approval_timeout())
            .map_err(|e| match e {
                ConfirmError::Busy => err(
                    ActionCode::Busy,
                    "morsec: another request is waiting for you on Home. Answer it first",
                ),
                ConfirmError::CoolingDown => err(
                    ActionCode::RateLimited,
                    format!(
                        "morsec: this was refused a moment ago. Wait {} seconds and try again",
                        ms_approve::broker::COOLDOWN.as_secs()
                    ),
                ),
                ConfirmError::AuthFailed(why) => err(
                    ActionCode::TouchIdFailed,
                    format!(
                        "morsec: Touch ID did not confirm ({}), so nothing was done",
                        ms_approve::render::inert(&why)
                    ),
                ),
                ConfirmError::Expired => err(
                    ActionCode::TouchIdFailed,
                    "morsec: Touch ID was not answered in time, so nothing was done",
                ),
                ConfirmError::Ended => err(
                    ActionCode::Stopped,
                    "morsec: morsec was stopped while Touch ID was up, so nothing was done",
                ),
                ConfirmError::Internal(m) => err(ActionCode::Internal, format!("morsec: {m}")),
            })?;
        self.approvals
            .verify(&t, &Binding::of(req))
            .map_err(|e| err(ActionCode::Refused, format!("morsec: refused at use: {e}")))?;
        Ok(t)
    }

    // ---- admin actions (SPEC D-9 to D-18) ----------------------------------------------

    pub(crate) fn dash_stop(&self, a: &Actor) -> ActionResult {
        from_reply(self.stop_as(&a.session, "dashboard: stop"))
    }

    pub(crate) fn dash_start(&self, a: &Actor) -> ActionResult {
        let key = daemon_key();
        if !self.is_stopped() {
            return Ok(ActionOk::new("morsec is already on"));
        }
        let stops_seen = self.stops.load(Ordering::SeqCst);
        let req = admin_request(
            &a.session,
            key.clone(),
            Tier::Production,
            &["dashboard", "start"],
        );
        let token = self
            .dash_confirm(
                &req,
                "start morsec again from the dashboard: agents can use your keys through it",
            )
            .map_err(|e| self.refuse(a, &key, "start", e))?;
        match self.resume(&a.session, &token, stops_seen, "dashboard: start") {
            ResponseBody::Ok { message } => Ok(ActionOk::new(message)),
            other => from_reply(other).map_err(|e| self.refuse(a, &key, "start", e)),
        }
    }

    pub(crate) fn dash_approve(&self, a: &Actor, id: &str, session_scope: bool) -> ActionResult {
        let pending = self.approvals.pending().filter(|p| p.id == id);
        let key = pending
            .as_ref()
            .map_or_else(daemon_key, |p| p.request.key.clone());
        let scope = if session_scope {
            Scope::Session
        } else {
            Scope::Once
        };
        match self.approvals.decide(id, true, scope) {
            Ok(ms_approve::ApprovalOutcome::Approved(t)) => {
                self.dash_receipt(a, &key, "approve", ReceiptResult::Approved, Some(&t));
                Ok(ActionOk::new(match scope {
                    Scope::Once => "Approved with Touch ID: this exact command, once",
                    Scope::Session => {
                        "Approved with Touch ID: this exact command, for this agent session"
                    }
                }))
            }
            Ok(_) => Err(self.refuse(
                a,
                &key,
                "approve",
                err(ActionCode::TouchIdFailed, "morsec: not approved"),
            )),
            Err(e) => Err(self.refuse(a, &key, "approve", decide_error(e))),
        }
    }

    pub(crate) fn dash_deny(&self, a: &Actor, id: &str) -> ActionResult {
        let key = self
            .approvals
            .pending()
            .filter(|p| p.id == id)
            .map_or_else(daemon_key, |p| p.request.key);
        match self.approvals.decide(id, false, Scope::Once) {
            Ok(_) => {
                self.dash_receipt(a, &key, "deny", ReceiptResult::Denied, None);
                Ok(ActionOk::new("Denied. The agent was told no"))
            }
            Err(e) => Err(self.refuse(a, &key, "deny", decide_error(e))),
        }
    }

    pub(crate) fn dash_dismiss(&self, a: &Actor, id: &str) -> ActionResult {
        let key = daemon_key();
        let mut alerts = lock(&self.alerts);
        let Some(i) = alerts.iter().position(|e| e.id() == id) else {
            drop(alerts);
            return Err(self.refuse(
                a,
                &key,
                "dismiss warning",
                err(ActionCode::Gone, "morsec: that warning is gone already"),
            ));
        };
        if !alerts[i].kind.dismissable() {
            drop(alerts);
            return Err(self.refuse(
                a,
                &key,
                "dismiss warning",
                err(
                    ActionCode::Invalid,
                    "morsec: this warning stays until what it names is fixed. Run ms doctor in a terminal",
                ),
            ));
        }
        alerts.remove(i);
        drop(alerts);
        self.dash_receipt(a, &key, "dismiss warning", ReceiptResult::Allowed, None);
        Ok(ActionOk::new("Dismissed"))
    }

    /// Re-check (SPEC D-16): connectors' state files are read on every view already; this
    /// re-fingerprints the watched settings files, clears a settings-changed alert whose file
    /// is unchanged since it was raised, and re-tests the proxy port. No receipt: it changes
    /// nothing else.
    pub(crate) fn dash_recheck(&self) -> Result<AgentsView, ActionError> {
        lock(&self.alerts).retain(|e| match &e.kind {
            AlertKind::SettingsChanged { path, fingerprint } => {
                crate::drift::fingerprint(path) != *fingerprint
            }
            _ => true,
        });
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], self.proxy_port));
        let up = self.proxy_port != 0
            && std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
        if up {
            self.clear_alert("the swap proxy is not running");
        } else if self.proxy_port != 0 {
            self.alert(
                AlertKind::ProxyDown,
                format!(
                    "the swap proxy is not running: nothing accepts connections on 127.0.0.1:{}",
                    self.proxy_port
                ),
            );
        }
        self.dash_agents()
            .map_err(|e| err(ActionCode::Internal, e.message))
    }

    pub(crate) fn dash_scan_run(&self, a: &Actor) -> ActionResult {
        let key = daemon_key();
        if self.is_stopped() {
            return Err(self.refuse(
                a,
                &key,
                "scan",
                err(
                    ActionCode::Stopped,
                    "morsec: morsec is stopped, so the scan does not read the vault. Start it first",
                ),
            ));
        }
        if self.dash_acts.scan_running.swap(true, Ordering::SeqCst) {
            return Err(self.refuse(
                a,
                &key,
                "scan",
                err(ActionCode::Busy, "morsec: a scan is already running"),
            ));
        }
        // The same request `ms scan` asks for (L11), through the confirm path.
        let req = admin_request(&a.session, key.clone(), Tier::Production, &["ms", "scan"]);
        let token = match self.dash_confirm(
            &req,
            "run the leak scan from the dashboard: morsec reads every key's value and searches your agents' transcripts for it",
        ) {
            Ok(t) => t,
            Err(e) => {
                self.dash_acts.scan_running.store(false, Ordering::SeqCst);
                return Err(self.refuse(a, &key, "scan", e));
            }
        };
        self.dash_receipt(a, &key, "scan", ReceiptResult::Approved, Some(&token));
        *lock(&self.dash_acts.scan_error) = None;
        let Some(me) = self.me.upgrade() else {
            self.dash_acts.scan_running.store(false, Ordering::SeqCst);
            return Err(err(ActionCode::Internal, "morsec: msd is stopping"));
        };
        let session = a.session.clone();
        let spawned = std::thread::Builder::new()
            .name("dash-scan".into())
            .spawn(move || {
                let r = me.scan_approved(&session);
                if let ResponseBody::Error { message, .. } = r {
                    *lock(&me.dash_acts.scan_error) = Some(message);
                }
                me.dash_acts.scan_running.store(false, Ordering::SeqCst);
            });
        if spawned.is_err() {
            self.dash_acts.scan_running.store(false, Ordering::SeqCst);
            return Err(err(
                ActionCode::Internal,
                "morsec: could not start the scan",
            ));
        }
        Ok(ActionOk::new("Scanning…"))
    }

    /// Add project's folder check (SPEC D-17): no mutation, no file read beyond the folder's
    /// own entries and its parents' `.git`.
    pub(crate) fn dash_check_path(&self, raw: &str) -> Result<PathCheck, ActionError> {
        let no = |reason: &str| {
            Ok(PathCheck {
                ok: false,
                reason: Some(reason.to_owned()),
                ..PathCheck::default()
            })
        };
        if ms_dash::shell::quote(raw).is_none() {
            return no(
                "That path holds a line break or a hidden character. Type the folder's path again",
            );
        }
        let p = Path::new(raw.trim());
        if !p.is_absolute() {
            return no(
                "Give the folder's full path, starting with / (for example /Users/you/code/shop)",
            );
        }
        let Ok(folder) = std::fs::canonicalize(p) else {
            return no("That folder doesn't exist, or morsec can't see it");
        };
        if !folder.is_dir() {
            return no("That is a file, not a folder");
        }
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .and_then(|h| std::fs::canonicalize(h).ok())
            .unwrap_or_else(|| PathBuf::from("/nonexistent-home"));
        use ms_projects::mode::{MachineWhy, Mode as M};
        // The folder itself first: `/` or the home folder is refused whatever is in it.
        let why = |w: MachineWhy| match w {
            MachineWhy::Home => "That is your home folder; pick the project folder",
            MachineWhy::TooHigh => "That folder holds your home folder; pick the project folder",
            MachineWhy::Excluded => {
                "morsec doesn't set up projects in system or library folders, or at the top of a disk; pick the project folder"
            }
            _ => {
                "No project here: no git repository and no project file (package.json, .env, Cargo.toml, …)"
            }
        };
        if let Some(w) = ms_projects::mode::refused_root(&folder, &home) {
            return no(why(w));
        }
        let git_top = folder
            .ancestors()
            .find(|a| a.join(".git").exists())
            .map(Path::to_path_buf);
        let has_marker = std::fs::read_dir(&folder).ok().is_some_and(|rd| {
            rd.flatten().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(ms_projects::mode::is_marker)
            })
        });
        let mode = ms_projects::mode::detect(ms_projects::mode::Inputs {
            cwd: &folder,
            home: &home,
            git_top: git_top.as_deref(),
            cwd_has_marker: has_marker,
        });
        let root = match mode {
            M::Project(r) => r,
            M::Machine(w) => return no(why(w)),
        };
        let shown = root.display().to_string();
        let Some(command) = ms_dash::shell::in_folder(&shown, "ms init") else {
            return no("That folder's name holds a hidden character, so no command is offered");
        };
        let project = self.dash_projects().ok().and_then(|f| {
            f.projects
                .iter()
                .find(|r| Path::new(&r.root) == root)
                .map(|r| r.slug.clone())
        });
        Ok(PathCheck {
            ok: true,
            folder: Some(shown),
            reason: None,
            project,
            command: Some(command),
        })
    }

    /// One rule edit (SPEC D-14): `ms_rules::edit` as `ms rules` does; loosening needs Touch
    /// ID and is refused while stopped, tightening needs none.
    pub(crate) fn dash_rules(&self, a: &Actor, key: &KeyName, edit: &RuleEdit) -> ActionResult {
        let what = "rules change";
        let (current, tampered) = {
            let l = self.read_live();
            (l.rules.keys.get(key).cloned(), l.rules.tampered)
        };
        if tampered {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Refused,
                    "morsec: the rules failed their integrity check, so they can't be changed. Run ms doctor",
                ),
            ));
        }
        let Some(current) = current else {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Gone,
                    format!("morsec: no key named {key} has a rule"),
                ),
            ));
        };
        let e =
            to_edit(edit).map_err(|m| self.refuse(a, key, what, err(ActionCode::Invalid, m)))?;
        let next = ms_rules::edit::apply(&current, key, &[e])
            .map_err(|m| self.refuse(a, key, what, err(ActionCode::Invalid, m)))?;
        match ms_rules::classify_rule(Some(&current), Some(&next)) {
            Change::Same => Ok(ActionOk::new(format!("No change to {key}"))),
            Change::Tighten => {
                let (v, _) = self
                    .change_rule(key, Some(next), false)
                    .map_err(|e| self.refuse(a, key, what, rules_error(e)))?;
                self.dash_receipt(
                    a,
                    key,
                    "rules change (tighten)",
                    ReceiptResult::Allowed,
                    None,
                );
                Ok(ActionOk::new(format!("Saved: rules version {v}")))
            }
            Change::Loosen => {
                if self.is_stopped() {
                    return Err(self.refuse(
                        a,
                        key,
                        "rules change (loosen)",
                        err(
                            ActionCode::Stopped,
                            "morsec: morsec is stopped, so rules can't be loosened. Start it first",
                        ),
                    ));
                }
                let stops_seen = self.stops.load(Ordering::SeqCst);
                let tier = current.tier.max(next.tier);
                let text = rule_text(key, &next);
                let req = admin_request(
                    &a.session,
                    key.clone(),
                    tier,
                    &["dashboard", "rules", key.as_str(), &text],
                );
                let reason = format!(
                    "let {} ({} key) {} — change made in the dashboard",
                    ms_approve::render::inert(key.as_str()),
                    tier_str(tier),
                    describe(edit)
                );
                let token = self
                    .dash_confirm(&req, &reason)
                    .map_err(|e| self.refuse(a, key, "rules change (loosen)", e))?;
                if self.is_stopped() || self.stops.load(Ordering::SeqCst) != stops_seen {
                    return Err(self.refuse(
                        a,
                        key,
                        "rules change (loosen)",
                        err(
                            ActionCode::Stopped,
                            "morsec: morsec was stopped while Touch ID was up, so nothing changed",
                        ),
                    ));
                }
                let (v, _) = self
                    .change_rule(key, Some(next), true)
                    .map_err(|e| self.refuse(a, key, "rules change (loosen)", rules_error(e)))?;
                self.dash_receipt(
                    a,
                    key,
                    "rules change (loosen)",
                    ReceiptResult::Approved,
                    Some(&token),
                );
                Ok(ActionOk::new(format!(
                    "Saved with Touch ID: rules version {v}"
                )))
            }
        }
    }

    /// Counts one Show or Copy against [`REVEAL_LIMIT`] in [`REVEAL_WINDOW`], before Touch ID.
    pub(crate) fn take_reveal(&self) -> Result<(), ActionError> {
        let now = Instant::now();
        let mut w = lock(&self.dash_acts.reveals);
        while w
            .front()
            .is_some_and(|t| now.duration_since(*t) >= REVEAL_WINDOW)
        {
            w.pop_front();
        }
        if w.len() >= REVEAL_LIMIT {
            let wait = w.front().map_or(REVEAL_WINDOW, |t| {
                REVEAL_WINDOW.saturating_sub(now.duration_since(*t))
            });
            let mins = wait.as_secs().div_ceil(60).max(1);
            return Err(err(
                ActionCode::RateLimited,
                format!("morsec: too many in 10 minutes. Wait {mins} min"),
            ));
        }
        w.push_back(now);
        Ok(())
    }
}

impl Daemon {
    // ---- value actions (SPEC D-12, D-13) ------------------------------------------------

    /// The key's tier for an approval (production when it has no rule).
    fn tier_of(&self, key: &KeyName) -> Tier {
        self.read_live()
            .rules
            .keys
            .get(key)
            .map_or(Tier::Production, |r| r.tier)
    }

    /// The checks every value action makes before Touch ID: not stopped, not morsec's own key,
    /// stored here and usable by this build.
    fn value_precheck(&self, a: &Actor, key: &KeyName, what: &str) -> Result<KeyMeta, ActionError> {
        if self.is_stopped() {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Stopped,
                    "morsec: morsec is stopped, so no value is read or changed. Start it first",
                ),
            ));
        }
        if ms_rules::is_reserved(key) {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Invalid,
                    format!("morsec: {key} is one of morsec's own keys"),
                ),
            ));
        }
        let listing = self
            .scan_keys()
            .map_err(|e| self.refuse(a, key, what, err(ActionCode::Internal, e.to_string())))?;
        if listing.unusable.contains(key) {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Refused,
                    format!("morsec: {}", ms_vault::unusable_hint(key)),
                ),
            ));
        }
        listing
            .keys
            .into_iter()
            .find(|m| &m.name == key)
            .ok_or_else(|| {
                self.refuse(
                    a,
                    key,
                    what,
                    err(
                        ActionCode::Gone,
                        format!("morsec: {key} is not in the vault"),
                    ),
                )
            })
    }

    /// The value is text (Show and Copy put text only on screen and on the pasteboard).
    fn is_text(&self, key: &KeyName) -> Result<bool, ActionError> {
        self.vault
            .read_with(key, |b| std::str::from_utf8(b).is_ok())
            .map_err(|e| err(ActionCode::Internal, e.to_string()))
    }

    /// The approval request for value action `action` on `key`: bound to the dashboard session,
    /// the key and `["dashboard", <action>, <key>]`.
    pub(crate) fn value_request(
        &self,
        session: &ms_core::SessionId,
        key: &KeyName,
        action: &str,
    ) -> ApprovalRequest {
        admin_request(
            session,
            key.clone(),
            self.tier_of(key),
            &["dashboard", action, key.as_str()],
        )
    }

    /// Touch ID for one value action on `key`: the request is bound to the dashboard session,
    /// the key and `["dashboard", <action>, <key>]`, so the once token covers that key and that
    /// action only.
    fn value_confirm(
        &self,
        a: &Actor,
        key: &KeyName,
        action: &str,
        what: &str,
        reason: &str,
    ) -> Result<ApprovalToken, ActionError> {
        let req = self.value_request(&a.session, key, action);
        let stops_seen = self.stops.load(Ordering::SeqCst);
        let t = self
            .dash_confirm(&req, reason)
            .map_err(|e| self.refuse(a, key, what, e))?;
        if self.is_stopped() || self.stops.load(Ordering::SeqCst) != stops_seen {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Stopped,
                    "morsec: morsec was stopped while Touch ID was up, so nothing was done",
                ),
            ));
        }
        Ok(t)
    }

    pub(crate) fn dash_show(&self, a: &Actor, key: &KeyName) -> Result<Revealed, ActionError> {
        let what = "show value";
        self.value_precheck(a, key, what)?;
        if !self.is_text(key)? {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::NotText,
                    "morsec: this value is not text; use Copy",
                ),
            ));
        }
        self.take_reveal()
            .map_err(|e| self.refuse(a, key, what, e))?;
        let reason = format!(
            "show the value of {} in the morsec dashboard",
            ms_approve::render::inert(key.as_str())
        );
        let token = self.value_confirm(a, key, "show", what, &reason)?;
        let v = self
            .vault
            .read_with(key, |b| ms_core::SecretBytes::new(b.to_vec()))
            .map_err(|e| self.refuse(a, key, what, err(ActionCode::Internal, e.to_string())))?;
        self.dash_receipt(a, key, what, ReceiptResult::Approved, Some(&token));
        Ok(Revealed::new(v))
    }

    pub(crate) fn dash_copy(&self, a: &Actor, key: &KeyName) -> ActionResult {
        let what = "copy value";
        self.value_precheck(a, key, what)?;
        if !self.is_text(key)? {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::NotText,
                    "morsec: this value is not text, so it can't go on the clipboard",
                ),
            ));
        }
        self.take_reveal()
            .map_err(|e| self.refuse(a, key, what, e))?;
        let reason = format!(
            "copy the value of {} to the clipboard (cleared after {} s)",
            ms_approve::render::inert(key.as_str()),
            CLEAR_AFTER.as_secs()
        );
        let token = self.value_confirm(a, key, "copy", what, &reason)?;
        let cb = self.clipboard();
        let wrote = self
            .vault
            .read_with(key, |b| match std::str::from_utf8(b) {
                Ok(t) => crate::pasteboard::copy_then_clear(cb, t, CLEAR_AFTER),
                Err(_) => Err("not text".to_owned()),
            })
            .map_err(|e| self.refuse(a, key, what, err(ActionCode::Internal, e.to_string())))?;
        if let Err(e) = wrote {
            tracing::warn!(error = %e, "could not write the pasteboard");
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Unavailable,
                    "morsec: the clipboard is not reachable from msd (no desktop session)",
                ),
            ));
        }
        self.dash_receipt(a, key, what, ReceiptResult::Approved, Some(&token));
        Ok(ActionOk::new(format!(
            "Copied. The clipboard is cleared in {} seconds",
            CLEAR_AFTER.as_secs()
        )))
    }

    /// Stores `value` for an existing key, putting the old value back if the store fails (the
    /// keychain's replace is delete-then-add, and the `Vault` trait is frozen): SPEC D-13.
    pub(crate) fn replace_value(
        &self,
        key: &KeyName,
        meta: KeyMeta,
        value: ms_core::SecretBytes,
    ) -> Result<(), String> {
        let old = self
            .vault
            .read_with(key, |b| ms_core::SecretBytes::new(b.to_vec()))
            .map_err(|e| {
                format!("morsec: the current value can't be read ({e}); nothing changed")
            })?;
        match self.vault_put(key, value, meta.clone()) {
            Ok(()) => Ok(()),
            Err(e) => match self.vault.put(key, old, meta) {
                Ok(()) => Err(format!(
                    "morsec: the new value could not be stored ({e}); the old value is still in use"
                )),
                Err(e2) => Err(format!(
                    "morsec: the new value could not be stored ({e}) and the old one could not be put back ({e2}); {key} is missing now. Add it again with: ms add {key}"
                )),
            },
        }
    }

    /// `vault.put`, with a failure tests can ask for.
    fn vault_put(
        &self,
        key: &KeyName,
        value: ms_core::SecretBytes,
        meta: KeyMeta,
    ) -> ms_core::Result<()> {
        #[cfg(test)]
        if self.dash_acts.fail_next_put.swap(false, Ordering::SeqCst) {
            drop(value);
            let _ = self.vault.delete(key);
            return Err(ms_core::Error::Socket("injected put failure".into()));
        }
        self.vault.put(key, value, meta)
    }

    pub(crate) fn dash_replace(
        &self,
        a: &Actor,
        key: &KeyName,
        value: ms_core::SecretBytes,
    ) -> ActionResult {
        let what = "replace value";
        if value.is_empty() {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Invalid,
                    "morsec: the new value is empty; nothing changed",
                ),
            ));
        }
        let meta = self.value_precheck(a, key, what)?;
        let reason = format!(
            "replace the value of {} (from the dashboard)",
            ms_approve::render::inert(key.as_str())
        );
        let token = self.value_confirm(a, key, "replace", what, &reason)?;
        self.replace_value(key, meta, value)
            .map_err(|m| self.refuse(a, key, what, err(ActionCode::Internal, m)))?;
        self.dash_receipt(a, key, what, ReceiptResult::Approved, Some(&token));
        Ok(ActionOk::new(format!("Replaced {key}")))
    }

    pub(crate) fn dash_add_key(&self, a: &Actor, new: NewKey) -> ActionResult {
        let what = "add key";
        let NewKey {
            key,
            value,
            mode,
            tier,
        } = new;
        if value.is_empty() {
            return Err(self.refuse(
                a,
                &key,
                what,
                err(
                    ActionCode::Invalid,
                    "morsec: the value is empty; nothing stored",
                ),
            ));
        }
        let meta = KeyMeta {
            name: key.clone(),
            mode,
            tier,
            created_unix_ms: now_ms(),
        };
        match self.put_key_as(&a.session, key.clone(), meta, value, "dashboard: add key") {
            ResponseBody::Ok { message } => Ok(ActionOk::new(message)),
            ResponseBody::Error { message, code } => Err(self.refuse(
                a,
                &key,
                what,
                err(
                    match code {
                        ErrorCode::Denied | ErrorCode::Invalid => ActionCode::Invalid,
                        _ => ActionCode::Internal,
                    },
                    message,
                ),
            )),
            _ => Err(err(ActionCode::Internal, "morsec: unexpected answer")),
        }
    }

    /// Project lines that hold `key`'s ref, as `project file:line`; `Err` when the records
    /// can't be read (fails closed).
    pub(crate) fn references(&self, key: &KeyName) -> Result<Vec<String>, String> {
        let file = self.dash_projects()?;
        let mut out = Vec::new();
        for p in &file.projects {
            for f in &p.files {
                for s in f.secrets.iter().filter(|s| &s.key == key) {
                    out.push(format!("{} {}:{}", p.slug, f.path, s.line));
                }
            }
        }
        Ok(out)
    }

    /// Deletes `key`'s value and rule (the rule through `change_rule`: a tightening).
    pub(crate) fn delete_key(&self, key: &KeyName) -> Result<(), String> {
        match self.vault.delete(key) {
            Ok(()) | Err(ms_core::Error::NoSuchKey(_)) => {}
            Err(e) => return Err(format!("morsec: the value could not be deleted ({e})")),
        }
        if self.read_live().rules.keys.contains_key(key) {
            self.change_rule(key, None, false).map_err(|e| {
                format!("morsec: the value was deleted; its rule could not be ({e})")
            })?;
        }
        Ok(())
    }

    pub(crate) fn dash_delete(&self, a: &Actor, key: &KeyName, force: bool) -> ActionResult {
        let what = "delete key";
        if self.is_stopped() {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Stopped,
                    "morsec: morsec is stopped. Start it first",
                ),
            ));
        }
        if ms_rules::is_reserved(key) {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Invalid,
                    format!("morsec: {key} is one of morsec's own keys"),
                ),
            ));
        }
        let stored = self
            .scan_keys()
            .map(|l| l.keys.iter().any(|m| &m.name == key))
            .unwrap_or(false);
        if !stored && !self.read_live().rules.keys.contains_key(key) {
            return Err(self.refuse(
                a,
                key,
                what,
                err(
                    ActionCode::Gone,
                    format!("morsec: there is no key named {key}"),
                ),
            ));
        }
        if !force {
            match self.references(key) {
                Ok(refs) if refs.is_empty() => {}
                Ok(refs) => {
                    return Err(self.refuse(
                        a,
                        key,
                        what,
                        err(
                            ActionCode::Referenced,
                            format!(
                                "morsec: project files still refer to {key}: {}. Undo it there first, or delete it anyway",
                                refs.join(", ")
                            ),
                        ),
                    ));
                }
                Err(m) => {
                    return Err(self.refuse(
                        a,
                        key,
                        what,
                        err(
                            ActionCode::Referenced,
                            format!(
                                "{m}. morsec can't tell whether a project still uses {key}; delete it anyway only if you are sure"
                            ),
                        ),
                    ));
                }
            }
        }
        let reason = format!(
            "delete {} and its rule; this can't be undone",
            ms_approve::render::inert(key.as_str())
        );
        let token = self.value_confirm(
            a,
            key,
            if force { "delete-force" } else { "delete" },
            what,
            &reason,
        )?;
        self.delete_key(key)
            .map_err(|m| self.refuse(a, key, what, err(ActionCode::Internal, m)))?;
        self.dash_receipt(a, key, what, ReceiptResult::Approved, Some(&token));
        Ok(ActionOk::new(format!("Deleted {key} and its rule")))
    }

    pub(crate) fn dash_undo(
        &self,
        a: &Actor,
        project: Option<&str>,
        key: Option<&KeyName>,
    ) -> Result<UndoView, ActionError> {
        let keys: Option<Vec<KeyName>> = key.map(|k| vec![k.clone()]);
        let confirm = |req: &ApprovalRequest, reason: &str| {
            self.dash_confirm(req, &format!("{reason} (from the dashboard)"))
        };
        let receipt = |k: &KeyName, r: ReceiptResult, t: Option<&ApprovalToken>| {
            self.dash_receipt(a, k, "undo", r, t);
        };
        self.undo_run(
            &a.session,
            project,
            keys.as_deref(),
            &confirm,
            &receipt,
            "dashboard",
        )
    }
}

/// A dashboard edit as the shared edit (folders resolved like `ms rules --add-root`).
fn to_edit(e: &RuleEdit) -> Result<ms_rules::edit::Edit, String> {
    use ms_rules::edit::Edit;
    let folder = |raw: &str| -> Result<PathBuf, String> {
        let p = PathBuf::from(raw.trim());
        let p = std::fs::canonicalize(&p).unwrap_or(p);
        ms_rules::validate_root(&p).map_err(|e| format!("morsec: {e}"))?;
        Ok(p)
    };
    Ok(match e {
        RuleEdit::AddHost(h) => Edit::AddHost(h.trim().to_owned()),
        RuleEdit::RemoveHost(h) => Edit::RemoveHost(h.trim().to_owned()),
        RuleEdit::AddCommand { words } => Edit::AddCommand(words.clone()),
        RuleEdit::RemoveCommand { words } => Edit::RemoveCommand(words.clone()),
        RuleEdit::AddFolder(f) => Edit::AddRoot(folder(f)?),
        RuleEdit::RemoveFolder(f) => Edit::RemoveRoot(PathBuf::from(f.trim())),
        RuleEdit::SetTier(t) => Edit::SetTier((*t).into()),
    })
}

/// The edit in words for the Touch ID sheet, inert.
fn describe(e: &RuleEdit) -> String {
    let i = ms_approve::render::inert;
    match e {
        RuleEdit::AddHost(h) => format!("reach {}", i(h.trim())),
        RuleEdit::RemoveHost(h) => format!("no longer reach {}", i(h.trim())),
        RuleEdit::AddCommand { words } => format!(
            "run {}",
            words
                .iter()
                .map(|w| ms_approve::render::quoted(w))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        RuleEdit::RemoveCommand { .. } => "lose a command".into(),
        RuleEdit::AddFolder(f) => format!("run its commands in {}", i(f.trim())),
        RuleEdit::RemoveFolder(f) => format!("no longer run in {}", i(f.trim())),
        RuleEdit::SetTier(t) => format!(
            "be a {} key (test keys never ask before each use)",
            tier_str((*t).into())
        ),
    }
}

/// The proposed rule as its TOML, bound into the approval like `ms rules` (its hash is the
/// argv's).
fn rule_text(key: &KeyName, r: &KeyRule) -> String {
    let mut one = ms_rules::Rules::default();
    one.keys.insert(key.clone(), r.clone());
    one.to_toml()
}

fn rules_error(e: ms_rules::RulesError) -> ActionError {
    match e {
        e @ ms_rules::RulesError::Invalid { .. } => err(ActionCode::Invalid, e.to_string()),
        e => err(ActionCode::Internal, e.to_string()),
    }
}

fn decide_error(e: DecideError) -> ActionError {
    match e {
        DecideError::NotPending(_) => err(ActionCode::Gone, "That request is no longer waiting"),
        DecideError::InProgress => err(
            ActionCode::Busy,
            "Touch ID is already up for this request. Answer the sheet on this Mac",
        ),
        DecideError::AuthFailed(why) => err(
            ActionCode::TouchIdFailed,
            format!(
                "Touch ID did not confirm ({}), so the request was denied",
                ms_approve::render::inert(&why)
            ),
        ),
        DecideError::Expired => err(
            ActionCode::TouchIdFailed,
            "The request timed out before Touch ID finished; nothing was approved",
        ),
        DecideError::Ended => err(
            ActionCode::Stopped,
            "morsec was stopped while Touch ID was up; nothing was approved",
        ),
        DecideError::Internal(m) => err(ActionCode::Internal, m),
    }
}

impl DashActions for DashSource {
    fn stop(&self, a: &Actor) -> ActionResult {
        self.daemon()?.dash_stop(a)
    }
    fn start(&self, a: &Actor) -> ActionResult {
        self.daemon()?.dash_start(a)
    }
    fn approve(&self, a: &Actor, id: &str, session_scope: bool) -> ActionResult {
        self.daemon()?.dash_approve(a, id, session_scope)
    }
    fn deny(&self, a: &Actor, id: &str) -> ActionResult {
        self.daemon()?.dash_deny(a, id)
    }
    fn dismiss(&self, a: &Actor, id: &str) -> ActionResult {
        self.daemon()?.dash_dismiss(a, id)
    }
    fn recheck(&self, _a: &Actor) -> Result<AgentsView, ActionError> {
        self.daemon()?.dash_recheck()
    }
    fn scan_run(&self, a: &Actor) -> ActionResult {
        self.daemon()?.dash_scan_run(a)
    }
    fn check_path(&self, _a: &Actor, path: &str) -> Result<PathCheck, ActionError> {
        self.daemon()?.dash_check_path(path)
    }
    fn rules(&self, a: &Actor, key: &KeyName, edit: &RuleEdit) -> ActionResult {
        self.daemon()?.dash_rules(a, key, edit)
    }
    fn show(&self, a: &Actor, key: &KeyName) -> Result<Revealed, ActionError> {
        self.daemon()?.dash_show(a, key)
    }
    fn copy(&self, a: &Actor, key: &KeyName) -> ActionResult {
        self.daemon()?.dash_copy(a, key)
    }
    fn replace(&self, a: &Actor, key: &KeyName, value: ms_core::SecretBytes) -> ActionResult {
        self.daemon()?.dash_replace(a, key, value)
    }
    fn add_key(&self, a: &Actor, new: NewKey) -> ActionResult {
        self.daemon()?.dash_add_key(a, new)
    }
    fn delete(&self, a: &Actor, key: &KeyName, force: bool) -> ActionResult {
        self.daemon()?.dash_delete(a, key, force)
    }
    fn undo(
        &self,
        a: &Actor,
        project: Option<&str>,
        key: Option<&KeyName>,
    ) -> Result<UndoView, ActionError> {
        self.daemon()?.dash_undo(a, project, key)
    }
    fn refused(&self, a: &Actor, action: Action, key: Option<&KeyName>, why: &str) {
        if let Ok(d) = self.daemon() {
            let k = key.cloned().unwrap_or_else(daemon_key);
            d.dash_receipt(
                a,
                &k,
                &format!("{} ({})", action.target(), ms_approve::render::inert(why)),
                ReceiptResult::Blocked(Reason::HostNotAllowed),
                None,
            );
        }
    }
}

impl DashSource {
    fn daemon(&self) -> Result<Arc<Daemon>, ActionError> {
        self.d()
            .map_err(|_| err(ActionCode::Unavailable, "morsec: msd is stopping"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::tests::*;
    use crate::pasteboard::{Marked, fake::Fake};
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{AgentKind, SecretBytes, SessionId};
    use ms_dash::actions::TierArg;
    use ms_ipc::{ErrorCode, PeerInfo, RequestBody};
    use std::collections::BTreeSet;

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

    fn k(s: &str) -> KeyName {
        KeyName::new(s).unwrap()
    }

    fn value(h: &H, key: &str) -> Option<Vec<u8>> {
        h.d.vault().read_with(&k(key), <[u8]>::to_vec).ok()
    }

    /// A daemon whose Touch ID always fails.
    fn denying() -> H {
        let dir = tempfile::tempdir().unwrap();
        open_auth(
            crate::backend::Backend::Memory(Arc::new(ms_vault::memory::MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
            FakeAuthenticator::deny("cancelled"),
        )
    }

    fn with_fake_clipboard(h: &H) -> Arc<Fake> {
        let f = Arc::new(Fake::default());
        h.d.set_clipboard(Arc::new(Marked(f.clone())));
        f
    }

    /// Runs `f` while an agent's request waits for a person (asked through the broker the
    /// proxy uses). Returns `f`'s result and the asker's outcome.
    fn while_pending<T: Send>(
        h: &H,
        req: ApprovalRequest,
        f: impl FnOnce(&ms_approve::Pending) -> T + Send,
    ) -> (T, ms_approve::ApprovalOutcome) {
        std::thread::scope(|sc| {
            let approvals = h.d.approvals.clone();
            let asker = sc.spawn(move || {
                use ms_approve::Approver;
                approvals.ask(&req, Duration::from_secs(5))
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let p = loop {
                if let Some(p) = h.d.approvals.pending() {
                    break p;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            };
            let out = f(&p);
            (out, asker.join().unwrap())
        })
    }

    fn agent_request(argv: Vec<String>) -> ApprovalRequest {
        ApprovalRequest {
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 42,
                started_unix_ms: 1,
            },
            key: k("pg/production"),
            tier: Tier::Production,
            argv_hash: ms_rules::argv_hash(&argv),
            argv_display: argv,
            cwd: PathBuf::from("/repo"),
            effect: None,
        }
    }

    // protects=SPEC D-10: each alert kind becomes its plain-words warning with the fix the table
    // names (a Re-check button and ms doctor for settings drift, ms init --trust for a new CA,
    // ms doctor otherwise), Dismiss only on the informational two, a stable id per alert, and
    // agent-influenced text inert; fails_when=a kind maps to another title or fix, Dismiss is
    // offered on a failure, or a path's control characters reach the page;
    // no_claim=the page's buttons (browser QA)
    #[test]
    fn alerts_map_to_warnings() {
        let h = fresh();
        let cases = [
            (
                AlertKind::CaReissued { hosts: 3 },
                "ca",
                "Some tools may not trust morsec yet",
            ),
            (
                AlertKind::SettingsChanged {
                    path: PathBuf::from("/Users/x/.claude/settings.json"),
                    fingerprint: None,
                },
                "drift",
                "Claude Code's settings changed",
            ),
            (
                AlertKind::ProxyDown,
                "proxy",
                "morsec's proxy is not running",
            ),
            (
                AlertKind::VaultUnlisted,
                "vault",
                "morsec couldn't read or save its state",
            ),
            (
                AlertKind::FloorNotSaved,
                "floor",
                "morsec couldn't read or save its state",
            ),
            (
                AlertKind::ProjectsUnreadable,
                "proj",
                "Project records failed their check",
            ),
            (
                AlertKind::BindingSkipped,
                "skipped \u{202e}x",
                "skipped \\u{202e}x",
            ),
        ];
        for (kind, text, _) in &cases {
            h.d.alert(kind.clone(), *text);
        }
        let texts = h.d.alert_texts();
        let ws = h.d.warnings_for(&texts);
        assert_eq!(ws.len(), cases.len());
        for (w, (kind, _, title)) in ws.iter().zip(&cases) {
            assert_eq!(&w.title, title);
            assert_eq!(w.dismiss, kind.dismissable());
            assert!(w.id.starts_with("w-") && w.id.len() == 18, "{}", w.id);
            let cmds: Vec<&str> = w.fix.iter().filter_map(|f| f.command.as_deref()).collect();
            match kind {
                AlertKind::CaReissued { .. } => {
                    assert_eq!(cmds, ["ms init --trust"]);
                    assert!(w.detail.contains("3 websites"));
                }
                AlertKind::SettingsChanged { .. } => {
                    assert_eq!(w.fix[0].action.as_deref(), Some("/api/agents/recheck"));
                    assert_eq!(w.fix[0].label.as_deref(), Some("Re-check"));
                    assert_eq!(cmds, ["ms doctor"]);
                }
                _ => assert_eq!(cmds, ["ms doctor"]),
            }
            assert!(
                !w.title
                    .chars()
                    .any(ms_approve::render::is_invisible_or_bidi)
            );
        }
        assert_eq!(
            ws.iter().filter(|w| w.dismiss).count(),
            2,
            "only CaReissued and SettingsChanged"
        );
        assert_eq!(h.d.warnings_for(&texts)[0].id, ws[0].id, "stable");
        // Computed alerts (no kind) show as inert text with ms doctor.
        let w = h.d.warnings_for(&["the rules failed".into()]);
        assert_eq!(w[0].title, "the rules failed");
        assert!(!w[0].dismiss);
    }

    // protects=SPEC D-10 and criterion 5: ms status prints each alert's text exactly as before
    // (the kind is only for the dashboard); fails_when=the text changes or an alert is lost;
    // no_claim=the CLI's own formatting (service.rs)
    #[test]
    fn status_text_unchanged() {
        let h = fresh();
        let t = "the morsec CA was issued for 2 host(s); tools that use the system trust store need it trusted again: ms init --trust";
        h.d.alert(AlertKind::CaReissued { hosts: 2 }, t);
        h.d.alert(AlertKind::CaReissued { hosts: 2 }, t);
        match h.req(RequestBody::Status) {
            ResponseBody::Status { alerts, .. } => {
                assert_eq!(alerts.iter().filter(|a| a.as_str() == t).count(), 1);
            }
            other => panic!("{other:?}"),
        }
    }

    // protects=SPEC D-10: Dismiss clears an informational alert (a new CA, settings drift) from
    // msd's memory with a receipt and no Touch ID; a failure (proxy down) can't be dismissed;
    // an unknown id is gone; fails_when=a failure warning is hidden by Dismiss or a dismissal
    // leaves no receipt; no_claim=-
    #[test]
    fn dismiss_only_informational() {
        let h = fresh();
        h.d.alert(AlertKind::CaReissued { hosts: 1 }, "ca text");
        h.d.alert(AlertKind::ProxyDown, "the swap proxy is not running: x");
        let ws = h.d.warnings_for(&h.d.alert_texts());
        let r = h.d.dash_dismiss(&actor(), &ws[1].id).unwrap_err();
        assert_eq!(r.code, ActionCode::Invalid);
        assert!(h.d.dash_dismiss(&actor(), &ws[0].id).is_ok());
        assert_eq!(h.d.alert_texts(), ["the swap proxy is not running: x"]);
        assert_eq!(
            h.d.dash_dismiss(&actor(), &ws[0].id).unwrap_err().code,
            ActionCode::Gone
        );
        assert!(h.auth.reasons().is_empty());
        assert!(h.receipts_text().contains("dashboard: dismiss warning"));
    }

    // protects=SPEC D-9, criterion 6, T-102: Stop from the dashboard needs no Touch ID, takes
    // effect at once (the next swap is refused) and leaves a receipt; fails_when=it asks for
    // Touch ID or a swap still goes through; no_claim=the header control (browser QA)
    #[test]
    fn stop_needs_no_approval() {
        let h = fresh();
        assert!(h.d.dash_stop(&actor()).is_ok());
        assert!(h.d.is_stopped());
        assert!(h.auth.reasons().is_empty());
        let text = h.receipts_text();
        assert!(text.contains("dashboard: stop"), "{text}");
        assert!(text.contains("dashboard"));
    }

    // protects=SPEC D-9, criterion 6, T-102: Start from the dashboard raises Touch ID with
    // msd's own reason and resumes only when it confirms; a failed Touch ID leaves morsec
    // stopped and records a denial; fails_when=Start resumes without Touch ID;
    // no_claim=the real sheet (manual)
    #[test]
    fn start_from_dashboard_needs_touch_id() {
        let h = denying();
        h.d.dash_stop(&actor()).unwrap();
        let e = h.d.dash_start(&actor()).unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
        assert!(h.d.is_stopped());
        assert!(h.receipts_text().contains("dashboard: start"));
        let h = fresh();
        h.d.dash_stop(&actor()).unwrap();
        assert!(h.d.dash_start(&actor()).is_ok());
        assert!(!h.d.is_stopped());
        assert_eq!(h.auth.reasons().len(), 1);
        assert!(h.auth.reasons()[0].contains("start morsec"));
        assert!(h.receipts_text().contains("\"token_id\":\"once-"));
    }

    // protects=SPEC D-11, criterion 7, T-101: Approve on the dashboard decides exactly the
    // request it showed: another id is "no longer waiting" (409 gone), the right id raises
    // Touch ID with the reason built from the real request and approves it, and a second click
    // on the same id is gone; fails_when=a stale or guessed id approves the waiting request;
    // no_claim=the page's rendering (browser QA)
    #[test]
    fn approve_from_dashboard_binds_id() {
        let h = fresh();
        let ((wrong, right), outcome) = while_pending(
            &h,
            agent_request(vec!["psql".into(), "-c".into(), "select 1".into()]),
            |p| {
                let wrong = h.d.dash_approve(&actor(), "apr-0000", false);
                let right = h.d.dash_approve(&actor(), &p.id, false);
                (wrong, right)
            },
        );
        assert_eq!(wrong.unwrap_err().code, ActionCode::Gone);
        assert!(right.is_ok());
        assert!(matches!(outcome, ms_approve::ApprovalOutcome::Approved(_)));
        assert!(h.auth.reasons()[0].contains("pg/production"));
        assert!(h.auth.reasons()[0].contains("select 1"));
        assert_eq!(
            h.d.dash_approve(&actor(), "apr-0000", false)
                .unwrap_err()
                .code,
            ActionCode::Gone
        );
        assert!(h.receipts_text().contains("dashboard: approve"));
    }

    // protects=SPEC D-11 and criterion 7: Deny answers the waiting request at once with no
    // Touch ID and a receipt; fails_when=Deny raises a sheet or the request stays waiting;
    // no_claim=-
    #[test]
    fn deny_needs_no_touch_id() {
        let h = fresh();
        let (r, outcome) = while_pending(&h, agent_request(vec!["psql".into()]), |p| {
            h.d.dash_deny(&actor(), &p.id)
        });
        assert!(r.is_ok());
        assert_eq!(outcome, ms_approve::ApprovalOutcome::Denied);
        assert!(h.auth.reasons().is_empty());
        assert!(h.receipts_text().contains("dashboard: deny"));
    }

    // protects=SPEC D-11, criterion 7, INJ-3: Home's pending card carries the request as msd
    // renders it for ms approve: every argument on its own, quoted, control and bidi characters
    // escaped, none cut however long, the id to answer and the folder; fails_when=an argument is
    // dropped, cut, or a raw control/bidi character reaches the page; no_claim=the browser's
    // rendering (textContent, browser QA)
    #[test]
    fn pending_card_is_inert_and_complete() {
        let h = fresh();
        let long = "x".repeat(5000);
        let argv = vec![
            "psql".to_owned(),
            "evil\u{202e}gpj.exe".into(),
            "line\nbreak\u{1b}[2J".into(),
            long.clone(),
            String::new(),
        ];
        let (home, _) = while_pending(&h, agent_request(argv.clone()), |p| {
            let home = h.d.dash_home().unwrap();
            h.d.dash_deny(&actor(), &p.id).unwrap();
            (home, p.id.clone())
        });
        let (home, id) = home;
        let p = home.pending.unwrap();
        assert_eq!(p.id, id);
        assert_eq!(p.command.len(), argv.len());
        assert_eq!(p.command[0], "\"psql\"");
        assert_eq!(p.command[1], "\"evil\\u{202e}gpj.exe\"");
        assert_eq!(p.command[2], "\"line\\nbreak\\e[2J\"");
        assert_eq!(p.command[3].len(), long.len() + 2, "never cut");
        assert_eq!(p.command[4], "\"\"");
        assert_eq!(p.cwd, "\"/repo\"");
        assert_eq!(p.agent, "Claude Code");
        assert!(!p.deciding);
        let all = serde_json::to_string(&p).unwrap();
        assert!(!all.contains('\u{202e}') && !all.contains('\u{1b}'));
    }

    // protects=SPEC D-14, criterion 8, T-97: a loosening edit from the dashboard (a new host)
    // raises Touch ID naming the key and the host, and is saved only when it confirms; while
    // stopped it is refused before any sheet; a bad host answers the message ms rules gives;
    // fails_when=a loosening is saved without Touch ID or while stopped; no_claim=the real sheet
    #[test]
    fn rules_edit_loosen_needs_touch_id() {
        let h = denying();
        h.put("stripe/test", Tier::Test);
        let add = RuleEdit::AddHost("api.stripe.com".into());
        let e =
            h.d.dash_rules(&actor(), &k("stripe/test"), &add)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
        assert!(h.d.rules().keys[&k("stripe/test")].hosts.is_empty());

        let h = fresh();
        h.put("stripe/test", Tier::Test);
        assert!(h.d.dash_rules(&actor(), &k("stripe/test"), &add).is_ok());
        assert_eq!(h.d.rules().keys[&k("stripe/test")].hosts.len(), 1);
        let reasons = h.auth.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("stripe/test") && reasons[0].contains("api.stripe.com"));
        assert!(
            h.receipts_text()
                .contains("dashboard: rules change (loosen)")
        );

        let bad = RuleEdit::AddHost("http://x".into());
        let e =
            h.d.dash_rules(&actor(), &k("stripe/test"), &bad)
                .unwrap_err();
        let cli = ms_rules::edit::apply(
            &h.d.rules().keys[&k("stripe/test")],
            &k("stripe/test"),
            &[ms_rules::edit::Edit::AddHost("http://x".into())],
        )
        .unwrap_err();
        assert_eq!((e.code, e.message), (ActionCode::Invalid, cli));

        h.d.dash_stop(&actor()).unwrap();
        let wider = RuleEdit::AddHost("files.stripe.com".into());
        let e =
            h.d.dash_rules(&actor(), &k("stripe/test"), &wider)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::Stopped);
        assert_eq!(h.auth.reasons().len(), 1, "no sheet while stopped");
    }

    // protects=SPEC D-14, criterion 8: tightening (a host removed, test → production) is saved
    // with no Touch ID, also while stopped, with a receipt; fails_when=a tightening asks for
    // Touch ID or is refused; no_claim=-
    #[test]
    fn rules_edit_tighten_needs_none() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let key = k("stripe/test");
        h.d.dash_rules(&actor(), &key, &RuleEdit::AddHost("api.stripe.com".into()))
            .unwrap();
        let n = h.auth.reasons().len();
        h.d.dash_stop(&actor()).unwrap();
        h.d.dash_rules(&actor(), &key, &RuleEdit::SetTier(TierArg::Production))
            .unwrap();
        h.d.dash_rules(
            &actor(),
            &key,
            &RuleEdit::RemoveHost("api.stripe.com".into()),
        )
        .unwrap();
        let r = &h.d.rules().keys[&key];
        assert!(r.hosts.is_empty() && r.tier == Tier::Production);
        assert_eq!(h.auth.reasons().len(), n, "no Touch ID to tighten");
        assert!(
            h.receipts_text()
                .contains("dashboard: rules change (tighten)")
        );
    }

    // protects=SPEC D-12, criterion 9, T-89: every Show raises its own Touch ID sheet (test keys
    // too), naming the key; a failed Touch ID shows nothing; the answer holds the value and the
    // receipt does not; fails_when=a second Show reuses an earlier approval, a test key skips
    // Touch ID, or the value reaches a receipt; no_claim=the real sheet
    #[test]
    fn reveal_requires_fresh_approval() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        for _ in 0..2 {
            let v = h.d.dash_show(&actor(), &k("stripe/test")).unwrap();
            assert_eq!(v.len(), CANARY.len());
        }
        let reasons = h.auth.reasons();
        assert_eq!(reasons.len(), 2, "one sheet per Show");
        assert!(reasons[0].contains("show the value of stripe/test"));
        assert!(!h.receipts_text().contains(CANARY));
        assert!(h.receipts_text().contains("dashboard: show value"));
        let h = denying();
        h.put("stripe/test", Tier::Test);
        let e = h.d.dash_show(&actor(), &k("stripe/test")).unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
    }

    // protects=SPEC D-12 and T-89: the once token a value action gets is bound to the dashboard
    // session, that key and that action: it is refused for Copy of the same key, for Show of
    // another key, and for a second use; fails_when=a token approved for one key or action
    // verifies for another; no_claim=-
    #[test]
    fn reveal_token_bound_to_key_and_action() {
        let h = fresh();
        h.put("stripe/a", Tier::Test);
        h.put("stripe/b", Tier::Test);
        let s = actor().session;
        let show_a = h.d.value_request(&s, &k("stripe/a"), "show");
        assert_eq!(show_a.argv_display, ["dashboard", "show", "stripe/a"]);
        let t =
            h.d.approvals
                .confirm(&show_a, "r", Duration::from_secs(1))
                .unwrap();
        let copy_a = h.d.value_request(&s, &k("stripe/a"), "copy");
        let show_b = h.d.value_request(&s, &k("stripe/b"), "show");
        assert!(h.d.approvals.verify(&t, &Binding::of(&copy_a)).is_err());
        assert!(h.d.approvals.verify(&t, &Binding::of(&show_b)).is_err());
        let mut other = show_a.clone();
        other.session.pid = 8;
        assert!(h.d.approvals.verify(&t, &Binding::of(&other)).is_err());
        assert!(h.d.approvals.verify(&t, &Binding::of(&show_a)).is_ok());
        assert!(
            h.d.approvals.verify(&t, &Binding::of(&show_a)).is_err(),
            "once"
        );
    }

    // protects=SPEC D-12 and criterion 9: while stopped, Show and Copy are refused before any
    // Touch ID sheet; fails_when=a stopped msd reads a value or raises a sheet; no_claim=-
    #[test]
    fn reveal_refused_while_stopped() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let _ = with_fake_clipboard(&h);
        h.d.dash_stop(&actor()).unwrap();
        assert_eq!(
            h.d.dash_show(&actor(), &k("stripe/test")).unwrap_err().code,
            ActionCode::Stopped
        );
        assert_eq!(
            h.d.dash_copy(&actor(), &k("stripe/test")).unwrap_err().code,
            ActionCode::Stopped
        );
        assert!(h.auth.reasons().is_empty());
    }

    // protects=SPEC D-12: a value that is not UTF-8 is refused for Show and Copy (409 not_text)
    // before any sheet; fails_when=binary is shown or copied; no_claim=-
    #[test]
    fn reveal_refuses_non_text() {
        let h = fresh();
        let key = k("bin/blob");
        let r = h.d.handle(
            &PeerInfo {
                uid: 501,
                gid: 20,
                pid: Some(42),
                accepted_unix_ms: 1,
            },
            RequestBody::PutKey {
                name: key.clone(),
                meta: KeyMeta {
                    name: key.clone(),
                    mode: Mode::Swap,
                    tier: Tier::Test,
                    created_unix_ms: 1,
                },
            },
            Some(SecretBytes::new(vec![0xff, 0xfe, 0x00])),
        );
        assert!(matches!(r, ResponseBody::Ok { .. }), "{r:?}");
        let _ = with_fake_clipboard(&h);
        assert_eq!(
            h.d.dash_show(&actor(), &key).unwrap_err().code,
            ActionCode::NotText
        );
        assert_eq!(
            h.d.dash_copy(&actor(), &key).unwrap_err().code,
            ActionCode::NotText
        );
        assert!(h.auth.reasons().is_empty());
    }

    // protects=SPEC D-12, criterion 11, T-90: Show and Copy together are limited to 10 per 10
    // minutes across sessions, counted before Touch ID, so the 11th raises no sheet;
    // fails_when=an 11th sheet appears; no_claim=the window's exact edge
    #[test]
    fn reveal_rate_limited() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let _ = with_fake_clipboard(&h);
        for i in 0..REVEAL_LIMIT {
            if i % 2 == 0 {
                h.d.dash_show(&actor(), &k("stripe/test")).unwrap();
            } else {
                h.d.dash_copy(&actor(), &k("stripe/test")).unwrap();
            }
        }
        let e = h.d.dash_show(&actor(), &k("stripe/test")).unwrap_err();
        assert_eq!(e.code, ActionCode::RateLimited);
        assert!(e.message.contains("Wait"), "{}", e.message);
        assert_eq!(
            h.d.dash_copy(&actor(), &k("stripe/test")).unwrap_err().code,
            ActionCode::RateLimited
        );
        assert_eq!(h.auth.reasons().len(), REVEAL_LIMIT, "no 11th sheet");
    }

    // protects=SPEC D-20 and criterion 10: Copy puts the value on the pasteboard (written by
    // msd, with every marker) after Touch ID and answers without the value; fails_when=the
    // answer holds the value or Copy skips Touch ID; no_claim=the real pasteboard (manual)
    #[test]
    fn copy_writes_the_pasteboard_after_touch_id() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let f = with_fake_clipboard(&h);
        let ok = h.d.dash_copy(&actor(), &k("stripe/test")).unwrap();
        assert!(!ok.message.contains(CANARY));
        assert_eq!(f.text().as_deref(), Some(CANARY));
        assert!(
            f.calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.contains("ConcealedType"))
        );
        assert_eq!(h.auth.reasons().len(), 1);
        assert!(h.auth.reasons()[0].contains("cleared after 30 s"));
    }

    // protects=SPEC D-13, criterion 12, T-95: Replace raises Touch ID naming the key, stores
    // the new value only when it confirms, and never echoes either value; fails_when=a value is
    // replaced without Touch ID or appears in the answer or a receipt; no_claim=the keychain
    #[test]
    fn replace_needs_touch_id() {
        let new = concat!("sk_live_", "REPLACED_CANARY_1");
        let h = denying();
        h.put("stripe/test", Tier::Test);
        let e =
            h.d.dash_replace(&actor(), &k("stripe/test"), SecretBytes::new(new.into()))
                .unwrap_err();
        assert_eq!(e.code, ActionCode::TouchIdFailed);
        assert_eq!(value(&h, "stripe/test").unwrap(), CANARY.as_bytes());
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let ok =
            h.d.dash_replace(&actor(), &k("stripe/test"), SecretBytes::new(new.into()))
                .unwrap();
        assert_eq!(ok.message, "Replaced stripe/test");
        assert_eq!(value(&h, "stripe/test").unwrap(), new.as_bytes());
        assert!(h.auth.reasons()[0].contains("replace the value of stripe/test"));
        let text = h.receipts_text();
        assert!(!text.contains(new) && !text.contains(CANARY));
        assert!(text.contains("dashboard: replace value"));
    }

    // protects=SPEC D-13 and T-95: when storing the new value fails (the keychain deletes before
    // it adds), the old value is put back and stays in use, and the answer says so;
    // fails_when=a failed replace leaves the key missing or holding the new value;
    // no_claim=a failure of the put-back itself (reported, not tested)
    #[test]
    fn replace_keeps_old_value_on_failure() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        h.d.dash_acts.fail_next_put.store(true, Ordering::SeqCst);
        let e =
            h.d.dash_replace(
                &actor(),
                &k("stripe/test"),
                SecretBytes::new(b"new-value".to_vec()),
            )
            .unwrap_err();
        assert!(
            e.message.contains("old value is still in use"),
            "{}",
            e.message
        );
        assert_eq!(value(&h, "stripe/test").unwrap(), CANARY.as_bytes());
    }

    // protects=SPEC D-13, criterion 12: Add creates a new key with no Touch ID (its rule allows
    // nothing) and refuses an existing name with the ms set command, leaving its value alone;
    // fails_when=Add replaces a value; no_claim=-
    #[test]
    fn add_key_new_only() {
        let h = fresh();
        let add = |name: &str, v: &str| {
            h.d.dash_add_key(
                &actor(),
                NewKey {
                    key: k(name),
                    value: SecretBytes::new(v.as_bytes().to_vec()),
                    mode: Mode::Swap,
                    tier: Tier::Test,
                },
            )
        };
        assert!(add("new/key", CANARY).is_ok());
        assert!(h.d.rules().keys[&k("new/key")].allows_nothing());
        let e = add("new/key", "other").unwrap_err();
        assert!(e.message.contains("ms set new/key"), "{}", e.message);
        assert_eq!(value(&h, "new/key").unwrap(), CANARY.as_bytes());
        assert!(h.auth.reasons().is_empty());
        assert!(h.receipts_text().contains("dashboard: add key"));
    }

    // protects=SPEC D-13, criterion 13, T-96: Delete is refused (409 referenced) while a project
    // file still holds the key's ref, naming the project, file and line, before any sheet; with
    // force it deletes after Touch ID; fails_when=a referenced key is deleted without force;
    // no_claim=-
    #[test]
    fn delete_refused_while_referenced() {
        let h = fresh();
        dash_fixture(&h);
        let e =
            h.d.dash_delete(&actor(), &k(STRIPE_KEY), false)
                .unwrap_err();
        assert_eq!(e.code, ActionCode::Referenced);
        assert!(e.message.contains("shop .env:1"), "{}", e.message);
        let n = h.auth.reasons().len();
        assert!(h.d.dash_delete(&actor(), &k(STRIPE_KEY), true).is_ok());
        assert_eq!(h.auth.reasons().len(), n + 1);
        assert!(value(&h, STRIPE_KEY).is_none());
    }

    // protects=SPEC D-13, criterion 13, T-96: Delete raises Touch ID ("this can't be undone"),
    // and only then removes the value and the rule; a failed Touch ID removes nothing;
    // fails_when=a key or rule goes without Touch ID, or one of the two stays; no_claim=-
    #[test]
    fn delete_needs_touch_id_and_removes_rule() {
        let h = denying();
        h.put("loose/key", Tier::Test);
        assert_eq!(
            h.d.dash_delete(&actor(), &k("loose/key"), false)
                .unwrap_err()
                .code,
            ActionCode::TouchIdFailed
        );
        assert!(value(&h, "loose/key").is_some());
        let h = fresh();
        h.put("loose/key", Tier::Test);
        h.d.dash_delete(&actor(), &k("loose/key"), false).unwrap();
        assert!(value(&h, "loose/key").is_none());
        assert!(!h.d.rules().keys.contains_key(&k("loose/key")));
        assert!(h.auth.reasons()[0].contains("can't be undone"));
        assert!(h.receipts_text().contains("dashboard: delete key"));
        assert_eq!(
            h.d.dash_delete(&actor(), &k("loose/key"), false)
                .unwrap_err()
                .code,
            ActionCode::Gone
        );
    }

    // protects=SPEC D-18, criterion 15: Run scan raises Touch ID (the same ["ms","scan"]
    // request), runs in the background with `running` set, refuses a second while one runs and
    // refuses while stopped; a failed Touch ID starts nothing; fails_when=a scan reads values
    // without Touch ID, two run at once, or one starts while stopped; no_claim=the scan's
    // findings (scan.rs)
    #[test]
    fn scan_from_dashboard_needs_touch_id() {
        let h = denying();
        assert_eq!(
            h.d.dash_scan_run(&actor()).unwrap_err().code,
            ActionCode::TouchIdFailed
        );
        assert!(!h.d.dash_scan_state().0);
        let h = fresh();
        let roots = tempfile::tempdir().unwrap();
        *lock(&h.d.dash_acts.scan_roots) = Some(vec![roots.path().to_path_buf()]);
        h.put("stripe/test", Tier::Test);
        h.d.dash_acts.scan_running.store(true, Ordering::SeqCst);
        assert_eq!(
            h.d.dash_scan_run(&actor()).unwrap_err().code,
            ActionCode::Busy
        );
        h.d.dash_acts.scan_running.store(false, Ordering::SeqCst);
        assert!(h.d.dash_scan_run(&actor()).is_ok());
        assert!(h.auth.reasons()[0].contains("leak scan"));
        let deadline = Instant::now() + Duration::from_secs(10);
        while h.d.dash_scan_state().0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(h.d.dash_scan().last.is_some());
        h.d.dash_stop(&actor()).unwrap();
        assert_eq!(
            h.d.dash_scan_run(&actor()).unwrap_err().code,
            ActionCode::Stopped
        );
    }

    // protects=SPEC D-16, criterion 16: Re-check clears a settings-changed alert whose file is
    // unchanged since the alert was raised, and keeps one whose file changed again;
    // fails_when=a settled alert stays or a fresh change is hidden; no_claim=connector state
    // (read on every view)
    #[test]
    fn recheck_clears_settled_drift() {
        let h = fresh();
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a.json"), d.path().join("b.json"));
        std::fs::write(&a, "{}").unwrap();
        std::fs::write(&b, "{}").unwrap();
        for p in [&a, &b] {
            h.d.alert(
                AlertKind::SettingsChanged {
                    path: p.clone(),
                    fingerprint: crate::drift::fingerprint(p),
                },
                format!("{} changed", p.display()),
            );
        }
        std::fs::write(&b, "{\"changed\":true}").unwrap();
        let v = h.d.dash_recheck().unwrap();
        assert_eq!(h.d.alert_texts(), [format!("{} changed", b.display())]);
        assert_eq!(v.warnings.len(), 1);
        assert!(h.auth.reasons().is_empty());
    }

    // protects=SPEC D-17, criterion 17: Add project's check refuses the home folder, its
    // parents, /, a relative or missing path and a folder with no project, each with its reason,
    // and gives `cd '<folder>' && ms init` for a project folder; fails_when=a machine root gets a
    // command; no_claim=what ms init then does (init_project tests)
    #[test]
    fn check_path_refuses_machine_roots() {
        let h = fresh();
        let home = std::env::var("HOME").unwrap();
        let reason = |p: &str| h.d.dash_check_path(p).unwrap().reason.unwrap_or_default();
        assert!(reason(&home).contains("home folder"), "{}", reason(&home));
        assert!(reason("/").contains("holds your home folder"));
        assert!(reason("code/shop").contains("full path"));
        assert!(reason("/no/such/dir/x").contains("doesn't exist"));
        let d = tempfile::tempdir().unwrap();
        let empty = std::fs::canonicalize(d.path()).unwrap().join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(reason(empty.to_str().unwrap()).contains("No project here"));
        std::fs::write(empty.join("package.json"), "{}").unwrap();
        let c = h.d.dash_check_path(empty.to_str().unwrap()).unwrap();
        assert!(c.ok);
        assert_eq!(
            c.command.unwrap(),
            format!("cd '{}' && ms init", empty.display())
        );
        assert!(h.receipts_text().is_empty() || !h.receipts_text().contains("check folder"));
    }

    // protects=T-100: commands the page copies are built by msd with the folder single-quoted:
    // a quote, $(…) and backticks stay inert; a newline or bidi character in a folder name gets
    // no command at all; fails_when=a crafted folder name can break out of the quoting;
    // no_claim=other shells
    #[test]
    fn copy_commands_are_shell_quoted() {
        let h = fresh();
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let odd = base.join("it's $(touch pwned) `x`");
        std::fs::create_dir(&odd).unwrap();
        std::fs::write(odd.join(".env"), "A=1\n").unwrap();
        let c = h.d.dash_check_path(odd.to_str().unwrap()).unwrap();
        let cmd = c.command.unwrap();
        assert_eq!(
            cmd,
            format!(
                "cd '{}/it'\\''s $(touch pwned) `x`' && ms init",
                base.display()
            )
        );
        for bad in ["nl\nname", "bidi\u{202e}name"] {
            let p = base.join(bad);
            std::fs::create_dir(&p).unwrap();
            std::fs::write(p.join(".env"), "A=1\n").unwrap();
            let c = h.d.dash_check_path(p.to_str().unwrap()).unwrap();
            assert!(!c.ok && c.command.is_none(), "{bad:?}");
        }
        // The Project screen's commands are quoted the same way.
        assert_eq!(
            ms_dash::shell::in_folder("/a/it's", "ms init").unwrap(),
            "cd '/a/it'\\''s' && ms init"
        );
    }

    // protects=SPEC D-22 and criterion 19: every dashboard action, done or refused, leaves one
    // receipt under the dashboard session with `dashboard: <action>`, the Touch ID token id when
    // one confirmed, and never a value; fails_when=an action leaves no receipt, a receipt carries
    // a value, or it is charged to another session; no_claim=envelope refusals (ms-dash tests)
    #[test]
    fn dashboard_action_writes_receipt() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let _ = with_fake_clipboard(&h);
        let a = actor();
        h.d.dash_show(&a, &k("stripe/test")).unwrap();
        h.d.dash_copy(&a, &k("stripe/test")).unwrap();
        let _ = h.d.dash_show(&a, &k("no/such"));
        h.d.dash_stop(&a).unwrap();
        let _ = h.d.dash_show(&a, &k("stripe/test"));
        h.d.dash_start(&a).unwrap();
        let records = ms_receipts::read_all(&h.dir.path().join("receipts")).unwrap();
        let mine: Vec<_> = records
            .iter()
            .filter_map(|r| match &r.rec.entry {
                ms_receipts::Entry::Receipt(x) if x.target.starts_with("dashboard: ") => Some(x),
                _ => None,
            })
            .collect();
        let targets: Vec<(&str, String)> = mine
            .iter()
            .map(|x| (x.target.as_str(), format!("{:?}", x.result)))
            .collect();
        assert_eq!(
            targets,
            [
                ("dashboard: show value", "Approved".to_owned()),
                ("dashboard: copy value", "Approved".into()),
                ("dashboard: show value", "Blocked(NoSuchKey)".into()),
                ("dashboard: stop", "Allowed".into()),
                ("dashboard: show value", "Blocked(Stopped)".into()),
                ("dashboard: start", "Approved".into()),
            ]
        );
        for x in &mine {
            assert_eq!(x.session, a.session);
        }
        assert!(
            mine[0]
                .approval
                .as_ref()
                .and_then(|a| a.token_id.as_deref())
                .is_some_and(|i| i.starts_with("once-"))
        );
        assert!(
            mine[2]
                .approval
                .as_ref()
                .and_then(|a| a.token_id.as_ref())
                .is_none()
        );
        assert_eq!(mine[3].key.as_str(), DAEMON_KEY_NAME);
        assert!(!h.receipts_text().contains(CANARY));
    }

    const DAEMON_KEY_NAME: &str = crate::daemon::DAEMON_KEY;

    /// Writes each recorded line of `rec` into its file under the root, as ms init left it.
    fn write_refs(rec: &ms_projects::record::ProjectRecord) {
        for f in &rec.files {
            let mut text = String::new();
            let max = f.secrets.iter().map(|s| s.line).max().unwrap_or(0);
            for n in 1..=max {
                match f.secrets.iter().find(|s| s.line == n) {
                    Some(s) => text.push_str(&format!("{}=ms://{}\n", s.var, s.key)),
                    None => text.push_str("# other\n"),
                }
            }
            let path = Path::new(&rec.root).join(&f.path);
            std::fs::write(path, text).unwrap();
        }
    }

    /// The shop fixture saved, its .env written; returns the record.
    fn saved_shop(h: &H) -> ms_projects::record::ProjectRecord {
        let rec = shop(h);
        let rules = proposal(h, &rec);
        let r = h.approved(|| save(h, &rec, &rules));
        assert!(matches!(r, ResponseBody::Ok { .. }), "{r:?}");
        write_refs(&rec);
        rec
    }

    // protects=SPEC D-21 and T-94: with a tampered projects.toml, Undo fails closed before any
    // Touch ID sheet and writes nothing; fails_when=a forged record drives Undo;
    // no_claim=the MAC itself (ms-projects store tests)
    #[test]
    fn undo_refuses_tampered_record() {
        let h = fresh();
        let rec = saved_shop(&h);
        let env = Path::new(&rec.root).join(".env");
        let before = std::fs::read_to_string(&env).unwrap();
        let file = h.dir.path().join(crate::daemon::PROJECTS_FILE);
        let mut t = std::fs::read_to_string(&file).unwrap();
        t.push_str("\n# edited\n");
        std::fs::write(&file, t).unwrap();
        let n = h.auth.reasons().len();
        let e = h.d.dash_undo(&actor(), Some("shop"), None).unwrap_err();
        assert_eq!(e.code, ActionCode::Refused);
        assert!(e.message.contains("integrity"), "{}", e.message);
        assert_eq!(h.auth.reasons().len(), n, "no sheet");
        assert_eq!(std::fs::read_to_string(&env).unwrap(), before);
    }

    // protects=SPEC D-21: Undo of a whole project writes every value back, deletes (value and
    // rule) the keys no other project refers to, keeps a key another project still uses, drops
    // the record, and never puts a value in its answer or a receipt; per-key Undo restores just
    // that key; fails_when=a key still used elsewhere is deleted, a restored key stays, or a value
    // leaks; no_claim=the file checks (ms-projects undo tests)
    #[test]
    fn undo_deletes_only_unreferenced_keys() {
        let h = fresh();
        let mut rec = shop(&h);
        // The Stripe key is also on a line of .env.local (the same value, reused).
        let mut local = rec.files[0].clone();
        local.path = ".env.local".into();
        local.secrets.truncate(1);
        local.secrets[0].var = "LOCAL_STRIPE".into();
        local.secrets[0].action = ms_projects::record::SecretAction::Reuse;
        rec.files.push(local);
        let rules = proposal(&h, &rec);
        assert!(matches!(
            h.approved(|| save(&h, &rec, &rules)),
            ResponseBody::Ok { .. }
        ));
        write_refs(&rec);

        // One key first, from the Secret screen: its line comes back and the key goes.
        let v =
            h.d.dash_undo(&actor(), Some("shop"), Some(&k(OPENAI_KEY)))
                .unwrap();
        assert_eq!(v.restored.len(), 1);
        assert_eq!(v.deleted_keys, [OPENAI_KEY]);
        assert!(value(&h, OPENAI_KEY).is_none());

        // The person edited .env.local meanwhile: that line is skipped, so the Stripe key, still
        // referred to there, stays; the keys whose every line came back go.
        let local_path = Path::new(&rec.root).join(".env.local");
        std::fs::write(&local_path, "LOCAL_STRIPE=edited\n").unwrap();
        let v = h.d.dash_undo(&actor(), Some("shop"), None).unwrap();
        assert_eq!(v.restored.len(), 3, "{v:?}");
        assert_eq!(v.skipped.len(), 1, "{v:?}");
        let deleted: BTreeSet<String> = v.deleted_keys.iter().cloned().collect();
        assert!(
            deleted.contains(DB_KEY) && deleted.contains(UNKNOWN_KEY),
            "{deleted:?}"
        );
        assert!(
            !deleted.contains(STRIPE_KEY),
            "still referred to by .env.local"
        );
        assert!(value(&h, STRIPE_KEY).is_some());
        assert!(h.d.rules().keys.contains_key(&k(STRIPE_KEY)));
        assert!(!h.d.rules().keys.contains_key(&k(DB_KEY)));
        let env = std::fs::read_to_string(Path::new(&rec.root).join(".env")).unwrap();
        assert_eq!(env.matches(CANARY).count(), 4, "{env}");
        // The record keeps only the skipped line.
        let file = h.d.dash_projects().unwrap();
        let p = file.get("shop").unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.files[0].path, ".env.local");

        // Put the ref back and undo the rest: now the key goes too, and the record with it.
        std::fs::write(&local_path, format!("LOCAL_STRIPE=ms://{STRIPE_KEY}\n")).unwrap();
        let v = h.d.dash_undo(&actor(), Some("shop"), None).unwrap();
        assert_eq!(v.deleted_keys, [STRIPE_KEY]);
        assert!(h.d.dash_projects().unwrap().get("shop").is_none());
        let all = format!("{v:?}{}", h.receipts_text());
        assert!(!all.contains(CANARY));
        assert!(h.receipts_text().contains("dashboard: undo"));
    }

    // protects=SPEC D-21: the Touch ID reason names every file that will receive a value and how
    // many values; fails_when=a file is missing from the sheet; no_claim=the real sheet
    #[test]
    fn undo_reason_names_every_file() {
        let h = fresh();
        let mut rec = shop(&h);
        let mut local = rec.files[0].clone();
        local.path = ".env.local".into();
        local.secrets.truncate(1);
        local.secrets[0].var = "LOCAL_STRIPE".into();
        rec.files[0].secrets.remove(0);
        rec.files.push(local);
        let rules = proposal(&h, &rec);
        assert!(matches!(
            h.approved(|| save(&h, &rec, &rules)),
            ResponseBody::Ok { .. }
        ));
        write_refs(&rec);
        let v = h.d.dash_undo(&actor(), Some("shop"), None).unwrap();
        assert_eq!(v.restored.len(), 4, "{v:?}");
        let reason = h.auth.reasons().pop().unwrap();
        assert!(reason.contains("write 4 values back into"), "{reason}");
        assert!(
            reason.contains("shop/.env") && reason.contains("shop/.env.local"),
            "{reason}"
        );
    }

    // protects=SPEC D-24 and T-96: KeyReplace, KeyDelete and ProjectUndo are refused inside an
    // agent session, from a sandboxed caller and while stopped; from the user's terminal they
    // go through the person's approval; fails_when=an agent or its sandbox replaces, deletes or
    // undoes anything; no_claim=the CLI's own refusal (set_rm_undo.rs)
    #[test]
    fn key_requests_refused_in_agent_session() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let key = k("stripe/test");
        let reqs = || {
            vec![
                (RequestBody::KeyReplace { key: key.clone() }, true),
                (
                    RequestBody::KeyDelete {
                        key: key.clone(),
                        force: true,
                    },
                    false,
                ),
                (
                    RequestBody::ProjectUndo {
                        slug: "shop".into(),
                        keys: None,
                    },
                    false,
                ),
            ]
        };
        let send = |h: &H, r: RequestBody, v: bool| {
            h.req_value(r, v.then(|| SecretBytes::new(b"new".to_vec())))
        };
        for (r, v) in reqs() {
            let out = send(h.as_(agent()), r, v);
            assert!(
                matches!(&out, ResponseBody::Error { code: ErrorCode::Denied, message } if message.contains("agent session")),
                "{out:?}"
            );
        }
        h.as_(terminal());
        h.d.set_sandbox_probe(|_| true);
        for (r, v) in reqs() {
            let out = send(&h, r, v);
            assert!(
                matches!(&out, ResponseBody::Error { code: ErrorCode::Denied, message } if message.contains("sandboxed")),
                "{out:?}"
            );
        }
        h.d.set_sandbox_probe(|_| false);
        h.d.dash_stop(&actor()).unwrap();
        for (r, v) in reqs() {
            let out = send(&h, r, v);
            assert!(
                matches!(&out, ResponseBody::Error { message, .. } if message.contains("stopped")),
                "{out:?}"
            );
        }
        assert_eq!(value(&h, "stripe/test").unwrap(), CANARY.as_bytes());
        assert!(h.auth.reasons().is_empty());
        // From the user's terminal, with the person's approval.
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let r = h.approved(|| {
            send(
                &h,
                RequestBody::KeyReplace {
                    key: k("stripe/test"),
                },
                true,
            )
        });
        assert!(matches!(r, ResponseBody::Ok { .. }), "{r:?}");
        assert_eq!(value(&h, "stripe/test").unwrap(), b"new");
        let r = h.approved(|| {
            send(
                &h,
                RequestBody::KeyDelete {
                    key: k("stripe/test"),
                    force: false,
                },
                false,
            )
        });
        assert!(matches!(r, ResponseBody::Ok { .. }), "{r:?}");
        assert!(value(&h, "stripe/test").is_none());
    }
}
