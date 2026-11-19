//! The dashboard's actions (L33 dash-actions, SPEC D-9 to D-23): the route table, the request
//! and answer shapes, and [`DashActions`], which msd implements, one method per action.
//!
//! Every action passes the L32 envelope (Host, Origin, JSON, 64 KiB, cookie, CSRF, 20 req/s)
//! plus the checks `http.rs` adds for actions: a bucket of 30 per minute per session, the
//! connection's process checked again at request time, and `Sec-Fetch-Site: same-origin`
//! required on value and destructive routes. Touch ID is raised by msd, never by the page.
//!
//! Exactly one method returns a value: [`DashActions::show`], as a [`Revealed`], which only
//! [`crate::http::reveal_response`] turns into bytes.

use std::net::SocketAddr;

use ms_core::{KeyName, Mode, SecretBytes, SessionId, Tier};
use serde::{Deserialize, Serialize};

use crate::api::AgentsView;

/// Who asks: the dashboard session (the browser's process, `other("dashboard")`) and the
/// connection's address pair, for the request-time process re-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// `other("dashboard")` with the browser's pid and start time.
    pub session: SessionId,
    /// The client's address.
    pub peer: SocketAddr,
    /// The listener's address.
    pub local: SocketAddr,
}

/// One action route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// `POST /api/stop`.
    Stop,
    /// `POST /api/start`.
    Start,
    /// `POST /api/approvals/{id}/approve`.
    Approve,
    /// `POST /api/approvals/{id}/deny`.
    Deny,
    /// `POST /api/warnings/{id}/dismiss`.
    Dismiss,
    /// `POST /api/agents/recheck`.
    Recheck,
    /// `POST /api/scan/run`.
    ScanRun,
    /// `POST /api/projects/check-path`.
    CheckPath,
    /// `POST /api/keys/{key}/rules`.
    Rules,
    /// `POST /api/keys/{key}/show`.
    Show,
    /// `POST /api/keys/{key}/copy`.
    Copy,
    /// `POST /api/keys/{key}/replace`.
    Replace,
    /// `POST /api/keys`.
    AddKey,
    /// `POST /api/keys/{key}/delete`.
    Delete,
    /// `POST /api/keys/{key}/undo`.
    UndoKey,
    /// `POST /api/projects/{slug}/undo`.
    UndoProject,
    /// `POST /api/agents/{agent}/connect/preview` (L35).
    ConnectPreview,
    /// `POST /api/agents/{agent}/connect` (L35): Touch ID.
    Connect,
    /// `POST /api/agents/{agent}/disconnect/preview` (L35).
    DisconnectPreview,
    /// `POST /api/agents/{agent}/disconnect` (L35): Touch ID.
    Disconnect,
    /// `POST /api/projects/preview` (L35).
    ProjectPreview,
    /// `POST /api/projects/add` (L35): Touch ID.
    ProjectAdd,
}

impl Action {
    /// What the receipt's target says after `dashboard: ` (SPEC D-22).
    pub fn target(self) -> &'static str {
        match self {
            Action::Stop => "stop",
            Action::Start => "start",
            Action::Approve => "approve",
            Action::Deny => "deny",
            Action::Dismiss => "dismiss warning",
            Action::Recheck => "re-check",
            Action::ScanRun => "scan",
            Action::CheckPath => "check folder",
            Action::Rules => "rules change",
            Action::Show => "show value",
            Action::Copy => "copy value",
            Action::Replace => "replace value",
            Action::AddKey => "add key",
            Action::Delete => "delete key",
            Action::UndoKey | Action::UndoProject => "undo",
            Action::ConnectPreview => "connect preview",
            Action::Connect => "connect",
            Action::DisconnectPreview => "disconnect preview",
            Action::Disconnect => "disconnect",
            Action::ProjectPreview => "add project preview",
            Action::ProjectAdd => "add project",
        }
    }

    /// Value, destructive and approving actions (approve, start, rules, scan too: review N3):
    /// `Sec-Fetch-Site: same-origin` must be present (browsers
    /// always send it; other clients don't).
    pub fn sensitive(self) -> bool {
        matches!(
            self,
            Action::Approve
                | Action::Dismiss
                | Action::Start
                | Action::Rules
                | Action::ScanRun
                | Action::Show
                | Action::Copy
                | Action::Replace
                | Action::AddKey
                | Action::Delete
                | Action::UndoKey
                | Action::UndoProject
                | Action::ConnectPreview
                | Action::Connect
                | Action::DisconnectPreview
                | Action::Disconnect
                | Action::ProjectPreview
                | Action::ProjectAdd
        )
    }
}

/// Every action route (POST). `{key}` is a percent-encoded key name, `{slug}` a project slug,
/// `{id}` an approval or warning id. `parity_routes_exist` checks each "Screen" subcommand's
/// action is here.
pub const ACTION_ROUTES: &[(&str, Action)] = &[
    ("/api/stop", Action::Stop),
    ("/api/start", Action::Start),
    ("/api/approvals/{id}/approve", Action::Approve),
    ("/api/approvals/{id}/deny", Action::Deny),
    ("/api/warnings/{id}/dismiss", Action::Dismiss),
    ("/api/agents/recheck", Action::Recheck),
    ("/api/scan/run", Action::ScanRun),
    ("/api/projects/check-path", Action::CheckPath),
    ("/api/keys/{key}/rules", Action::Rules),
    ("/api/keys/{key}/show", Action::Show),
    ("/api/keys/{key}/copy", Action::Copy),
    ("/api/keys/{key}/replace", Action::Replace),
    ("/api/keys", Action::AddKey),
    ("/api/keys/{key}/delete", Action::Delete),
    ("/api/keys/{key}/undo", Action::UndoKey),
    ("/api/projects/{slug}/undo", Action::UndoProject),
    (
        "/api/agents/{agent}/connect/preview",
        Action::ConnectPreview,
    ),
    ("/api/agents/{agent}/connect", Action::Connect),
    (
        "/api/agents/{agent}/disconnect/preview",
        Action::DisconnectPreview,
    ),
    ("/api/agents/{agent}/disconnect", Action::Disconnect),
    ("/api/projects/preview", Action::ProjectPreview),
    ("/api/projects/add", Action::ProjectAdd),
];

/// The route for `path` and its one parameter (raw, still percent-encoded), if any.
pub fn match_route(path: &str) -> Option<(Action, Option<String>)> {
    let segs: Vec<&str> = path.split('/').collect();
    'routes: for (pattern, action) in ACTION_ROUTES {
        let pat: Vec<&str> = pattern.split('/').collect();
        if pat.len() != segs.len() {
            continue;
        }
        let mut param = None;
        for (p, s) in pat.iter().zip(&segs) {
            if p.starts_with('{') {
                if s.is_empty() {
                    continue 'routes;
                }
                param = Some((*s).to_owned());
            } else if p != s {
                continue 'routes;
            }
        }
        return Some((*action, param));
    }
    None
}

/// A project slug as `ms init` makes them: `a-z0-9-`, 1 to 64 bytes.
pub fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An agent the dashboard can connect: `claude-code` or `codex` (L35).
pub fn valid_agent(s: &str) -> bool {
    matches!(s, "claude-code" | "codex")
}

/// A plan digest: 64 lowercase hex digits (L35).
pub fn valid_plan(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An approval or warning id: 1 to 64 of `A-Za-z0-9-`.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Machine-readable reasons an action did not happen (SPEC D-23). The page maps each to plain
/// words and the next step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCode {
    /// Touch ID did not confirm (cancelled, failed, timed out).
    TouchIdFailed,
    /// Another request holds the approval slot, or a scan runs.
    Busy,
    /// morsec is stopped.
    Stopped,
    /// A project file still refers to the key.
    Referenced,
    /// Over a limit.
    RateLimited,
    /// The value is not text.
    NotText,
    /// The request's content is not acceptable.
    Invalid,
    /// The thing acted on is gone (an answered approval, a deleted key).
    Gone,
    /// Refused: the caller, the process check, or a rule.
    Refused,
    /// Something msd needs is not reachable (the pasteboard without a GUI session).
    Unavailable,
    /// What the person was shown changed since (a plan digest no longer matches, L35).
    Changed,
    /// msd failed.
    Internal,
}

impl ActionCode {
    /// The HTTP status for it.
    pub fn status(self) -> u16 {
        match self {
            ActionCode::TouchIdFailed | ActionCode::Refused => 403,
            ActionCode::Busy
            | ActionCode::Stopped
            | ActionCode::Referenced
            | ActionCode::NotText
            | ActionCode::Changed
            | ActionCode::Gone => 409,
            ActionCode::RateLimited => 429,
            ActionCode::Invalid => 400,
            ActionCode::Unavailable => 503,
            ActionCode::Internal => 500,
        }
    }
}

/// An action that did not happen: shown through `textContent`. Never holds a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionError {
    /// Why.
    pub code: ActionCode,
    /// For people, with the next step.
    pub message: String,
}

impl ActionError {
    /// An error with `code`.
    pub fn new(code: ActionCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// An action that happened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ActionOk {
    /// What was done, for people. Never a value.
    pub message: String,
}

impl ActionOk {
    /// Done, with `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An action's answer.
pub type ActionResult = Result<ActionOk, ActionError>;

/// A value msd read for Show. It has no accessor outside this crate and no `Debug` that shows
/// it: [`crate::http::reveal_response`] is the one place it becomes bytes.
pub struct Revealed(pub(crate) SecretBytes);

impl Revealed {
    /// Wraps a value read after Touch ID.
    pub fn new(v: SecretBytes) -> Self {
        Self(v)
    }

    /// Its length in bytes (never the bytes).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Revealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Revealed([hidden])")
    }
}

/// One rule edit from the Secret screen (SPEC D-14): one per request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleEdit {
    /// `api.example.com` or `*.example.com`.
    AddHost(String),
    /// A host the rule names.
    RemoveHost(String),
    /// A command, one word per element.
    AddCommand {
        /// The words.
        words: Vec<String>,
    },
    /// A command the rule names.
    RemoveCommand {
        /// The words.
        words: Vec<String>,
    },
    /// An absolute folder a run key's commands may run in.
    AddFolder(String),
    /// A folder the rule names.
    RemoveFolder(String),
    /// `test` or `production`.
    SetTier(TierArg),
    /// One exact host HTTPS git may use the key for (adds the host too). L35.
    AddGitHost(String),
    /// A git host the rule names (the host itself stays). L35.
    RemoveGitHost(String),
    /// A variable a run key may be put in. L35.
    AddEnv(String),
    /// A variable the rule names. L35.
    RemoveEnv(String),
    /// A known_hosts line (ed25519) for SSH git. L35.
    AddSshHostKey(String),
    /// A host key the rule names. L35.
    RemoveSshHostKey(String),
}

/// A tier as the page sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierArg {
    /// Test.
    Test,
    /// Production.
    Production,
}

impl From<TierArg> for Tier {
    fn from(t: TierArg) -> Self {
        match t {
            TierArg::Test => Tier::Test,
            TierArg::Production => Tier::Production,
        }
    }
}

/// A mode as the page sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeArg {
    /// Swap.
    Swap,
    /// Run.
    Run,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Swap => Mode::Swap,
            ModeArg::Run => Mode::Run,
        }
    }
}

/// `POST /api/keys`: a new key.
pub struct NewKey {
    /// Its name.
    pub key: KeyName,
    /// Its value, from a hidden field.
    pub value: SecretBytes,
    /// Swap or run.
    pub mode: Mode,
    /// Test or production.
    pub tier: Tier,
}

impl std::fmt::Debug for NewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKey")
            .field("key", &self.key)
            .field("value", &"[hidden]")
            .finish_non_exhaustive()
    }
}

/// What Add project's folder check found (SPEC D-17). No mutation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PathCheck {
    /// The folder can be set up as a project.
    pub ok: bool,
    /// The canonical folder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Why it can't, in plain words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// It already is this project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The shell-quoted command to run in a terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// One changed line of an agent settings file, redacted (L35 SPEC D-1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanLineView {
    /// `+` or `-`.
    pub sign: String,
    /// 1-based line number.
    pub n: usize,
    /// The line, with values morsec didn't write shown as `…`.
    pub text: String,
}

/// One file a connect or disconnect touches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlanFileView {
    /// The file (`~/…`).
    pub path: String,
    /// `create`, `change`, `remove`, or for morsec's own files `write`, `keep`, `drop`.
    pub verb: String,
    /// Changed lines (settings files only).
    pub lines: Vec<PlanLineView>,
    /// Too large to show line by line.
    pub too_large: bool,
}

/// A connect or disconnect, before it happens (L35 SPEC D-1). No value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentPlanView {
    /// `claude-code` or `codex`.
    pub agent: String,
    /// `connect` or `disconnect`.
    pub action: String,
    /// The digest the apply must send back.
    pub plan: String,
    /// Already connected (or not connected): nothing would change.
    pub nothing_to_do: bool,
    /// Files, in write order.
    pub files: Vec<PlanFileView>,
    /// Things to know.
    pub notes: Vec<String>,
}

/// One env file Add project would import (L35 SPEC D-11). No value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectFileView {
    /// Relative to the project folder.
    pub path: String,
    /// Lines that would get a ref.
    pub secrets: usize,
    /// New keys.
    pub new_keys: usize,
    /// Lines that reuse another line's key (same value).
    pub reused: usize,
    /// Why it can't be imported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One key Add project would create or adopt, and what it may do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectKeyView {
    /// The key.
    pub key: String,
    /// The service it was recognised as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Hosts it may reach once set up.
    pub reaches: Vec<String>,
    /// Folders its commands may run in.
    pub runs_in: Vec<String>,
    /// `website` or `command` when it would allow nothing yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
}

/// Add project's preview: the folder check, then what setup would do. No value, no masked value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectPreviewView {
    /// The folder can be set up.
    pub ok: bool,
    /// Why not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The terminal command, as a fallback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The digest the add must send back.
    pub plan: String,
    /// Project name.
    pub slug: String,
    /// Display name.
    pub display: String,
    /// The canonical folder.
    pub root: String,
    /// It already is a project (a re-scan).
    pub existing: bool,
    /// Env files.
    pub files: Vec<ProjectFileView>,
    /// Keys and what they may do.
    pub keys: Vec<ProjectKeyView>,
    /// Keys written into code (reported, never imported).
    pub findings: usize,
    /// Why the walk stopped early.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_early: Option<String>,
    /// Files too large to read.
    pub too_large: Vec<String>,
    /// Nothing new to import.
    pub nothing_to_do: bool,
}

/// What Add project did: the `ms init` summary rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectAddView {
    /// For people.
    pub message: String,
    /// Project name.
    pub slug: String,
    /// (label, text) rows, as `ms init` prints them.
    pub rows: Vec<(String, String)>,
    /// Something did not go through (a file skipped, the rules not approved).
    pub partial: bool,
}

/// One restored or skipped line of an Undo (no value).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UndoLineView {
    /// Project slug.
    pub project: String,
    /// File, relative to the project root.
    pub file: String,
    /// 1-based line.
    pub line: u64,
    /// Variable name.
    pub var: String,
    /// Why it was skipped (skipped lines only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What an Undo did (SPEC D-21).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UndoView {
    /// For people.
    pub message: String,
    /// Lines that got their value back.
    pub restored: Vec<UndoLineView>,
    /// Lines left as they were, with the reason.
    pub skipped: Vec<UndoLineView>,
    /// Keys deleted (value and rule) because nothing refers to them any more.
    pub deleted_keys: Vec<String>,
}

/// msd's side of the actions. Every method is blocking (Touch ID, vault, receipts) and writes
/// its own receipt, done or refused (SPEC D-22).
pub trait DashActions: Send + Sync + 'static {
    /// `ms stop`: no approval.
    fn stop(&self, a: &Actor) -> ActionResult;
    /// `ms start`: Touch ID.
    fn start(&self, a: &Actor) -> ActionResult;
    /// Approve the waiting request `id` (Touch ID through `ms approve`'s path).
    fn approve(&self, a: &Actor, id: &str, session_scope: bool) -> ActionResult;
    /// Deny the waiting request `id` (no Touch ID).
    fn deny(&self, a: &Actor, id: &str) -> ActionResult;
    /// Clears an informational warning.
    fn dismiss(&self, a: &Actor, id: &str) -> ActionResult;
    /// Re-runs msd's own checks; changes nothing but settled alerts.
    fn recheck(&self, a: &Actor) -> Result<AgentsView, ActionError>;
    /// Starts a leak scan (Touch ID) in the background.
    fn scan_run(&self, a: &Actor) -> ActionResult;
    /// Add project's folder check.
    fn check_path(&self, a: &Actor, path: &str) -> Result<PathCheck, ActionError>;
    /// One rule edit: loosening needs Touch ID, tightening none.
    fn rules(&self, a: &Actor, key: &KeyName, edit: &RuleEdit) -> ActionResult;
    /// Show: Touch ID every time; the only method that returns a value.
    fn show(&self, a: &Actor, key: &KeyName) -> Result<Revealed, ActionError>;
    /// Copy: Touch ID, then msd writes the pasteboard itself.
    fn copy(&self, a: &Actor, key: &KeyName) -> ActionResult;
    /// Replace a value: Touch ID.
    fn replace(&self, a: &Actor, key: &KeyName, value: SecretBytes) -> ActionResult;
    /// A new key (no Touch ID: its rule allows nothing).
    fn add_key(&self, a: &Actor, new: NewKey) -> ActionResult;
    /// Delete a key and its rule: Touch ID.
    fn delete(&self, a: &Actor, key: &KeyName, force: bool) -> ActionResult;
    /// Undo an import: a whole project, or one key in `project` (or in every project that has
    /// it when `project` is `None`). Touch ID.
    fn undo(
        &self,
        a: &Actor,
        project: Option<&str>,
        key: Option<&KeyName>,
    ) -> Result<UndoView, ActionError>;
    /// Connect or disconnect `agent`, before it happens (L35): the redacted changes and the plan
    /// digest. No mutation, no Touch ID.
    fn agent_preview(
        &self,
        _a: &Actor,
        _agent: &str,
        _disconnect: bool,
    ) -> Result<AgentPlanView, ActionError> {
        Err(ActionError::new(
            ActionCode::Unavailable,
            "morsec: not available",
        ))
    }
    /// Connect or disconnect `agent` as previewed with digest `plan`: Touch ID.
    fn agent_apply(
        &self,
        _a: &Actor,
        _agent: &str,
        _disconnect: bool,
        _plan: &str,
    ) -> ActionResult {
        Err(ActionError::new(
            ActionCode::Unavailable,
            "morsec: not available",
        ))
    }
    /// Add project's preview (L35): the folder check, then what setup would do. Reads only.
    fn project_preview(&self, _a: &Actor, _path: &str) -> Result<ProjectPreviewView, ActionError> {
        Err(ActionError::new(
            ActionCode::Unavailable,
            "morsec: not available",
        ))
    }
    /// Sets the folder up as previewed with digest `plan`: Touch ID.
    fn project_add(
        &self,
        _a: &Actor,
        _path: &str,
        _plan: &str,
    ) -> Result<ProjectAddView, ActionError> {
        Err(ActionError::new(
            ActionCode::Unavailable,
            "morsec: not available",
        ))
    }
    /// A `blocked` receipt for an action the envelope refused before msd saw it (rate limit,
    /// missing `Sec-Fetch-Site`, bad input). Called at most 30 times a minute per session.
    fn refused(&self, a: &Actor, action: Action, key: Option<&KeyName>, why: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D-23: each route pattern matches its own paths only, with its one parameter;
    // fails_when=a path matches the wrong action or an empty parameter is accepted;
    // no_claim=parameter validation (http.rs)
    #[test]
    fn routes_match() {
        assert_eq!(match_route("/api/stop"), Some((Action::Stop, None)));
        assert_eq!(
            match_route("/api/keys/shop%2Fx/show"),
            Some((Action::Show, Some("shop%2Fx".into())))
        );
        assert_eq!(match_route("/api/keys"), Some((Action::AddKey, None)));
        assert_eq!(
            match_route("/api/projects/check-path"),
            Some((Action::CheckPath, None))
        );
        assert_eq!(
            match_route("/api/projects/shop/undo"),
            Some((Action::UndoProject, Some("shop".into())))
        );
        for bad in [
            "/api/keys//show",
            "/api/keys/x/show/more",
            "/api/stop/",
            "/api/home",
        ] {
            assert_eq!(match_route(bad), None, "{bad}");
        }
        assert!(valid_slug("shop-2") && !valid_slug("Shop") && !valid_slug(""));
        assert!(valid_id("apr-0af") && !valid_id("a b") && !valid_id(&"a".repeat(65)));
    }
}
