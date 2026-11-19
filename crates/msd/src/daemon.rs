//! The daemon's shared state and its IPC request handling.
//!
//! One [`Daemon`] owns the vault backend, the receipts store, the live rules (with the kill-switch
//! flag) and the set of sessions a LOG-2 alert stopped. The socket handler and the swap proxy
//! both read it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use ms_approve::{ApprovalOutcome, ApprovalToken, Approver, Binding, HumanApprover, Scope};
use ms_core::{
    AgentKind, ApprovalRequest, KeyMeta, KeyName, Mode, ReceiptEvent, ReceiptResult, SecretBytes,
    SessionId, Tier,
};
use ms_ipc::{ApprovalScope, ErrorCode, PeerInfo, PendingApproval, RequestBody, ResponseBody};
use ms_receipts::{Alert, AlertAction, AlertHandler, ReceiptDetail, ReceiptStore, StoreConfig};
use ms_rules::{Change, KeyRule, Rules, RulesError, RulesStore, is_reserved};
use ms_session::Caller;
use ms_vault::{Listing, Vault, VaultExt};
use tokio::sync::watch;

pub mod dash_actions;
mod dash_connect;
mod dash_data;
pub mod dev;
mod mcp;
mod projects;
mod run;
mod ssh_git;
pub(crate) mod undo;

pub use dash_actions::{AlertKind, Clipboard};
pub use dash_data::{ConnChecker, DashSource};
pub use projects::{PROJECTS_FILE, reset_project_records};

use crate::backend::{Backend, DAEMON_STATE_KEY, RULES_HMAC_KEY};
use crate::paths::Paths;

/// The reserved key daemon events (stop, start, init) are recorded under.
pub const DAEMON_KEY: &str = "morsec/daemon";
/// Approval method recorded for a person's approval (L11): `ms approve` plus Touch ID.
pub const TOUCH_ID_METHOD: &str = "touch-id";
/// How long a request waits for a person (L11 SPEC D-4).
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Most alerts kept for `ms status`.
const MAX_ALERTS: usize = 20;

/// The daemon state item: `running v=<n>` or `stopped v=<n>`, where `n` is the highest rules
/// version msd has saved or loaded (the rules rollback floor). Kept in the vault so an agent can
/// neither delete it nor put an older copy back (SPEC D-C; security review S3). The bare forms
/// `running` / `stopped` read as floor 0.
pub fn encode_state(stopped: bool, floor: u64) -> Vec<u8> {
    format!("{} v={floor}", if stopped { "stopped" } else { "running" }).into_bytes()
}

/// Parses [`encode_state`]'s format. `None` for anything else.
pub fn parse_state(v: &[u8]) -> Option<(bool, u64)> {
    let s = std::str::from_utf8(v).ok()?;
    let (word, floor) = match s.split_once(" v=") {
        Some((w, n)) => (w, n.parse().ok()?),
        None => (s, 0),
    };
    match word {
        "running" => Some((false, floor)),
        "stopped" => Some((true, floor)),
        _ => None,
    }
}

/// The rules in force and the rollback floor.
#[derive(Debug)]
struct Live {
    /// The user rules (verified), with the runtime `stopped` / `tampered` flags.
    rules: Rules,
    /// Lowest rules version a load may accept (rollback guard): the highest version seen.
    min_version: u64,
}

/// Stops sessions a LOG-2 alert names.
struct StopSessions(Arc<Mutex<HashSet<SessionId>>>);

impl AlertHandler for StopSessions {
    fn on_alert(&self, alert: &Alert) {
        if alert.action == AlertAction::StopSession {
            tracing::warn!(
                pid = alert.session.pid,
                blocked = alert.blocked_count,
                "LOG-2 alert: stopping the session"
            );
            lock(&self.0).insert(alert.session.clone());
        }
    }
}

/// Who is calling: the kernel peer → [`Caller`] (L06 in production; fixed in tests).
pub type Identify = Arc<dyn Fn(&PeerInfo) -> Option<Caller> + Send + Sync>;

/// L06 identification for a daemon running as `uid`.
pub fn identify_by_session(uid: u32) -> Identify {
    let check = ms_session::SessionPeerCheck::new(uid);
    // Compared with the accept time, not now: a process that started after the connection was
    // accepted is not the peer (PID reuse).
    Arc::new(
        move |peer: &PeerInfo| match check.caller(peer, peer.accepted_unix_ms) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(error = %e, "could not identify the caller");
                None
            }
        },
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Everything msd shares between the socket and the proxy.
pub struct Daemon {
    backend: Backend,
    vault: Arc<dyn Vault>,
    paths: Paths,
    mac_key: KeyName,
    receipts: Arc<ReceiptStore>,
    live: RwLock<Live>,
    stopped_sessions: Arc<Mutex<HashSet<SessionId>>>,
    alerts: Mutex<Vec<dash_actions::AlertEntry>>,
    identify: Identify,
    approvals: Arc<HumanApprover>,
    /// How long a request waits for a person, in ms ([`APPROVAL_TIMEOUT`]; shorter in tests).
    approval_timeout_ms: std::sync::atomic::AtomicU64,
    proxy_gen: watch::Sender<u64>,
    proxy_port: u16,
    /// Serializes rules changes (load, classify, save).
    write: Mutex<()>,
    /// Serializes `ms stop` / `ms start` (memory flag and vault flag change together).
    flag: Mutex<()>,
    /// Serializes `ProjectSave` (load, check, approve, save) (L31).
    projects_write: Mutex<()>,
    /// Counts `ms stop`s, so a resume approved before a newer stop can't undo it.
    stops: std::sync::atomic::AtomicU64,
    /// The proxy CA in use (certificate PEM, hosts), when a host is bound.
    ca: Mutex<Option<(String, Vec<String>)>>,
    /// This daemon, for work that outlives a request (L16: a run's SSH agent records receipts
    /// and checks `ms stop` while the run lasts).
    me: std::sync::Weak<Daemon>,
    /// What `ms doctor --probe` runs reported, and the canaries the proxy saw (L17).
    probes: Arc<crate::doctor::Probes>,
    /// The local dashboard (L32) and the browser opener, set once at start; tests may run
    /// without one.
    dash: std::sync::OnceLock<(ms_dash::Dash, crate::open::Opener)>,
    /// The last transcript scan's report and when it finished, for the dashboard's Scan screen
    /// (L32 SPEC D-6). Locations and key names only, never a value.
    last_scan: Mutex<Option<(u64, ResponseBody)>>,
    /// The receipts the dashboard last read, keyed by the store's next sequence number; the lock
    /// also lets one dashboard request read the files at a time (reviews R8, S6).
    dash_receipts: Mutex<Option<(u64, Arc<Vec<ms_receipts::StoredRecord>>)>>,
    /// When `DashOpen` last opened a browser tab (fix round 2, F2).
    dash_last_open: Mutex<Option<std::time::Instant>>,
    /// Running `ms dev` sessions (L34), memory only.
    dev: dev::DevSessions,
    /// Is this PID sandboxed (L34 review D-A)? `ms_session::is_sandboxed`, failing closed.
    sandbox_probe: Mutex<fn(u32) -> bool>,
    /// The dashboard's actions' own state (L33): the scan it started, the Show/Copy window,
    /// the pasteboard writer.
    dash_acts: dash_actions::ActState,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("backend", &self.backend.label())
            .field("state", &self.paths.state)
            .field("proxy_port", &self.proxy_port)
            .finish_non_exhaustive()
    }
}

/// Why msd could not start.
#[derive(Debug)]
pub enum OpenError {
    /// `ms init` has not run (keychain backend).
    NotInitialized(String),
    /// Anything else.
    Other(ms_core::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NotInitialized(m) => f.write_str(m),
            OpenError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<ms_core::Error> for OpenError {
    fn from(e: ms_core::Error) -> Self {
        OpenError::Other(e)
    }
}

/// The highest `rule_version` recorded in the receipt chain (the rules rollback floor).
pub fn max_rule_version(dir: &std::path::Path) -> ms_core::Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let records = ms_receipts::read_all(dir)?;
    Ok(records
        .iter()
        .filter_map(|r| match &r.rec.entry {
            ms_receipts::Entry::Receipt(rc) => Some(rc.rule_version),
            _ => None,
        })
        .max()
        .unwrap_or(0))
}

fn store_config() -> StoreConfig {
    StoreConfig {
        stop_session_on_alert: true,
        ..StoreConfig::default()
    }
}

fn now_ms() -> u64 {
    ms_session::peer::now_unix_ms()
}

fn reply_err(code: ErrorCode, msg: impl Into<String>) -> ResponseBody {
    ResponseBody::error(code, msg)
}

fn daemon_key() -> KeyName {
    KeyName::new(DAEMON_KEY).unwrap_or_else(|_| unreachable!("constant key name is valid"))
}

impl Daemon {
    /// Opens the services in `paths` and loads the live state.
    pub fn open(
        backend: Backend,
        paths: Paths,
        proxy_port: u16,
        approvals: Arc<HumanApprover>,
        identify: Identify,
    ) -> Result<Arc<Self>, OpenError> {
        backend.ensure_ready().map_err(|e| {
            if backend.is_memory() {
                OpenError::Other(e)
            } else {
                OpenError::NotInitialized(format!(
                    "morsec: the vault is not set up ({e}). Run: ms init"
                ))
            }
        })?;
        let vault = backend.vault();
        let mac_key = KeyName::new(RULES_HMAC_KEY)?;
        let mut alerts: Vec<String> = Vec::new();

        let state_key = KeyName::new(DAEMON_STATE_KEY)?;
        let (stopped, vault_floor) = match vault.read_with(&state_key, <[u8]>::to_vec) {
            Ok(v) => match parse_state(&v) {
                Some((stopped, floor)) => (stopped, Some(floor)),
                None => {
                    alerts.push("the stop flag in the vault is unreadable, so morsec stays stopped and every key is denied. Resume with: ms init --resume, then restart msd".into());
                    (true, None)
                }
            },
            Err(ms_core::Error::NoSuchKey(_)) if backend.is_memory() => {
                backend.put_internal(&state_key, SecretBytes::new(encode_state(false, 0)))?;
                (false, Some(0))
            }
            Err(e) => {
                alerts.push(format!(
                    "the stop flag could not be read from the vault ({e}), so morsec stays stopped and every key is denied. Resume with: ms init --resume, then restart msd"
                ));
                (true, None)
            }
        };

        // The rollback floor: the higher of the vault's and the receipt chain's, read before the
        // store is opened for appending. With the vault's floor unknown the rules are treated as
        // tampered (fail closed) but the floor kept is the receipts' one, never a sentinel: it is
        // what the next persist writes back (code review R7).
        let floor = match max_rule_version(&paths.receipts) {
            Ok(v) => Some(v.max(vault_floor.unwrap_or(0))),
            Err(e) => {
                alerts.push(format!(
                    "the receipts could not be read ({e}); every key is denied until this is fixed"
                ));
                None
            }
        };
        let stopped_sessions = Arc::new(Mutex::new(HashSet::new()));
        let receipts = ReceiptStore::open(&paths.receipts, vault.clone(), store_config())?
            .with_alert_handler(Box::new(StopSessions(stopped_sessions.clone())));

        let store = RulesStore::new(&paths.rules, &*vault, mac_key.clone());
        let (mut rules, min_version) = match floor {
            None => (Rules::tampered(), 0),
            Some(floor) if vault_floor.is_none() => (Rules::tampered(), floor),
            Some(floor) => match store.load(floor) {
                Ok(r) => {
                    let v = r.version.max(floor);
                    (r, v)
                }
                Err(RulesError::NotInitialized { .. }) if backend.is_memory() && floor == 0 => {
                    let r = store
                        .create(&Rules::default())
                        .map_err(|e| ms_core::Error::Socket(e.to_string()))?;
                    let v = r.version;
                    (r, v)
                }
                Err(RulesError::NotInitialized { path }) => {
                    return Err(OpenError::NotInitialized(format!(
                        "morsec: no rules file at {path}, so morsec is not set up. Run: ms init"
                    )));
                }
                Err(e) => {
                    tracing::error!(error = %e, "rules failed to load; denying everything");
                    alerts.push(format!(
                        "the rules failed their integrity check, so every key is denied: {e}"
                    ));
                    (Rules::tampered(), floor)
                }
            },
        };

        rules.stopped = stopped;

        let (proxy_gen, _) = watch::channel(0);
        Ok(Arc::new_cyclic(|me| Self {
            me: me.clone(),
            backend,
            vault,
            paths,
            mac_key,
            receipts: Arc::new(receipts),
            live: RwLock::new(Live { rules, min_version }),
            stopped_sessions,
            alerts: Mutex::new(
                alerts
                    .into_iter()
                    .map(|t| dash_actions::AlertEntry::new(AlertKind::Other, t))
                    .collect(),
            ),
            identify,
            approvals,
            approval_timeout_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(APPROVAL_TIMEOUT.as_millis()).unwrap_or(120_000),
            ),
            proxy_gen,
            proxy_port,
            write: Mutex::new(()),
            flag: Mutex::new(()),
            projects_write: Mutex::new(()),
            ca: Mutex::new(None),
            probes: Arc::default(),
            dash: std::sync::OnceLock::new(),
            last_scan: Mutex::new(None),
            dash_receipts: Mutex::new(None),
            dash_last_open: Mutex::new(None),
            dev: dev::DevSessions::default(),
            sandbox_probe: Mutex::new(|pid| ms_session::is_sandboxed(pid).unwrap_or(true)),
            stops: std::sync::atomic::AtomicU64::new(0),
            dash_acts: dash_actions::ActState::default(),
        }))
    }

    /// The vault backend.
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// The vault.
    pub fn vault(&self) -> Arc<dyn Vault> {
        self.vault.clone()
    }

    /// The files.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The receipts store.
    pub fn receipts(&self) -> Arc<ReceiptStore> {
        self.receipts.clone()
    }

    /// The approver for the swap proxy: asks a person, then checks the token against the exact
    /// request before the proxy acts on it (L11 SPEC D-6).
    pub fn approver(&self) -> Arc<dyn Approver> {
        Arc::new(DevAwareApprover {
            daemon: self.me.clone(),
            inner: VerifyingApprover(self.approvals.clone()),
        })
    }

    /// Changes how long a request waits for a person (tests; production uses [`APPROVAL_TIMEOUT`]).
    #[cfg(test)]
    pub fn set_approval_timeout(&self, t: Duration) {
        self.approval_timeout_ms.store(
            u64::try_from(t.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    fn approval_timeout(&self) -> Duration {
        Duration::from_millis(
            self.approval_timeout_ms
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// Asks a person to approve exactly `req` (`ms approve` + Touch ID), then checks the token
    /// against `req` itself before returning it (L11 SPEC D-6). This is the call an executor
    /// makes right before acting (L15/L16 run mode, admin changes, `ms scan`); the error is the
    /// reply to send.
    // The error is the reply itself; it is built once per refused request, so its size is moot.
    #[allow(clippy::result_large_err)]
    pub fn approve_exact(&self, req: &ApprovalRequest) -> Result<ApprovalToken, ResponseBody> {
        self.approve_with(req, false)
    }

    /// [`Daemon::approve_exact`] for a request msd built for one of its own actions: tagged
    /// admin at creation (once only, shown as morsec's own; L33 SR1).
    #[allow(clippy::result_large_err)]
    pub fn approve_admin(&self, req: &ApprovalRequest) -> Result<ApprovalToken, ResponseBody> {
        self.approve_with(req, true)
    }

    #[allow(clippy::result_large_err)]
    fn approve_with(
        &self,
        req: &ApprovalRequest,
        admin: bool,
    ) -> Result<ApprovalToken, ResponseBody> {
        let what = render_what(req);
        let outcome = if admin {
            self.approvals.ask_admin(req, self.approval_timeout())
        } else {
            self.approvals.ask(req, self.approval_timeout())
        };
        match outcome {
            ApprovalOutcome::Approved(t) => match self.approvals.verify(&t, &Binding::of(req)) {
                Ok(_) => Ok(t),
                Err(e) => Err(reply_err(
                    ErrorCode::Denied,
                    format!("morsec: {what} was refused at execution: {e}"),
                )),
            },
            ApprovalOutcome::Denied if self.approvals.busy() => Err(reply_err(
                ErrorCode::Busy,
                format!(
                    "morsec: {what} needs an approval, and another approval is already waiting (one at a time). Answer it with ms approve, then retry"
                ),
            )),
            ApprovalOutcome::Denied => Err(reply_err(
                ErrorCode::NeedsApproval,
                format!(
                    "morsec: {what} was not approved (denied by the person in ms approve or the dashboard, Touch ID did not confirm, ms stop ran, or this session asked again within {}s of a refusal)",
                    ms_approve::broker::COOLDOWN.as_secs()
                ),
            )),
            ApprovalOutcome::TimedOut => Err(reply_err(
                ErrorCode::NeedsApproval,
                format!(
                    "morsec: nobody approved {what} within {}s, so it was refused. While it waits, run ms approve in your own terminal (not inside an agent)",
                    self.approval_timeout().as_secs()
                ),
            )),
        }
    }

    /// `ApprovalPending`: the request waiting for a person.
    fn pending_approval(&self) -> ResponseBody {
        ResponseBody::Approval {
            pending: self.approvals.pending().map(|p| PendingApproval {
                id: p.id,
                request: p.request,
                requested_unix_ms: p.requested_unix_ms,
                expires_unix_ms: p.expires_unix_ms,
                admin: p.admin,
            }),
        }
    }

    /// `ApprovalDecide` from a caller outside every agent tree (checked by `handle`).
    fn decide_approval(
        &self,
        id: &str,
        approve: bool,
        scope: Option<ApprovalScope>,
    ) -> ResponseBody {
        let scope = match scope {
            Some(ApprovalScope::Session) => Scope::Session,
            Some(ApprovalScope::Once) | None => Scope::Once,
        };
        match self.approvals.decide(id, approve, scope) {
            Ok(ApprovalOutcome::Approved(_)) => ResponseBody::Ok {
                message: match scope {
                    Scope::Once => "approved with Touch ID: this exact command, once".into(),
                    Scope::Session => {
                        "approved with Touch ID: this exact command, for this agent session".into()
                    }
                },
            },
            Ok(_) => ResponseBody::Ok {
                message: "denied".into(),
            },
            Err(e) => reply_err(ErrorCode::Denied, format!("morsec: {e}")),
        }
    }

    /// The proxy port.
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    /// Wakes the proxy supervisor so it rebuilds from the current rules.
    pub fn proxy_changes(&self) -> watch::Receiver<u64> {
        self.proxy_gen.subscribe()
    }

    fn rebuild_proxy(&self) {
        self.proxy_gen.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Records the CA the proxy now uses (`None` for the throwaway placeholder CA).
    pub fn set_ca(&self, ca: Option<(String, Vec<String>)>) {
        *lock(&self.ca) = ca;
    }

    /// Drops alerts starting with `prefix` (a condition that cleared).
    pub fn clear_alert(&self, prefix: &str) {
        lock(&self.alerts).retain(|a| !a.text.starts_with(prefix));
    }

    /// Adds an alert of `kind` for `ms status` (deduplicated by text, bounded). `ms status`
    /// prints the text as before; the dashboard shows it in plain words with its fix (L33 SPEC
    /// D-10).
    pub fn alert(&self, kind: AlertKind, msg: impl Into<String>) {
        let msg = msg.into();
        // A condition the person dismissed doesn't come back by itself (QA P8).
        if self.dismissed(&kind, &msg) {
            return;
        }
        let mut a = lock(&self.alerts);
        if !a.iter().any(|e| e.text == msg) {
            // A newer alert of the same condition replaces the older one (QA P9).
            a.retain(|e| !e.kind.same_as(&kind));
            if a.len() >= MAX_ALERTS {
                a.remove(0);
            }
            a.push(dash_actions::AlertEntry::new(kind, msg));
        }
    }

    /// The alerts' texts, as `ms status` prints them.
    fn alert_texts(&self) -> Vec<String> {
        self.prune_alerts();
        lock(&self.alerts).iter().map(|a| a.text.clone()).collect()
    }

    fn read_live(&self) -> std::sync::RwLockReadGuard<'_, Live> {
        self.live.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_live(&self) -> std::sync::RwLockWriteGuard<'_, Live> {
        self.live.write().unwrap_or_else(|e| e.into_inner())
    }

    /// A copy of the rules in force (with the runtime flags).
    pub fn rules(&self) -> Rules {
        self.read_live().rules.clone()
    }

    /// `ms stop` is in effect.
    pub fn is_stopped(&self) -> bool {
        self.read_live().rules.stopped
    }

    /// A LOG-2 alert stopped this session.
    pub fn session_stopped(&self, s: &SessionId) -> bool {
        lock(&self.stopped_sessions).contains(s)
    }

    /// Policy for one swap: `(decision, rules version)`.
    pub fn decide(&self, s: &SessionId, req: &ms_core::Request) -> (ms_core::Decision, u64) {
        let live = self.read_live();
        if self.session_stopped(s) {
            return (
                ms_core::Decision::Deny {
                    reason: ms_core::Reason::Stopped,
                },
                live.rules.version,
            );
        }
        let key = match req {
            ms_core::Request::Swap { key, .. }
            | ms_core::Request::Run { key, .. }
            | ms_core::Request::Mint { key, .. } => key,
        };
        if let Some(reason) = self.dev_refusal(s, key) {
            return (ms_core::Decision::Deny { reason }, live.rules.version);
        }
        (ms_rules::decide(&live.rules, s, req), live.rules.version)
    }

    /// The rules version in force.
    pub fn rules_version(&self) -> u64 {
        self.read_live().rules.version
    }

    /// The doctor probe store (L17); the proxy's egress observer records canaries in it.
    pub fn probes(&self) -> Arc<crate::doctor::Probes> {
        self.probes.clone()
    }

    fn caller(&self, peer: &PeerInfo) -> Option<Caller> {
        (self.identify)(peer)
    }

    // Private helper; each argument is one receipt field.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        session: &SessionId,
        key: &KeyName,
        mode: Mode,
        target: &str,
        rule_version: u64,
        result: ReceiptResult,
        method: Option<&str>,
    ) -> ms_core::Result<()> {
        self.receipts
            .append_detailed(
                ReceiptEvent {
                    time_unix_ms: now_ms(),
                    session: session.clone(),
                    key: key.clone(),
                    mode,
                    target: target.to_owned(),
                    argv_hash: None,
                    rule_version,
                    approval_id: None,
                    result,
                },
                ReceiptDetail {
                    approval_method: method.map(str::to_owned),
                    ..ReceiptDetail::default()
                },
            )
            .map(drop)
    }

    /// Records an approved action with its token id (L11).
    // Private helper; each argument is one receipt field.
    #[allow(clippy::too_many_arguments)]
    fn record_approved(
        &self,
        session: &SessionId,
        key: &KeyName,
        mode: Mode,
        target: &str,
        rule_version: u64,
        token: &ApprovalToken,
    ) -> ms_core::Result<()> {
        self.receipts
            .append_detailed(
                ReceiptEvent {
                    time_unix_ms: now_ms(),
                    session: session.clone(),
                    key: key.clone(),
                    mode,
                    target: target.to_owned(),
                    argv_hash: None,
                    rule_version,
                    approval_id: Some(token.id.clone()),
                    result: ReceiptResult::Approved,
                },
                ReceiptDetail {
                    approval_method: Some(TOUCH_ID_METHOD.to_owned()),
                    ..ReceiptDetail::default()
                },
            )
            .map(drop)
    }

    /// Handles one IPC request. Blocking (vault, receipts, approvals): run it off the reactor.
    pub fn handle(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        let caller = self.caller(peer);
        // A peer that can't be identified (it exited and left the connection to a child, or its
        // PID was reused) is refused everything but status and stop: treating it as "not an
        // agent" would fail open.
        if caller.is_none() && !request.is_control() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: the process that opened this connection can't be identified any more, so the request is refused. Reconnect from a running process",
            );
        }
        let session = session_of(caller.as_ref(), peer);
        if self.session_stopped(&session) && !request.is_control() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: this agent session was stopped after repeated blocked attempts (LOG-2). Start a new session",
            );
        }
        let in_agent = matches!(caller, Some(Caller::Agent(_)));
        match request {
            RequestBody::Status => self.status(),
            RequestBody::PutKey { name, meta } => match value {
                Some(v) => self.put_key(&session, in_agent, name, meta, v),
                None => reply_err(ErrorCode::Protocol, "morsec: PutKey came without a value"),
            },
            RequestBody::ListKeys => match self.list_keys() {
                Ok(keys) => ResponseBody::Keys { keys },
                Err(e) => reply_err(ErrorCode::Internal, e.to_string()),
            },
            RequestBody::RulesGet { key } => self.rules_get(key.as_ref()),
            // `at_terminal` (the pre-L11 path) is ignored: every loosening and resume needs a
            // person's approval with Touch ID (L11 SPEC D-9).
            RequestBody::RulesProposeLoosen { key, rule, .. } => {
                self.propose(&session, &key, rule.as_deref())
            }
            RequestBody::Stop => self.stop(&session),
            RequestBody::Start { .. } => self.start(&session),
            // Only a person outside every agent tree reviews and decides approvals (SPEC D-2).
            RequestBody::ApprovalPending | RequestBody::ApprovalDecide { .. } if in_agent => {
                reply_err(
                    ErrorCode::Denied,
                    "morsec: approvals can't be seen or given from inside an agent session. Run ms approve in your own terminal",
                )
            }
            RequestBody::ApprovalPending => self.pending_approval(),
            RequestBody::ApprovalDecide { id, approve, scope } => {
                self.decide_approval(&id, approve, scope)
            }
            // A scan answers "is this value in a file I can write?": an oracle for short values,
            // so only the user's own terminal may ask (L09 SPEC D-3).
            RequestBody::Scan if in_agent => reply_err(
                ErrorCode::Denied,
                "morsec: ms scan can't run inside an agent session. Run it from your own terminal",
            ),
            RequestBody::Scan => self.scan(&session),
            // Saving a project loosens its new keys' rules (after one approval) and writes its
            // record: only from the user's own terminal (L31 SPEC D-2). Listing is read-only.
            RequestBody::ProjectSave { .. } if in_agent => reply_err(
                ErrorCode::Denied,
                "morsec: projects can't be set up from inside an agent session. Run ms init in your own terminal",
            ),
            // L34 review F3: an agent command that double-forked out of its tree is still in the
            // agent's sandbox.
            RequestBody::ProjectSave { .. } if self.caller_sandboxed(caller.as_ref()) => reply_err(
                ErrorCode::Denied,
                "morsec: projects can't be set up from a sandboxed process (an agent's command sandbox). Run ms init in your own terminal",
            ),
            RequestBody::ProjectSave { record, rules } => {
                self.project_save(&session, &record, &rules)
            }
            RequestBody::ProjectList => self.project_list(),
            // Values follow a DevStart reply, so it is served only by `handle_values` (L34).
            RequestBody::DevStart { .. } => reply_err(
                ErrorCode::Protocol,
                "morsec: DevStart must be sent with Client::request_with_values",
            ),
            RequestBody::DevEnd { .. } if in_agent => reply_err(
                ErrorCode::Denied,
                "morsec: ms dev sessions can't be changed from inside an agent session",
            ),
            RequestBody::DevEnd { session } => self.dev_end(caller.as_ref(), &session),
            RequestBody::ProjectGet { slug } => self.project_get(&slug),
            // The launch token signs a browser in: only the user's own terminal may mint one
            // (L32, design §6.2.2). The page is read-only, so a stopped msd still serves it.
            RequestBody::DashOpen { .. } if in_agent => reply_err(
                ErrorCode::Denied,
                "morsec: the dashboard can't be opened from inside an agent session. Ask the user to run ms dashboard in their own terminal",
            ),
            RequestBody::DashOpen { view } => self.dash_open(view.as_deref()),
            // Replacing, deleting and undoing change what morsec holds or write values into
            // files: only from the user's own terminal (L33 SPEC D-24).
            RequestBody::KeyReplace { .. }
            | RequestBody::KeyDelete { .. }
            | RequestBody::ProjectUndo { .. }
                if in_agent =>
            {
                reply_err(
                    ErrorCode::Denied,
                    "morsec: keys can't be replaced, deleted or undone from inside an agent session. Ask the user to run it in their own terminal",
                )
            }
            RequestBody::KeyReplace { .. }
            | RequestBody::KeyDelete { .. }
            | RequestBody::ProjectUndo { .. }
                if self.caller_sandboxed(caller.as_ref()) =>
            {
                reply_err(
                    ErrorCode::Denied,
                    "morsec: keys can't be replaced, deleted or undone from a sandboxed process (an agent's command sandbox). Run it in your own terminal",
                )
            }
            RequestBody::KeyReplace { key } => match value {
                Some(v) => self.key_replace(&session, &key, v),
                None => reply_err(
                    ErrorCode::Protocol,
                    "morsec: KeyReplace came without a value",
                ),
            },
            RequestBody::KeyDelete { key, force } => self.key_delete(&session, &key, force),
            RequestBody::ProjectUndo { slug, keys } => {
                self.project_undo(&session, &slug, keys.as_deref())
            }
            RequestBody::DoctorProbe { nonce, report } => self.probes.handle(
                match &caller {
                    Some(Caller::Agent(s)) => Some(s.clone()),
                    _ => None,
                },
                nonce.as_deref(),
                report,
                now_ms(),
            ),
            RequestBody::Run { argv, cwd, env } => {
                run::run_buffered(self, peer, argv, cwd, env, None)
            }
            RequestBody::McpCall {
                tool,
                rules_version,
                cwd,
                arguments,
            } => mcp::call(self, peer, &session, &tool, rules_version, cwd, &arguments),
            RequestBody::RunStream { .. }
            | RequestBody::RunInput { .. }
            | RequestBody::RunInputEnd => reply_err(
                ErrorCode::Protocol,
                "morsec: run input is only valid inside a run stream",
            ),
            other => reply_err(
                ErrorCode::NotImplemented,
                format!(
                    "morsec: this request is not built yet (planned in loop {})",
                    other.owner_loop()
                ),
            ),
        }
    }

    /// Handles a request whose reply may be followed by raw value frames (L34 `DevStart`).
    /// Blocking (vault, approvals): run it off the reactor. Anything else goes to `handle`.
    pub fn handle_values(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> (ResponseBody, Vec<SecretBytes>) {
        let RequestBody::DevStart { argv, cwd } = request else {
            return (self.handle(peer, request, value), Vec::new());
        };
        let caller = self.caller(peer);
        let session = session_of(caller.as_ref(), peer);
        if self.session_stopped(&session) {
            return (
                reply_err(
                    ErrorCode::Denied,
                    "morsec: this session was stopped after repeated blocked attempts (LOG-2)",
                ),
                Vec::new(),
            );
        }
        self.dev_start(caller.as_ref(), &argv, &cwd)
    }

    /// `ms scan` from outside an agent session (L09). Refused while stopped: the kill switch
    /// means no value is read. Every scan leaves one receipt per key it read, so its use as a
    /// guessing oracle by a detached process is at least on the record (L09 security review S1);
    /// a reply whose receipts could not be written is withheld.
    fn scan(&self, session: &SessionId) -> ResponseBody {
        if self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop), so ms scan does not read the vault. Resume first",
            );
        }
        // A scan reads every value: a person approves it first (L11, closes L09's INJ-5
        // residual: a detached process could otherwise use it as a guessing oracle).
        let req = admin_request(session, daemon_key(), Tier::Production, &["ms", "scan"]);
        if let Err(resp) = self.approve_admin(&req) {
            let _ = self.record(
                session,
                &daemon_key(),
                Mode::Run,
                "ms scan",
                self.rules_version(),
                ReceiptResult::Denied,
                None,
            );
            return resp;
        }
        self.scan_approved(session)
    }

    /// The scan itself, once a person approved it (`ms scan`, or the dashboard's Run scan).
    fn scan_approved(&self, session: &SessionId) -> ResponseBody {
        if self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec was stopped (ms stop) while the scan waited for approval",
            );
        }
        let Listing { keys, unusable } = match self.scan_keys() {
            Ok(l) => l,
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        // A stop during the scan withholds the report even if morsec was resumed since (review F2).
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let mut report = crate::scan::scan(
            &*self.vault,
            keys.iter().map(|m| m.name.clone()).collect(),
            &self.scan_roots(),
            crate::scan::SCAN_BUDGET,
        );
        note_unusable(&mut report, &unusable);
        if let ResponseBody::ScanReport { findings, .. } = &report {
            let rv = self.rules_version();
            // Every listed key, including ones too short to search or unreadable: over-recording
            // is the safe direction for an audit trail.
            for m in &keys {
                let n = findings.iter().filter(|f| f.key == m.name).count();
                let target = format!(
                    "ms scan: agent transcripts, {n} finding{}",
                    if n == 1 { "" } else { "s" }
                );
                if let Err(e) = self.record(
                    session,
                    &m.name,
                    m.mode,
                    &target,
                    rv,
                    ReceiptResult::Allowed,
                    None,
                ) {
                    return reply_err(
                        ErrorCode::Internal,
                        format!(
                            "morsec: the scan's receipt could not be written ({e}), so its result is withheld"
                        ),
                    );
                }
            }
        }
        // `ms stop` during the scan: the report is not delivered (security re-check N-B). The
        // receipts above still record that the values were read.
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec was stopped (ms stop) during the scan, so its result is withheld",
            );
        }
        if matches!(report, ResponseBody::ScanReport { .. }) {
            *lock(&self.last_scan) = Some((now_ms(), report.clone()));
        }
        report
    }

    fn list_keys(&self) -> ms_core::Result<Vec<KeyMeta>> {
        Ok(self.scan_keys()?.keys)
    }

    /// The vault's keys (morsec's own excluded), and the keys another morsec build stored.
    fn scan_keys(&self) -> ms_core::Result<Listing> {
        let mut l = self.vault.scan()?;
        l.keys.retain(|m| !is_reserved(&m.name));
        l.unusable.retain(|n| !is_reserved(n));
        Ok(l)
    }

    fn status(&self) -> ResponseBody {
        let (keys, unusable) = match self.scan_keys() {
            Ok(l) => (
                Some(u32::try_from(l.keys.len()).unwrap_or(u32::MAX)),
                l.unusable,
            ),
            Err(e) => {
                self.alert(
                    AlertKind::VaultUnlisted,
                    format!("the vault could not be listed: {e}"),
                );
                (None, Vec::new())
            }
        };
        let (running, tampered) = {
            let l = self.read_live();
            (!l.rules.stopped, l.rules.tampered)
        };
        let mut alerts = self.alert_texts();
        if tampered && !alerts.iter().any(|a| a.contains("integrity")) {
            alerts.push("the rules failed their integrity check, so every key is denied".into());
        }
        // Worked out on every status, never stored: it clears once the user removes the items.
        alerts.extend(ms_vault::unusable_alert(&unusable));
        let (ca_pem, ca_hosts) = lock(&self.ca).clone().unzip();
        ResponseBody::Status {
            daemon: "msd".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            mode: self.backend.label().into(),
            running: Some(running),
            keys,
            proxy_port: Some(self.proxy_port),
            alerts,
            ca_pem,
            ca_hosts: ca_hosts.unwrap_or_default(),
            unusable,
        }
    }

    fn put_key(
        &self,
        session: &SessionId,
        in_agent: bool,
        name: KeyName,
        meta: KeyMeta,
        value: SecretBytes,
    ) -> ResponseBody {
        let _ = in_agent;
        self.put_key_as(session, name, meta, value, "ms add")
    }

    /// Stores a new key (`PutKey`, the dashboard's Add). An existing key is never replaced here,
    /// for any caller (L33 SPEC D-13, T-95): replacing goes through `KeyReplace` / the
    /// dashboard's Replace, which need Touch ID. `target` names the receipt.
    pub(crate) fn put_key_as(
        &self,
        session: &SessionId,
        name: KeyName,
        meta: KeyMeta,
        value: SecretBytes,
        target: &str,
    ) -> ResponseBody {
        if is_reserved(&name) {
            return reply_err(
                ErrorCode::Invalid,
                format!(
                    "morsec: {name} is one of morsec's own key names. Pick another name, e.g. myapp/key"
                ),
            );
        }
        if meta.name != name {
            return reply_err(
                ErrorCode::Invalid,
                "morsec: the key's metadata names a different key",
            );
        }
        if value.expose().is_empty() {
            return reply_err(
                ErrorCode::Invalid,
                "morsec: the value is empty; nothing stored",
            );
        }
        // The check and the write happen under one lock that every value change takes, so a
        // concurrent PutKey can't slip a replace in between (review S3).
        let _k = self.keys_lock();
        let exists = match self.scan_keys() {
            Ok(l) if l.unusable.contains(&name) => {
                // The keychain lets only the build that stored it delete it, so this msd can't
                // replace it; say exactly what the user runs instead of failing on the listing.
                return reply_err(
                    ErrorCode::Denied,
                    format!("morsec: {}", ms_vault::unusable_hint(&name)),
                );
            }
            Ok(l) => l.keys.iter().any(|m| m.name == name),
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        // Replacing a key changes what morsec sends on the user's behalf: never silently, for
        // anyone. A person replaces a value with ms set (Touch ID).
        if exists {
            return reply_err(
                ErrorCode::Denied,
                format!("morsec: {name} already exists. Replace it with: ms set {name}"),
            );
        }
        let (mode, tier) = (meta.mode, meta.tier);
        if let Err(e) = self.vault.put(&name, value, meta) {
            return reply_err(ErrorCode::Internal, e.to_string());
        }
        drop(_k);
        // A new key gets a rule that allows nothing until the user adds hosts or commands.
        let mut note = String::new();
        let needs_rule = !self.read_live().rules.keys.contains_key(&name);
        if needs_rule {
            match self.change_rule(&name, Some(KeyRule::new(mode, tier)), false) {
                Ok(_) if target.starts_with("dashboard") => {
                    note = ". Give it a website or a command on its page to make it usable".into()
                }
                Ok(_) => {
                    note =
                        format!(". It is usable once you allow hosts or commands: ms rules {name}")
                }
                Err(e) => {
                    note = format!(". Its rule could not be created ({e}); run ms rules {name}")
                }
            }
        }
        let version = self.rules_version();
        if let Err(e) = self.record(
            session,
            &name,
            mode,
            target,
            version,
            ReceiptResult::Allowed,
            None,
        ) {
            tracing::error!(error = %e, "could not record a key store");
        }
        ResponseBody::Ok {
            message: format!(
                "stored {name} ({}, {}){note}",
                mode_str(mode),
                tier_str(tier)
            ),
        }
    }

    fn rules_get(&self, key: Option<&KeyName>) -> ResponseBody {
        let live = self.read_live();
        if live.rules.tampered {
            return reply_err(
                ErrorCode::Denied,
                "morsec: the rules failed their integrity check, so every key is denied. Inspect them, then re-create them with: ms init --force",
            );
        }
        let mut out = Rules {
            version: live.rules.version,
            ..Rules::default()
        };
        match key {
            Some(k) => match live.rules.keys.get(k) {
                Some(r) => {
                    out.keys.insert(k.clone(), r.clone());
                }
                None => {
                    return reply_err(
                        ErrorCode::Invalid,
                        format!("morsec: no key named {k}. List keys with: ms rules"),
                    );
                }
            },
            None => out.keys = live.rules.keys.clone(),
        }
        let mut notes = Vec::new();
        if live.rules.stopped {
            notes.push("morsec is stopped (ms stop): every request is refused".to_owned());
        }
        ResponseBody::Rules {
            version: out.version,
            toml: out.to_toml(),
            notes,
        }
    }

    /// Replaces (or with `None` removes) one key's rule, refusing a loosening change unless
    /// `approved`. Returns the saved version.
    fn change_rule(
        &self,
        key: &KeyName,
        rule: Option<KeyRule>,
        approved: bool,
    ) -> Result<(u64, Change), RulesError> {
        let _w = lock(&self.write);
        let (current, min_version) = {
            let l = self.read_live();
            if l.rules.tampered {
                return Err(RulesError::Tampered {
                    why: "the rules in force failed their integrity check".into(),
                });
            }
            (l.rules.clone(), l.min_version)
        };
        let mut next = current.clone();
        match rule {
            Some(r) => {
                next.keys.insert(key.clone(), r);
            }
            None => {
                next.keys.remove(key);
            }
        }
        let (change, _) = ms_rules::classify(&current, &next);
        if change == Change::Same {
            return Ok((current.version, change));
        }
        let store = RulesStore::new(&self.paths.rules, &*self.vault, self.mac_key.clone());
        let mut saved = store.save(&next, approved, min_version)?;
        {
            let mut l = self.write_live();
            saved.stopped = l.rules.stopped;
            l.min_version = l.min_version.max(saved.version);
            l.rules = saved;
        }
        {
            let _f = lock(&self.flag);
            if let Err(e) = self.persist_state(self.is_stopped()) {
                // The receipt chain still records the version, so the floor is not lost.
                tracing::error!(error = %e, "could not save the rules floor in the vault");
                self.alert(
                    AlertKind::FloorNotSaved,
                    format!("the rules version could not be saved in the vault ({e})"),
                );
            }
        }
        self.rebuild_proxy();
        Ok((self.rules_version(), change))
    }

    fn propose(&self, session: &SessionId, key: &KeyName, rule: Option<&str>) -> ResponseBody {
        if is_reserved(key) {
            return reply_err(
                ErrorCode::Invalid,
                format!("morsec: {key} is one of morsec's own key names; it has no rule"),
            );
        }
        let new_rule = match rule {
            None => None,
            Some(text) => match Rules::from_toml(text, "the proposed rule") {
                Ok(r) if r.keys.len() == 1 && r.keys.contains_key(key) => r.keys.get(key).cloned(),
                Ok(_) => {
                    return reply_err(
                        ErrorCode::Invalid,
                        format!("morsec: the proposed rules must hold exactly one key, {key}"),
                    );
                }
                Err(e) => return reply_err(ErrorCode::Invalid, e.to_string()),
            },
        };
        let (current, tampered) = {
            let l = self.read_live();
            (l.rules.keys.get(key).cloned(), l.rules.tampered)
        };
        if tampered {
            return self.rules_get(None);
        }
        let change = ms_rules::classify_rule(current.as_ref(), new_rule.as_ref());
        // While stopped nothing is loosened, and nobody can hold the one approval slot with
        // loosenings so that ms start keeps getting Busy (security review S4).
        if change == Change::Loosen && self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop), so rules can't be loosened. Resume first with: ms start",
            );
        }
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let token = match change {
            Change::Same => {
                return ResponseBody::Ok {
                    message: format!("no change to {key}"),
                };
            }
            Change::Tighten => None,
            Change::Loosen => {
                // The person approves the exact rule text (its hash is the bound argv).
                let text = rule.unwrap_or("(remove the rule)");
                // The higher of the current and proposed tier, so a downgrade from production
                // shows as production (security review S2).
                let tier = [current.as_ref(), new_rule.as_ref()]
                    .into_iter()
                    .flatten()
                    .map(|r| r.tier)
                    .max()
                    .unwrap_or(Tier::Production);
                let req = admin_request(
                    session,
                    key.clone(),
                    tier,
                    &["ms", "rules", key.as_str(), text],
                );
                match self.approve_admin(&req) {
                    Ok(t) => Some(t),
                    Err(resp) => {
                        let v = self.rules_version();
                        let _ = self.record(
                            session,
                            key,
                            Mode::Swap,
                            "rules change",
                            v,
                            ReceiptResult::Denied,
                            None,
                        );
                        return resp;
                    }
                }
            }
        };
        // ms stop while the person was approving: the loosening is not applied (security re-check).
        if token.is_some()
            && (self.is_stopped()
                || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen)
        {
            return reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran while this change waited for approval, so it was not applied",
            );
        }
        let mode = new_rule
            .as_ref()
            .or(current.as_ref())
            .map_or(Mode::Swap, |r| r.mode);
        match self.change_rule(key, new_rule, token.is_some()) {
            Ok((version, _)) => {
                let recorded = match &token {
                    Some(t) => self.record_approved(
                        session,
                        key,
                        mode,
                        "rules change (loosen)",
                        version,
                        t,
                    ),
                    None => self.record(
                        session,
                        key,
                        mode,
                        "rules change (tighten)",
                        version,
                        ReceiptResult::Allowed,
                        None,
                    ),
                };
                if let Err(e) = recorded {
                    tracing::error!(error = %e, "could not record a rules change");
                }
                ResponseBody::Ok {
                    message: format!("saved: rules version {version}"),
                }
            }
            Err(RulesError::NeedsApproval { keys }) => reply_err(
                ErrorCode::NeedsApproval,
                format!("morsec: loosening {keys} needs an approval"),
            ),
            Err(e @ RulesError::Invalid { .. }) => reply_err(ErrorCode::Invalid, e.to_string()),
            Err(e) => reply_err(ErrorCode::Internal, e.to_string()),
        }
    }

    /// Writes the stop flag and the rollback floor. The caller holds `flag`.
    fn persist_state(&self, stopped: bool) -> ms_core::Result<()> {
        let floor = self.read_live().min_version;
        self.backend.put_internal(
            &KeyName::new(DAEMON_STATE_KEY)?,
            SecretBytes::new(encode_state(stopped, floor)),
        )
    }

    fn stop(&self, session: &SessionId) -> ResponseBody {
        self.stop_as(session, "ms stop")
    }

    /// `ms stop` (or the dashboard's Stop): no approval, at once. `target` names the receipt.
    fn stop_as(&self, session: &SessionId, target: &str) -> ResponseBody {
        let _f = lock(&self.flag);
        self.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // In memory first: from here on every request is refused, whatever happens below.
        let version = {
            let mut l = self.write_live();
            l.rules.stopped = true;
            l.rules.version
        };
        // Every ms dev session ends too (L34): its credential stops working at once.
        self.end_all_dev();
        // Every approval token and session grant ends now; a request waiting for a person is
        // denied (L11).
        if let Err(e) = self.approvals.revoke_all() {
            tracing::error!(error = %e, "could not revoke approvals");
        }
        // No proxy rebuild: the proxy's session resolver returns no session while stopped, so
        // the next request is refused without the listener going away.
        let mut message = if target.starts_with("dashboard") {
            "morsec stopped: every agent request is now refused. Start it again with Start (Touch ID)".to_owned()
        } else {
            "morsec stopped: every agent request is now refused. Resume from your own terminal with: ms start (needs Touch ID)".to_owned()
        };
        if let Err(e) = self.persist_state(true) {
            tracing::error!(error = %e, "could not persist the stop flag");
            self.alert(
                AlertKind::FloorNotSaved,
                format!(
                    "ms stop could not be saved in the vault ({e}); if msd restarts it may resume"
                ),
            );
            message.push_str(&format!(
                ". Warning: the stop could not be saved in the vault ({e}), so a restart of msd would resume"
            ));
        }
        if let Err(e) = self.record(
            session,
            &daemon_key(),
            Mode::Run,
            target,
            version,
            ReceiptResult::Allowed,
            None,
        ) {
            tracing::error!(error = %e, "could not record ms stop");
        }
        ResponseBody::Ok { message }
    }

    fn start(&self, session: &SessionId) -> ResponseBody {
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        if !self.is_stopped() {
            return ResponseBody::Ok {
                message: "morsec is already on".into(),
            };
        }
        let key = daemon_key();
        let token = match self.approve_admin(&admin_request(
            session,
            key.clone(),
            Tier::Production,
            &["ms", "start"],
        )) {
            Ok(t) => t,
            Err(resp) => {
                let v = self.rules_version();
                let _ = self.record(
                    session,
                    &key,
                    Mode::Run,
                    "ms start",
                    v,
                    ReceiptResult::Denied,
                    None,
                );
                return resp;
            }
        };
        self.resume(session, &token, stops_seen, "ms start")
    }

    /// Resumes after `token` approved it: the flag is re-checked under the lock (the approval
    /// happened outside it, a Touch ID prompt must not hold up ms stop), so a concurrent stop
    /// can't be undone. `target` names the receipt.
    fn resume(
        &self,
        session: &SessionId,
        token: &ApprovalToken,
        stops_seen: u64,
        target: &str,
    ) -> ResponseBody {
        let key = daemon_key();
        let _f = lock(&self.flag);
        if !self.is_stopped() {
            return ResponseBody::Ok {
                message: "morsec is already on".into(),
            };
        }
        if self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran again while this resume was waiting for approval; still stopped. Resume again if you meant to",
            );
        }
        // Persist first: if the vault write fails, stay stopped.
        if let Err(e) = self.persist_state(false) {
            return reply_err(
                ErrorCode::Internal,
                format!("morsec: could not save the resume in the vault ({e}); still stopped"),
            );
        }
        let version = {
            let mut l = self.write_live();
            l.rules.stopped = false;
            l.rules.version
        };
        lock(&self.stopped_sessions).clear();
        if let Err(e) = self.record_approved(session, &key, Mode::Run, target, version, token) {
            tracing::error!(error = %e, "could not record ms start");
        }
        ResponseBody::Ok {
            message: "morsec on".into(),
        }
    }
}

/// An approval request for one of morsec's own actions (`ms start`, loosening a rule, `ms scan`):
/// the key's tier (production for morsec's own), no cwd, `argv` hashed the way run mode hashes commands.
fn admin_request(session: &SessionId, key: KeyName, tier: Tier, argv: &[&str]) -> ApprovalRequest {
    let argv: Vec<String> = argv.iter().map(|a| (*a).to_owned()).collect();
    ApprovalRequest {
        session: session.clone(),
        key,
        tier,
        argv_hash: ms_rules::argv_hash(&argv),
        argv_display: argv,
        cwd: std::path::PathBuf::new(),
        effect: None,
    }
}

/// "ms start", "pg/production for psql …": how a refusal names the request (inert).
fn render_what(req: &ApprovalRequest) -> String {
    let cmd = req
        .argv_display
        .iter()
        .take(3)
        .map(|a| ms_approve::render::inert(a))
        .collect::<Vec<_>>()
        .join(" ");
    let more = if req.argv_display.len() > 3 {
        " …"
    } else {
        ""
    };
    format!("{} ({cmd}{more})", req.key)
}

/// The swap proxy's approver: a person's approval, checked against the exact request before the
/// proxy uses it (SPEC D-6).
struct VerifyingApprover(Arc<HumanApprover>);

impl Approver for VerifyingApprover {
    fn ask(&self, req: &ApprovalRequest, timeout: Duration) -> ApprovalOutcome {
        match self.0.ask(req, timeout) {
            ApprovalOutcome::Approved(t) => match self.0.verify(&t, &Binding::of(req)) {
                Ok(_) => ApprovalOutcome::Approved(t),
                Err(e) => {
                    tracing::warn!(key = %req.key, error = %e, "approval refused at use");
                    ApprovalOutcome::Denied
                }
            },
            other => other,
        }
    }
}

/// The proxy's approver with the L34 hook: a production key of an `ms dev` session's project,
/// covered by that run's one approval, is answered with that approval's token (its id goes on
/// the receipt); everything else asks a person.
struct DevAwareApprover {
    daemon: std::sync::Weak<Daemon>,
    inner: VerifyingApprover,
}

impl Approver for DevAwareApprover {
    fn ask(&self, req: &ApprovalRequest, timeout: Duration) -> ApprovalOutcome {
        if let Some(t) = self.daemon.upgrade().and_then(|d| d.dev_approval(req)) {
            return ApprovalOutcome::Approved(t);
        }
        self.inner.ask(req, timeout)
    }
}

/// The session to record for a caller. An unattributed caller (a terminal, or a detached
/// process) is recorded as `other("terminal")` with its own PID.
fn session_of(caller: Option<&Caller>, peer: &PeerInfo) -> SessionId {
    match caller {
        Some(Caller::Agent(s)) => s.clone(),
        Some(Caller::Unattributed {
            pid,
            started_unix_ms,
        }) => SessionId {
            agent: AgentKind::Other("terminal".into()),
            pid: *pid,
            started_unix_ms: *started_unix_ms,
        },
        None => SessionId {
            agent: AgentKind::Other("unknown".into()),
            pid: peer.pid.and_then(|p| u32::try_from(p).ok()).unwrap_or(0),
            started_unix_ms: 0,
        },
    }
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Swap => "swap",
        Mode::Run => "run",
        Mode::Mint => "mint",
    }
}

fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Test => "test",
        Tier::Production => "production",
    }
}

/// The IPC handler: runs [`Daemon::handle`] on the blocking pool.
#[derive(Debug, Clone)]
pub struct IpcHandler(pub Arc<Daemon>);

impl ms_ipc::Handler for IpcHandler {
    async fn handle(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        let d = self.0.clone();
        let peer = *peer;
        tokio::task::spawn_blocking(move || d.handle(&peer, request, value))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "request handler failed");
                reply_err(
                    ErrorCode::Internal,
                    "morsec: the daemon failed handling this request",
                )
            })
    }

    async fn handle_with_values(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> (ResponseBody, Vec<SecretBytes>) {
        let d = self.0.clone();
        let peer = *peer;
        tokio::task::spawn_blocking(move || d.handle_values(&peer, request, value))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "request handler failed");
                (
                    reply_err(
                        ErrorCode::Internal,
                        "morsec: the daemon failed handling this request",
                    ),
                    Vec::new(),
                )
            })
    }

    async fn handle_stream(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        io: ms_ipc::StreamIo,
    ) -> ResponseBody {
        match request {
            RequestBody::RunStream { argv, cwd, env } => {
                run::run_stream(self.0.clone(), *peer, argv, cwd, env, io).await
            }
            _ => reply_err(ErrorCode::Protocol, "morsec: not a streaming request"),
        }
    }
}

/// A leak scan can't read keys another program stored, so it didn't search for them: a clean
/// report must not claim otherwise, and these are the likeliest to sit in older transcripts.
fn note_unusable(report: &mut ResponseBody, unusable: &[KeyName]) {
    if unusable.is_empty() {
        return;
    }
    if let ResponseBody::ScanReport {
        notes, complete, ..
    } = report
    {
        *complete = false;
        let names: Vec<&str> = unusable.iter().map(KeyName::as_str).collect();
        notes.push(format!(
            "not searched, because another program stored them and morsec can't read them: {}. \
             Re-add them (ms doctor shows how), then scan again",
            names.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{Decision, Reason, Request};
    use ms_vault::memory::MemoryVault;
    use std::path::PathBuf;

    pub(super) const CANARY: &str = "sk_test_MSD_CANARY_5b1e";

    pub(super) struct H {
        pub(super) d: Arc<Daemon>,
        pub(super) auth: Arc<FakeAuthenticator>,
        pub(super) backend: Backend,
        pub(super) dir: tempfile::TempDir,
        pub(super) who: Arc<Mutex<Option<Caller>>>,
    }

    pub(super) fn agent() -> Caller {
        Caller::Agent(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
            started_unix_ms: 1,
        })
    }

    pub(super) fn terminal() -> Caller {
        Caller::Unattributed {
            pid: 43,
            started_unix_ms: 1,
        }
    }

    pub(super) fn peer() -> PeerInfo {
        PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(42),
            accepted_unix_ms: 1,
        }
    }

    /// The PID of the person's `ms approve` (always outside any agent), and of an agent's
    /// process trying to approve.
    pub(super) const APPROVER_PID: i32 = 99;
    pub(super) const AGENT_APPROVER_PID: i32 = 98;

    pub(super) fn peer_pid(pid: i32) -> PeerInfo {
        PeerInfo {
            pid: Some(pid),
            ..peer()
        }
    }

    pub(super) fn open_with(
        backend: Backend,
        dir: tempfile::TempDir,
        who: Arc<Mutex<Option<Caller>>>,
    ) -> H {
        open_auth(backend, dir, who, FakeAuthenticator::approve())
    }

    pub(super) fn open_auth(
        backend: Backend,
        dir: tempfile::TempDir,
        who: Arc<Mutex<Option<Caller>>>,
        auth: FakeAuthenticator,
    ) -> H {
        let w = who.clone();
        let identify: Identify = Arc::new(move |p: &PeerInfo| match p.pid {
            Some(APPROVER_PID) => Some(Caller::Unattributed {
                pid: 99,
                started_unix_ms: 1,
            }),
            Some(AGENT_APPROVER_PID) => Some(agent()),
            _ => lock(&w).clone(),
        });
        let auth = Arc::new(auth);
        let approvals = Arc::new(HumanApprover::new(auth.clone()).unwrap());
        approvals.set_cooldown(Duration::ZERO);
        let d = Daemon::open(
            backend.clone(),
            Paths::under(dir.path()),
            0,
            approvals,
            identify,
        )
        .unwrap();
        d.set_approval_timeout(Duration::from_millis(300));
        d.set_sandbox_probe(|_| false);
        H {
            d,
            auth,
            backend,
            dir,
            who,
        }
    }

    pub(super) fn fresh() -> H {
        let dir = tempfile::tempdir().unwrap();
        open_with(
            Backend::Memory(Arc::new(MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
        )
    }

    /// Closes and reopens the daemon over the same vault and files (a restart).
    pub(super) fn restart(h: H) -> H {
        let H {
            d,
            backend,
            dir,
            who,
            ..
        } = h;
        drop(d);
        open_with(backend, dir, who)
    }

    impl H {
        pub(super) fn as_(&self, c: Caller) -> &Self {
            *lock(&self.who) = Some(c);
            self
        }
        pub(super) fn req(&self, r: RequestBody) -> ResponseBody {
            self.d.handle(&peer(), r, None)
        }
        pub(super) fn req_value(&self, r: RequestBody, v: Option<SecretBytes>) -> ResponseBody {
            self.d.handle(&peer(), r, v)
        }
        pub(super) fn put(&self, name: &str, tier: Tier) -> ResponseBody {
            let k = KeyName::new(name).unwrap();
            self.d.handle(
                &peer(),
                RequestBody::PutKey {
                    name: k.clone(),
                    meta: KeyMeta {
                        name: k,
                        mode: Mode::Swap,
                        tier,
                        created_unix_ms: 1,
                    },
                },
                Some(SecretBytes::new(CANARY.as_bytes().to_vec())),
            )
        }
        pub(super) fn propose(
            &self,
            key: &str,
            rule: Option<&str>,
            at_terminal: bool,
        ) -> ResponseBody {
            self.req(RequestBody::RulesProposeLoosen {
                key: KeyName::new(key).unwrap(),
                rule: rule.map(|r| format!("version = 1\n[keys.\"{key}\"]\n{r}")),
                at_terminal,
            })
        }
        /// Runs `f` (which waits for an approval) while a person at `approver_pid` answers the
        /// pending request with `approve` / `scope`. Returns `f`'s reply and the decision's.
        pub(super) fn answered(
            &self,
            approver_pid: i32,
            approve: bool,
            scope: Option<ApprovalScope>,
            f: impl FnOnce() -> ResponseBody + Send,
        ) -> (ResponseBody, ResponseBody) {
            std::thread::scope(|sc| {
                let decider = sc.spawn(|| {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    loop {
                        let r = self.d.handle(
                            &peer_pid(approver_pid),
                            RequestBody::ApprovalPending,
                            None,
                        );
                        match r {
                            ResponseBody::Approval { pending: Some(p) } => {
                                return self.d.handle(
                                    &peer_pid(approver_pid),
                                    RequestBody::ApprovalDecide {
                                        id: p.id,
                                        approve,
                                        scope,
                                    },
                                    None,
                                );
                            }
                            ResponseBody::Approval { pending: None } => {}
                            other => return other,
                        }
                        if std::time::Instant::now() > deadline {
                            return ResponseBody::error(ErrorCode::Internal, "nothing pending");
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
                let out = f();
                (out, decider.join().unwrap())
            })
        }
        /// `f`, approved by the person with Touch ID (once).
        pub(super) fn approved(&self, f: impl FnOnce() -> ResponseBody + Send) -> ResponseBody {
            let (out, decision) = self.answered(APPROVER_PID, true, None, f);
            assert!(is_ok(&decision), "{decision:?}");
            out
        }
        pub(super) fn swap(&self, key: &str, host: &str) -> Decision {
            let s = match agent() {
                Caller::Agent(s) => s,
                Caller::Unattributed { .. } => unreachable!(),
            };
            self.d
                .decide(
                    &s,
                    &Request::Swap {
                        key: KeyName::new(key).unwrap(),
                        host: host.into(),
                    },
                )
                .0
        }
        pub(super) fn receipts_text(&self) -> String {
            let mut out = String::new();
            for e in std::fs::read_dir(self.dir.path().join("receipts")).unwrap() {
                out.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
            }
            out
        }
    }

    pub(super) fn is_ok(r: &ResponseBody) -> bool {
        matches!(r, ResponseBody::Ok { .. })
    }

    pub(super) fn code(r: &ResponseBody) -> Option<ErrorCode> {
        match r {
            ResponseBody::Error { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub(super) fn msg(r: &ResponseBody) -> String {
        match r {
            ResponseBody::Error { message, .. } | ResponseBody::Ok { message } => message.clone(),
            other => format!("{other:?}"),
        }
    }

    // protects=SPEC vault-foreign-items 2-4: a key another morsec build stored doesn't wedge the
    // vault: status keeps a key count and names it with the removal command, ms add of that name
    // says exactly what to run, ms add of another name still works; fails_when=status loses the
    // count, the warning lacks the command, or a put fails on the listing; no_claim=the keychain
    // itself (ms-vault foreign_items_are_unusable_not_fatal)
    #[test]
    pub(super) fn unusable_keys_from_another_build() {
        let h = fresh();
        let Backend::Memory(v) = &h.backend else {
            panic!("tests use the memory vault")
        };
        v.mark_unusable(KeyName::new("env/old-key").unwrap());
        assert!(is_ok(&h.put("stripe/test", Tier::Test)));
        match h.req(RequestBody::Status) {
            ResponseBody::Status { keys, alerts, .. } => {
                assert_eq!(keys, Some(1));
                assert!(
                    alerts.iter().any(|a| a.contains(
                        "security delete-generic-password -s cc.morsec.vault -a env/old-key"
                    ) && a.contains("ms add env/old-key")),
                    "{alerts:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        match h.req(RequestBody::ListKeys) {
            ResponseBody::Keys { keys } => assert_eq!(keys.len(), 1),
            other => panic!("{other:?}"),
        }
        let r = h.put("env/old-key", Tier::Test);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(
            msg(&r).contains("security delete-generic-password -s cc.morsec.vault -a env/old-key"),
            "{r:?}"
        );
        assert!(is_ok(&h.put("stripe/other", Tier::Test)));
        match h.req(RequestBody::Status) {
            ResponseBody::Status { unusable, .. } => {
                assert_eq!(unusable, vec![KeyName::new("env/old-key").unwrap()]);
            }
            other => panic!("{other:?}"),
        }
        // A leak scan says it did not search them, and is not complete.
        let mut report = ResponseBody::ScanReport {
            findings: Vec::new(),
            files_scanned: 1,
            bytes_scanned: 1,
            keys_checked: 1,
            skipped_keys: Vec::new(),
            notes: Vec::new(),
            complete: true,
        };
        note_unusable(&mut report, &[KeyName::new("env/old-key").unwrap()]);
        match report {
            ResponseBody::ScanReport {
                notes, complete, ..
            } => {
                assert!(!complete);
                assert!(
                    notes
                        .iter()
                        .any(|n| n.contains("not searched") && n.contains("env/old-key")),
                    "{notes:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    // protects=PutKey stores end to end (L04's missing reply): Ok, listed by ListKeys (never with a
    // value), a new key gets a rule that allows nothing, reserved names and agent replacements are
    // refused, a terminal replacement works, and the value never reaches receipts;
    // fails_when=an agent can overwrite a key, a morsec/ key can be written, or a new key is usable
    // before the user allows a target; no_claim=the keychain backend (L01 tests it)
    #[test]
    pub(super) fn put_key_and_list() {
        let h = fresh();
        let r = h.put("stripe/test", Tier::Test);
        assert!(is_ok(&r), "{r:?}");
        assert!(msg(&r).contains("ms rules stripe/test"), "{r:?}");
        match h.req(RequestBody::ListKeys) {
            ResponseBody::Keys { keys } => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].name.as_str(), "stripe/test");
            }
            other => panic!("{other:?}"),
        }
        assert!(h.d.rules().keys[&KeyName::new("stripe/test").unwrap()].allows_nothing());
        assert!(matches!(
            h.swap("stripe/test", "api.stripe.com"),
            Decision::Deny {
                reason: Reason::HostNotAllowed
            }
        ));
        assert_eq!(
            code(&h.put("morsec/receipts-hmac", Tier::Test)),
            Some(ErrorCode::Invalid)
        );
        assert_eq!(
            code(&h.as_(agent()).put("stripe/test", Tier::Test)),
            Some(ErrorCode::Denied)
        );
        assert!(is_ok(&h.as_(agent()).put("openai/test", Tier::Test)));
        assert_eq!(
            code(&h.as_(terminal()).put("stripe/test", Tier::Test)),
            Some(ErrorCode::Denied),
            "PutKey never replaces (L33)"
        );
        assert!(!h.receipts_text().contains(CANARY));
        match h.req(RequestBody::Status) {
            ResponseBody::Status {
                keys,
                running,
                mode,
                ..
            } => {
                assert_eq!(
                    (keys, running, mode.as_str()),
                    (Some(2), Some(true), "dev-memory")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    // protects=L33 SPEC D-13 and T-95 (was open before L33: PutKey silently replaced a value
    // for any caller outside an agent session): PutKey on an existing key is refused for every
    // caller, the agent, a terminal and the person's approver alike, with the ms set command, and
    // the stored value is unchanged; a new name still stores; fails_when=any caller replaces a
    // value through PutKey; no_claim=KeyReplace (dash_actions replace tests)
    #[test]
    pub(super) fn put_key_refuses_existing_key() {
        let h = fresh();
        assert!(is_ok(&h.put("stripe/test", Tier::Test)));
        for who in [agent(), terminal()] {
            let k = KeyName::new("stripe/test").unwrap();
            let r = h.as_(who).d.handle(
                &peer(),
                RequestBody::PutKey {
                    name: k.clone(),
                    meta: KeyMeta {
                        name: k,
                        mode: Mode::Swap,
                        tier: Tier::Test,
                        created_unix_ms: 2,
                    },
                },
                Some(SecretBytes::new(b"replaced-value".to_vec())),
            );
            assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
            assert!(msg(&r).contains("ms set stripe/test"), "{r:?}");
        }
        let v =
            h.d.vault()
                .read_with(&KeyName::new("stripe/test").unwrap(), <[u8]>::to_vec)
                .unwrap();
        assert_eq!(v, CANARY.as_bytes());
        assert!(is_ok(&h.put("stripe/other", Tier::Test)));
    }

    // protects=AUTH-4 kill switch: after Stop the next decision is Deny(Stopped), status says
    // stopped, and a restart of msd keeps it stopped (the flag is in the vault); fails_when=the
    // next request is allowed, or killing msd resumes it; no_claim=the proxy path (tests/cli.rs)
    #[test]
    pub(super) fn stop_is_immediate_and_survives_restart() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let r = h.approved(|| {
            h.propose(
                "stripe/test",
                Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n"),
                false,
            )
        });
        assert!(is_ok(&r), "{r:?}");
        assert_eq!(h.swap("stripe/test", "api.stripe.com"), Decision::Allow);
        assert!(
            is_ok(&h.as_(agent()).req(RequestBody::Stop)),
            "an agent may always stop"
        );
        assert!(matches!(
            h.swap("stripe/test", "api.stripe.com"),
            Decision::Deny {
                reason: Reason::Stopped
            }
        ));
        let h = restart(h);
        assert!(h.d.is_stopped());
        assert!(matches!(
            h.swap("stripe/test", "api.stripe.com"),
            Decision::Deny {
                reason: Reason::Stopped
            }
        ));
        match h.req(RequestBody::Status) {
            ResponseBody::Status { running, .. } => assert_eq!(running, Some(false)),
            other => panic!("{other:?}"),
        }
        assert!(h.receipts_text().contains("ms stop"));
    }

    // protects=AUTH-3/SPEC D-9: ms start needs a person's approval with Touch ID: unanswered it
    // times out, denied or failed Touch ID it stays stopped, at_terminal no longer bypasses
    // anything, an agent can't approve its own resume, and an approved resume persists across a
    // restart and is recorded with the token id and method touch-id; fails_when=morsec resumes
    // without a Touch ID approval from outside every agent tree; no_claim=the real LAContext sheet
    #[test]
    pub(super) fn start_needs_touch_id_approval() {
        let h = fresh();
        h.req(RequestBody::Stop);
        let r = h.req(RequestBody::Start { at_terminal: true });
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(msg(&r).contains("ms approve"), "{r:?}");
        assert!(h.d.is_stopped());
        // An agent's process tries to approve: refused, and the request times out.
        let (r, d) = h.answered(AGENT_APPROVER_PID, true, None, || {
            h.as_(agent()).req(RequestBody::Start { at_terminal: true })
        });
        assert_eq!(code(&d), Some(ErrorCode::Denied), "{d:?}");
        assert!(msg(&d).contains("inside an agent session"), "{d:?}");
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(h.d.is_stopped());
        // The person denies.
        let (r, _) = h.answered(APPROVER_PID, false, None, || {
            h.as_(terminal())
                .req(RequestBody::Start { at_terminal: false })
        });
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(h.d.is_stopped());
        assert!(h.auth.reasons().is_empty(), "deny needs no Touch ID");
        // The person approves with Touch ID.
        let r = h.approved(|| {
            h.as_(terminal())
                .req(RequestBody::Start { at_terminal: false })
        });
        assert!(is_ok(&r), "{r:?}");
        assert!(!h.d.is_stopped());
        let reasons = h.auth.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains(r#""ms" "start""#), "{}", reasons[0]);
        let text = h.receipts_text();
        assert!(
            text.contains(TOUCH_ID_METHOD) && text.contains("once-"),
            "{text}"
        );
        let h = restart(h);
        assert!(!h.d.is_stopped());
    }

    // protects=SPEC D-4: a failed or cancelled Touch ID denies the request and nothing changes;
    // fails_when=morsec resumes after a failed Touch ID; no_claim=lockout handling of the sheet
    #[test]
    pub(super) fn failed_touch_id_denies() {
        let dir = tempfile::tempdir().unwrap();
        let h = open_auth(
            Backend::Memory(Arc::new(MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
            FakeAuthenticator::deny("cancelled"),
        );
        h.req(RequestBody::Stop);
        let (r, d) = h.answered(APPROVER_PID, true, None, || {
            h.req(RequestBody::Start { at_terminal: false })
        });
        assert_eq!(code(&d), Some(ErrorCode::Denied), "{d:?}");
        assert!(msg(&d).contains("Touch ID did not confirm"), "{d:?}");
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(h.d.is_stopped());
    }

    // protects=SPEC D-2/D-3 over IPC: an agent can neither list nor decide approvals; only one
    // request waits at a time and a second is refused at once with Busy; ms stop denies the
    // waiting one; fails_when=an agent sees or answers a request, or a second request is parked;
    // no_claim=the real process-tree walk (agent_e2e)
    #[test]
    pub(super) fn approvals_ipc_rules() {
        let h = fresh();
        let r = h.d.handle(
            &peer_pid(AGENT_APPROVER_PID),
            RequestBody::ApprovalPending,
            None,
        );
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(matches!(
            h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None),
            ResponseBody::Approval { pending: None }
        ));
        h.d.set_approval_timeout(Duration::from_secs(5));
        h.req(RequestBody::Stop);
        std::thread::scope(|sc| {
            let first = sc.spawn(|| h.req(RequestBody::Start { at_terminal: false }));
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let p = loop {
                if let ResponseBody::Approval { pending: Some(p) } =
                    h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None)
                {
                    break p;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(p.request.argv_display, vec!["ms", "start"]);
            let started = std::time::Instant::now();
            let second = h.d.handle(&peer(), RequestBody::Scan, None);
            assert_eq!(
                code(&second),
                Some(ErrorCode::Denied),
                "stopped: {second:?}"
            );
            let second = h.req(RequestBody::Start { at_terminal: false });
            assert_eq!(code(&second), Some(ErrorCode::Busy), "{second:?}");
            assert!(started.elapsed() < Duration::from_secs(2));
            let r = h.d.handle(
                &peer_pid(AGENT_APPROVER_PID),
                RequestBody::ApprovalDecide {
                    id: p.id.clone(),
                    approve: true,
                    scope: None,
                },
                None,
            );
            assert_eq!(code(&r), Some(ErrorCode::Denied));
            // ms stop denies the waiting request.
            assert!(is_ok(&h.as_(agent()).req(RequestBody::Stop)));
            let first = first.join().unwrap();
            assert_eq!(code(&first), Some(ErrorCode::NeedsApproval), "{first:?}");
        });
        assert!(h.d.is_stopped());
        assert!(h.auth.reasons().is_empty());
    }

    // protects=rules over IPC (open from L03, L11): tightening is saved without approval;
    // loosening times out without one (at_terminal no longer bypasses it) and is saved after a
    // person approves with Touch ID, the sheet naming the exact rule; reserved keys and multi-key
    // payloads are refused; RulesGet returns the saved rules; fails_when=a loosening is saved
    // without Touch ID; no_claim=the real LAContext sheet
    #[test]
    pub(super) fn rules_changes() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let loose = "mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\", \"files.stripe.com\"]\n";
        let r = h.as_(agent()).propose("stripe/test", Some(loose), false);
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        let r = h.as_(terminal()).propose("stripe/test", Some(loose), true);
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        let r = h.approved(|| h.as_(agent()).propose("stripe/test", Some(loose), false));
        assert!(is_ok(&r), "{r:?}");
        assert!(
            h.auth.reasons()[0].contains("files.stripe.com"),
            "{:?}",
            h.auth.reasons()
        );
        let tight = "mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n";
        let r = h.as_(agent()).propose("stripe/test", Some(tight), false);
        assert!(is_ok(&r), "agents may tighten: {r:?}");
        assert!(matches!(
            h.swap("stripe/test", "files.stripe.com"),
            Decision::Deny {
                reason: Reason::HostNotAllowed
            }
        ));
        assert_eq!(
            code(
                &h.as_(terminal())
                    .propose("morsec/daemon", Some(tight), true)
            ),
            Some(ErrorCode::Invalid)
        );
        let two = h.req(RequestBody::RulesProposeLoosen {
            key: KeyName::new("stripe/test").unwrap(),
            rule: Some(format!(
                "version = 1\n[keys.\"stripe/test\"]\n{tight}[keys.\"other/x\"]\n{tight}"
            )),
            at_terminal: true,
        });
        assert_eq!(code(&two), Some(ErrorCode::Invalid));
        match h.req(RequestBody::RulesGet { key: None }) {
            ResponseBody::Rules { version, toml, .. } => {
                let r = Rules::from_toml(&toml, "reply").unwrap();
                assert_eq!(r.version, version);
                assert_eq!(r.keys.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        // Removing a rule is tightening.
        assert!(is_ok(&h.as_(agent()).propose("stripe/test", None, false)));
    }

    // protects=security review S2/S4: while stopped a loosening is refused at once (it can't hold
    // the approval slot against ms start); the tier shown for a downgrade is the higher one;
    // fails_when=a loosening waits for approval while stopped, or a production→test downgrade is
    // shown as test; no_claim=rate limits on prompts before a stop
    #[test]
    pub(super) fn loosening_while_stopped_and_downgrade_tier() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let prod = "mode = \"swap\"\ntier = \"production\"\nhosts = [\"api.stripe.com\"]\n";
        let r = h.approved(|| h.propose("stripe/test", Some(prod), false));
        assert!(is_ok(&r), "{r:?}");
        let down = "mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n";
        let r = h.approved(|| h.as_(agent()).propose("stripe/test", Some(down), false));
        assert!(is_ok(&r), "{r:?}");
        let last = h.auth.reasons().pop().unwrap();
        assert!(last.contains("(production key)"), "{last}");
        h.req(RequestBody::Stop);
        let wider =
            "mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\", \"x.example\"]\n";
        let started = std::time::Instant::now();
        let r = h.as_(agent()).propose("stripe/test", Some(wider), false);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(msg(&r).contains("stopped"), "{r:?}");
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(!h.d.approvals.busy());
    }

    // protects=fail closed on tampering: a rules file with a bad MAC loads as tampered (every key
    // denied, RulesGet refused, status alert), and an older validly MAC'd file put back after
    // later changes is refused by the receipt-chain rollback floor; fails_when=a forged or
    // replayed rules file is used; no_claim=tail truncation of the receipts (L24)
    #[test]
    pub(super) fn tampered_and_rolled_back_rules_fail_closed() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let rules = h.dir.path().join("rules.toml");
        let mac = ms_rules::store::mac_path(&rules);
        let old = (std::fs::read(&rules).unwrap(), std::fs::read(&mac).unwrap());
        let r = h.approved(|| {
            h.propose(
                "stripe/test",
                Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n"),
                false,
            )
        });
        assert!(is_ok(&r));
        h.propose("stripe/test", None, false);
        // Replay the older, validly MAC'd file.
        std::fs::write(&rules, &old.0).unwrap();
        std::fs::write(&mac, &old.1).unwrap();
        let h = restart(h);
        assert!(h.d.rules().tampered, "rollback accepted");
        assert!(matches!(
            h.swap("stripe/test", "api.stripe.com"),
            Decision::Deny {
                reason: Reason::RulesTampered
            }
        ));
        assert_eq!(
            code(&h.req(RequestBody::RulesGet { key: None })),
            Some(ErrorCode::Denied)
        );
        // S3: deleting the receipts does not lower the floor (it is also in the vault).
        std::fs::remove_dir_all(h.dir.path().join("receipts")).unwrap();
        let h = restart(h);
        assert!(
            h.d.rules().tampered,
            "rollback accepted after deleting receipts"
        );
        // A forged edit.
        std::fs::write(&rules, "version = 99\n").unwrap();
        let h = restart(h);
        assert!(h.d.rules().tampered);
        match h.req(RequestBody::Status) {
            ResponseBody::Status { alerts, .. } => {
                assert!(alerts.iter().any(|a| a.contains("integrity")), "{alerts:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    // protects=LOG-2: when one session's blocked attempts reach the threshold, msd stops that
    // session (its swaps are denied and its socket requests refused, except status/stop) while
    // other sessions carry on; fails_when=the alerting session keeps working; no_claim=the
    // detector's thresholds (L02 tests)
    #[test]
    pub(super) fn log2_alert_stops_the_session() {
        let h = fresh();
        let s = match agent() {
            Caller::Agent(s) => s,
            Caller::Unattributed { .. } => unreachable!(),
        };
        for i in 0..5 {
            h.d.receipts()
                .append_detailed(
                    ReceiptEvent {
                        time_unix_ms: now_ms() + i,
                        session: s.clone(),
                        key: KeyName::new("stripe/test").unwrap(),
                        mode: Mode::Swap,
                        target: "paste.example.net".into(),
                        argv_hash: None,
                        rule_version: 1,
                        approval_id: None,
                        result: ReceiptResult::Blocked(Reason::HostNotAllowed),
                    },
                    ReceiptDetail::default(),
                )
                .unwrap();
        }
        assert!(h.d.session_stopped(&s));
        let r = h.as_(agent()).put("x/y", Tier::Test);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(matches!(
            h.as_(agent()).req(RequestBody::Status),
            ResponseBody::Status { .. }
        ));
        assert!(is_ok(&h.as_(terminal()).put("x/y", Tier::Test)));
    }

    // protects=L09 SPEC D-3: ms scan (a guessing oracle for short values) is refused inside an
    // agent session and for an unidentified caller; fails_when=either gets a scan report;
    // no_claim=the terminal path (scan.rs tests and tests/e2e run it; here it would read the
    // real home directory)
    #[test]
    pub(super) fn scan_refused_inside_agent() {
        let h = fresh();
        assert!(is_ok(&h.put("stripe/test", Tier::Test)));
        let r = h.as_(agent()).req(RequestBody::Scan);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(msg(&r).contains("your own terminal"), "{r:?}");
        *lock(&h.who) = None;
        assert_eq!(code(&h.req(RequestBody::Scan)), Some(ErrorCode::Denied));
        // L11 (INJ-5): from a terminal, nothing is read until a person approves; unanswered it
        // times out, and a denial is recorded.
        let r = h.as_(terminal()).req(RequestBody::Scan);
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        let (r, _) = h.answered(APPROVER_PID, false, None, || h.req(RequestBody::Scan));
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(h.receipts_text().contains("ms scan"));
        // The kill switch: a stopped morsec reads no value, even for the user's terminal.
        let h = fresh();
        assert!(is_ok(&h.put("stripe/test", Tier::Test)));
        assert!(is_ok(&h.req(RequestBody::Stop)));
        let r = h.as_(terminal()).req(RequestBody::Scan);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(msg(&r).contains("stopped"), "{r:?}");
    }

    // protects=R1: a caller that can't be identified (the connecting process exited and a child
    // kept the fd, or its PID was reused) is refused everything but status and stop, so it can't
    // replace a key, use the terminal path or slip out of a LOG-2 stop; fails_when=None is treated
    // as a non-agent; no_claim=the kernel side (peer_cred of a dead PID)
    #[test]
    pub(super) fn unidentified_caller_is_refused() {
        let h = fresh();
        assert!(is_ok(&h.put("stripe/test", Tier::Test)));
        *lock(&h.who) = None;
        assert_eq!(
            code(&h.put("stripe/test", Tier::Test)),
            Some(ErrorCode::Denied)
        );
        assert_eq!(code(&h.put("new/key", Tier::Test)), Some(ErrorCode::Denied));
        assert_eq!(
            code(&h.req(RequestBody::Start { at_terminal: false })),
            Some(ErrorCode::Denied)
        );
        assert!(is_ok(&h.req(RequestBody::Stop)));
        assert_eq!(
            code(&h.req(RequestBody::Start { at_terminal: false })),
            Some(ErrorCode::Denied)
        );
        assert!(h.d.is_stopped());
        assert!(matches!(
            h.req(RequestBody::Status),
            ResponseBody::Status { .. }
        ));
    }

    // protects=R2: concurrent stop and start never leave morsec on after a stop reported success;
    // fails_when=the in-memory flag and the vault flag disagree after the race; no_claim=fairness
    #[test]
    pub(super) fn stop_and_start_are_serialized() {
        let h = Arc::new(fresh());
        // A person who approves whatever is waiting, for the whole test.
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let person = {
            let (h, done) = (h.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    if let ResponseBody::Approval { pending: Some(p) } =
                        h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None)
                    {
                        let _ = h.d.handle(
                            &peer_pid(APPROVER_PID),
                            RequestBody::ApprovalDecide {
                                id: p.id,
                                approve: true,
                                scope: None,
                            },
                            None,
                        );
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        for _ in 0..50 {
            let (a, b) = (h.clone(), h.clone());
            let t1 = std::thread::spawn(move || {
                a.as_(terminal())
                    .req(RequestBody::Start { at_terminal: false })
            });
            let t2 = std::thread::spawn(move || b.d.handle(&peer(), RequestBody::Stop, None));
            let _ = t1.join().unwrap();
            let _ = t2.join().unwrap();
            let mem = h.d.is_stopped();
            let saved = h
                .backend
                .vault()
                .read_with(&KeyName::new(DAEMON_STATE_KEY).unwrap(), <[u8]>::to_vec)
                .unwrap();
            assert_eq!(
                Some(mem),
                parse_state(&saved).map(|s| s.0),
                "memory and vault disagree"
            );
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        person.join().unwrap();
        assert!(!h.auth.reasons().is_empty(), "no start was ever approved");
    }

    // protects=the state item format round-trips and anything else is rejected (fail closed);
    // fails_when=garbage parses as running; no_claim=-
    #[test]
    pub(super) fn state_format() {
        assert_eq!(parse_state(&encode_state(true, 7)), Some((true, 7)));
        assert_eq!(parse_state(&encode_state(false, 0)), Some((false, 0)));
        assert_eq!(parse_state(b"running"), Some((false, 0)));
        for bad in [&b"garbage"[..], b"running v=x", b"stopped v=", b""] {
            assert_eq!(parse_state(bad), None);
        }
    }

    // protects=R7: an unreadable state item keeps msd stopped with every key denied, but never
    // persists a sentinel floor: after a stop and a resume, a restart loads the rules again;
    // fails_when=u64::MAX (or any unknown floor) is written and the rules stay tampered forever;
    // no_claim=rollback resistance while the state item is unreadable (documented residual)
    #[test]
    pub(super) fn unreadable_state_never_persists_a_sentinel_floor() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let state = KeyName::new(DAEMON_STATE_KEY).unwrap();
        h.backend
            .put_internal(&state, SecretBytes::new(b"garbage".to_vec()))
            .unwrap();
        let h = restart(h);
        assert!(h.d.is_stopped() && h.d.rules().tampered);
        assert!(is_ok(&h.req(RequestBody::Stop)));
        assert!(is_ok(&h.approved(|| {
            h.as_(terminal())
                .req(RequestBody::Start { at_terminal: false })
        })));
        let saved = h.backend.vault().read_with(&state, <[u8]>::to_vec).unwrap();
        let (_, floor) = parse_state(&saved).unwrap();
        assert!(floor < 100, "sentinel floor persisted: {floor}");
        let h = restart(h);
        assert!(!h.d.is_stopped());
        assert!(!h.d.rules().tampered, "rules stuck tampered");
    }

    // protects=S1: the proxy CA certificate and hosts come from the vault, never from ca.pem; a
    // planted certificate in ca.pem is ignored (and overwritten by the export), and the same CA is
    // reused across calls; fails_when=a file on disk decides which certificate msd serves or
    // trusts; no_claim=rcgen/X.509 parsing
    #[test]
    pub(super) fn ca_comes_from_the_vault_not_the_file() {
        let h = fresh();
        let hosts: std::collections::BTreeSet<String> = ["api.stripe.com".to_owned()].into();
        let first = crate::proxy::ensure_ca(&h.d, &hosts).unwrap();
        let pem = first.cert_pem().to_owned();
        let file = h.dir.path().join("ca.pem");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), pem);
        std::fs::write(
            &file,
            "-----BEGIN CERTIFICATE-----\nATTACKER\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let again = crate::proxy::ensure_ca(&h.d, &hosts).unwrap();
        assert_eq!(again.cert_pem(), pem, "the planted file was used");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), pem);
        assert!(!h.dir.path().join("ca-hosts.json").exists());
    }

    // protects=an unreadable stop flag fails closed: msd starts stopped with an alert;
    // fails_when=a damaged flag reads as running; no_claim=a deleted keychain item (the keychain
    // backend reports it the same way: not found → stopped)
    #[test]
    pub(super) fn unreadable_stop_flag_means_stopped() {
        let h = fresh();
        h.backend
            .put_internal(
                &KeyName::new(DAEMON_STATE_KEY).unwrap(),
                SecretBytes::new(b"garbage".to_vec()),
            )
            .unwrap();
        let h = restart(h);
        assert!(h.d.is_stopped());
    }

    // ---- L31 guided-init: ProjectSave / ProjectList / ProjectGet ----

    pub(super) const STRIPE_KEY: &str = "shop/stripe-secret-key";
    pub(super) const OPENAI_KEY: &str = "shop/openai-api-key";
    pub(super) const DB_KEY: &str = "shop/database-url";
    pub(super) const UNKNOWN_KEY: &str = "shop/session-secret";

    /// A project root (canonical) and its record naming `keys` as (key, provider).
    pub(super) fn project(
        h: &H,
        keys: &[(&str, Option<&str>)],
    ) -> ms_projects::record::ProjectRecord {
        use ms_projects::record::*;
        let root = h.dir.path().join("shop");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        ProjectRecord {
            slug: "shop".into(),
            display: "shop".into(),
            root: root.display().to_string(),
            created_unix_ms: 1,
            scan: ScanRecord::default(),
            files: vec![FileRecord {
                path: ".env".into(),
                git_history_commits: None,
                secrets: keys
                    .iter()
                    .enumerate()
                    .map(|(i, (k, p))| SecretRecord {
                        var: format!("VAR_{i}"),
                        line: i as u64 + 1,
                        key: KeyName::new(k).unwrap(),
                        quote: Quote::None,
                        action: SecretAction::Import,
                        provider: p.map(str::to_owned),
                    })
                    .collect(),
            }],
            findings: Vec::new(),
            hints: Vec::new(),
        }
    }

    pub(super) fn put_mode(h: &H, name: &str, mode: Mode, tier: Tier) {
        let k = KeyName::new(name).unwrap();
        let r = h.d.handle(
            &peer(),
            RequestBody::PutKey {
                name: k.clone(),
                meta: KeyMeta {
                    name: k,
                    mode,
                    tier,
                    created_unix_ms: 1,
                },
            },
            Some(SecretBytes::new(CANARY.as_bytes().to_vec())),
        );
        assert!(is_ok(&r), "{r:?}");
    }

    /// The rules the CLI would propose for `rec` against the rules in force.
    pub(super) fn proposal(h: &H, rec: &ms_projects::record::ProjectRecord) -> Rules {
        ms_projects::save::initial_rules(ms_import::catalog::Catalog::builtin(), rec, &h.d.rules())
    }

    pub(super) fn save(
        h: &H,
        rec: &ms_projects::record::ProjectRecord,
        rules: &Rules,
    ) -> ResponseBody {
        h.req(RequestBody::ProjectSave {
            record: rec.to_toml(),
            rules: ms_projects::save::canonical(rules),
        })
    }

    /// The four keys of the fixture: two known swap keys, a run key and an unknown one.
    pub(super) fn shop(h: &H) -> ms_projects::record::ProjectRecord {
        h.put(STRIPE_KEY, Tier::Test);
        h.put(OPENAI_KEY, Tier::Test);
        put_mode(h, DB_KEY, Mode::Run, Tier::Production);
        h.put(UNKNOWN_KEY, Tier::Production);
        project(
            h,
            &[
                (STRIPE_KEY, Some("stripe")),
                (OPENAI_KEY, Some("openai")),
                (DB_KEY, Some("pg")),
                (UNKNOWN_KEY, None),
            ],
        )
    }

    // protects=SPEC criterion 5 / design §8 "Agent drives ProjectInit": ProjectSave from an agent
    // session is Denied and changes no rule and writes no record, while the read-only ProjectList
    // and ProjectGet answer agents; fails_when=an agent's ProjectSave is applied or reaches the
    // approver; no_claim=a detached same-user process (it is not an agent session: T-04)
    #[test]
    pub(super) fn project_requests_refused_in_agent_session() {
        let h = fresh();
        let rec = shop(&h);
        let rules = proposal(&h, &rec);
        let r = save(h.as_(agent()), &rec, &rules);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(msg(&r).contains("own terminal"), "{r:?}");
        assert!(h.auth.reasons().is_empty(), "no approval was asked");
        assert!(!h.dir.path().join(PROJECTS_FILE).exists());
        assert!(matches!(
            h.swap(STRIPE_KEY, "api.stripe.com"),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            h.as_(agent()).req(RequestBody::ProjectList),
            ResponseBody::Projects { .. }
        ));
    }

    // protects=SPEC criterion 5 checks in msd: a key outside the slug, an existing key whose rule
    // already allows something, a host on a run rule, an extra host, a key not in the vault and
    // a non-canonical root are Invalid before any approval; refused while stopped;
    // fails_when=any of them reaches the approver or is applied; no_claim=the checker's full
    // table (ms-projects save_checks)
    #[test]
    pub(super) fn project_save_checks() {
        let h = fresh();
        let rec = shop(&h);
        let good = proposal(&h, &rec);
        assert_eq!(good.keys.len(), 3, "{good:?}");

        let mut outside = good.clone();
        outside.keys.insert(
            KeyName::new("other/k").unwrap(),
            KeyRule::new(Mode::Swap, Tier::Test),
        );
        let mut run_host = good.clone();
        run_host
            .keys
            .get_mut(&KeyName::new(DB_KEY).unwrap())
            .unwrap()
            .hosts = vec![ms_rules::HostPattern::parse("db.example.com").unwrap()];
        let mut extra_host = good.clone();
        extra_host
            .keys
            .get_mut(&KeyName::new(STRIPE_KEY).unwrap())
            .unwrap()
            .hosts
            .push(ms_rules::HostPattern::parse("evil.example").unwrap());
        let mut foreign_rec = rec.clone();
        foreign_rec.files[0].secrets[0].key = KeyName::new("shop/not-stored").unwrap();
        let mut relative_root = rec.clone();
        relative_root.root = format!("{}/x/..", rec.root);
        let mut linked_root = rec.clone();
        let link = h.dir.path().join("link-to-shop");
        std::os::unix::fs::symlink(&rec.root, &link).unwrap();
        linked_root.root = link.display().to_string();
        for (what, r, rules) in [
            ("key outside the slug", &rec, &outside),
            ("host on a run rule", &rec, &run_host),
            ("extra host", &rec, &extra_host),
            ("key not in the vault", &foreign_rec, &good),
            ("not normalised root", &relative_root, &good),
            ("symlinked root", &linked_root, &good),
        ] {
            let resp = save(h.as_(terminal()), r, rules);
            assert_eq!(code(&resp), Some(ErrorCode::Invalid), "{what}: {resp:?}");
        }
        // An existing key with a non-empty rule: "use ms rules".
        let r = h.approved(|| {
            h.propose(
                STRIPE_KEY,
                Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n"),
                false,
            )
        });
        assert!(is_ok(&r), "{r:?}");
        let before = h.auth.reasons().len();
        let r = save(&h, &rec, &good);
        assert_eq!(code(&r), Some(ErrorCode::Invalid), "{r:?}");
        assert!(msg(&r).contains("ms rules"), "{r:?}");
        assert_eq!(h.auth.reasons().len(), before, "no approval was asked");

        // Refused while stopped.
        assert!(is_ok(&h.req(RequestBody::Stop)));
        let r = save(&h, &rec, &Rules::default());
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(!h.dir.path().join(PROJECTS_FILE).exists());
    }

    // protects=SPEC D-2 / criterion 2: one Touch ID approves the first rules of every new key of
    // the project at once; the approval lists each key with its hosts or root and is bound to the
    // rules hash (a changed set is a different request and asks again); after it the known swap
    // keys reach their catalog hosts, the run key gets only the root, the unknown key still allows
    // nothing; a denial applies nothing and a re-run asks again; fails_when=more than one prompt
    // for one save, a changed set reuses the approval, or anything applies on denial;
    // no_claim=the real LAContext sheet (manual check)
    #[test]
    pub(super) fn project_save_one_approval_bound_to_rules() {
        let h = fresh();
        let rec = shop(&h);
        let rules = proposal(&h, &rec);

        // Denied: nothing applied, no record.
        let (r, _) = h.answered(APPROVER_PID, false, None, || save(&h, &rec, &rules));
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        assert!(matches!(
            h.swap(STRIPE_KEY, "api.stripe.com"),
            Decision::Deny { .. }
        ));
        assert!(!h.dir.path().join(PROJECTS_FILE).exists());

        // A smaller set is a different request: its argv (and hash) differ.
        let mut smaller = rules.clone();
        smaller.keys.remove(&KeyName::new(OPENAI_KEY).unwrap());
        assert_ne!(
            ms_projects::save::rules_hash(&smaller),
            ms_projects::save::rules_hash(&rules)
        );
        let argv = ms_projects::save::approval_argv(&rec, &rules);
        assert_ne!(
            ms_rules::argv_hash(&argv),
            ms_rules::argv_hash(&ms_projects::save::approval_argv(&rec, &smaller))
        );

        // Approved once: every rule applied with one Touch ID.
        let seen = std::sync::Mutex::new(None);
        let before = h.auth.reasons().len();
        let out = std::thread::scope(|sc| {
            sc.spawn(|| {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while std::time::Instant::now() < deadline {
                    if let ResponseBody::Approval { pending: Some(p) } =
                        h.d.handle(&peer_pid(APPROVER_PID), RequestBody::ApprovalPending, None)
                    {
                        *lock(&seen) = Some(p.request.clone());
                        let _ = h.d.handle(
                            &peer_pid(APPROVER_PID),
                            RequestBody::ApprovalDecide {
                                id: p.id,
                                approve: true,
                                scope: None,
                            },
                            None,
                        );
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            save(&h, &rec, &rules)
        });
        assert!(is_ok(&out), "{out:?}");
        assert_eq!(h.auth.reasons().len(), before + 1, "exactly one Touch ID");
        let req = lock(&seen).clone().expect("an approval was asked");
        assert_eq!(req.argv_display, argv);
        assert_eq!(req.argv_hash, ms_rules::argv_hash(&argv));
        let shown = req.argv_display.join("\n");
        for k in [STRIPE_KEY, OPENAI_KEY, DB_KEY] {
            assert!(shown.contains(k), "{shown}");
        }
        assert!(
            shown.contains("api.stripe.com") && shown.contains(&rec.root),
            "{shown}"
        );
        assert!(shown.contains(&hex::encode(ms_projects::save::rules_hash(&rules))));
        assert_eq!(h.swap(STRIPE_KEY, "api.stripe.com"), Decision::Allow);
        assert_eq!(h.swap(OPENAI_KEY, "api.openai.com"), Decision::Allow);
        assert!(matches!(
            h.swap(STRIPE_KEY, "evil.example"),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            h.swap(UNKNOWN_KEY, "api.stripe.com"),
            Decision::Deny { .. }
        ));
        let live = h.d.rules();
        let db = &live.keys[&KeyName::new(DB_KEY).unwrap()];
        assert_eq!(db.roots, vec![PathBuf::from(&rec.root)]);
        assert!(db.hosts.is_empty() && db.commands.is_empty());
        assert!(h.receipts_text().contains("ms init: first rules"));

        // The same proposal again: those keys are no longer fresh, so it is refused; an empty
        // set saves the record with no approval.
        assert_eq!(code(&save(&h, &rec, &rules)), Some(ErrorCode::Invalid));
        let n = h.auth.reasons().len();
        assert!(is_ok(&save(&h, &rec, &proposal(&h, &rec))));
        assert_eq!(h.auth.reasons().len(), n, "nothing to approve");
    }

    // protects=SPEC ProjectList / ProjectGet: one line per project with protected / needs-you
    // counts from the rules in force, the record back as TOML with each key's targets, an
    // unknown slug Invalid, and no value anywhere in the replies; fails_when=counts ignore the
    // rules or a value appears; no_claim=the CLI's rendering (ms-cli projects)
    #[test]
    pub(super) fn project_list_and_get() {
        let h = fresh();
        let rec = shop(&h);
        assert!(matches!(
            h.req(RequestBody::ProjectList),
            ResponseBody::Projects { projects } if projects.is_empty()
        ));
        let rules = proposal(&h, &rec);
        assert!(is_ok(&h.approved(|| save(&h, &rec, &rules))));
        match h.req(RequestBody::ProjectList) {
            ResponseBody::Projects { projects } => {
                assert_eq!(projects.len(), 1);
                let p = &projects[0];
                assert_eq!((p.slug.as_str(), p.protected, p.needs_you), ("shop", 2, 2));
            }
            other => panic!("{other:?}"),
        }
        match h.req(RequestBody::ProjectGet {
            slug: "shop".into(),
        }) {
            ResponseBody::Project { record, keys } => {
                assert_eq!(
                    ms_projects::record::ProjectRecord::from_toml(&record).unwrap(),
                    rec
                );
                let stripe = keys.iter().find(|k| k.key.as_str() == STRIPE_KEY).unwrap();
                assert!(stripe.ready && stripe.stored);
                assert!(stripe.targets.iter().any(|t| t == "api.stripe.com"));
                let unknown = keys.iter().find(|k| k.key.as_str() == UNKNOWN_KEY).unwrap();
                assert!(!unknown.ready && unknown.targets.is_empty());
                assert!(!format!("{record}{keys:?}").contains(CANARY));
            }
            other => panic!("{other:?}"),
        }
        let r = h.req(RequestBody::ProjectGet {
            slug: "nope".into(),
        });
        assert_eq!(code(&r), Some(ErrorCode::Invalid));
    }

    // protects=SPEC criterion 7: a byte flip in projects.toml, a file MAC'd with another key, an
    // older valid file put back (rollback, floor kept in the vault across a restart) and a removed
    // file make ProjectList / ProjectGet / ProjectSave Denied with "integrity check", while swaps
    // for existing keys keep working; fails_when=a tampered record is served or saved over, or
    // keys stop working; no_claim=the store's full tamper table (ms-projects store tests)
    #[test]
    pub(super) fn projects_toml_tamper_fails_closed() {
        let h = fresh();
        let rec = shop(&h);
        let rules = proposal(&h, &rec);
        assert!(is_ok(&h.approved(|| save(&h, &rec, &rules))));
        let file = h.dir.path().join(PROJECTS_FILE);
        let mac = ms_rules::store::mac_path(&file);
        let v1 = (std::fs::read(&file).unwrap(), std::fs::read(&mac).unwrap());
        // A second save (version 2), so v1 is a rollback.
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        let v2 = (std::fs::read(&file).unwrap(), std::fs::read(&mac).unwrap());
        let denied = |h: &H, what: &str| {
            for r in [
                h.req(RequestBody::ProjectList),
                h.req(RequestBody::ProjectGet {
                    slug: "shop".into(),
                }),
                save(h, &rec, &Rules::default()),
            ] {
                assert_eq!(code(&r), Some(ErrorCode::Denied), "{what}: {r:?}");
                assert!(msg(&r).contains("integrity check"), "{what}: {r:?}");
            }
            assert_eq!(
                h.swap(STRIPE_KEY, "api.stripe.com"),
                Decision::Allow,
                "{what}: keys keep working"
            );
        };

        let mut flipped = v2.0.clone();
        let i = flipped.len() / 3;
        flipped[i] ^= 0x20;
        std::fs::write(&file, &flipped).unwrap();
        denied(&h, "byte flip");

        std::fs::write(&file, &v1.0).unwrap();
        std::fs::write(&mac, &v1.1).unwrap();
        denied(&h, "rollback");
        let h = restart(h);
        // The floor survives a restart (it is in the vault, not in memory).
        denied(&h, "rollback after restart");

        let other = MemoryVault::new();
        let k = KeyName::new(crate::backend::PROJECTS_HMAC_KEY).unwrap();
        other
            .put(
                &k,
                SecretBytes::new(vec![3; 32]),
                KeyMeta {
                    name: k.clone(),
                    mode: Mode::Swap,
                    tier: Tier::Production,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let foreign = ms_projects::store::ProjectsStore::new(d2.path().join("p.toml"), &other, k);
        // Saved often enough that its version is above the floor: only the MAC is wrong.
        let mut v = 0;
        for _ in 0..5 {
            v = foreign
                .save(
                    &ms_projects::record::ProjectsFile {
                        version: 0,
                        projects: vec![rec.clone()],
                    },
                    v,
                )
                .unwrap();
        }
        std::fs::copy(d2.path().join("p.toml"), &file).unwrap();
        std::fs::copy(d2.path().join("p.toml.mac"), &mac).unwrap();
        denied(&h, "foreign MAC");

        std::fs::remove_file(&file).unwrap();
        denied(&h, "removed");
        // Put back the latest good file: served again.
        std::fs::write(&file, &v2.0).unwrap();
        std::fs::write(&mac, &v2.1).unwrap();
        assert!(matches!(
            h.req(RequestBody::ProjectList),
            ResponseBody::Projects { .. }
        ));
    }

    // protects=security review S1: with project records on disk, a missing rollback floor in the
    // vault fails closed (an older, validly MAC'd file put back is not served), while a fresh
    // install with no records and no floor works; fails_when=the floor's absence reads as 0 when
    // records exist; no_claim=deleting a keychain item (only msd may; the memory vault stands in)
    #[test]
    pub(super) fn missing_projects_floor_fails_closed() {
        let h = fresh();
        assert!(matches!(
            h.req(RequestBody::ProjectList),
            ResponseBody::Projects { .. }
        ));
        let rec = shop(&h);
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        let file = h.dir.path().join(PROJECTS_FILE);
        let mac = ms_rules::store::mac_path(&file);
        let v1 = (std::fs::read(&file).unwrap(), std::fs::read(&mac).unwrap());
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        let Backend::Memory(v) = &h.backend else {
            panic!("tests use the memory vault")
        };
        v.delete(&KeyName::new(crate::backend::PROJECTS_STATE_KEY).unwrap())
            .unwrap();
        std::fs::write(&file, &v1.0).unwrap();
        std::fs::write(&mac, &v1.1).unwrap();
        let r = h.req(RequestBody::ProjectList);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        let r = save(&h, &rec, &Rules::default());
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
    }

    // protects=review R2: after `msd --init --force` replaces morsec/projects-hmac, the old
    // records are moved aside and the floor reset, so the next ms init saves a fresh record and
    // ProjectList answers (instead of Denied forever); the old file is kept, renamed;
    // fails_when=project requests stay Denied after a reset, or the old file is deleted;
    // no_claim=the keychain reset itself (ms-vault projects_internal_items)
    #[test]
    pub(super) fn force_reset_moves_project_records_aside() {
        let h = fresh();
        let rec = shop(&h);
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        // What --init --force does to the projects key: a new random one.
        let Backend::Memory(v) = &h.backend else {
            panic!("tests use the memory vault")
        };
        let k = KeyName::new(crate::backend::PROJECTS_HMAC_KEY).unwrap();
        v.put(
            &k,
            crate::backend::random_32().unwrap(),
            KeyMeta {
                name: k.clone(),
                mode: Mode::Swap,
                tier: Tier::Production,
                created_unix_ms: 0,
            },
        )
        .unwrap();
        let h = restart(h);
        assert_eq!(
            code(&h.req(RequestBody::ProjectList)),
            Some(ErrorCode::Denied),
            "without the reset the old records can't verify"
        );
        reset_project_records(h.dir.path(), &h.backend, "old-1").unwrap();
        let h = restart(h);
        assert!(matches!(
            h.req(RequestBody::ProjectList),
            ResponseBody::Projects { projects } if projects.is_empty()
        ));
        assert!(is_ok(&save(&h, &rec, &Rules::default())));
        assert!(matches!(
            h.req(RequestBody::ProjectList),
            ResponseBody::Projects { projects } if projects.len() == 1
        ));
        assert!(h.dir.path().join(format!("{PROJECTS_FILE}.old-1")).exists());
        assert!(
            h.dir
                .path()
                .join(format!("{PROJECTS_FILE}.mac.old-1"))
                .exists()
        );
    }

    // ---- L32 dashboard -------------------------------------------------------------------------

    /// A runtime and the dashboard installed on `h`, with `check` as the connection check.
    /// The URLs the test opener was handed (the user's browser, in production).
    type Opened = Arc<Mutex<Vec<String>>>;

    pub(super) fn with_dash(h: &H, check: ConnChecker) -> (tokio::runtime::Runtime, Opened) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        // Below the ephemeral range, where parallel tests' client sockets don't land.
        let port = (0u16..)
            .map(|i| {
                20_000
                    + ((std::process::id() as u16)
                        .wrapping_mul(31)
                        .wrapping_add(i * 97))
                        % 25_000
            })
            .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
            .unwrap();
        let opened: Opened = Arc::default();
        let o = opened.clone();
        let _g = rt.enter();
        crate::dash::install_with(
            &h.d,
            ms_dash::DashConfig::new(port),
            check,
            Arc::new(move |url: &str| {
                lock(&o).push(url.to_owned());
                true
            }),
        );
        drop(_g);
        (rt, opened)
    }

    pub(super) fn dash_open(h: &H, view: Option<&str>) -> ResponseBody {
        h.req(RequestBody::DashOpen {
            view: view.map(str::to_owned),
        })
    }

    pub(super) fn allow_all() -> ConnChecker {
        Arc::new(|_, _| {
            Ok(SessionId {
                agent: AgentKind::Other("dashboard".into()),
                pid: 7,
                started_unix_ms: 1,
            })
        })
    }

    // protects=design §5.3, §6.2.2 and §8 (agent runs ms dashboard to get a token): DashOpen from
    // an agent session is Denied and neither binds nor opens anything; from outside one it starts
    // the listener, opens the browser on the port it holds, also while stopped; a bad view is
    // Invalid; fails_when=an agent's ask binds or opens, or the terminal's doesn't;
    // no_claim=a detached process (it is not an agent session: it gets the same answer as the
    // terminal, which holds no token: dash_open_never_returns_token)
    #[test]
    pub(super) fn dash_open_refused_in_agent_session() {
        let h = fresh();
        let r = dash_open(&h, None);
        assert_eq!(
            code(&r),
            Some(ErrorCode::Internal),
            "no dashboard installed"
        );
        let (_rt, opened) = with_dash(&h, allow_all());
        let r = dash_open(h.as_(agent()), None);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(msg(&r).contains("agent session"), "{r:?}");
        assert_eq!(
            h.d.dash().unwrap().port(),
            None,
            "an agent's ask binds nothing"
        );
        assert!(lock(&opened).is_empty(), "an agent's ask opens nothing");
        h.as_(terminal()).req(RequestBody::Stop);
        match dash_open(&h, Some("project/shop")) {
            ResponseBody::Dash { port, opened: true } => {
                assert_eq!(Some(port), h.d.dash().unwrap().port());
                assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
                let urls = lock(&opened).clone();
                assert_eq!(urls.len(), 1);
                assert!(
                    urls[0].starts_with(&format!("http://127.0.0.1:{port}/#t=")),
                    "{urls:?}"
                );
                assert!(urls[0].ends_with("&v=project/shop"), "{urls:?}");
            }
            other => panic!("{other:?}"),
        }
        for bad in ["project/Shop", "project/a&t=x", "projects", "../x"] {
            assert_eq!(
                code(&dash_open(&h, Some(bad))),
                Some(ErrorCode::Invalid),
                "{bad}"
            );
        }
    }

    // protects=fix round 2 F2: a process looping DashOpen opens no second tab while the last
    // sign-in link is unused, nor within 3 s of the last tab, and gets the same port back, so it
    // can neither flood the browser nor push the real tab's CSRF tokens out; once the link is
    // used and the gap has passed a new tab opens; fails_when=a second tab opens inside either
    // limit; no_claim=-
    #[test]
    pub(super) fn dash_open_is_rate_limited() {
        use std::io::{Read, Write};
        let h = fresh();
        let (_rt, opened) = with_dash(&h, allow_all());
        let port = match dash_open(&h, None) {
            ResponseBody::Dash { port, opened: true } => port,
            other => panic!("{other:?}"),
        };
        for _ in 0..10 {
            assert!(matches!(
                dash_open(&h, None),
                ResponseBody::Dash { port: p, opened: true } if p == port
            ));
        }
        assert_eq!(lock(&opened).len(), 1, "the link is unused: no second tab");
        // The browser signs in with the link.
        let token = lock(&opened)[0].split("#t=").nth(1).unwrap().to_owned();
        let body = format!("{{\"token\":\"{token}\"}}");
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            format!(
                "POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
        let mut got = String::new();
        let _ = c.read_to_string(&mut got);
        assert!(got.starts_with("HTTP/1.1 200"), "{got}");
        let _ = dash_open(&h, None);
        assert_eq!(lock(&opened).len(), 1, "within 3 s of the last tab");
        std::thread::sleep(Duration::from_millis(3200));
        let _ = dash_open(&h, None);
        assert_eq!(lock(&opened).len(), 2, "after the gap");
    }

    // protects=SPEC D-12 and security review S1: the launch token is handed to the browser
    // opener only; the IPC reply to any caller outside an agent session (a detached process
    // included) holds the port and `opened`, never the token, so the caller can't sign in;
    // fails_when=the reply's encoding contains the token or any 64-hex string;
    // no_claim=what the opener does with the URL (LaunchServices)
    #[test]
    pub(super) fn dash_open_never_returns_token() {
        let h = fresh();
        let (_rt, opened) = with_dash(&h, allow_all());
        // A detached process is unattributed, exactly like the user's terminal.
        let reply = dash_open(h.as_(terminal()), None);
        let wire = String::from_utf8(ms_ipc::protocol::encode(1, &reply).unwrap()).unwrap();
        let url = lock(&opened)[0].clone();
        let token = url.split("#t=").nth(1).unwrap();
        assert_eq!(token.len(), 64);
        assert!(!wire.contains(token), "{wire}");
        let hex_run = wire
            .split(|c: char| !c.is_ascii_hexdigit())
            .any(|w| w.len() >= 32);
        assert!(!hex_run, "{wire}");
        assert!(matches!(reply, ResponseBody::Dash { opened: true, .. }));
    }

    // protects=design §6.2.1 and SPEC D-9 (LOG-1, LOG-2): a connection the process check refuses
    // gets no byte, and msd writes a blocked receipt under morsec/dashboard charged to the agent
    // session; fails_when=the refused client reads a response, or no receipt names the session;
    // no_claim=the OS process walk (dash.rs conn_check_* and ms-cli dashboard.rs)
    #[test]
    pub(super) fn refused_connection_writes_blocked_receipt() {
        use std::io::{Read, Write};
        let h = fresh();
        let agent_session = match agent() {
            Caller::Agent(s) => s,
            Caller::Unattributed { .. } => unreachable!(),
        };
        let s2 = agent_session.clone();
        let (_rt, _) = with_dash(
            &h,
            Arc::new(move |_, _| {
                Err(ms_dash::Refusal {
                    session: s2.clone(),
                    why: "a connection from an agent session".into(),
                })
            }),
        );
        let port = match dash_open(&h, None) {
            ResponseBody::Dash { port, .. } => port,
            other => panic!("{other:?}"),
        };
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = c.write_all(format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes());
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        assert!(got.is_empty(), "{}", String::from_utf8_lossy(&got));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let text = h.receipts_text();
            if text.contains("morsec/dashboard") {
                assert!(
                    text.contains("dashboard: a connection from an agent session"),
                    "{text}"
                );
                assert!(text.contains("host_not_allowed"), "{text}");
                assert!(text.contains("claude_code"), "{text}");
                break;
            }
            assert!(std::time::Instant::now() < deadline, "no receipt: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The `shop` fixture saved (approved), a key in no project, a receipt for the Stripe key and
    /// a scan report.
    pub(super) fn dash_fixture(h: &H) {
        let mut rec = shop(h);
        rec.files[0].git_history_commits = Some(2);
        rec.findings.push(ms_projects::record::FindingRecord {
            path: "src/pay.ts".into(),
            line: 4,
            provider: "stripe".into(),
            masked: "sk_live_… (40 bytes)".into(),
        });
        let rules = proposal(h, &rec);
        assert!(is_ok(&h.approved(|| save(h, &rec, &rules))));
        h.put("loose/key", Tier::Test);
        let _ = h.swap(STRIPE_KEY, "api.stripe.com");
        let _ = h.d.record(
            &match agent() {
                Caller::Agent(s) => s,
                Caller::Unattributed { .. } => unreachable!(),
            },
            &KeyName::new(STRIPE_KEY).unwrap(),
            Mode::Swap,
            "api.stripe.com",
            1,
            ReceiptResult::Blocked(Reason::HostNotAllowed),
            None,
        );
        *lock(&h.d.last_scan) = Some((
            5,
            ResponseBody::ScanReport {
                findings: vec![ms_ipc::ScanFinding {
                    file: "/x/t.jsonl".into(),
                    line: 3,
                    key: KeyName::new(STRIPE_KEY).unwrap(),
                    encoding: "raw".into(),
                }],
                files_scanned: 1,
                bytes_scanned: 10,
                keys_checked: 5,
                skipped_keys: Vec::new(),
                notes: Vec::new(),
                complete: true,
            },
        ));
    }

    // protects=SPEC criterion 9: the views show the project's rows (file, line, key, provider,
    // status), code findings, git warnings, keys in no project, a key's hosts and where it is used,
    // receipts with filters (an invalid key matching nothing; the receipt cache following new
    // records), the last scan, and counts on Home; fails_when=a screen misses its data, misreports
    // a status or shows stale receipts; no_claim=the page's rendering (browser pass)
    #[test]
    pub(super) fn dashboard_views_from_records() {
        let h = fresh();
        dash_fixture(&h);
        let home = h.d.dash_home().unwrap();
        assert!(home.running);
        assert_eq!(home.projects, 1);
        assert_eq!(home.keys, 5);
        assert_eq!(home.protected, 2, "{home:?}");
        assert_eq!(
            home.needs_website, 3,
            "unknown, the run key with no command, the loose key"
        );
        assert!(home.blocked_24h >= 1);
        assert_eq!(home.agents.len(), 2);
        // L33 D-6, D-7: the keys not usable yet, in the one vocabulary.
        assert_eq!(home.not_usable.len(), 3);
        let words: Vec<&str> = home.not_usable.iter().map(|k| k.status.as_str()).collect();
        assert!(words.contains(&"needs a command") && words.contains(&"needs a website"));
        assert!(home.warnings.len() >= home.alerts.len().min(1));
        for a in &home.agents {
            // No connect command for an agent that isn't installed (review Q17).
            match &a.command {
                None => assert!(!a.installed && !a.connected),
                Some(c) => assert!(
                    *c == format!("ms connect {}", a.id) || *c == format!("ms disconnect {}", a.id)
                ),
            }
        }

        let ps = h.d.dash_projects_view().unwrap();
        assert_eq!(ps.projects.len(), 1);
        let card = &ps.projects[0];
        assert_eq!((card.protected, card.needs_website), (2, 2));
        assert_eq!((card.findings, card.committed_files), (1, 1));
        assert_eq!(ps.loose.len(), 1);
        assert_eq!(ps.loose[0].key, "loose/key");
        assert!(!ps.loose[0].ready);

        let p = h.d.dash_project("shop").unwrap();
        assert_eq!(p.rows.len(), 4);
        let stripe = p.rows.iter().find(|r| r.key == STRIPE_KEY).unwrap();
        assert_eq!(stripe.status, "protected");
        assert_eq!(stripe.provider.as_deref(), Some("stripe"));
        assert_eq!(stripe.file, ".env");
        assert!(stripe.last_use_unix_ms.is_some());
        let unknown = p.rows.iter().find(|r| r.key == UNKNOWN_KEY).unwrap();
        assert_eq!(unknown.status, "needs a website");
        let db = p.rows.iter().find(|r| r.key == DB_KEY).unwrap();
        assert_eq!(db.status, "needs a command");
        assert_eq!(p.findings[0].masked, "sk_live_… (40 bytes)");
        assert_eq!(p.committed[0].commits, 2);
        assert_eq!(p.not_usable, 2);
        assert_eq!(
            p.dev_command.as_deref(),
            Some(format!("cd '{}' && ms dev -- npm run dev", p.root).as_str())
        );
        assert_eq!(
            p.rescan_command.as_deref(),
            Some(format!("cd '{}' && ms init", p.root).as_str())
        );
        assert_eq!(h.d.dash_project("nope").unwrap_err().status, 404);

        let s = h.d.dash_secret(&KeyName::new(STRIPE_KEY).unwrap()).unwrap();
        assert_eq!(s.hosts, ["api.stripe.com"]);
        assert_eq!(s.used_in.len(), 1);
        assert_eq!(s.used_in[0].var, "VAR_0");
        assert!(s.stored && s.ready);
        assert!(!s.uses.is_empty());
        let db = h.d.dash_secret(&KeyName::new(DB_KEY).unwrap()).unwrap();
        assert_eq!(db.mode.as_deref(), Some("run"));
        assert!(!db.roots.is_empty());
        assert_eq!(
            h.d.dash_secret(&KeyName::new("no/such").unwrap())
                .unwrap_err()
                .status,
            404
        );

        let all =
            h.d.dash_activity(&ms_dash::api::ActivityQuery::default())
                .unwrap();
        assert!(all.matched >= 2);
        let blocked =
            h.d.dash_activity(&ms_dash::api::ActivityQuery {
                result: Some("blocked".into()),
                project: Some("shop".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            blocked
                .rows
                .iter()
                .all(|r| r.result == "blocked" && r.key.starts_with("shop/"))
        );
        assert!(!blocked.rows.is_empty());
        let bad = h.d.dash_activity(&ms_dash::api::ActivityQuery {
            since: Some("yesterday-ish".into()),
            ..Default::default()
        });
        assert_eq!(bad.unwrap_err().status, 400);
        // An invalid key filter matches nothing instead of failing the screen (review R2).
        let none =
            h.d.dash_activity(&ms_dash::api::ActivityQuery {
                key: Some("Not A Key!".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(none.matched, 0);
        assert!(none.total > 0);
        assert_eq!(none.projects, ["shop"]);
        // "other" is any agent the filter has no name for (L33 D-15): the fixture has none.
        let other =
            h.d.dash_activity(&ms_dash::api::ActivityQuery {
                agent: Some("other".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(other.rows.iter().all(|r| !matches!(
            r.agent.as_str(),
            "claude-code" | "codex" | "terminal" | "dashboard" | "ms-dev"
        )));
        // The cached receipts follow new records (review R8).
        let before = h.d.dash_activity(&Default::default()).unwrap().matched;
        let _ = h.swap(STRIPE_KEY, "api.stripe.com");
        let _ = h.d.record(
            &match agent() {
                Caller::Agent(s) => s,
                Caller::Unattributed { .. } => unreachable!(),
            },
            &KeyName::new(STRIPE_KEY).unwrap(),
            Mode::Swap,
            "api.stripe.com",
            1,
            ReceiptResult::Allowed,
            None,
        );
        assert_eq!(
            h.d.dash_activity(&Default::default()).unwrap().matched,
            before + 1
        );
        let (name, ctype, body) =
            h.d.dash_export(&Default::default(), ms_dash::api::ExportFormat::Csv)
                .unwrap();
        assert_eq!(name, "morsec-receipts.csv");
        assert!(ctype.starts_with("text/csv"));
        assert!(String::from_utf8(body).unwrap().contains(STRIPE_KEY));
        assert!(h.d.dash_verify().unwrap().ok);
        assert!(h.d.dash_verify().unwrap().macs_checked);

        let scan = h.d.dash_scan().last.unwrap();
        assert_eq!(scan.findings[0].key, STRIPE_KEY);
        let agents = h.d.dash_agents().unwrap();
        assert!(
            agents
                .checks
                .iter()
                .any(|c| c.text.contains("rules verified"))
        );
    }

    // protects=SPEC D-3 and criterion 10, L33 criterion 22: no dashboard view (Home, Projects,
    // Project, every Secret, Activity, export JSON and CSV, Verify, Agents, Scan) and no action's
    // answer but Show's (Copy, Re-check, check-path, rules, Replace, Delete, Undo, Stop, Start),
    // nor any receipt, carries a vault value: the fixture's keys all hold the canary;
    // fails_when=the canary appears in any serialized view, answer or receipt;
    // no_claim=the HTTP layer (it serializes these same views; ms-cli dashboard.rs fetches them)
    #[test]
    pub(super) fn dashboard_never_serves_a_canary() {
        let h = fresh();
        dash_fixture(&h);
        let mut out = Vec::new();
        out.push(serde_json::to_string(&h.d.dash_home().unwrap()).unwrap());
        out.push(serde_json::to_string(&h.d.dash_projects_view().unwrap()).unwrap());
        out.push(serde_json::to_string(&h.d.dash_project("shop").unwrap()).unwrap());
        for k in [STRIPE_KEY, OPENAI_KEY, DB_KEY, UNKNOWN_KEY, "loose/key"] {
            out.push(
                serde_json::to_string(&h.d.dash_secret(&KeyName::new(k).unwrap()).unwrap())
                    .unwrap(),
            );
        }
        out.push(serde_json::to_string(&h.d.dash_activity(&Default::default()).unwrap()).unwrap());
        for f in [
            ms_dash::api::ExportFormat::Json,
            ms_dash::api::ExportFormat::Csv,
        ] {
            out.push(
                String::from_utf8(h.d.dash_export(&Default::default(), f).unwrap().2).unwrap(),
            );
        }
        out.push(serde_json::to_string(&h.d.dash_verify().unwrap()).unwrap());
        out.push(serde_json::to_string(&h.d.dash_agents().unwrap()).unwrap());
        out.push(serde_json::to_string(&h.d.dash_scan()).unwrap());
        // L33: every action's answer but Show's (which is the value, behind Touch ID).
        let a = ms_dash::Actor {
            session: SessionId {
                agent: AgentKind::Other("dashboard".into()),
                pid: 7,
                started_unix_ms: 1,
            },
            peer: "127.0.0.1:50000".parse().unwrap(),
            local: "127.0.0.1:7311".parse().unwrap(),
        };
        let paste = Arc::new(crate::pasteboard::fake::Fake::default());
        h.d.set_clipboard(Arc::new(crate::pasteboard::Marked(paste.clone())));
        let k = KeyName::new(STRIPE_KEY).unwrap();
        out.push(format!("{:?}", h.d.dash_copy(&a, &k)));
        out.push(format!("{:?}", h.d.dash_recheck()));
        out.push(format!("{:?}", h.d.dash_check_path("/")));
        out.push(format!(
            "{:?}",
            h.d.dash_rules(
                &a,
                &k,
                &ms_dash::actions::RuleEdit::AddHost("files.stripe.com".into())
            )
        ));
        out.push(format!(
            "{:?}",
            h.d.dash_replace(
                &a,
                &KeyName::new("loose/key").unwrap(),
                SecretBytes::new(CANARY.as_bytes().to_vec())
            )
        ));
        out.push(format!("{:?}", h.d.dash_delete(&a, &k, false)));
        out.push(format!("{:?}", h.d.dash_undo(&a, Some("shop"), None)));
        out.push(format!("{:?}", h.d.dash_stop(&a)));
        out.push(format!("{:?}", h.d.dash_start(&a)));
        out.push(serde_json::to_string(&h.d.dash_home().unwrap()).unwrap());
        out.push(h.receipts_text());
        assert_eq!(
            paste.text().as_deref(),
            Some(CANARY),
            "Copy went to the pasteboard"
        );
        let all = out.join("\n");
        assert!(all.contains(STRIPE_KEY), "the views were built");
        assert!(!all.contains(CANARY), "a value reached a view");
        assert!(
            !all.contains(&CANARY[8..]),
            "part of a value reached a view"
        );
    }

    // ---- L34 ms-dev ----
    mod dev_tests {
        use super::*;
        include!("daemon/dev_tests.rs");
    }
}
