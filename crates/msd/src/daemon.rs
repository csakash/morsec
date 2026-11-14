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
use ms_vault::{Vault, VaultExt};
use tokio::sync::watch;

mod run;
mod ssh_git;

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
    alerts: Mutex<Vec<String>>,
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
    /// Counts `ms stop`s, so a resume approved before a newer stop can't undo it.
    stops: std::sync::atomic::AtomicU64,
    /// The proxy CA in use (certificate PEM, hosts), when a host is bound.
    ca: Mutex<Option<(String, Vec<String>)>>,
    /// This daemon, for work that outlives a request (L16: a run's SSH agent records receipts
    /// and checks `ms stop` while the run lasts).
    me: std::sync::Weak<Daemon>,
    /// What `ms doctor --probe` runs reported, and the canaries the proxy saw (L17).
    probes: Arc<crate::doctor::Probes>,
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
        let mut alerts = Vec::new();

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
            alerts: Mutex::new(alerts),
            identify,
            approvals,
            approval_timeout_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(APPROVAL_TIMEOUT.as_millis()).unwrap_or(120_000),
            ),
            proxy_gen,
            proxy_port,
            write: Mutex::new(()),
            flag: Mutex::new(()),
            ca: Mutex::new(None),
            probes: Arc::default(),
            stops: std::sync::atomic::AtomicU64::new(0),
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
        Arc::new(VerifyingApprover(self.approvals.clone()))
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
        let what = render_what(req);
        match self.approvals.ask(req, self.approval_timeout()) {
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
                    "morsec: {what} was not approved (denied in ms approve, Touch ID did not confirm, ms stop ran, or this session asked again within {}s of a refusal)",
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
        lock(&self.alerts).retain(|a| !a.starts_with(prefix));
    }

    /// Adds an alert for `ms status` (deduplicated, bounded).
    pub fn alert(&self, msg: impl Into<String>) {
        let msg = msg.into();
        let mut a = lock(&self.alerts);
        if !a.contains(&msg) {
            if a.len() >= MAX_ALERTS {
                a.remove(0);
            }
            a.push(msg);
        }
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
            RequestBody::DoctorProbe { nonce, report } => self.probes.handle(
                match &caller {
                    Some(Caller::Agent(s)) => Some(s.clone()),
                    _ => None,
                },
                nonce.as_deref(),
                report,
                now_ms(),
            ),
            RequestBody::Run { argv, cwd, env } => run::run_buffered(self, peer, argv, cwd, env),
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
        if let Err(resp) = self.approve_exact(&req) {
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
        if self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec was stopped (ms stop) while the scan waited for approval",
            );
        }
        let keys = match self.list_keys() {
            Ok(k) => k,
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        // A stop during the scan withholds the report even if morsec was resumed since (review F2).
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let report = crate::scan::scan(
            &*self.vault,
            keys.iter().map(|m| m.name.clone()).collect(),
            &crate::scan::roots(),
            crate::scan::SCAN_BUDGET,
        );
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
        report
    }

    fn list_keys(&self) -> ms_core::Result<Vec<KeyMeta>> {
        Ok(self
            .vault
            .list()?
            .into_iter()
            .filter(|m| !is_reserved(&m.name))
            .collect())
    }

    fn status(&self) -> ResponseBody {
        let keys = match self.list_keys() {
            Ok(k) => Some(u32::try_from(k.len()).unwrap_or(u32::MAX)),
            Err(e) => {
                self.alert(format!("the vault could not be listed: {e}"));
                None
            }
        };
        let (running, tampered) = {
            let l = self.read_live();
            (!l.rules.stopped, l.rules.tampered)
        };
        let mut alerts = lock(&self.alerts).clone();
        if tampered && !alerts.iter().any(|a| a.contains("integrity")) {
            alerts.push("the rules failed their integrity check, so every key is denied".into());
        }
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
        let exists = match self.vault.list() {
            Ok(list) => list.iter().any(|m| m.name == name),
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        // Replacing a key changes what morsec sends on the user's behalf. From inside an agent
        // session that is refused; a person replaces keys from their own terminal.
        if exists && in_agent {
            return reply_err(
                ErrorCode::Denied,
                format!(
                    "morsec: {name} already exists, and keys can't be replaced from inside an agent session. Replace it from your own terminal: ms add {name}"
                ),
            );
        }
        let (mode, tier) = (meta.mode, meta.tier);
        if let Err(e) = self.vault.put(&name, value, meta) {
            return reply_err(ErrorCode::Internal, e.to_string());
        }
        // A new key gets a rule that allows nothing until the user adds hosts or commands.
        let mut note = String::new();
        let needs_rule = !self.read_live().rules.keys.contains_key(&name);
        if needs_rule {
            match self.change_rule(&name, Some(KeyRule::new(mode, tier)), false) {
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
            "ms add",
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
                self.alert(format!(
                    "the rules version could not be saved in the vault ({e})"
                ));
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
                match self.approve_exact(&req) {
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
        let _f = lock(&self.flag);
        self.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // In memory first: from here on every request is refused, whatever happens below.
        let version = {
            let mut l = self.write_live();
            l.rules.stopped = true;
            l.rules.version
        };
        // Every approval token and session grant ends now; a request waiting for a person is
        // denied (L11).
        if let Err(e) = self.approvals.revoke_all() {
            tracing::error!(error = %e, "could not revoke approvals");
        }
        // No proxy rebuild: the proxy's session resolver returns no session while stopped, so
        // the next request is refused without the listener going away.
        let mut message = "morsec stopped: every agent request is now refused. Resume from your own terminal with: ms start (needs Touch ID)".to_owned();
        if let Err(e) = self.persist_state(true) {
            tracing::error!(error = %e, "could not persist the stop flag");
            self.alert(format!(
                "ms stop could not be saved in the vault ({e}); if msd restarts it may resume"
            ));
            message.push_str(&format!(
                ". Warning: the stop could not be saved in the vault ({e}), so a restart of msd would resume"
            ));
        }
        if let Err(e) = self.record(
            session,
            &daemon_key(),
            Mode::Run,
            "ms stop",
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
        let token = match self.approve_exact(&admin_request(
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
        // The approval happens outside the lock (a Touch ID prompt must not hold up ms stop);
        // the flag is re-checked under it, so a concurrent stop can't be undone.
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
        if let Err(e) = self.record_approved(session, &key, Mode::Run, "ms start", version, &token)
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ms_approve::auth::fake::FakeAuthenticator;
    use ms_core::{Decision, Reason, Request};
    use ms_vault::memory::MemoryVault;

    const CANARY: &str = "sk_test_MSD_CANARY_5b1e";

    struct H {
        d: Arc<Daemon>,
        auth: Arc<FakeAuthenticator>,
        backend: Backend,
        dir: tempfile::TempDir,
        who: Arc<Mutex<Option<Caller>>>,
    }

    fn agent() -> Caller {
        Caller::Agent(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
            started_unix_ms: 1,
        })
    }

    fn terminal() -> Caller {
        Caller::Unattributed {
            pid: 43,
            started_unix_ms: 1,
        }
    }

    fn peer() -> PeerInfo {
        PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(42),
            accepted_unix_ms: 1,
        }
    }

    /// The PID of the person's `ms approve` (always outside any agent), and of an agent's
    /// process trying to approve.
    const APPROVER_PID: i32 = 99;
    const AGENT_APPROVER_PID: i32 = 98;

    fn peer_pid(pid: i32) -> PeerInfo {
        PeerInfo {
            pid: Some(pid),
            ..peer()
        }
    }

    fn open_with(backend: Backend, dir: tempfile::TempDir, who: Arc<Mutex<Option<Caller>>>) -> H {
        open_auth(backend, dir, who, FakeAuthenticator::approve())
    }

    fn open_auth(
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
        H {
            d,
            auth,
            backend,
            dir,
            who,
        }
    }

    fn fresh() -> H {
        let dir = tempfile::tempdir().unwrap();
        open_with(
            Backend::Memory(Arc::new(MemoryVault::new())),
            dir,
            Arc::new(Mutex::new(Some(terminal()))),
        )
    }

    /// Closes and reopens the daemon over the same vault and files (a restart).
    fn restart(h: H) -> H {
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
        fn as_(&self, c: Caller) -> &Self {
            *lock(&self.who) = Some(c);
            self
        }
        fn req(&self, r: RequestBody) -> ResponseBody {
            self.d.handle(&peer(), r, None)
        }
        fn put(&self, name: &str, tier: Tier) -> ResponseBody {
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
        fn propose(&self, key: &str, rule: Option<&str>, at_terminal: bool) -> ResponseBody {
            self.req(RequestBody::RulesProposeLoosen {
                key: KeyName::new(key).unwrap(),
                rule: rule.map(|r| format!("version = 1\n[keys.\"{key}\"]\n{r}")),
                at_terminal,
            })
        }
        /// Runs `f` (which waits for an approval) while a person at `approver_pid` answers the
        /// pending request with `approve` / `scope`. Returns `f`'s reply and the decision's.
        fn answered(
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
        fn approved(&self, f: impl FnOnce() -> ResponseBody + Send) -> ResponseBody {
            let (out, decision) = self.answered(APPROVER_PID, true, None, f);
            assert!(is_ok(&decision), "{decision:?}");
            out
        }
        fn swap(&self, key: &str, host: &str) -> Decision {
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
        fn receipts_text(&self) -> String {
            let mut out = String::new();
            for e in std::fs::read_dir(self.dir.path().join("receipts")).unwrap() {
                out.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap());
            }
            out
        }
    }

    fn is_ok(r: &ResponseBody) -> bool {
        matches!(r, ResponseBody::Ok { .. })
    }

    fn code(r: &ResponseBody) -> Option<ErrorCode> {
        match r {
            ResponseBody::Error { code, .. } => Some(*code),
            _ => None,
        }
    }

    fn msg(r: &ResponseBody) -> String {
        match r {
            ResponseBody::Error { message, .. } | ResponseBody::Ok { message } => message.clone(),
            other => format!("{other:?}"),
        }
    }

    // protects=PutKey stores end to end (L04's missing reply): Ok, listed by ListKeys (never with a
    // value), a new key gets a rule that allows nothing, reserved names and agent replacements are
    // refused, a terminal replacement works, and the value never reaches receipts;
    // fails_when=an agent can overwrite a key, a morsec/ key can be written, or a new key is usable
    // before the user allows a target; no_claim=the keychain backend (L01 tests it)
    #[test]
    fn put_key_and_list() {
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
        assert!(is_ok(&h.as_(terminal()).put("stripe/test", Tier::Test)));
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

    // protects=AUTH-4 kill switch: after Stop the next decision is Deny(Stopped), status says
    // stopped, and a restart of msd keeps it stopped (the flag is in the vault); fails_when=the
    // next request is allowed, or killing msd resumes it; no_claim=the proxy path (tests/cli.rs)
    #[test]
    fn stop_is_immediate_and_survives_restart() {
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
    fn start_needs_touch_id_approval() {
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
    fn failed_touch_id_denies() {
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
    fn approvals_ipc_rules() {
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
    fn rules_changes() {
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
    fn loosening_while_stopped_and_downgrade_tier() {
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
    fn tampered_and_rolled_back_rules_fail_closed() {
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
    fn log2_alert_stops_the_session() {
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
    fn scan_refused_inside_agent() {
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
    fn unidentified_caller_is_refused() {
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
    fn stop_and_start_are_serialized() {
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
    fn state_format() {
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
    fn unreadable_state_never_persists_a_sentinel_floor() {
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
    fn ca_comes_from_the_vault_not_the_file() {
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
    fn unreadable_stop_flag_means_stopped() {
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
}
