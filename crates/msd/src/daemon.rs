//! The daemon's shared state and its IPC request handling.
//!
//! One [`Daemon`] owns the vault backend, the receipts store, the live rules (with the kill-switch
//! flag) and the set of sessions a LOG-2 alert stopped. The socket handler and the swap proxy
//! both read it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use ms_approve::{ApprovalOutcome, Approver};
use ms_core::{
    AgentKind, ApprovalRequest, KeyMeta, KeyName, Mode, ReceiptEvent, ReceiptResult, SecretBytes,
    SessionId, Tier,
};
use ms_ipc::{ErrorCode, PeerInfo, RequestBody, ResponseBody};
use ms_receipts::{Alert, AlertAction, AlertHandler, ReceiptDetail, ReceiptStore, StoreConfig};
use ms_rules::{Change, KeyRule, Rules, RulesError, RulesStore, is_reserved};
use ms_session::Caller;
use ms_vault::{Vault, VaultExt};
use tokio::sync::watch;

mod run;

use crate::approve::PRE_L11;
use crate::backend::{Backend, DAEMON_STATE_KEY, RULES_HMAC_KEY};
use crate::paths::Paths;

/// The reserved key daemon events (stop, start, init) are recorded under.
pub const DAEMON_KEY: &str = "morsec/daemon";
/// Approval method recorded for the pre-L11 terminal path (SPEC D-A).
pub const TERMINAL_METHOD: &str = "terminal-pre-l11";
/// How long an approval may take.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
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
    approver: Arc<dyn Approver>,
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
        approver: Arc<dyn Approver>,
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
        Ok(Arc::new(Self {
            backend,
            vault,
            paths,
            mac_key,
            receipts: Arc::new(receipts),
            live: RwLock::new(Live { rules, min_version }),
            stopped_sessions,
            alerts: Mutex::new(alerts),
            identify,
            approver,
            proxy_gen,
            proxy_port,
            write: Mutex::new(()),
            flag: Mutex::new(()),
            ca: Mutex::new(None),
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

    /// The approver (L11 replaces the stub).
    pub fn approver(&self) -> Arc<dyn Approver> {
        self.approver.clone()
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
        let unattributed = matches!(caller, Some(Caller::Unattributed { .. }));
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
            RequestBody::RulesProposeLoosen {
                key,
                rule,
                at_terminal,
            } => self.propose(&session, unattributed, &key, rule.as_deref(), at_terminal),
            RequestBody::Stop => self.stop(&session),
            RequestBody::Start { at_terminal } => self.start(&session, unattributed, at_terminal),
            // A scan answers "is this value in a file I can write?": an oracle for short values,
            // so only the user's own terminal may ask (L09 SPEC D-3).
            RequestBody::Scan if in_agent => reply_err(
                ErrorCode::Denied,
                "morsec: ms scan can't run inside an agent session. Run it from your own terminal",
            ),
            RequestBody::Scan => self.scan(&session),
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

    /// Pre-L11 approval for an administrative change (SPEC D-A): the stub approver first, then
    /// the terminal path for an unattributed caller that confirmed at its terminal.
    // The error is the reply itself; it is built once per refused request, so its size is moot.
    #[allow(clippy::result_large_err)]
    fn admin_approval(
        &self,
        session: &SessionId,
        unattributed: bool,
        at_terminal: bool,
        key: &KeyName,
        argv: Vec<String>,
    ) -> Result<Option<&'static str>, ResponseBody> {
        if at_terminal {
            if unattributed {
                return Ok(Some(TERMINAL_METHOD));
            }
            return Err(reply_err(
                ErrorCode::Denied,
                "morsec: --at-terminal only works from your own terminal, outside any agent session. Run it there",
            ));
        }
        let req = ApprovalRequest {
            session: session.clone(),
            key: key.clone(),
            tier: Tier::Production,
            argv_hash: ms_rules::argv_hash(&argv),
            argv_display: argv,
            cwd: std::path::PathBuf::new(),
            effect: None,
        };
        match self.approver.ask(&req, APPROVAL_TIMEOUT) {
            ApprovalOutcome::Approved(_) => Ok(None),
            ApprovalOutcome::Denied | ApprovalOutcome::TimedOut => Err(reply_err(
                ErrorCode::NeedsApproval,
                format!(
                    "morsec: this needs an approval, and {PRE_L11}. Until then, run the same command from your own terminal (not inside an agent) with --at-terminal"
                ),
            )),
        }
    }

    fn propose(
        &self,
        session: &SessionId,
        unattributed: bool,
        key: &KeyName,
        rule: Option<&str>,
        at_terminal: bool,
    ) -> ResponseBody {
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
        let method = match change {
            Change::Same => {
                return ResponseBody::Ok {
                    message: format!("no change to {key}"),
                };
            }
            Change::Tighten => None,
            Change::Loosen => {
                let argv = vec!["ms".into(), "rules".into(), key.to_string()];
                match self.admin_approval(session, unattributed, at_terminal, key, argv) {
                    Ok(m) => m.or(Some("approver")),
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
        let mode = new_rule
            .as_ref()
            .or(current.as_ref())
            .map_or(Mode::Swap, |r| r.mode);
        match self.change_rule(key, new_rule, change == Change::Loosen && method.is_some()) {
            Ok((version, _)) => {
                let result = if change == Change::Loosen {
                    ReceiptResult::Approved
                } else {
                    ReceiptResult::Allowed
                };
                if let Err(e) = self.record(
                    session,
                    key,
                    mode,
                    if change == Change::Loosen {
                        "rules change (loosen)"
                    } else {
                        "rules change (tighten)"
                    },
                    version,
                    result,
                    method.filter(|m| *m != "approver"),
                ) {
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
        // No proxy rebuild: the proxy's session resolver returns no session while stopped, so
        // the next request is refused without the listener going away.
        let mut message = "morsec stopped: every agent request is now refused. Resume from your own terminal with: ms init --resume (ms start once Touch ID arrives in L11)".to_owned();
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

    fn start(&self, session: &SessionId, unattributed: bool, at_terminal: bool) -> ResponseBody {
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        if !self.is_stopped() {
            return ResponseBody::Ok {
                message: "morsec is already on".into(),
            };
        }
        let key = daemon_key();
        let method = match self.admin_approval(
            session,
            unattributed,
            at_terminal,
            &key,
            vec!["ms".into(), "start".into()],
        ) {
            Ok(m) => m,
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
                return match resp {
                    ResponseBody::Error {
                        code: ErrorCode::NeedsApproval,
                        ..
                    } => reply_err(
                        ErrorCode::NeedsApproval,
                        format!(
                            "morsec: ms start needs Touch ID, and {PRE_L11}. Until then, resume from your own terminal (not inside an agent): ms init --resume"
                        ),
                    ),
                    other => other,
                };
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
        if let Err(e) = self.record(
            session,
            &key,
            Mode::Run,
            "ms start",
            version,
            ReceiptResult::Approved,
            method,
        ) {
            tracing::error!(error = %e, "could not record ms start");
        }
        ResponseBody::Ok {
            message: "morsec on".into(),
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
    use crate::approve::DenyApprover;
    use ms_core::{Decision, Reason, Request};
    use ms_vault::memory::MemoryVault;

    const CANARY: &str = "sk_test_MSD_CANARY_5b1e";

    struct H {
        d: Arc<Daemon>,
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

    fn open_with(backend: Backend, dir: tempfile::TempDir, who: Arc<Mutex<Option<Caller>>>) -> H {
        let w = who.clone();
        let identify: Identify = Arc::new(move |_| lock(&w).clone());
        let d = Daemon::open(
            backend.clone(),
            Paths::under(dir.path()),
            0,
            Arc::new(DenyApprover),
            identify,
        )
        .unwrap();
        H {
            d,
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
        let r = h.propose(
            "stripe/test",
            Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n"),
            true,
        );
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

    // protects=ms start needs an approval: the pre-L11 stub denies it with the --resume hint, the
    // terminal path is refused for an agent caller, and works for an unattributed caller (recorded
    // as terminal-pre-l11), persisting across a restart; fails_when=an agent resumes morsec or a
    // plain ms start succeeds before L11; no_claim=that an unattributed caller is a person (SPEC D-A
    // residual)
    #[test]
    fn start_needs_approval_or_terminal() {
        let h = fresh();
        h.req(RequestBody::Stop);
        let r = h.req(RequestBody::Start { at_terminal: false });
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval));
        assert!(msg(&r).contains("ms init --resume"), "{r:?}");
        let r = h.as_(agent()).req(RequestBody::Start { at_terminal: true });
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        assert!(h.d.is_stopped());
        let r = h
            .as_(terminal())
            .req(RequestBody::Start { at_terminal: true });
        assert!(is_ok(&r), "{r:?}");
        assert!(!h.d.is_stopped());
        assert!(h.receipts_text().contains(TERMINAL_METHOD));
        let h = restart(h);
        assert!(!h.d.is_stopped());
    }

    // protects=rules over IPC (open from L03): tightening is saved without approval; loosening is
    // refused (NeedsApproval) without one, refused on the terminal path for an agent, saved on the
    // terminal path from a terminal; reserved keys and multi-key payloads are refused; RulesGet
    // returns the saved rules; fails_when=an agent loosens a rule; no_claim=Touch ID (L11)
    #[test]
    fn rules_changes() {
        let h = fresh();
        h.put("stripe/test", Tier::Test);
        let loose = "mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\", \"files.stripe.com\"]\n";
        let r = h.as_(agent()).propose("stripe/test", Some(loose), false);
        assert_eq!(code(&r), Some(ErrorCode::NeedsApproval), "{r:?}");
        let r = h.as_(agent()).propose("stripe/test", Some(loose), true);
        assert_eq!(code(&r), Some(ErrorCode::Denied), "{r:?}");
        let r = h.as_(terminal()).propose("stripe/test", Some(loose), true);
        assert!(is_ok(&r), "{r:?}");
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
        let r = h.propose(
            "stripe/test",
            Some("mode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\"]\n"),
            true,
        );
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
            code(&h.req(RequestBody::Start { at_terminal: true })),
            Some(ErrorCode::Denied)
        );
        assert!(is_ok(&h.req(RequestBody::Stop)));
        assert_eq!(
            code(&h.req(RequestBody::Start { at_terminal: true })),
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
        for _ in 0..50 {
            let (a, b) = (h.clone(), h.clone());
            let t1 = std::thread::spawn(move || {
                a.as_(terminal())
                    .req(RequestBody::Start { at_terminal: true })
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
        assert!(is_ok(
            &h.as_(terminal())
                .req(RequestBody::Start { at_terminal: true })
        ));
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
