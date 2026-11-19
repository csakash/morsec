//! `ms dev` sessions (L34, SPEC D-1 to D-8): the user's own command, served by the swap proxy.
//!
//! `DevStart` comes from `ms dev` in the user's terminal. msd refuses it inside an agent session,
//! while stopped, for an agent binary and outside every recorded project root; asks one Touch ID
//! when a key of the project is production; then binds a dev session to the **`ms dev` process**
//! (the kernel peer: PID and start time) and hands back a random proxy credential. The proxy
//! serves a connection as that session only when it presents the credential **and** its process
//! has the `ms dev` process on its parent chain with no agent above it (`proxy.rs`), so a copied
//! credential is useless outside the tree. Dev sessions use only their project's keys.
//!
//! Run-mode values of the project's keys whose rule names a root holding the cwd go back to
//! `ms dev` as raw frames after the reply (never in JSON), for the child's environment.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use ms_approve::ApprovalToken;
use ms_core::{
    AgentKind, ApprovalRequest, KeyName, Mode, ReceiptResult, SecretBytes, SessionId, Tier,
};
use ms_ipc::{ErrorCode, ResponseBody};
use ms_projects::record::ProjectRecord;
use ms_session::Caller;
use ms_vault::VaultExt;

use super::{Daemon, daemon_key, lock, reply_err};

/// The agent name dev sessions carry in receipts and policy: `other("ms-dev")`. Nothing else
/// makes it (the walk names only real agents; unattributed callers are `other("terminal")`).
pub const DEV_AGENT: &str = "ms-dev";

/// Most dev sessions held at once (each is one `ms dev` process).
const MAX_DEV_SESSIONS: usize = 64;

/// One running `ms dev`.
#[derive(Debug, Clone)]
pub struct DevSession {
    /// Public id (for `DevEnd` and logs).
    pub id: String,
    /// `other("ms-dev")` with the `ms dev` process's PID and start time.
    pub session: SessionId,
    /// The project.
    pub slug: String,
    /// Every key of the project: the only keys this session may use.
    pub keys: BTreeSet<KeyName>,
    /// The production keys the one approval covered.
    pub production: BTreeSet<KeyName>,
    /// The approval for this run, when a key was production.
    pub approval: Option<ApprovalToken>,
}

/// The dev sessions, by credential. Memory only: a restart ends them all.
#[derive(Debug, Default)]
pub struct DevSessions(std::sync::Mutex<HashMap<String, DevSession>>);

impl DevSessions {
    /// How many are held (tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        lock(&self.0).len()
    }

    fn by_session(&self, s: &SessionId) -> Option<DevSession> {
        lock(&self.0).values().find(|d| d.session == *s).cloned()
    }
}

/// The session id a dev session is recorded under.
pub fn dev_session_id(pid: u32, started_unix_ms: u64) -> SessionId {
    SessionId {
        agent: AgentKind::Other(DEV_AGENT.into()),
        pid,
        started_unix_ms,
    }
}

/// True for a dev session's id.
pub fn is_dev(s: &SessionId) -> bool {
    matches!(&s.agent, AgentKind::Other(a) if a == DEV_AGENT)
}

fn hex_random(n: usize) -> Result<String, String> {
    let b = crate::backend::random_32().map_err(|e| e.to_string())?;
    Ok(hex::encode(&b.expose()[..n.min(32)]))
}

/// The agent a program name is, after the last `/` (L34 SPEC D-8).
pub fn agent_binary(argv0: &str) -> Option<AgentKind> {
    let base = argv0.rsplit('/').next().unwrap_or(argv0);
    ms_session::agent_kind(base)
}

/// The project whose root holds `cwd` (both canonical); the deepest root wins.
pub fn project_for<'a>(projects: &'a [ProjectRecord], cwd: &Path) -> Option<&'a ProjectRecord> {
    projects
        .iter()
        .filter(|p| cwd.starts_with(Path::new(&p.root)))
        .max_by_key(|p| p.root.len())
}

/// The variables to give values (L34 SPEC D-3): every recorded variable of `record` whose key is
/// run mode with a rule root holding `cwd`, by variable name. A variable recorded with two
/// different keys takes the root `.env`'s key, else is skipped with a note. Names the run
/// mode would never put a reference in (PATH, loaders, proxies…) are skipped.
pub fn run_env(
    record: &ProjectRecord,
    rules: &ms_rules::Rules,
    cwd: &Path,
    notes: &mut Vec<String>,
) -> BTreeMap<String, KeyName> {
    if rules.tampered || rules.stopped {
        return BTreeMap::new();
    }
    let runs = |k: &KeyName| {
        rules.keys.get(k).is_some_and(|r| {
            r.mode == Mode::Run && r.roots.iter().any(|root| cwd.starts_with(root))
        })
    };
    let mut seen: BTreeMap<String, Vec<(&str, &KeyName)>> = BTreeMap::new();
    for f in &record.files {
        for s in &f.secrets {
            if runs(&s.key) {
                seen.entry(s.var.clone())
                    .or_default()
                    .push((f.path.as_str(), &s.key));
            }
        }
    }
    let mut out = BTreeMap::new();
    for (var, uses) in seen {
        if !ms_run::input::env_name_allowed(&var) {
            notes.push(format!(
                "{var} was not set: morsec never puts a value in a variable that changes how programs load code or connect"
            ));
            continue;
        }
        let keys: BTreeSet<&KeyName> = uses.iter().map(|(_, k)| *k).collect();
        let chosen = if keys.len() == 1 {
            keys.into_iter().next()
        } else {
            uses.iter().find(|(p, _)| *p == ".env").map(|(_, k)| *k)
        };
        match chosen {
            Some(k) => {
                out.insert(var, k.clone());
            }
            None => notes.push(format!(
                "{var} was not set: it holds different keys in different files and none of them is the root .env"
            )),
        }
    }
    out
}

impl Daemon {
    /// The dev session a proxy credential names, if it is live.
    pub fn dev_by_credential(&self, credential: &str) -> Option<SessionId> {
        lock(&self.dev.0).get(credential).map(|d| d.session.clone())
    }

    /// The dev session with this id, if any.
    pub fn dev_session(&self, s: &SessionId) -> Option<DevSession> {
        if !is_dev(s) {
            return None;
        }
        self.dev.by_session(s)
    }

    /// Drops every dev session whose `ms dev` process is gone (`alive(pid, start)` false).
    pub fn reap_dev(&self, alive: impl Fn(u32, u64) -> bool) -> usize {
        let mut m = lock(&self.dev.0);
        let before = m.len();
        m.retain(|_, d| alive(d.session.pid, d.session.started_unix_ms));
        before - m.len()
    }

    /// Ends every dev session (`ms stop`).
    pub(super) fn end_all_dev(&self) {
        lock(&self.dev.0).clear();
    }

    /// Policy hook (SPEC D-5): a dev session may use only its project's keys, and only while
    /// it is registered. `None` means "decide as for anyone".
    pub(super) fn dev_refusal(&self, s: &SessionId, key: &KeyName) -> Option<ms_core::Reason> {
        if !is_dev(s) {
            return None;
        }
        match self.dev.by_session(s) {
            None => Some(ms_core::Reason::Stopped),
            Some(d) if !d.keys.contains(key) => Some(ms_core::Reason::NoSuchKey),
            Some(_) => None,
        }
    }

    /// Approver hook (SPEC D-4): a production key of this dev session's project, covered by the
    /// run's one approval, gets that approval's token; anything else asks a person.
    pub(super) fn dev_approval(&self, req: &ApprovalRequest) -> Option<ApprovalToken> {
        let d = self.dev_session(&req.session)?;
        if d.production.contains(&req.key) {
            d.approval
        } else {
            None
        }
    }

    /// `DevEnd`: only the `ms dev` process that started the session may end it.
    pub(super) fn dev_end(&self, caller: Option<&Caller>, id: &str) -> ResponseBody {
        let Some(Caller::Unattributed {
            pid,
            started_unix_ms,
        }) = caller
        else {
            return reply_err(
                ErrorCode::Denied,
                "morsec: only the ms dev process that started a session can end it",
            );
        };
        let me = dev_session_id(*pid, *started_unix_ms);
        let mut m = lock(&self.dev.0);
        let before = m.len();
        m.retain(|_, d| {
            let ends = d.id == id && d.session == me;
            if ends {
                tracing::info!(project = %d.slug, pid = d.session.pid, "ms dev session ended");
            }
            !ends
        });
        if m.len() == before {
            return reply_err(
                ErrorCode::Denied,
                "morsec: no such ms dev session for this process",
            );
        }
        ResponseBody::Ok {
            message: "ms dev session ended".into(),
        }
    }

    /// `DevStart` (SPEC D-1 to D-8). Returns the reply and the values that follow it.
    pub(super) fn dev_start(
        &self,
        caller: Option<&Caller>,
        argv: &[String],
        cwd: &Path,
    ) -> (ResponseBody, Vec<SecretBytes>) {
        let none = |r: ResponseBody| (r, Vec::new());
        let (pid, started) = match caller {
            Some(Caller::Unattributed {
                pid,
                started_unix_ms,
            }) => (*pid, *started_unix_ms),
            Some(Caller::Agent(_)) => {
                return none(reply_err(
                    ErrorCode::Denied,
                    "morsec: ms dev runs your own command with your project's keys, so it can't start inside an agent session. Run it in your own terminal",
                ));
            }
            None => {
                return none(reply_err(
                    ErrorCode::Denied,
                    "morsec: the process asking can't be identified, so ms dev was refused",
                ));
            }
        };
        if self.is_stopped() {
            return none(reply_err(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop), so ms dev can't start. Resume first with: ms start",
            ));
        }
        let Some(argv0) = argv.first().filter(|a| !a.is_empty()) else {
            return none(reply_err(
                ErrorCode::Invalid,
                "morsec: give the command to run after ms dev --",
            ));
        };
        if argv.len() > 256 || argv.iter().any(|a| a.len() > 4096 || a.contains('\0')) {
            return none(reply_err(
                ErrorCode::Invalid,
                "morsec: the command is too long for ms dev",
            ));
        }
        if let Some(kind) = agent_binary(argv0) {
            return none(reply_err(
                ErrorCode::Denied,
                format!(
                    "morsec: ms dev doesn't start coding agents ({kind:?}): an agent would get your project's run-mode values. Start agents normally; morsec swaps keys for them"
                ),
            ));
        }
        let Ok(cwd) = std::fs::canonicalize(cwd) else {
            return none(reply_err(
                ErrorCode::Invalid,
                "morsec: the working directory can't be resolved",
            ));
        };
        let (file, _) = match self.load_projects() {
            Ok(f) => f,
            Err(r) => return none(r),
        };
        let Some(record) = project_for(&file.projects, &cwd).cloned() else {
            return none(reply_err(
                ErrorCode::Invalid,
                format!(
                    "morsec: {} is in no project morsec knows. Run ms init in the project first (ms projects lists them)",
                    ms_projects::record::printable(&cwd.display().to_string())
                ),
            ));
        };
        let keys: BTreeSet<KeyName> = record.keys().into_iter().collect();
        let rules = self.rules();
        if rules.tampered {
            return none(self.rules_get(None));
        }
        let production: BTreeSet<KeyName> = keys
            .iter()
            .filter(|k| {
                rules
                    .keys
                    .get(*k)
                    .is_some_and(|r| r.tier == Tier::Production)
            })
            .cloned()
            .collect();
        let terminal = SessionId {
            agent: AgentKind::Other("terminal".into()),
            pid,
            started_unix_ms: started,
        };
        let dev = dev_session_id(pid, started);
        let version = self.rules_version();

        // One approval for the run when the project has a production key (SPEC D-4).
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let approval = if production.is_empty() {
            None
        } else {
            let mut shown = vec![
                "ms".to_owned(),
                "dev".into(),
                "--project".into(),
                record.slug.clone(),
                "--root".into(),
                record.root.clone(),
                "--keys".into(),
            ];
            shown.extend(production.iter().map(|k| k.as_str().to_owned()));
            shown.push("--".into());
            shown.extend(argv.iter().cloned());
            let req = ApprovalRequest {
                session: terminal.clone(),
                key: daemon_key(),
                tier: Tier::Production,
                argv_hash: ms_rules::argv_hash(&shown),
                argv_display: shown,
                cwd: cwd.clone(),
                effect: Some(format!(
                    "this command may use {} production key(s) of project {} until it exits",
                    production.len(),
                    record.slug
                )),
            };
            match self.approve_exact(&req) {
                Ok(t) => Some(t),
                Err(resp) => {
                    for k in &production {
                        let _ = self.record(
                            &terminal,
                            k,
                            Mode::Run,
                            "ms dev: start",
                            version,
                            ReceiptResult::Denied,
                            None,
                        );
                    }
                    return none(resp);
                }
            }
        };
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return none(reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran while ms dev waited for approval, so it did not start",
            ));
        }

        // Run-mode values for the child's environment (SPEC D-3).
        let rules = self.rules();
        let mut notes = Vec::new();
        let wanted = run_env(&record, &rules, &cwd, &mut notes);
        let mut names = Vec::new();
        let mut values = Vec::new();
        let target = format!(
            "ms dev: {} (environment)",
            ms_projects::record::printable(argv0)
        );
        for (var, key) in &wanted {
            let tier = rules.keys.get(key).map(|r| r.tier);
            if tier == Some(Tier::Production) && approval.is_none() {
                notes.push(format!(
                    "{var} was not set: its key became production after the approval was asked"
                ));
                continue;
            }
            match self.vault.read_with(key, |v| SecretBytes::new(v.to_vec())) {
                Ok(v) => {
                    let receipt = match (&approval, tier) {
                        (Some(t), Some(Tier::Production)) => {
                            self.record_approved(&dev, key, Mode::Run, &target, version, t)
                        }
                        _ => self.record(
                            &dev,
                            key,
                            Mode::Run,
                            &target,
                            version,
                            ReceiptResult::Allowed,
                            None,
                        ),
                    };
                    // A value whose use can't be recorded is not handed out.
                    if let Err(e) = receipt {
                        tracing::error!(error = %e, "could not record an ms dev value");
                        notes.push(format!(
                            "{var} was not set: the receipt could not be written"
                        ));
                        continue;
                    }
                    names.push(var.clone());
                    values.push(v);
                }
                Err(e) => notes.push(format!("{var} was not set: {key} can't be read ({e})")),
            }
        }
        let swapped: Vec<String> = keys
            .iter()
            .filter(|k| {
                rules
                    .keys
                    .get(*k)
                    .is_some_and(|r| r.mode == Mode::Swap && !r.allows_nothing())
            })
            .map(|k| k.as_str().to_owned())
            .collect();

        let (id, credential) = match (hex_random(8), hex_random(32)) {
            (Ok(i), Ok(c)) => (i, format!("{}{c}", ms_session::DEV_PROXY_USER_PREFIX)),
            _ => {
                return none(reply_err(
                    ErrorCode::Internal,
                    "morsec: could not make a session credential",
                ));
            }
        };
        {
            let mut m = lock(&self.dev.0);
            // One session per ms dev process: a second DevStart replaces the first.
            m.retain(|_, d| d.session != dev);
            if m.len() >= MAX_DEV_SESSIONS {
                return none(reply_err(
                    ErrorCode::Busy,
                    format!("morsec: {MAX_DEV_SESSIONS} ms dev sessions are running already"),
                ));
            }
            m.insert(
                credential.clone(),
                DevSession {
                    id: id.clone(),
                    session: dev.clone(),
                    slug: record.slug.clone(),
                    keys,
                    production,
                    approval: approval.clone(),
                },
            );
        }
        if let Err(e) = self.record(
            &dev,
            &daemon_key(),
            Mode::Run,
            &format!("ms dev: project {} started", record.slug),
            version,
            if approval.is_some() {
                ReceiptResult::Approved
            } else {
                ReceiptResult::Allowed
            },
            None,
        ) {
            tracing::error!(error = %e, "could not record ms dev start");
        }
        let ca_pem = lock(&self.ca).as_ref().map(|(pem, _)| pem.clone());
        (
            ResponseBody::DevStarted {
                session: id,
                credential,
                proxy_port: self.proxy_port,
                project: record.slug.clone(),
                root: record.root.clone(),
                ca_pem,
                env: names,
                swapped,
                notes,
            },
            values,
        )
    }
}
