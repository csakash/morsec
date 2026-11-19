//! `ms dev` sessions (L34, SPEC D-1 to D-8): the user's own command, served by the swap proxy.
//!
//! `DevStart` comes from `ms dev` in the user's terminal. msd refuses it inside an agent session,
//! from a sandboxed process (an agent's command that double-forked out of its tree is still in
//! the agent's sandbox), while stopped, for an agent binary and outside every recorded project
//! root; asks one Touch ID for every run (SPEC D-4, review D-A), showing the keys, the variables
//! that get values and that other websites are reachable; then binds a dev session to the **`ms dev` process**
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
    /// The production keys the run's approval listed.
    pub production: BTreeSet<KeyName>,
    /// The run's approval, and what it was bound to.
    pub approval: ApprovalToken,
    /// The binding of that approval (to check it is still live: `ms stop` revokes it).
    pub binding: ms_approve::Binding,
    /// When it was approved, Unix ms (production swaps are covered for the rule's session
    /// length at most, SPEC D-B).
    pub approved_unix_ms: u64,
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

/// The agent a program name is, after the last `/`, or by where agents install themselves
/// (`…/claude/versions/2.0.5`) (L34 SPEC D-8).
pub fn agent_binary(argv0: &str) -> Option<AgentKind> {
    let base = argv0.rsplit('/').next().unwrap_or(argv0);
    ms_session::agent_kind(base).or_else(|| ms_session::agent_install_path(argv0))
}

/// Longest command shown on the approval sheet, in characters as the sheet quotes them (two
/// quotes and a space per argument). The Touch ID reason is capped at 480 characters and its own
/// header takes about 200, so this leaves room for the cut marker after it.
const SHEET_COMMAND_CHARS: usize = 160;

/// The command as the approval sheet shows it (review F1), and whether it was cut: every
/// argument when it fits in [`SHEET_COMMAND_CHARS`], else the leading ones and a short marker.
/// When cut, the caller binds the full command by its SHA-256 at the end of the sheet's argv.
pub fn command_for_sheet(argv: &[String]) -> (Vec<String>, bool) {
    let cost = |a: &String| a.chars().count() + 3;
    let total: usize = argv.iter().map(cost).sum();
    if total <= SHEET_COMMAND_CHARS {
        return (argv.to_vec(), false);
    }
    let budget = SHEET_COMMAND_CHARS.saturating_sub(40);
    let mut out = Vec::new();
    let mut used = 0;
    for a in argv {
        if used + cost(a) > budget {
            let room = budget.saturating_sub(used + 3);
            if room > 8 {
                out.push(a.chars().take(room).collect());
                used += room + 3;
            }
            break;
        }
        out.push(a.clone());
        used += cost(a);
    }
    out.push(format!(
        "…(command cut: {} more characters)",
        total.saturating_sub(used)
    ));
    (out, true)
}

/// The project whose root holds `cwd` (both canonical); the deepest root wins.
pub fn project_for<'a>(projects: &'a [ProjectRecord], cwd: &Path) -> Option<&'a ProjectRecord> {
    projects
        .iter()
        .filter(|p| cwd.starts_with(Path::new(&p.root)))
        .max_by_key(|p| p.root.len())
}

/// The variables to give values (L34 SPEC D-3, review S2): every recorded variable of `record`
/// whose key is run mode with exactly the rule `ms init` gives a database URL: the project root as
/// its only root, no commands, not read-only, and no environment names or this variable among
/// them. A run key whose rule was changed by hand is skipped with a note. A variable recorded with
/// two different keys takes the root `.env`'s key, else is skipped with a note. Names that steer
/// programs (PATH, loaders, proxies…) are skipped.
pub fn run_env(
    record: &ProjectRecord,
    rules: &ms_rules::Rules,
    cwd: &Path,
    notes: &mut Vec<String>,
) -> BTreeMap<String, KeyName> {
    if rules.tampered || rules.stopped || !cwd.starts_with(Path::new(&record.root)) {
        return BTreeMap::new();
    }
    let root = vec![std::path::PathBuf::from(&record.root)];
    let mut seen: BTreeMap<String, Vec<(&str, &KeyName)>> = BTreeMap::new();
    let mut odd: BTreeSet<String> = BTreeSet::new();
    for f in &record.files {
        for s in &f.secrets {
            let Some(r) = rules.keys.get(&s.key).filter(|r| r.mode == Mode::Run) else {
                continue;
            };
            let shaped = r.roots == root
                && r.commands.is_empty()
                && !r.read_only
                && (r.env.is_empty() || r.env.contains(&s.var));
            if shaped {
                seen.entry(s.var.clone())
                    .or_default()
                    .push((f.path.as_str(), &s.key));
            } else {
                odd.insert(s.var.clone());
            }
        }
    }
    for var in &odd {
        notes.push(format!(
            "{var} was not set: its key's rule was changed by hand (commands, other roots, read-only or other variables), and ms dev only gives values ms init set up"
        ));
    }
    let mut out = BTreeMap::new();
    for (var, uses) in seen {
        if odd.contains(&var) {
            continue;
        }
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

    /// Records the end of a dev session (best effort).
    fn record_dev_end(&self, d: &DevSession, why: &str) {
        tracing::info!(project = %d.slug, pid = d.session.pid, why, "ms dev session ended");
        if let Err(e) = self.record(
            &d.session,
            &daemon_key(),
            Mode::Run,
            &format!("ms dev: project {} ended ({why})", d.slug),
            self.rules_version(),
            ReceiptResult::Allowed,
            None,
        ) {
            tracing::error!(error = %e, "could not record the end of an ms dev session");
        }
    }

    /// Drops every dev session whose `ms dev` process is gone (`alive(pid, start)` false).
    pub fn reap_dev(&self, alive: impl Fn(u32, u64) -> bool) -> usize {
        let gone: Vec<DevSession> = {
            let mut m = lock(&self.dev.0);
            // Review F5: liveness is decided once per session, so every removed one is reported.
            let dead: Vec<String> = m
                .iter()
                .filter(|(_, d)| !alive(d.session.pid, d.session.started_unix_ms))
                .map(|(c, _)| c.clone())
                .collect();
            dead.iter().filter_map(|c| m.remove(c)).collect()
        };
        for d in &gone {
            self.record_dev_end(d, "its process is gone");
        }
        gone.len()
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

    /// Approver hook (SPEC D-4, review D-B): a production key of this dev session's project
    /// that the run's approval listed gets that approval's token, while the token is live (not
    /// revoked by `ms stop`) and for at most `min(token expiry, the key's session length)` after
    /// the approval. Anything else asks a person as usual.
    pub(super) fn dev_approval(&self, req: &ApprovalRequest) -> Option<ApprovalToken> {
        let d = self.dev_session(&req.session)?;
        if !d.production.contains(&req.key) || !self.approvals.is_live(&d.approval, &d.binding) {
            return None;
        }
        let ttl = self.rules().keys.get(&req.key)?.session_ttl_secs;
        let until = d
            .approval
            .expires_unix_ms
            .min(d.approved_unix_ms.saturating_add(ttl.saturating_mul(1000)));
        (super::now_ms() < until).then_some(d.approval)
    }

    /// Moves every dev session's approval time `ms` milliseconds into the past (tests of the
    /// production window; 0 puts it back to now).
    #[cfg(test)]
    pub fn age_dev_approvals(&self, ms: u64) {
        let now = super::now_ms();
        for d in lock(&self.dev.0).values_mut() {
            d.approved_unix_ms = now.saturating_sub(ms);
        }
    }

    /// True when `caller` is an unattributed process inside a sandbox (or the check failed).
    pub(super) fn caller_sandboxed(&self, caller: Option<&Caller>) -> bool {
        match caller {
            Some(Caller::Unattributed { pid, .. }) => (*lock(&self.sandbox_probe))(*pid),
            _ => false,
        }
    }

    /// Replaces the sandbox probe (tests: fake callers have no real process).
    #[cfg(test)]
    pub fn set_sandbox_probe(&self, f: fn(u32) -> bool) {
        *lock(&self.sandbox_probe) = f;
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
        let ended: Vec<DevSession> = {
            let mut m = lock(&self.dev.0);
            let ended = m
                .values()
                .filter(|d| d.id == id && d.session == me)
                .cloned()
                .collect();
            m.retain(|_, d| !(d.id == id && d.session == me));
            ended
        };
        if ended.is_empty() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: no such ms dev session for this process",
            );
        }
        for d in &ended {
            self.record_dev_end(d, "the command exited");
        }
        ResponseBody::Ok {
            message: "ms dev session ended".into(),
        }
    }

    /// `DevStart` (SPEC D-1 to D-8, review D-A). Returns the reply and the values that follow.
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
        // Review D-A: a double fork leaves an agent's tree but not its sandbox.
        if self.caller_sandboxed(caller) {
            return none(reply_err(
                ErrorCode::Denied,
                "morsec: ms dev was asked from a sandboxed process (an agent's command sandbox), so it was refused. Run it in your own terminal",
            ));
        }
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
        let dev = dev_session_id(pid, started);
        let full = |m: &HashMap<String, DevSession>| {
            m.len() >= MAX_DEV_SESSIONS && !m.values().any(|d| d.session == dev)
        };
        let busy = || {
            none(reply_err(
                ErrorCode::Busy,
                format!("morsec: {MAX_DEV_SESSIONS} ms dev sessions are running already"),
            ))
        };
        // Review R3: before anything is asked, read or recorded.
        if full(&lock(&self.dev.0)) {
            return busy();
        }

        // What the person approves: computed from the rules as they are now (the snapshot).
        let keys: BTreeSet<KeyName> = record.keys().into_iter().collect();
        let snap = self.rules();
        if snap.tampered {
            return none(self.rules_get(None));
        }
        let mut notes = Vec::new();
        let wanted = run_env(&record, &snap, &cwd, &mut notes);
        let production: BTreeSet<KeyName> = keys
            .iter()
            .filter(|k| {
                snap.keys
                    .get(*k)
                    .is_some_and(|r| r.tier == Tier::Production)
            })
            .cloned()
            .collect();
        let swapped: Vec<String> = keys
            .iter()
            .filter(|k| {
                snap.keys
                    .get(*k)
                    .is_some_and(|r| r.mode == Mode::Swap && !r.allows_nothing())
            })
            .map(|k| k.as_str().to_owned())
            .collect();
        let terminal = SessionId {
            agent: AgentKind::Other("terminal".into()),
            pid,
            started_unix_ms: started,
        };

        // One approval for every run (review D-A), bound to all of this.
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        // Review F1: the Touch ID reason is capped, so the command comes right after the project
        // and before the (possibly long) root and key lists; a huge command is cut here with a
        // marker and its full SHA-256 stays in the bound argv.
        let mut shown = vec![
            "ms".to_owned(),
            "dev".into(),
            "--project".into(),
            record.slug.clone(),
            format!("--command({} args)", argv.len()),
        ];
        let (cmd_shown, cut) = command_for_sheet(argv);
        shown.extend(cmd_shown);
        shown.push("--root".into());
        shown.push(record.root.clone());
        shown.push("--swap".into());
        shown.extend(swapped.iter().cloned());
        shown.push("--env".into());
        shown.extend(wanted.iter().map(|(v, k)| format!("{v}={k}")));
        shown.push("--production".into());
        shown.extend(production.iter().map(|k| k.as_str().to_owned()));
        shown.push("--other-websites".into());
        shown.push("allowed".into());
        if cut {
            shown.push("--full-command-sha256".into());
            shown.push(hex::encode(ms_rules::argv_hash(argv)));
        }
        let req = ApprovalRequest {
            session: terminal.clone(),
            key: daemon_key(),
            tier: Tier::Production,
            argv_hash: ms_rules::argv_hash(&shown),
            argv_display: shown,
            cwd: cwd.clone(),
            effect: Some(format!(
                "until it exits, this command may use {} key(s) of project {} through morsec ({} production), gets {} value(s) in its environment, and may reach other websites",
                swapped.len(),
                record.slug,
                production.len(),
                wanted.len()
            )),
        };
        // Review F2: one run, one approval. A session-scope token (answered `s`) would stretch the
        // production window (D-4b) to hours, so it is refused.
        let approval = match self.approve_admin(&req) {
            Ok(t) if ms_approve::Scope::of_id(&t.id) == Some(ms_approve::Scope::Once) => t,
            Ok(_) => {
                let _ = self.record(
                    &terminal,
                    &daemon_key(),
                    Mode::Run,
                    &format!("ms dev: project {} start", record.slug),
                    snap.version,
                    ReceiptResult::Denied,
                    None,
                );
                return none(reply_err(
                    ErrorCode::NeedsApproval,
                    "morsec: ms dev takes an approval for this run only. Run it again and answer o (once), not s",
                ));
            }
            Err(resp) => {
                let _ = self.record(
                    &terminal,
                    &daemon_key(),
                    Mode::Run,
                    &format!("ms dev: project {} start", record.slug),
                    snap.version,
                    ReceiptResult::Denied,
                    None,
                );
                return none(resp);
            }
        };
        let approved_unix_ms = super::now_ms();
        // Review F4: don't read a single value after ms stop.
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return none(reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran while ms dev waited for approval, so it did not start",
            ));
        }

        // Run-mode values (SPEC D-3). Review R1: only for keys whose rule is still exactly what
        // the person saw; R9: receipts carry the rules version in force now.
        let rules = self.rules();
        let version = rules.version;
        let mut names = Vec::new();
        let mut values = Vec::new();
        let target = format!(
            "ms dev: {} (environment)",
            ms_projects::record::printable(argv0)
        );
        for (var, key) in &wanted {
            let now = rules.keys.get(key);
            if rules.tampered || now != snap.keys.get(key) {
                notes.push(format!(
                    "{var} was not set: the rule of {key} changed while the approval was asked"
                ));
                continue;
            }
            let value = match self.vault.read_with(key, |v| SecretBytes::new(v.to_vec())) {
                Ok(v) => v,
                Err(e) => {
                    notes.push(format!("{var} was not set: {key} can't be read ({e})"));
                    continue;
                }
            };
            // Review R4: a frame can't be empty or larger than the IPC limit.
            if value.expose().is_empty() || value.expose().len() > ms_ipc::MAX_FRAME {
                notes.push(format!(
                    "{var} was not set: the value of {key} is empty or too large"
                ));
                continue;
            }
            let receipt = if now.is_some_and(|r| r.tier == Tier::Production) {
                self.record_approved(&dev, key, Mode::Run, &target, version, &approval)
            } else {
                self.record(
                    &dev,
                    key,
                    Mode::Run,
                    &target,
                    version,
                    ReceiptResult::Allowed,
                    None,
                )
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
            values.push(value);
        }

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
            // Review R2: under the session lock, so ms stop (which sets the flag, then clears
            // the sessions under this lock) either is seen here or clears this one.
            if self.is_stopped()
                || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen
            {
                return none(reply_err(
                    ErrorCode::Denied,
                    "morsec: ms stop ran while ms dev waited for approval, so it did not start",
                ));
            }
            // One session per ms dev process: a second DevStart replaces the first.
            m.retain(|_, d| d.session != dev);
            if full(&m) {
                return busy();
            }
            m.insert(
                credential.clone(),
                DevSession {
                    id: id.clone(),
                    session: dev.clone(),
                    slug: record.slug.clone(),
                    keys,
                    production,
                    binding: ms_approve::Binding::of(&req),
                    approval: approval.clone(),
                    approved_unix_ms,
                },
            );
        }
        if let Err(e) = self.record_approved(
            &dev,
            &daemon_key(),
            Mode::Run,
            &format!("ms dev: project {} started", record.slug),
            version,
            &approval,
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
