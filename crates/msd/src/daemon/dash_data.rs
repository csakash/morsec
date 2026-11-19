//! The dashboard's data (L32 dash-core): `DashOpen`, and the read-only views `ms-dash` serves.
//!
//! Every view is built from names, refs, paths, hosts, counts and statuses: nothing here opens a
//! vault value (no `with_secret`, no `read_with` of a user key), so nothing a page asks can carry
//! one (SPEC D-3, criterion 10). The only write is a `blocked` receipt for a refused connection or
//! request (SPEC D-9).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use ms_core::{KeyName, Mode, Reason, ReceiptResult, SessionId};
use ms_dash::api::{
    ActivityQuery, ActivityRow, ActivityView, AgentView, AgentsView, CheckView, CommittedView,
    ExportFormat, FindingView, HomeView, KeyRow, PendingView, ProjectCard, ProjectView,
    ProjectsView, ScanFindingView, ScanSnapshot, ScanView, SecretRow, SecretView, UsedIn,
    VerifyView,
};
use ms_dash::{ApiError, DASH_KEY, DashData, Refusal};
use ms_ipc::{ErrorCode, ResponseBody};
use ms_projects::record::{ProjectRecord, ProjectsFile};
use ms_receipts::query::{agent_label, parse_agent};
use ms_receipts::{Entry, Query, ResultClass, StoredRecord};
use ms_rules::KeyRule;

use super::{Daemon, lock, mode_str, now_ms, reply_err, tier_str};

/// Rows Activity shows when the page asks for no limit, and the most it may ask for.
const DEFAULT_ROWS: usize = 200;
const MAX_ROWS: usize = 1000;
/// Uses shown on the Secret screen.
const SECRET_USES: usize = 20;

fn key(raw: &str) -> KeyName {
    KeyName::new(raw).unwrap_or_else(|_| unreachable!("constant key name is valid"))
}

fn reason_str(r: &Reason) -> &'static str {
    match r {
        Reason::NotImplemented => "not implemented",
        Reason::HostNotAllowed => "host not allowed",
        Reason::CommandNotAllowed => "command not allowed",
        Reason::Stopped => "stopped",
        Reason::NoSuchKey => "no such key",
        Reason::RulesTampered => "rules tampered",
    }
}

fn result_str(c: ResultClass) -> &'static str {
    match c {
        ResultClass::Allowed => "allowed",
        ResultClass::Approved => "approved",
        ResultClass::Blocked => "blocked",
        ResultClass::Denied => "denied",
        ResultClass::Failed => "failed",
        ResultClass::Alert => "alert",
    }
}

fn row(r: &StoredRecord) -> Option<ActivityRow> {
    match &r.rec.entry {
        Entry::Receipt(x) => Some(ActivityRow {
            seq: r.seq,
            time_unix_ms: r.rec.time_unix_ms,
            kind: "receipt".into(),
            agent: agent_label(&x.session.agent),
            pid: x.session.pid,
            key: x.key.to_string(),
            mechanism: mode_str(x.mechanism).into(),
            target: x.target.clone(),
            result: result_str(ResultClass::of(&x.result)).into(),
            reason: match &x.result {
                ReceiptResult::Blocked(why) => Some(reason_str(why).into()),
                ReceiptResult::Failed(why) => Some(why.clone()),
                _ => None,
            },
        }),
        Entry::Alert(a) => Some(ActivityRow {
            seq: r.seq,
            time_unix_ms: r.rec.time_unix_ms,
            kind: "alert".into(),
            agent: agent_label(&a.session.agent),
            pid: a.session.pid,
            key: String::new(),
            mechanism: String::new(),
            target: format!(
                "{} blocked or denied attempts in {} s",
                a.blocked_count,
                a.window_ms / 1000
            ),
            result: "alert".into(),
            reason: None,
        }),
        Entry::Checkpoint(_) => None,
    }
}

fn status_word(stored: bool, ready: bool, mode: Option<Mode>) -> &'static str {
    match (stored, ready, mode) {
        (false, _, _) => "not stored",
        (true, true, _) => "protected",
        (true, false, Some(Mode::Run)) => "needs a command",
        (true, false, Some(Mode::Mint)) => "needs a scope",
        (true, false, _) => "needs a website",
    }
}

fn u32_of(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError {
        status: 400,
        message: message.into(),
    }
}

/// What the views need from the rules for one key.
fn ready(rule: Option<&KeyRule>, tampered: bool) -> bool {
    !tampered && rule.is_some_and(|r| !r.allows_nothing())
}

impl Daemon {
    /// Installs the dashboard (once, at start).
    pub fn set_dash(&self, dash: ms_dash::Dash) {
        let _ = self.dash.set(dash);
    }

    /// The dashboard, when this daemon serves one.
    pub fn dash(&self) -> Option<&ms_dash::Dash> {
        self.dash.get()
    }

    /// `DashOpen` (the caller is outside every agent session; checked by `handle`).
    pub(super) fn dash_open(&self) -> ResponseBody {
        let Some(dash) = self.dash.get() else {
            return reply_err(ErrorCode::Internal, "morsec: this msd serves no dashboard");
        };
        match dash.open() {
            Ok(o) => ResponseBody::Dash {
                port: o.port,
                launch_token: o.token,
            },
            Err(e) => reply_err(ErrorCode::Internal, e),
        }
    }

    /// A `blocked` receipt for a dashboard refusal (SPEC D-9).
    pub(crate) fn record_dash_refusal(&self, r: &Refusal) {
        let target = format!("dashboard: {}", ms_approve::render::inert(&r.why));
        if let Err(e) = self.record(
            &r.session,
            &key(DASH_KEY),
            Mode::Run,
            &target,
            self.rules_version(),
            ReceiptResult::Blocked(Reason::HostNotAllowed),
            None,
        ) {
            tracing::error!(error = %e, "could not record a dashboard refusal");
        }
    }

    fn receipts_all(&self) -> Result<Vec<StoredRecord>, ApiError> {
        ms_receipts::read_all(self.receipts.dir())
            .map_err(|e| ApiError::internal(format!("morsec: the receipts can't be read: {e}")))
    }

    /// The project records, or why they can't be shown (fails closed, like `ms projects`).
    fn dash_projects(&self) -> Result<ProjectsFile, String> {
        self.load_projects().map(|(f, _)| f).map_err(|r| match r {
            ResponseBody::Error { message, .. } => message,
            _ => "morsec: the project records can't be read".into(),
        })
    }

    /// Every stored key (morsec's own excluded) with its creation time.
    fn stored_keys(&self) -> BTreeMap<KeyName, u64> {
        self.scan_keys()
            .map(|l| {
                l.keys
                    .into_iter()
                    .map(|m| (m.name, m.created_unix_ms))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn key_row(&self, k: &KeyName, stored: &BTreeMap<KeyName, u64>) -> KeyRow {
        let live = self.read_live();
        let rule = live.rules.keys.get(k);
        let is_ready = ready(rule, live.rules.tampered);
        KeyRow {
            key: k.to_string(),
            mode: rule.map(|r| mode_str(r.mode).into()),
            tier: rule.map(|r| tier_str(r.tier).into()),
            ready: is_ready,
            stored: stored.contains_key(k),
            status: status_word(stored.contains_key(k), is_ready, rule.map(|r| r.mode)).into(),
            targets: rule.map(super::projects::targets).unwrap_or_default(),
        }
    }

    fn agent_views(&self, records: &[StoredRecord]) -> Vec<AgentView> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        let stats = ms_receipts::stats::stats(records);
        let last_seen = |label: &str| {
            records
                .iter()
                .rev()
                .find(|r| match &r.rec.entry {
                    Entry::Receipt(x) => agent_label(&x.session.agent) == label,
                    _ => false,
                })
                .map(|r| r.rec.time_unix_ms)
        };
        [
            ("claude-code", "Claude Code", ".claude"),
            ("codex", "Codex", ".codex"),
        ]
        .into_iter()
        .map(|(id, name, dir)| {
            let (installed, connected) = match &home {
                Some(h) => {
                    let state = if id == "codex" {
                        ms_connect::codex::Paths::for_home(h, None).state
                    } else {
                        ms_connect::claude::Paths::for_home(h, None).state
                    };
                    (h.join(dir).is_dir(), state.is_file())
                }
                None => (false, false),
            };
            let mine = stats.sessions.iter().filter(|s| s.agent == id);
            let (sessions, blocked) = mine.fold((0u64, 0u64), |(n, b), s| (n + 1, b + s.blocked));
            AgentView {
                id: id.into(),
                name: name.into(),
                installed,
                connected,
                sessions,
                blocked,
                last_seen_unix_ms: last_seen(id),
            }
        })
        .collect()
    }

    /// The records matching `q`, oldest first, and how many there are in all.
    fn matching(&self, q: &ActivityQuery) -> Result<(Vec<StoredRecord>, usize), ApiError> {
        let now = now_ms();
        let since = q
            .since
            .as_deref()
            .map(|s| ms_receipts::time::parse_time(s, now))
            .transpose()
            .map_err(|e| bad_request(format!("morsec: {e}")))?;
        let key = q
            .key
            .as_deref()
            .map(KeyName::new)
            .transpose()
            .map_err(|e| bad_request(e.to_string()))?;
        let result = match q.result.as_deref() {
            Some(r) => Some(
                ResultClass::parse(r)
                    .ok_or_else(|| bad_request("morsec: unknown result filter"))?,
            ),
            None => None,
        };
        let query = Query {
            since,
            until: None,
            agent: q.agent.as_deref().map(parse_agent),
            key,
            result,
            pid: None,
            limit: None,
        };
        let all = self.receipts_all()?;
        let total = all.iter().filter(|r| row(r).is_some()).count();
        let prefix = q.project.as_ref().map(|p| format!("{p}/"));
        let rows = query
            .run(&all)
            .into_iter()
            .filter(|r| match (&prefix, &r.rec.entry) {
                (None, _) => true,
                (Some(p), Entry::Receipt(x)) => x.key.as_str().starts_with(p.as_str()),
                (Some(_), _) => false,
            })
            .collect();
        Ok((rows, total))
    }

    pub(crate) fn dash_home(&self) -> Result<HomeView, ApiError> {
        let ResponseBody::Status {
            running,
            keys,
            alerts,
            mode,
            version,
            ..
        } = self.status()
        else {
            return Err(ApiError::internal("morsec: status unavailable"));
        };
        let stored = self.stored_keys();
        let (protected, needs) = {
            let live = self.read_live();
            let protected = stored
                .keys()
                .filter(|k| ready(live.rules.keys.get(*k), live.rules.tampered))
                .count();
            (protected, stored.len() - protected)
        };
        let records = self.receipts_all()?;
        let day_ago = now_ms().saturating_sub(24 * 3600 * 1000);
        let blocked_24h = records
            .iter()
            .filter(|r| r.rec.time_unix_ms >= day_ago)
            .filter(|r| {
                matches!(&r.rec.entry, Entry::Receipt(x) if matches!(x.result, ReceiptResult::Blocked(_)))
            })
            .count() as u64;
        let projects = self.dash_projects();
        Ok(HomeView {
            running: running.unwrap_or(true),
            vault: mode,
            version,
            keys: keys.unwrap_or(0),
            projects: projects.as_ref().map_or(0, |f| u32_of(f.projects.len())),
            protected: u32_of(protected),
            needs_website: u32_of(needs),
            blocked_24h,
            alerts,
            pending: self.approvals.pending().map(|p| PendingView {
                agent: agent_label(&p.request.session.agent),
                key: p.request.key.to_string(),
                tier: tier_str(p.request.tier).into(),
                command: p.request.argv_display.clone(),
                cwd: p.request.cwd.display().to_string(),
                expires_unix_ms: p.expires_unix_ms,
            }),
            agents: self.agent_views(&records),
            projects_unreadable: projects.is_err(),
        })
    }

    pub(crate) fn dash_projects_view(&self) -> Result<ProjectsView, ApiError> {
        let stored = self.stored_keys();
        let (records, unreadable) = match self.dash_projects() {
            Ok(f) => (f.projects, None),
            Err(why) => (Vec::new(), Some(why)),
        };
        let in_projects: BTreeSet<KeyName> = records.iter().flat_map(ProjectRecord::keys).collect();
        let projects = records
            .iter()
            .map(|p| {
                let keys = self.key_statuses(p);
                let protected = keys.iter().filter(|k| k.ready).count();
                ProjectCard {
                    slug: p.slug.clone(),
                    display: p.display.clone(),
                    root: p.root.clone(),
                    protected: u32_of(protected),
                    needs_website: u32_of(keys.len() - protected),
                    findings: u32_of(p.findings.len()),
                    committed_files: u32_of(
                        p.files
                            .iter()
                            .filter(|f| f.git_history_commits.unwrap_or(0) > 0)
                            .count(),
                    ),
                    stopped_early: p.scan.stopped_early,
                }
            })
            .collect();
        // With unreadable records every key shows here: fail towards showing, never hiding.
        let loose = stored
            .keys()
            .filter(|k| !in_projects.contains(*k))
            .map(|k| self.key_row(k, &stored))
            .collect();
        Ok(ProjectsView {
            projects,
            loose,
            unreadable,
        })
    }

    pub(crate) fn dash_project(&self, slug: &str) -> Result<ProjectView, ApiError> {
        let file = self.dash_projects().map_err(ApiError::unavailable)?;
        let p = file
            .get(slug)
            .ok_or_else(|| ApiError::not_found("morsec: no such project"))?;
        let statuses: BTreeMap<KeyName, ms_ipc::KeyStatus> = self
            .key_statuses(p)
            .into_iter()
            .map(|k| (k.key.clone(), k))
            .collect();
        let records = self.receipts_all()?;
        let mut last_use: BTreeMap<&KeyName, u64> = BTreeMap::new();
        for r in &records {
            if let Entry::Receipt(x) = &r.rec.entry {
                last_use.insert(&x.key, r.rec.time_unix_ms);
            }
        }
        let rows = p
            .files
            .iter()
            .flat_map(|f| f.secrets.iter().map(move |s| (f, s)))
            .map(|(f, s)| {
                let st = statuses.get(&s.key);
                SecretRow {
                    var: s.var.clone(),
                    file: f.path.clone(),
                    line: s.line,
                    key: s.key.to_string(),
                    provider: s.provider.clone(),
                    tier: st.and_then(|k| k.tier).map(|t| tier_str(t).into()),
                    mode: st.and_then(|k| k.mode).map(|m| mode_str(m).into()),
                    status: status_word(
                        st.is_some_and(|k| k.stored),
                        st.is_some_and(|k| k.ready),
                        st.and_then(|k| k.mode),
                    )
                    .into(),
                    last_use_unix_ms: last_use.get(&s.key).copied(),
                }
            })
            .collect();
        Ok(ProjectView {
            slug: p.slug.clone(),
            display: p.display.clone(),
            root: p.root.clone(),
            created_unix_ms: p.created_unix_ms,
            scan_entries: p.scan.entries,
            scan_ms: p.scan.ms,
            stopped_early: p.scan.stopped_early,
            rows,
            findings: p
                .findings
                .iter()
                .map(|f| FindingView {
                    path: f.path.clone(),
                    line: f.line,
                    provider: f.provider.clone(),
                    masked: f.masked.clone(),
                })
                .collect(),
            committed: p
                .files
                .iter()
                .filter_map(|f| {
                    f.git_history_commits
                        .filter(|n| *n > 0)
                        .map(|commits| CommittedView {
                            path: f.path.clone(),
                            commits,
                        })
                })
                .collect(),
            hints: p.hints.iter().map(|h| h.path.clone()).collect(),
        })
    }

    pub(crate) fn dash_secret(&self, k: &KeyName) -> Result<SecretView, ApiError> {
        let stored = self.stored_keys();
        let projects = self.dash_projects().unwrap_or_default();
        let mut used_in: Vec<UsedIn> = Vec::new();
        for p in &projects.projects {
            for f in &p.files {
                for s in f.secrets.iter().filter(|s| &s.key == k) {
                    used_in.push(UsedIn {
                        project: p.slug.clone(),
                        file: f.path.clone(),
                        line: s.line,
                        var: s.var.clone(),
                    });
                }
            }
        }
        let provider = projects
            .projects
            .iter()
            .find_map(|p| p.provider_of(k).map(str::to_owned));
        let (rule, tampered) = {
            let live = self.read_live();
            (live.rules.keys.get(k).cloned(), live.rules.tampered)
        };
        if rule.is_none() && !stored.contains_key(k) && used_in.is_empty() {
            return Err(ApiError::not_found("morsec: no such key"));
        }
        let records = self.receipts_all()?;
        let uses = records
            .iter()
            .rev()
            .filter(|r| matches!(&r.rec.entry, Entry::Receipt(x) if &x.key == k))
            .filter_map(row)
            .take(SECRET_USES)
            .collect();
        let r = rule.as_ref();
        Ok(SecretView {
            key: k.to_string(),
            provider,
            mode: r.map(|r| mode_str(r.mode).into()),
            tier: r.map(|r| tier_str(r.tier).into()),
            created_unix_ms: stored.get(k).copied(),
            stored: stored.contains_key(k),
            ready: ready(r, tampered),
            status: status_word(
                stored.contains_key(k),
                ready(r, tampered),
                r.map(|r| r.mode),
            )
            .into(),
            hosts: r
                .map(|r| r.hosts.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            git_hosts: r.map(|r| r.git_hosts.clone()).unwrap_or_default(),
            commands: r
                .map(|r| r.commands.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            roots: r
                .map(|r| r.roots.iter().map(|p| p.display().to_string()).collect())
                .unwrap_or_default(),
            env: r.map(|r| r.env.clone()).unwrap_or_default(),
            read_only: r.is_some_and(|r| r.read_only),
            used_in,
            uses,
        })
    }

    pub(crate) fn dash_activity(&self, q: &ActivityQuery) -> Result<ActivityView, ApiError> {
        let (rows, total) = self.matching(q)?;
        let limit = q.limit.unwrap_or(DEFAULT_ROWS).clamp(1, MAX_ROWS);
        let matched = rows.len();
        Ok(ActivityView {
            rows: rows.iter().rev().filter_map(row).take(limit).collect(),
            matched,
            total,
        })
    }

    pub(crate) fn dash_export(
        &self,
        q: &ActivityQuery,
        format: ExportFormat,
    ) -> Result<(String, &'static str, Vec<u8>), ApiError> {
        let (rows, _) = self.matching(q)?;
        Ok(match format {
            ExportFormat::Json => {
                let mut s = ms_receipts::export_json(&rows);
                s.push('\n');
                (
                    "morsec-receipts.json".into(),
                    "application/json",
                    s.into_bytes(),
                )
            }
            ExportFormat::Csv => (
                "morsec-receipts.csv".into(),
                "text/csv; charset=utf-8",
                ms_receipts::export_csv(&rows).into_bytes(),
            ),
        })
    }

    pub(crate) fn dash_verify(&self) -> Result<VerifyView, ApiError> {
        let r = ms_receipts::verify(self.receipts.dir(), Some(&*self.vault))
            .map_err(|e| ApiError::internal(format!("morsec: verifying failed: {e}")))?;
        Ok(VerifyView {
            ok: r.ok(),
            records: r.records,
            files: r.files,
            macs_checked: r.macs_checked,
            text: r.to_string(),
        })
    }

    pub(crate) fn dash_agents(&self) -> Result<AgentsView, ApiError> {
        let records = self.receipts_all()?;
        let alerts = lock(&self.alerts).clone();
        let (tampered, stopped) = {
            let l = self.read_live();
            (l.rules.tampered, l.rules.stopped)
        };
        let mut checks = vec![
            CheckView {
                ok: !alerts.iter().any(|a| a.contains("proxy is not running")),
                text: format!("swap proxy on 127.0.0.1:{}", self.proxy_port),
            },
            CheckView {
                ok: !tampered,
                text: if tampered {
                    "the rules failed their integrity check: every key is denied".into()
                } else {
                    "rules verified".into()
                },
            },
            CheckView {
                ok: !stopped,
                text: if stopped {
                    "morsec is stopped: resume with ms start".into()
                } else {
                    "morsec is on".into()
                },
            },
        ];
        match lock(&self.ca).as_ref() {
            Some((_, hosts)) => checks.push(CheckView {
                ok: true,
                text: format!("proxy CA issued for {} hosts", hosts.len()),
            }),
            None => checks.push(CheckView {
                ok: true,
                text: "no host bound yet, so no proxy CA in use".into(),
            }),
        }
        checks.extend(alerts.into_iter().map(|a| CheckView { ok: false, text: a }));
        Ok(AgentsView {
            agents: self.agent_views(&records),
            checks,
        })
    }

    pub(crate) fn dash_scan(&self) -> ScanView {
        let last = lock(&self.last_scan).as_ref().and_then(|(at, r)| match r {
            ResponseBody::ScanReport {
                findings,
                files_scanned,
                bytes_scanned,
                keys_checked,
                skipped_keys,
                notes,
                complete,
            } => Some(ScanSnapshot {
                at_unix_ms: *at,
                complete: *complete,
                files_scanned: *files_scanned,
                bytes_scanned: *bytes_scanned,
                keys_checked: *keys_checked,
                findings: findings
                    .iter()
                    .map(|f| ScanFindingView {
                        file: f.file.clone(),
                        line: f.line,
                        key: f.key.to_string(),
                        encoding: f.encoding.clone(),
                    })
                    .collect(),
                skipped_keys: skipped_keys.iter().map(ToString::to_string).collect(),
                notes: notes.clone(),
            }),
            _ => None,
        });
        ScanView { last }
    }
}

/// The per-connection process check `DashSource` runs (`crate::dash::ConnCheck` in production).
pub type ConnChecker =
    Arc<dyn Fn(SocketAddr, SocketAddr) -> Result<SessionId, Refusal> + Send + Sync>;

/// msd's [`DashData`]: the daemon (weakly, so the dashboard it owns doesn't keep it alive) and
/// the connection check.
pub struct DashSource {
    d: Weak<Daemon>,
    check: ConnChecker,
}

impl std::fmt::Debug for DashSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DashSource")
    }
}

impl DashSource {
    /// A source over `d`, checking connections with `check`.
    pub fn new(d: &Arc<Daemon>, check: ConnChecker) -> Self {
        Self {
            d: Arc::downgrade(d),
            check,
        }
    }

    fn d(&self) -> Result<Arc<Daemon>, ApiError> {
        self.d
            .upgrade()
            .ok_or_else(|| ApiError::unavailable("morsec: msd is stopping"))
    }
}

impl DashData for DashSource {
    fn check_connection(&self, peer: SocketAddr, local: SocketAddr) -> Result<SessionId, Refusal> {
        (self.check)(peer, local)
    }
    fn record_refused(&self, refusal: &Refusal) {
        if let Ok(d) = self.d() {
            d.record_dash_refusal(refusal);
        }
    }
    fn home(&self) -> Result<HomeView, ApiError> {
        self.d()?.dash_home()
    }
    fn projects(&self) -> Result<ProjectsView, ApiError> {
        self.d()?.dash_projects_view()
    }
    fn project(&self, slug: &str) -> Result<ProjectView, ApiError> {
        self.d()?.dash_project(slug)
    }
    fn secret(&self, key: &KeyName) -> Result<SecretView, ApiError> {
        self.d()?.dash_secret(key)
    }
    fn activity(&self, q: &ActivityQuery) -> Result<ActivityView, ApiError> {
        self.d()?.dash_activity(q)
    }
    fn export(
        &self,
        q: &ActivityQuery,
        format: ExportFormat,
    ) -> Result<(String, &'static str, Vec<u8>), ApiError> {
        self.d()?.dash_export(q, format)
    }
    fn verify(&self) -> Result<VerifyView, ApiError> {
        self.d()?.dash_verify()
    }
    fn agents(&self) -> Result<AgentsView, ApiError> {
        self.d()?.dash_agents()
    }
    fn scan(&self) -> Result<ScanView, ApiError> {
        Ok(self.d()?.dash_scan())
    }
}
