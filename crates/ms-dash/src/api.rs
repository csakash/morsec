//! The API's views: what each screen shows. Names, refs, paths, hosts, counts and statuses only.
//! No struct here has a field that can hold a secret value (SPEC D-3, criterion 10); the masked
//! code finding is the catalog prefix and a length, as L31 records it.
//!
//! Every string in a view may come from a file, an agent or a user: the page renders all of it
//! with `textContent` (criterion 11).

use serde::Serialize;

/// Home (`GET /api/home`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HomeView {
    /// False after `ms stop`.
    pub running: bool,
    /// `keychain` or `dev-memory`.
    pub vault: String,
    /// msd's version.
    pub version: String,
    /// Keys in the vault (morsec's own excluded).
    pub keys: u32,
    /// Projects `ms init` set up.
    pub projects: u32,
    /// Keys whose rule allows something.
    pub protected: u32,
    /// Keys whose rule still allows nothing (no known service yet).
    pub needs_website: u32,
    /// Blocked receipts in the last 24 h.
    pub blocked_24h: u64,
    /// Things to look at (tampered rules, settings drift…).
    pub alerts: Vec<String>,
    /// The request waiting for a person, if any.
    pub pending: Option<PendingView>,
    /// Supported agents.
    pub agents: Vec<AgentView>,
    /// The project records failed their integrity check.
    pub projects_unreadable: bool,
}

/// The approval waiting for a person. Shown, never answered here (L33).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PendingView {
    /// Agent label.
    pub agent: String,
    /// Key.
    pub key: String,
    /// `test` or `production`.
    pub tier: String,
    /// The exact command, one element per argument.
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// When it times out, Unix ms.
    pub expires_unix_ms: u64,
}

/// Projects (`GET /api/projects`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectsView {
    /// One card per project.
    pub projects: Vec<ProjectCard>,
    /// Keys in no project ("Not in a project").
    pub loose: Vec<KeyRow>,
    /// Why the project records can't be shown, when they can't.
    pub unreadable: Option<String>,
}

/// One project card.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectCard {
    /// Slug.
    pub slug: String,
    /// The folder's own name.
    pub display: String,
    /// Canonical root.
    pub root: String,
    /// Keys that work.
    pub protected: u32,
    /// Keys with no known service yet.
    pub needs_website: u32,
    /// Keys written into code.
    pub findings: u32,
    /// Env files found in git history.
    pub committed_files: u32,
    /// The last scan stopped at a budget.
    pub stopped_early: bool,
}

/// One key: its rule's targets and status, never its value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct KeyRow {
    /// Key name.
    pub key: String,
    /// `swap`, `run`, `mint`, or none without a rule.
    pub mode: Option<String>,
    /// `test` or `production`.
    pub tier: Option<String>,
    /// The rule allows something.
    pub ready: bool,
    /// The key is in the vault.
    pub stored: bool,
    /// `protected`, `needs a website`, `needs a command`, `not stored`.
    pub status: String,
    /// Hosts (swap) or roots (run).
    pub targets: Vec<String>,
}

/// One project (`GET /api/projects/<slug>`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectView {
    /// Slug.
    pub slug: String,
    /// The folder's own name.
    pub display: String,
    /// Canonical root.
    pub root: String,
    /// When `ms init` first set it up, Unix ms.
    pub created_unix_ms: u64,
    /// Entries the last scan visited.
    pub scan_entries: u64,
    /// How long it took.
    pub scan_ms: u64,
    /// It stopped at a budget.
    pub stopped_early: bool,
    /// One row per variable in an env file.
    pub rows: Vec<SecretRow>,
    /// Keys written into code (never values).
    pub findings: Vec<FindingView>,
    /// Env files committed to git.
    pub committed: Vec<CommittedView>,
    /// Agent hint blocks written (`CLAUDE.md`, `AGENTS.md`).
    pub hints: Vec<String>,
}

/// One variable of a project's env file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SecretRow {
    /// Variable name.
    pub var: String,
    /// File, relative to the root.
    pub file: String,
    /// 1-based line.
    pub line: u64,
    /// The key it refers to.
    pub key: String,
    /// Catalog provider, when known.
    pub provider: Option<String>,
    /// Tier, when the key has a rule.
    pub tier: Option<String>,
    /// Mode, when the key has a rule.
    pub mode: Option<String>,
    /// `protected`, `needs a website`, `needs a command`, `not stored`.
    pub status: String,
    /// The last receipt for the key, Unix ms.
    pub last_use_unix_ms: Option<u64>,
}

/// A key written into code: where, which provider, masked as the catalog prefix and a length.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FindingView {
    /// File, relative to the root.
    pub path: String,
    /// 1-based line.
    pub line: u64,
    /// Provider.
    pub provider: String,
    /// `sk_live_… (107 bytes)`.
    pub masked: String,
}

/// An env file found in git history.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommittedView {
    /// File, relative to the root.
    pub path: String,
    /// Commits it appears in.
    pub commits: u64,
}

/// One key (`GET /api/keys/<key>`). The value is never here: the page shows "hidden" (L33 adds
/// Show and Copy behind Touch ID).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SecretView {
    /// Key name.
    pub key: String,
    /// Catalog provider, from the project record, when known.
    pub provider: Option<String>,
    /// Mode, when the key has a rule.
    pub mode: Option<String>,
    /// Tier, when the key has a rule.
    pub tier: Option<String>,
    /// When it was added, Unix ms, when it is in the vault.
    pub created_unix_ms: Option<u64>,
    /// In the vault.
    pub stored: bool,
    /// The rule allows something.
    pub ready: bool,
    /// `protected`, `needs a website`, `needs a command`, `not stored`.
    pub status: String,
    /// Swap hosts.
    pub hosts: Vec<String>,
    /// Git hosts (Basic password).
    pub git_hosts: Vec<String>,
    /// Run commands, each as its words joined by spaces.
    pub commands: Vec<String>,
    /// Run roots.
    pub roots: Vec<String>,
    /// Run environment variable names.
    pub env: Vec<String>,
    /// Read-only (MCP tools).
    pub read_only: bool,
    /// Where project files refer to it.
    pub used_in: Vec<UsedIn>,
    /// Its last 20 receipts, newest first.
    pub uses: Vec<ActivityRow>,
}

/// A project file line that holds the key's ref.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UsedIn {
    /// Project slug.
    pub project: String,
    /// File, relative to its root.
    pub file: String,
    /// 1-based line.
    pub line: u64,
    /// Variable name.
    pub var: String,
}

/// Filters for Activity and its export, from the query string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivityQuery {
    /// `30m`, `24h`, `7d`, a date (as `ms log --since`).
    pub since: Option<String>,
    /// One key.
    pub key: Option<String>,
    /// Keys of one project (`<slug>/…`).
    pub project: Option<String>,
    /// Agent label.
    pub agent: Option<String>,
    /// `allowed`, `approved`, `blocked`, `denied`, `failed`, `alert`.
    pub result: Option<String>,
    /// Most rows (default 200, at most 1,000; exports take every match).
    pub limit: Option<usize>,
}

/// Export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON document.
    Json,
    /// CSV.
    Csv,
}

/// Activity (`GET /api/activity`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ActivityView {
    /// Newest first.
    pub rows: Vec<ActivityRow>,
    /// Records matching the filters.
    pub matched: usize,
    /// Records in all.
    pub total: usize,
}

/// One receipt or alert, as `ms log` shows it (targets are redacted before they are written).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ActivityRow {
    /// Sequence number.
    pub seq: u64,
    /// Unix ms.
    pub time_unix_ms: u64,
    /// `receipt` or `alert`.
    pub kind: String,
    /// Agent label.
    pub agent: String,
    /// The session's root PID.
    pub pid: u32,
    /// Key (empty for an alert).
    pub key: String,
    /// `swap`, `run`, `mint` (empty for an alert).
    pub mechanism: String,
    /// Host or command, redacted.
    pub target: String,
    /// `allowed`, `approved`, `blocked`, `denied`, `failed`, `alert`.
    pub result: String,
    /// Why it was blocked or failed.
    pub reason: Option<String>,
}

/// `GET /api/activity/verify`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VerifyView {
    /// Nothing wrong.
    pub ok: bool,
    /// Records that passed.
    pub records: u64,
    /// Files read.
    pub files: usize,
    /// Record MACs checked too.
    pub macs_checked: bool,
    /// One line for people.
    pub text: String,
}

/// Agents (`GET /api/agents`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentsView {
    /// Supported agents.
    pub agents: Vec<AgentView>,
    /// msd's own checks.
    pub checks: Vec<CheckView>,
}

/// One supported agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentView {
    /// `claude-code`, `codex`.
    pub id: String,
    /// `Claude Code`, `Codex`.
    pub name: String,
    /// Its settings folder exists.
    pub installed: bool,
    /// `ms connect` applied (its state file exists).
    pub connected: bool,
    /// Sessions seen in the receipts.
    pub sessions: u64,
    /// Blocked receipts of its sessions.
    pub blocked: u64,
    /// Its last receipt, Unix ms.
    pub last_seen_unix_ms: Option<u64>,
}

/// One check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckView {
    /// Passed.
    pub ok: bool,
    /// What was checked and what to do.
    pub text: String,
}

/// Scan (`GET /api/scan`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanView {
    /// The last scan msd ran since it started, if any.
    pub last: Option<ScanSnapshot>,
}

/// A transcript leak scan's result: where values were found, never the values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanSnapshot {
    /// When it finished, Unix ms.
    pub at_unix_ms: u64,
    /// It read everything it meant to.
    pub complete: bool,
    /// Transcript files read.
    pub files_scanned: u64,
    /// Bytes read.
    pub bytes_scanned: u64,
    /// Keys searched for.
    pub keys_checked: u32,
    /// Findings.
    pub findings: Vec<ScanFindingView>,
    /// Keys too short to search.
    pub skipped_keys: Vec<String>,
    /// Notes.
    pub notes: Vec<String>,
}

/// Where a value was found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanFindingView {
    /// Transcript file.
    pub file: String,
    /// 1-based line.
    pub line: u64,
    /// The key whose value it was.
    pub key: String,
    /// `raw`, `base64`…
    pub encoding: String,
}

/// Parses Activity's query string (`a=b&c=d`, percent-encoded). Unknown names are ignored.
pub fn parse_activity_query(query: &str) -> ActivityQuery {
    let mut q = ActivityQuery::default();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(v) = percent_decode(v).filter(|v| !v.is_empty() && v.len() <= 256) else {
            continue;
        };
        match k {
            "since" => q.since = Some(v),
            "key" => q.key = Some(v),
            "project" => q.project = Some(v),
            "agent" => q.agent = Some(v),
            "result" => q.result = Some(v),
            "limit" => q.limit = v.parse().ok(),
            _ => {}
        }
    }
    q
}

/// `%XX` and `+` decoding; `None` for bad escapes or non-UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=Activity filters come only from known names, decoded, bounded; fails_when=a bad
    // escape or an overlong value is taken, or an unknown name changes the query;
    // no_claim=what msd does with the filters (msd tests)
    #[test]
    fn activity_query_parsing() {
        let q = parse_activity_query("since=24h&key=shop%2Fstripe&agent=claude-code&x=1&limit=5");
        assert_eq!(q.since.as_deref(), Some("24h"));
        assert_eq!(q.key.as_deref(), Some("shop/stripe"));
        assert_eq!(q.agent.as_deref(), Some("claude-code"));
        assert_eq!(q.limit, Some(5));
        assert_eq!(parse_activity_query("key=%zz").key, None);
        let long = format!("key={}", "a".repeat(300));
        assert_eq!(parse_activity_query(&long).key, None);
    }
}
