//! `ms init` in a project (L31 guided-init, design §4.3 to §4.7, SPEC "Project steps").
//!
//! The CLI runs the steps (SPEC D-1) with `ms_projects`, and values go to msd exactly as
//! `ms import` sends them (`IpcStore` → `PutKey`, each new key allowing nothing). Then one
//! `ProjectSave` carries the record and the first rules of the new keys, which msd applies after
//! one approval (SPEC D-2). No value is ever printed, put in the record, or in an error.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ms_core::KeyName;
use ms_import::KeyStore;
use ms_import::catalog::Catalog;
use ms_import::envfile::{self, EnvFile};
use ms_import::plan::{Action, Plan};
use ms_ipc::{Client, ErrorCode, KeyStatus, RequestBody, ResponseBody};
use ms_projects::naming::{Source, plan_project};
use ms_projects::record::{
    FileRecord, FindingRecord, HintRecord, ProjectRecord, Quote, ScanRecord, SecretAction,
    SecretRecord,
};
use ms_projects::walk::{Budgets, Walker};
use ms_rules::Rules;

use crate::import::{IpcStore, now_unix_ms};
use crate::terminal_safe;

/// Debug builds only: append every path the walk opened to this file (the SPEC criterion 1
/// audit the integration tests read).
pub(crate) const WALK_AUDIT_ENV: &str = "MORSEC_TEST_WALK_AUDIT";

/// What project setup did, for the summary.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub slug: String,
    pub display: String,
    pub root: PathBuf,
    /// Secret lines moved into the vault this run, and the files they were in.
    pub found: usize,
    pub files: usize,
    /// Keys of the project and whether each is ready.
    pub keys: Vec<KeyStatus>,
    /// Keys with no known provider (they allow nothing until the user adds a host).
    pub unknown: Vec<KeyName>,
    pub findings: Vec<FindingRecord>,
    /// (file, commits) for files with git history.
    pub committed: Vec<(String, u64)>,
    /// (file, why) for files left untouched.
    pub failed: Vec<(String, String)>,
    /// The approval was not given (or timed out): keys stored but inert.
    pub declined: Option<String>,
    /// The record could not be saved.
    pub save_error: Option<String>,
    /// The record was saved but the keys' first rules were not, for a reason other than the
    /// approval (an invalid proposal, the rules unreadable).
    pub rules_error: Option<String>,
    pub stopped_early: Option<String>,
    pub too_large: Vec<String>,
    /// Keys an earlier run stored whose refs were found but which no record listed (review R1).
    pub recovered: usize,
    /// Keys an earlier record listed that are gone from the vault (review R4).
    pub missing: Vec<KeyName>,
    /// Code findings left out of the record (limits, unrecordable paths).
    pub findings_skipped: usize,
    pub hints: Vec<String>,
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: starting the IPC client: {e}"))
}

fn ask(
    rt: &tokio::runtime::Runtime,
    body: RequestBody,
    wait: Option<Duration>,
) -> Result<ResponseBody, String> {
    rt.block_on(async {
        let path = ms_ipc::default_socket_path()?;
        let mut c = Client::connect(&path).await?;
        match wait {
            Some(w) => c.request_within(body, w).await,
            None => c.request(body).await,
        }
    })
    .map_err(|e| e.to_string())
}

const UNEXPECTED: &str = "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)";

fn as_error(r: ResponseBody) -> String {
    match r {
        ResponseBody::Error { message, .. } => message,
        _ => UNEXPECTED.to_owned(),
    }
}

/// `root` relative path → `root/rel`, refusing it unless its parent still resolves to the same
/// place under the root (a directory swapped for a symlink since the walk).
fn checked_path(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let path = root.join(rel);
    let parent = path.parent().unwrap_or(root);
    match std::fs::canonicalize(parent) {
        Ok(p) if p == parent => Ok(path),
        _ => Err("its folder changed since the scan (a symlink?); not imported".into()),
    }
}

fn secret_records(file: &EnvFile, plan: &Plan) -> Vec<SecretRecord> {
    plan.rows
        .iter()
        .filter(|r| r.action.rewrites())
        .filter_map(|r| {
            Some(SecretRecord {
                var: r.var.clone(),
                line: r.line as u64,
                key: r.key.clone()?,
                quote: Quote::from(file.entries()[r.entry].quote),
                action: if r.action == Action::Import {
                    SecretAction::Import
                } else {
                    SecretAction::Reuse
                },
                provider: r.provider.clone(),
            })
        })
        .collect()
}

/// Runs the project steps at `root` (canonical, checked by the caller).
pub(crate) fn run(root: &Path, name: Option<&str>) -> Result<Report, String> {
    // A root msd can't record (bidi or invisible characters, security review S3) is refused
    // before anything is read or moved.
    let root_text = root.to_str().unwrap_or("");
    if root_text.is_empty() || root_text.chars().any(ms_projects::record::is_unsafe_char) {
        return Err(
            "morsec: this folder's path has characters morsec can't show safely (control, bidi or invisible). Move the project to a plain path, then run ms init"
                .into(),
        );
    }
    let rt = runtime()?;
    let catalog = Catalog::builtin();
    let mut rep = Report {
        root: root.to_owned(),
        ..Report::default()
    };

    // 1. Name (design §4.4).
    let existing = match ask(&rt, RequestBody::ProjectList, None)? {
        ResponseBody::Projects { projects } => projects,
        other => return Err(as_error(other)),
    };
    let pairs: Vec<(String, PathBuf)> = existing
        .iter()
        .map(|p| (p.slug.clone(), PathBuf::from(&p.root)))
        .collect();
    let mine = pairs
        .iter()
        .find(|(_, r)| r == root)
        .map(|(s, _)| s.clone());
    rep.slug = match (&mine, name) {
        (Some(s), _) => s.clone(),
        (None, Some(n)) => {
            let base = ms_projects::slug::slug(n);
            if pairs.iter().any(|(s, _)| *s == base) {
                ms_projects::slug::suffixed(&base, root)
            } else {
                base
            }
        }
        (None, None) => {
            ms_projects::slug::choose(root, pairs.iter().map(|(s, r)| (s.as_str(), r.as_path())))
        }
    };
    let raw_display = name.map(str::to_owned).unwrap_or_else(|| {
        root.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    rep.display = ms_projects::record::display_name(&raw_display, &rep.slug);
    let previous = match &mine {
        Some(s) => match ask(&rt, RequestBody::ProjectGet { slug: s.clone() }, None)? {
            ResponseBody::Project { record, .. } => {
                Some(ProjectRecord::from_toml(&record).map_err(|e| e.to_string())?)
            }
            other => return Err(as_error(other)),
        },
        None => None,
    };

    // 2-3. Walk and classify (design §4.5).
    let scan = Walker::new(catalog, Budgets::default())
        .walk(root)
        .map_err(|e| e.to_string())?;
    if cfg!(debug_assertions)
        && let Some(p) = std::env::var_os(WALK_AUDIT_ENV).filter(|p| !p.is_empty())
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            for o in &scan.opened {
                let _ = writeln!(f, "{}", root.join(o).display());
            }
        }
    }
    if scan.stopped_early {
        rep.stopped_early = scan.stop_reason.clone();
    }
    rep.too_large = scan.too_large.clone();
    let examples: BTreeSet<String> = scan
        .examples
        .iter()
        .flat_map(|e| e.vars.iter().cloned())
        .collect();

    // 4. Plan every env file.
    let mut files: Vec<(String, PathBuf, EnvFile)> = Vec::new();
    for rel in &scan.env_files {
        let shown = terminal_safe(rel);
        let path = match checked_path(root, rel) {
            Ok(p) => p,
            Err(e) => {
                rep.failed.push((rel.clone(), e));
                continue;
            }
        };
        match EnvFile::read(&path, &shown) {
            Ok(f) => files.push((rel.clone(), path, f)),
            Err(e) => rep
                .failed
                .push((rel.clone(), terminal_safe(&e.to_string()))),
        }
    }
    let store = IpcStore::new().map_err(|e| e.to_string())?;
    let vault_keys = store.list().map_err(|e| e.to_string())?;
    let sources: Vec<Source<'_>> = files
        .iter()
        .map(|(rel, _, f)| Source {
            rel,
            entries: f.entries(),
        })
        .collect();
    let plans = plan_project(catalog, &rep.slug, &sources, &examples, &vault_keys);

    // 5. Store and rewrite, file by file. The base is the earlier record, without keys that are
    // gone from the vault (they are listed, review R4). A file is imported only when the record
    // can hold it (review R3), so no key exists without a record entry.
    let mut stored: BTreeSet<KeyName> = vault_keys.iter().map(|m| m.name.clone()).collect();
    let mut by_path: BTreeMap<String, FileRecord> = BTreeMap::new();
    let mut known: BTreeSet<KeyName> = BTreeSet::new();
    for f in previous.iter().flat_map(|p| p.files.iter()) {
        let mut f = f.clone();
        f.secrets.retain(|s| {
            let here = stored.contains(&s.key);
            if !here && !rep.missing.contains(&s.key) {
                rep.missing.push(s.key.clone());
            }
            here
        });
        known.extend(f.secrets.iter().map(|s| s.key.clone()));
        if !f.secrets.is_empty() {
            by_path.insert(f.path.clone(), f);
        }
    }
    for ((rel, path, file), plan) in files.iter().zip(plans) {
        let plan = match plan {
            Ok(p) => p,
            Err(e) => {
                rep.failed
                    .push((rel.clone(), terminal_safe(&e.to_string())));
                continue;
            }
        };
        let rewrites = plan.rows.iter().filter(|r| r.action.rewrites()).count();
        let adopted = adopt_refs(
            catalog,
            &rep.slug,
            rel,
            file,
            &plan,
            &stored,
            previous.as_ref(),
        );
        if rewrites == 0 && adopted.is_empty() {
            continue;
        }
        let (others_secrets, others_bytes) = by_path
            .iter()
            .filter(|(p, _)| *p != rel)
            .fold((0, 0), |(n, b), (p, f)| (n + f.secrets.len(), b + p.len()));
        let mine_before = by_path.get(rel).map_or(0, |f| f.secrets.len());
        if let Err(e) = ms_projects::record::admit_file(
            rel,
            mine_before + rewrites + adopted.len(),
            others_secrets,
            others_bytes,
        ) {
            rep.failed.push((
                rel.clone(),
                format!(
                    "can't be recorded ({}); not changed",
                    terminal_safe(&e.to_string())
                ),
            ));
            continue;
        }
        let mut fresh: Vec<SecretRecord> = Vec::new();
        let mut commits = None;
        if rewrites > 0 {
            let own: BTreeSet<&KeyName> = plan.imports().filter_map(|r| r.key.as_ref()).collect();
            if let Some(missing) = plan
                .rows
                .iter()
                .filter(|r| r.action.rewrites())
                .filter_map(|r| r.key.as_ref())
                .find(|k| !own.contains(k) && !stored.contains(*k))
            {
                rep.failed.push((
                    rel.clone(),
                    format!(
                        "shares a value with a file that was not imported ({missing}); not changed"
                    ),
                ));
                continue;
            }
            match envfile::commit(file, &plan, &store, now_unix_ms()) {
                Ok(done) => {
                    stored.extend(done.stored);
                    rep.found += done.rewritten;
                    rep.files += 1;
                    commits = envfile::git_history(path).map(|n| n as u64);
                    if let Some(n) = commits.filter(|n| *n > 0) {
                        rep.committed.push((rel.clone(), n));
                    }
                    fresh = secret_records(file, &plan);
                }
                Err(e) => {
                    rep.failed
                        .push((rel.clone(), terminal_safe(&e.to_string())));
                    continue;
                }
            }
        }
        for a in &adopted {
            if !known.contains(&a.key) {
                known.insert(a.key.clone());
                rep.recovered += 1;
            }
        }
        fresh.extend(adopted);
        let entry = by_path.entry(rel.clone()).or_insert_with(|| FileRecord {
            path: rel.clone(),
            git_history_commits: None,
            secrets: Vec::new(),
        });
        if commits.is_some() {
            entry.git_history_commits = commits;
        }
        let vars: BTreeSet<String> = fresh.iter().map(|s| s.var.clone()).collect();
        entry.secrets.retain(|s| !vars.contains(&s.var));
        entry.secrets.extend(fresh);
        entry.secrets.sort_by_key(|s| s.line);
    }

    // 7. Agent hint block (before the record, which lists it). A failure is listed, not fatal.
    rep.hints = match ms_projects::hint::apply(root, &rep.slug) {
        Ok(h) => h,
        Err(e) => {
            rep.failed.push((
                "CLAUDE.md / AGENTS.md".into(),
                format!("hint block not added: {}", terminal_safe(&e.to_string())),
            ));
            Vec::new()
        }
    };

    // The record: earlier runs' files and hints, this run's scan and findings.
    let mut record = ProjectRecord {
        slug: rep.slug.clone(),
        display: rep.display.clone(),
        root: root.display().to_string(),
        created_unix_ms: previous
            .as_ref()
            .map_or_else(now_unix_ms, |p| p.created_unix_ms),
        scan: ScanRecord {
            entries: scan.entries,
            stopped_early: scan.stopped_early,
            ms: scan.elapsed_ms,
        },
        files: by_path.into_values().collect(),
        findings: Vec::new(),
        hints: previous
            .as_ref()
            .map(|p| p.hints.clone())
            .unwrap_or_default(),
    };
    for h in &rep.hints {
        if !record.hints.iter().any(|x| &x.path == h) {
            record.hints.push(HintRecord { path: h.clone() });
        }
    }
    let (findings, skipped) = ms_projects::record::fit_findings(
        scan.findings
            .iter()
            .map(|f| FindingRecord {
                path: f.path.clone(),
                line: f.line as u64,
                provider: f.provider.clone(),
                masked: f.masked.clone(),
            })
            .collect(),
        record.path_bytes(),
    );
    record.findings = findings;
    rep.findings_skipped = skipped;
    rep.findings = record.findings.clone();

    // 6. Save the record first, with no rule change and no approval (review R1): whatever
    // happens to the approval below (denied, timed out, stopped, Ctrl-C), the next ms init knows
    // these keys and asks again.
    let saved = match record.validate() {
        Err(e) => Err(e.to_string()),
        Ok(()) => match ask(
            &rt,
            RequestBody::ProjectSave {
                record: record.to_toml(),
                rules: ms_projects::save::canonical(&Rules::default()),
            },
            None,
        ) {
            Ok(ResponseBody::Ok { .. }) => Ok(()),
            Ok(other) => Err(as_error(other)),
            Err(e) => Err(e),
        },
    };
    if let Err(e) = saved {
        rep.save_error = Some(terminal_safe(&e));
    } else {
        // Then one approval for the first rules of the new keys.
        let proposed = match ask(&rt, RequestBody::RulesGet { key: None }, None) {
            Ok(ResponseBody::Rules { toml, .. }) => {
                Rules::from_toml(&toml, "the rules from msd").map_err(|e| e.to_string())
            }
            Ok(other) => Err(as_error(other)),
            Err(e) => Err(e),
        }
        .map(|current| ms_projects::save::initial_rules(catalog, &record, &current));
        match proposed {
            Err(e) => rep.rules_error = Some(terminal_safe(&e)),
            Ok(p) if p.keys.is_empty() => {}
            Ok(p) => {
                let _review = crate::approve::inline_review("ms init");
                match ask(
                    &rt,
                    RequestBody::ProjectSave {
                        record: record.to_toml(),
                        rules: ms_projects::save::canonical(&p),
                    },
                    Some(crate::approve::APPROVAL_WAIT),
                ) {
                    Ok(ResponseBody::Ok { .. }) => {}
                    Ok(ResponseBody::Error {
                        code: ErrorCode::NeedsApproval | ErrorCode::Busy | ErrorCode::Denied,
                        message,
                    }) => {
                        rep.declined = Some(terminal_safe(&message));
                    }
                    Ok(ResponseBody::Error { message, .. }) => {
                        rep.rules_error = Some(terminal_safe(&message));
                    }
                    Ok(_) => rep.declined = Some(UNEXPECTED.to_owned()),
                    Err(e) => rep.declined = Some(terminal_safe(&e)),
                }
            }
        }
    }

    // The keys' state for the summary.
    rep.keys = match ask(
        &rt,
        RequestBody::ProjectGet {
            slug: rep.slug.clone(),
        },
        None,
    ) {
        Ok(ResponseBody::Project { keys, .. }) => keys,
        _ => Vec::new(),
    };
    let ready: BTreeSet<&KeyName> = rep
        .keys
        .iter()
        .filter(|k| k.ready)
        .map(|k| &k.key)
        .collect();
    rep.unknown = record
        .keys()
        .into_iter()
        .filter(|k| !ready.contains(k) && record.provider_of(k).is_none())
        .collect();
    Ok(rep)
}

/// Lines of `file` that already hold a ref to a key of this project that is in the vault
/// (review R1): an earlier `ms init` that stored keys but died before its record was saved,
/// or an `ms import --name <slug>/...`. They go into the record so the keys are not orphaned;
/// the provider comes from the earlier record, else from the variable name in the catalog.
fn adopt_refs(
    catalog: &Catalog,
    slug: &str,
    rel: &str,
    file: &EnvFile,
    plan: &Plan,
    stored: &BTreeSet<KeyName>,
    previous: Option<&ProjectRecord>,
) -> Vec<SecretRecord> {
    let prefix = format!("{slug}/");
    plan.rows
        .iter()
        .filter(|r| r.action == Action::AlreadyRef)
        .filter_map(|r| {
            let key = KeyName::new(r.masked.strip_prefix("ms://")?).ok()?;
            if !key.as_str().starts_with(&prefix) || !stored.contains(&key) {
                return None;
            }
            // Review R7: the file (agent-writable) never chooses a key's hosts. A key the
            // earlier record lists keeps exactly its recorded provider (None stays None); an
            // orphan takes one from the variable name only when ms init would have given that
            // variable this very name.
            let provider = match previous.filter(|p| p.keys().contains(&key)) {
                Some(p) => p.provider_of(&key).map(str::to_owned),
                None if ms_projects::naming::is_generated_name(slug, rel, &r.var, &key) => catalog
                    .providers
                    .iter()
                    .find(|p| p.matches_env_name(&r.var))
                    .map(|p| p.id.clone()),
                None => None,
            };
            Some(SecretRecord {
                var: r.var.clone(),
                line: r.line as u64,
                key,
                quote: Quote::from(file.entries()[r.entry].quote),
                action: SecretAction::Import,
                provider,
            })
        })
        .collect()
}

/// `~/code/shop` for a root under `home`.
pub(crate) fn tilde(p: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| p.strip_prefix(h).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => p.display().to_string(),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The project part of the summary (SPEC "Summary"), as (label, text) rows.
pub(crate) fn summary_rows(r: &Report, home: Option<&Path>) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    rows.push((
        "Project".to_owned(),
        format!("{}  ({})", r.display, tilde(&r.root, home)),
    ));
    let total = r.keys.len();
    let ready = r.keys.iter().filter(|k| k.ready).count();
    if r.found > 0 {
        rows.push((
            "Found".to_owned(),
            format!(
                "{} in {}",
                plural(r.found, "secret", "secrets"),
                plural(r.files, "file", "files")
            ),
        ));
    } else if total > 0 {
        let waiting = total - ready;
        rows.push((
            "Found".to_owned(),
            if waiting == 0 {
                format!("nothing new; {ready} already protected")
            } else {
                format!(
                    "nothing new; {ready} already protected, {waiting} still {} you",
                    if waiting == 1 { "needs" } else { "need" }
                )
            },
        ));
    } else {
        rows.push(("Found".to_owned(), "no secrets in this project".to_owned()));
    }
    if total > 0 {
        rows.push(("Protected".to_owned(), format!("{ready}, ready to use")));
    }
    if r.recovered > 0 {
        rows.push((
            "Recovered".to_owned(),
            format!(
                "{} an earlier run stored but never recorded",
                plural(r.recovered, "key", "keys")
            ),
        ));
    }
    if let Some(first) = r.missing.first() {
        rows.push((
            "Missing".to_owned(),
            format!(
                "{} no longer in the vault ({first}{}); its lines still hold the ref",
                plural(r.missing.len(), "key is", "keys are"),
                if r.missing.len() > 1 { " and more" } else { "" }
            ),
        ));
    }
    if let Some(why) = &r.declined {
        rows.push((
            "Approval".to_owned(),
            format!(
                "not given, so these keys are stored but can't be used yet. Run ms init again to approve ({why})"
            ),
        ));
    }
    if let Some(first) = r.unknown.first() {
        rows.push((
            "Needs you".to_owned(),
            format!(
                "{} no known service yet: ms rules {first} --add-host <host>",
                plural(r.unknown.len(), "has", "have")
            ),
        ));
    }
    let run_keys: Vec<&KeyStatus> = r
        .keys
        .iter()
        .filter(|k| !k.ready && k.mode == Some(ms_core::Mode::Run))
        .collect();
    if let Some(k) = run_keys.first() {
        rows.push((
            "Needs you".to_owned(),
            format!(
                "{} can run only in this folder and needs its commands: ms rules {} --add-command '[\"psql\", \"**\"]'",
                plural(run_keys.len(), "database key", "database keys"),
                k.key
            ),
        ));
    }
    if let Some(f) = r.findings.first() {
        rows.push((
            "In code".to_owned(),
            format!(
                "{} written straight into {}:{}{} (move it into .env, then ms init)",
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
            "In code".to_owned(),
            format!(
                "{} more not recorded (too many, or a path morsec can't record)",
                r.findings_skipped
            ),
        ));
    }
    for (file, n) in &r.committed {
        rows.push((
            "Committed".to_owned(),
            format!(
                "{file} is in {}: rotate those keys at each provider",
                plural(*n as usize, "git commit", "git commits")
            ),
        ));
    }
    for (file, why) in &r.failed {
        rows.push(("Skipped".to_owned(), format!("{file}: {why}")));
    }
    for file in &r.too_large {
        rows.push((
            "Skipped".to_owned(),
            format!("{file}: too large for a .env file"),
        ));
    }
    if let Some(why) = &r.stopped_early {
        rows.push((
            "Scan".to_owned(),
            format!("stopped {why}; run ms init --project PATH on a subfolder to cover the rest"),
        ));
    }
    if let Some(e) = &r.rules_error {
        rows.push((
            "Rules".to_owned(),
            format!("not saved: {e}. The keys are recorded but can't be used yet"),
        ));
    }
    if let Some(e) = &r.save_error {
        rows.push(("Record".to_owned(), format!("not saved: {e}")));
    }
    if !r.hints.is_empty() {
        rows.push((
            "Hint".to_owned(),
            format!(
                "added to {}: agents keep the ms:// refs as they are",
                r.hints.join(", ")
            ),
        ));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC summary: the rows name the project, the counts, the unknown key's exact fix,
    // the code finding's file:line, git history and "already protected" on a re-run; no dashboard
    // or ms dev line (SPEC D-3); fails_when=a row is missing or a dashboard line appears;
    // no_claim=terminal_safe (applied when printed)
    #[test]
    fn summary_rows_text() {
        let k = |n: &str, ready: bool| KeyStatus {
            key: KeyName::new(n).unwrap(),
            mode: Some(ms_core::Mode::Swap),
            tier: Some(ms_core::Tier::Test),
            ready,
            targets: Vec::new(),
            stored: true,
        };
        let mut r = Report {
            slug: "shop".into(),
            display: "shop".into(),
            root: "/Users/me/code/shop".into(),
            found: 14,
            files: 3,
            keys: vec![k("shop/a", true), k("shop/session-secret", false)],
            unknown: vec![KeyName::new("shop/session-secret").unwrap()],
            findings: vec![FindingRecord {
                path: "src/lib/stripe.ts".into(),
                line: 4,
                provider: "stripe".into(),
                masked: "sk_live_… (40 bytes)".into(),
            }],
            committed: vec![(".env".into(), 2)],
            ..Report::default()
        };
        let text: String = summary_rows(&r, Some(Path::new("/Users/me")))
            .iter()
            .map(|(a, b)| format!("{a:<10} {b}\n"))
            .collect();
        for want in [
            "Project    shop  (~/code/shop)",
            "Found      14 secrets in 3 files",
            "Protected  1, ready to use",
            "Needs you  1 has no known service yet: ms rules shop/session-secret --add-host <host>",
            "In code    1 key written straight into src/lib/stripe.ts:4",
            "Committed  .env is in 2 git commits: rotate those keys at each provider",
        ] {
            assert!(text.contains(want), "{want}\n{text}");
        }
        assert!(
            !text.contains("dashboard") && !text.contains("ms dev"),
            "{text}"
        );
        r.found = 0;
        let text: String = summary_rows(&r, None)
            .iter()
            .map(|(a, b)| format!("{a} {b}\n"))
            .collect();
        assert!(
            text.contains("nothing new; 1 already protected, 1 still needs you"),
            "{text}"
        );
    }
}
