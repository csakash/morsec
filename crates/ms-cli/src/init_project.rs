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
    pub stopped_early: Option<String>,
    pub too_large: Vec<String>,
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
    rep.display = name.map(str::to_owned).unwrap_or_else(|| {
        root.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| rep.slug.clone())
    });
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

    // 5. Store and rewrite, file by file.
    let mut stored: BTreeSet<KeyName> = vault_keys.iter().map(|m| m.name.clone()).collect();
    let mut new_files: BTreeMap<String, FileRecord> = BTreeMap::new();
    for ((rel, path, file), plan) in files.iter().zip(plans) {
        let plan = match plan {
            Ok(p) => p,
            Err(e) => {
                rep.failed
                    .push((rel.clone(), terminal_safe(&e.to_string())));
                continue;
            }
        };
        if !plan.rows.iter().any(|r| r.action.rewrites()) {
            continue;
        }
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
                let commits = envfile::git_history(path).map(|n| n as u64);
                if let Some(n) = commits.filter(|n| *n > 0) {
                    rep.committed.push((rel.clone(), n));
                }
                new_files.insert(
                    rel.clone(),
                    FileRecord {
                        path: rel.clone(),
                        git_history_commits: commits,
                        secrets: secret_records(file, &plan),
                    },
                );
            }
            Err(e) => rep
                .failed
                .push((rel.clone(), terminal_safe(&e.to_string()))),
        }
    }

    // 7. Agent hint block (before the record, which lists it).
    rep.hints = ms_projects::hint::apply(root, &rep.slug).map_err(|e| e.to_string())?;

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
        files: Vec::new(),
        findings: scan
            .findings
            .iter()
            .take(ms_projects::record::MAX_FINDINGS)
            .map(|f| FindingRecord {
                path: f.path.clone(),
                line: f.line as u64,
                provider: f.provider.clone(),
                masked: f.masked.clone(),
            })
            .collect(),
        hints: previous
            .as_ref()
            .map(|p| p.hints.clone())
            .unwrap_or_default(),
    };
    let mut by_path: BTreeMap<String, FileRecord> = previous
        .as_ref()
        .map(|p| {
            p.files
                .iter()
                .map(|f| (f.path.clone(), f.clone()))
                .collect()
        })
        .unwrap_or_default();
    for (path, mut f) in new_files {
        if let Some(old) = by_path.remove(&path) {
            let vars: BTreeSet<&str> = f.secrets.iter().map(|s| s.var.as_str()).collect();
            let kept: Vec<SecretRecord> = old
                .secrets
                .into_iter()
                .filter(|s| !vars.contains(s.var.as_str()))
                .collect();
            f.secrets.splice(0..0, kept);
        }
        by_path.insert(path, f);
    }
    record.files = by_path.into_values().collect();
    for h in &rep.hints {
        if !record.hints.iter().any(|x| &x.path == h) {
            record.hints.push(HintRecord { path: h.clone() });
        }
    }
    rep.findings = record.findings.clone();

    // 6. One approval for the first rules of the new keys.
    let current = match ask(&rt, RequestBody::RulesGet { key: None }, None)? {
        ResponseBody::Rules { toml, .. } => {
            Rules::from_toml(&toml, "the rules from msd").map_err(|e| e.to_string())?
        }
        other => return Err(as_error(other)),
    };
    let proposed = ms_projects::save::initial_rules(catalog, &record, &current);
    let save = |rules: &Rules| {
        ask(
            &rt,
            RequestBody::ProjectSave {
                record: record.to_toml(),
                rules: ms_projects::save::canonical(rules),
            },
            Some(crate::approve::APPROVAL_WAIT),
        )
    };
    let first = {
        let _review = (!proposed.keys.is_empty()).then(|| crate::approve::inline_review("ms init"));
        save(&proposed)?
    };
    match first {
        ResponseBody::Ok { .. } => {}
        ResponseBody::Error {
            code: ErrorCode::NeedsApproval | ErrorCode::Busy,
            message,
        } => {
            rep.declined = Some(terminal_safe(&message));
            // The record still goes in (no rule changes, no approval), so the next ms init
            // knows the keys and asks again.
            match save(&Rules::default())? {
                ResponseBody::Ok { .. } => {}
                other => rep.save_error = Some(as_error(other)),
            }
        }
        other => rep.save_error = Some(as_error(other)),
    }

    // The keys' state for the summary.
    rep.keys = match ask(
        &rt,
        RequestBody::ProjectGet {
            slug: rep.slug.clone(),
        },
        None,
    )? {
        ResponseBody::Project { keys, .. } => keys,
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
        rows.push((
            "Found".to_owned(),
            format!(
                "nothing new; {} already protected",
                plural(total, "key", "keys")
            ),
        ));
    } else {
        rows.push(("Found".to_owned(), "no secrets in this project".to_owned()));
    }
    if total > 0 {
        rows.push(("Protected".to_owned(), format!("{ready}, ready to use")));
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
        assert!(text.contains("already protected"), "{text}");
    }
}
