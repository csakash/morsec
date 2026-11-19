//! Project setup (L31 guided-init, design §4.3 to §4.7), shared by `ms init` and the dashboard's
//! Add project (L35 dash-connect, SPEC D-10).
//!
//! Two steps:
//!
//! - [`prepare`] names the project, reads the earlier record, walks the folder, reads and plans
//!   every env file. It **only reads**. [`Prepared::digest`] binds what a person was shown to what
//!   [`execute`] will do.
//! - [`execute`] stores, rewrites, adds the hint block, saves the record, then proposes the first
//!   rules: the L31 order and checks, unchanged.
//!
//! A [`Host`] gives both what they need: `ms init` implements it over IPC, msd directly. No value
//! is ever put in a report, a record, an error or a digest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ms_core::{KeyMeta, KeyName};
use ms_import::KeyStore;
use ms_import::catalog::Catalog;
use ms_import::envfile::{self, EnvFile};
use ms_import::plan::{Action, Plan};
use ms_rules::{KeyRule, Rules};
use sha2::{Digest, Sha256};

use crate::naming::{Source, plan_project};
use crate::record::{
    FileRecord, FindingRecord, HintRecord, ProjectRecord, Quote, ScanRecord, SecretAction,
    SecretRecord,
};
use crate::walk::{Budgets, Scan, Walker};

/// A save that did not go through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveError {
    /// The person did not approve (denied, timed out, busy, stopped): keys stay inert.
    Declined(String),
    /// Anything else (an invalid proposal, the records unreadable).
    Failed(String),
}

/// What setup needs from where it runs.
pub trait Host {
    /// Every project as (slug, root).
    fn projects(&self) -> Result<Vec<(String, PathBuf)>, String>;
    /// The record of `slug`.
    fn record(&self, slug: &str) -> Result<ProjectRecord, String>;
    /// Where new values go (each new key gets a rule that allows nothing).
    fn store(&self) -> &dyn KeyStore;
    /// The rules in force.
    fn rules(&self) -> Result<Rules, String>;
    /// Saves `record` with `rules` as the first rules of its new keys. Called first with no rules
    /// (no approval), then with the proposed ones.
    fn save(&self, record: &ProjectRecord, rules: &Rules) -> Result<(), SaveError>;
}

/// `s` without control, bidi or invisible characters (as the CLI's `terminal_safe`).
pub fn safe_text(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
        .collect()
}

/// One env file read for import.
#[derive(Debug)]
pub struct PreparedFile {
    /// Relative to the root.
    pub rel: String,
    /// Absolute.
    pub path: PathBuf,
    /// The file as read.
    pub file: EnvFile,
    /// Its plan, or why it can't be imported.
    pub plan: Result<Plan, String>,
}

/// Everything [`prepare`] read: what [`execute`] will act on.
#[derive(Debug)]
pub struct Prepared {
    /// Project name.
    pub slug: String,
    /// Display name.
    pub display: String,
    /// Canonical root.
    pub root: PathBuf,
    /// The earlier record, on a re-run.
    pub previous: Option<ProjectRecord>,
    /// The walk.
    pub scan: Scan,
    /// Env files read and planned.
    pub files: Vec<PreparedFile>,
    /// (file, why) for env files that could not be read.
    pub failed: Vec<(String, String)>,
    /// Keys already in the vault.
    pub vault_keys: Vec<KeyMeta>,
    /// Refs to this project's keys already in the files, per file index.
    pub adopted: Vec<Vec<SecretRecord>>,
    /// The first rules the new keys would get if everything goes through (a superset of what
    /// [`execute`] proposes when a file fails).
    pub proposed: Rules,
}

impl Prepared {
    /// SHA-256 over what a person is shown: name, root, every planned row (variable, line,
    /// action, key, provider, mode, tier) or its error, the adopted refs and the proposed rules.
    /// No value and no masked value goes in.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        let mut put = |s: &str| {
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        };
        put("morsec project setup v1");
        put(&self.slug);
        put(&self.display);
        put(&self.root.display().to_string());
        for (i, f) in self.files.iter().enumerate() {
            put("file");
            put(&f.rel);
            match &f.plan {
                Err(e) => {
                    put("error");
                    put(e);
                }
                Ok(p) => {
                    for r in &p.rows {
                        put(&format!(
                            "{}\u{1f}{}\u{1f}{:?}\u{1f}{}\u{1f}{}\u{1f}{:?}\u{1f}{:?}",
                            r.var,
                            r.line,
                            r.action,
                            r.key.as_ref().map_or("", KeyName::as_str),
                            r.provider.as_deref().unwrap_or(""),
                            r.mode,
                            r.tier
                        ));
                    }
                }
            }
            for a in self.adopted.get(i).into_iter().flatten() {
                put(&format!(
                    "adopt\u{1f}{}\u{1f}{}\u{1f}{}",
                    a.var, a.line, a.key
                ));
            }
        }
        for (rel, why) in &self.failed {
            put("failed");
            put(rel);
            put(why);
        }
        put("rules");
        put(&crate::save::canonical(&self.proposed));
        hex::encode(h.finalize())
    }

    /// Rows that would move a value into the vault (import and reuse), per file.
    pub fn rewrites(&self) -> usize {
        self.files
            .iter()
            .filter_map(|f| f.plan.as_ref().ok())
            .map(|p| p.rows.iter().filter(|r| r.action.rewrites()).count())
            .sum()
    }

    /// Nothing to import, and no ref to adopt that the earlier record doesn't already list.
    pub fn nothing_to_do(&self) -> bool {
        let known: Vec<KeyName> = self
            .previous
            .as_ref()
            .map(ProjectRecord::keys)
            .unwrap_or_default();
        self.rewrites() == 0
            && self
                .adopted
                .iter()
                .flatten()
                .all(|a| known.contains(&a.key))
    }
}

/// What setup did, for the summary.
#[derive(Debug, Default)]
pub struct Report {
    /// Project name.
    pub slug: String,
    /// Display name.
    pub display: String,
    /// Canonical root.
    pub root: PathBuf,
    /// Secret lines moved into the vault this run.
    pub found: usize,
    /// Files rewritten this run.
    pub files: usize,
    /// Code findings recorded.
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
    /// approval.
    pub rules_error: Option<String>,
    /// Why the walk stopped early.
    pub stopped_early: Option<String>,
    /// Files skipped for size.
    pub too_large: Vec<String>,
    /// Keys an earlier run stored whose refs were found but which no record listed (review R1).
    pub recovered: usize,
    /// Keys an earlier record listed that are gone from the vault (review R4).
    pub missing: Vec<KeyName>,
    /// Code findings left out of the record.
    pub findings_skipped: usize,
    /// Files the hint block was added to.
    pub hints: Vec<String>,
    /// The record as saved (or as it would have been).
    pub record: Option<ProjectRecord>,
    /// The first rules proposed (empty when none).
    pub proposed: Rules,
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

/// Names the project and reads everything setup needs at `root` (canonical, checked by the
/// caller). Writes nothing.
pub fn prepare(
    host: &dyn Host,
    catalog: &Catalog,
    root: &Path,
    name: Option<&str>,
) -> Result<Prepared, String> {
    prepare_with(host, catalog, root, name, Budgets::default())
}

/// [`prepare`] with explicit walk budgets (tests).
pub fn prepare_with(
    host: &dyn Host,
    catalog: &Catalog,
    root: &Path,
    name: Option<&str>,
    budgets: Budgets,
) -> Result<Prepared, String> {
    // A root msd can't record (bidi or invisible characters, security review S3) is refused
    // before anything is read or moved.
    let root_text = root.to_str().unwrap_or("");
    if root_text.is_empty() || root_text.chars().any(crate::record::is_unsafe_char) {
        return Err(
            "morsec: this folder's path has characters morsec can't show safely (control, bidi or invisible). Move the project to a plain path, then run ms init"
                .into(),
        );
    }

    // 1. Name (design §4.4).
    let pairs = host.projects()?;
    let mine = pairs
        .iter()
        .find(|(_, r)| r == root)
        .map(|(s, _)| s.clone());
    let slug = match (&mine, name) {
        (Some(s), _) => s.clone(),
        (None, Some(n)) => {
            let base = crate::slug::slug(n);
            if pairs.iter().any(|(s, _)| *s == base) {
                crate::slug::suffixed(&base, root)
            } else {
                base
            }
        }
        (None, None) => {
            crate::slug::choose(root, pairs.iter().map(|(s, r)| (s.as_str(), r.as_path())))
        }
    };
    let raw_display = name.map(str::to_owned).unwrap_or_else(|| {
        root.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    let display = crate::record::display_name(&raw_display, &slug);
    let previous = match &mine {
        Some(s) => Some(host.record(s)?),
        None => None,
    };

    // 2-3. Walk and classify (design §4.5).
    let scan = Walker::new(catalog, budgets)
        .walk(root)
        .map_err(|e| e.to_string())?;
    let examples: BTreeSet<String> = scan
        .examples
        .iter()
        .flat_map(|e| e.vars.iter().cloned())
        .collect();

    // 4. Read and plan every env file.
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut read: Vec<(String, PathBuf, EnvFile)> = Vec::new();
    for rel in &scan.env_files {
        let shown = safe_text(rel);
        let path = match checked_path(root, rel) {
            Ok(p) => p,
            Err(e) => {
                failed.push((rel.clone(), e));
                continue;
            }
        };
        match EnvFile::read(&path, &shown) {
            Ok(f) => read.push((rel.clone(), path, f)),
            Err(e) => failed.push((rel.clone(), safe_text(&e.to_string()))),
        }
    }
    let vault_keys = host.store().list().map_err(|e| e.to_string())?;
    let plans = {
        let sources: Vec<Source<'_>> = read
            .iter()
            .map(|(rel, _, f)| Source {
                rel,
                entries: f.entries(),
            })
            .collect();
        plan_project(catalog, &slug, &sources, &examples, &vault_keys)
    };
    let stored: BTreeSet<KeyName> = vault_keys.iter().map(|m| m.name.clone()).collect();
    let mut files = Vec::with_capacity(read.len());
    let mut adopted = Vec::with_capacity(read.len());
    for ((rel, path, file), plan) in read.into_iter().zip(plans) {
        let plan = plan.map_err(|e| safe_text(&e.to_string()));
        adopted.push(match &plan {
            Ok(p) => adopt_refs(catalog, &slug, &rel, &file, p, &stored, previous.as_ref()),
            Err(_) => Vec::new(),
        });
        files.push(PreparedFile {
            rel,
            path,
            file,
            plan,
        });
    }

    let mut p = Prepared {
        slug,
        display,
        root: root.to_owned(),
        previous,
        scan,
        files,
        failed,
        vault_keys,
        adopted,
        proposed: Rules::default(),
    };
    p.proposed = expected_rules(catalog, &p, &host.rules()?);
    Ok(p)
}

/// The first rules the new keys would get if every file goes through: `initial_rules` over the
/// record as it would be, with each key this run stores given the fresh rule `put` gives it.
fn expected_rules(catalog: &Catalog, p: &Prepared, current: &Rules) -> Rules {
    let mut record = ProjectRecord {
        slug: p.slug.clone(),
        display: p.display.clone(),
        root: p.root.display().to_string(),
        created_unix_ms: 0,
        scan: ScanRecord::default(),
        files: p
            .previous
            .as_ref()
            .map(|r| r.files.clone())
            .unwrap_or_default(),
        findings: Vec::new(),
        hints: Vec::new(),
    };
    let mut rules = current.clone();
    for (i, f) in p.files.iter().enumerate() {
        let Ok(plan) = &f.plan else { continue };
        for r in plan.imports() {
            if let (Some(k), Some(m), Some(t)) = (&r.key, r.mode, r.tier) {
                rules
                    .keys
                    .entry(k.clone())
                    .or_insert_with(|| KeyRule::new(m, t));
            }
        }
        let mut fresh = secret_records(&f.file, plan);
        fresh.extend(p.adopted[i].iter().cloned());
        if fresh.is_empty() {
            continue;
        }
        let vars: BTreeSet<String> = fresh.iter().map(|s| s.var.clone()).collect();
        match record.files.iter_mut().find(|x| x.path == f.rel) {
            Some(x) => {
                x.secrets.retain(|s| !vars.contains(&s.var));
                x.secrets.extend(fresh);
            }
            None => record.files.push(FileRecord {
                path: f.rel.clone(),
                git_history_commits: None,
                secrets: fresh,
            }),
        }
    }
    crate::save::initial_rules(catalog, &record, &rules)
}

/// Stores, rewrites, adds the hint block, saves the record and proposes the first rules for what
/// [`prepare`] read. `now_unix_ms` dates new keys and a new record.
pub fn execute(host: &dyn Host, catalog: &Catalog, p: Prepared, now_unix_ms: u64) -> Report {
    let Prepared {
        slug,
        display,
        root,
        previous,
        scan,
        files,
        failed,
        vault_keys,
        adopted,
        proposed: _,
    } = p;
    let mut rep = Report {
        slug,
        display,
        root,
        failed,
        too_large: scan.too_large.clone(),
        stopped_early: if scan.stopped_early {
            scan.stop_reason.clone()
        } else {
            None
        },
        ..Report::default()
    };
    let root = rep.root.clone();
    let store = host.store();

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
    for (pf, adopted) in files.iter().zip(adopted) {
        let rel = &pf.rel;
        let plan = match &pf.plan {
            Ok(p) => p,
            Err(e) => {
                rep.failed.push((rel.clone(), e.clone()));
                continue;
            }
        };
        let rewrites = plan.rows.iter().filter(|r| r.action.rewrites()).count();
        if rewrites == 0 && adopted.is_empty() {
            continue;
        }
        let (others_secrets, others_bytes) = by_path
            .iter()
            .filter(|(p, _)| *p != rel)
            .fold((0, 0), |(n, b), (p, f)| (n + f.secrets.len(), b + p.len()));
        let mine_before = by_path.get(rel).map_or(0, |f| f.secrets.len());
        if let Err(e) = crate::record::admit_file(
            rel,
            mine_before + rewrites + adopted.len(),
            others_secrets,
            others_bytes,
        ) {
            rep.failed.push((
                rel.clone(),
                format!(
                    "can't be recorded ({}); not changed",
                    safe_text(&e.to_string())
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
            match envfile::commit(&pf.file, plan, store, now_unix_ms) {
                Ok(done) => {
                    stored.extend(done.stored);
                    rep.found += done.rewritten;
                    rep.files += 1;
                    commits = envfile::git_history(&pf.path).map(|n| n as u64);
                    if let Some(n) = commits.filter(|n| *n > 0) {
                        rep.committed.push((rel.clone(), n));
                    }
                    fresh = secret_records(&pf.file, plan);
                }
                Err(e) => {
                    rep.failed.push((rel.clone(), safe_text(&e.to_string())));
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
    rep.hints = match crate::hint::apply(&root, &rep.slug) {
        Ok(h) => h,
        Err(e) => {
            rep.failed.push((
                "CLAUDE.md / AGENTS.md".into(),
                format!("hint block not added: {}", safe_text(&e.to_string())),
            ));
            Vec::new()
        }
    };

    // The record: earlier runs' files and hints, this run's scan and findings.
    let mut record = ProjectRecord {
        slug: rep.slug.clone(),
        display: rep.display.clone(),
        root: root.display().to_string(),
        created_unix_ms: previous.as_ref().map_or(now_unix_ms, |p| p.created_unix_ms),
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
    let (findings, skipped) = crate::record::fit_findings(
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
    // happens to the approval below, the next run knows these keys and asks again.
    let saved = match record.validate() {
        Err(e) => Err(e.to_string()),
        Ok(()) => host.save(&record, &Rules::default()).map_err(|e| match e {
            SaveError::Declined(m) | SaveError::Failed(m) => m,
        }),
    };
    if let Err(e) = saved {
        rep.save_error = Some(safe_text(&e));
    } else {
        // Then the first rules of the new keys.
        match host
            .rules()
            .map(|current| crate::save::initial_rules(catalog, &record, &current))
        {
            Err(e) => rep.rules_error = Some(safe_text(&e)),
            Ok(p) if p.keys.is_empty() => {}
            Ok(p) => {
                match host.save(&record, &p) {
                    Ok(()) => {}
                    Err(SaveError::Declined(m)) => rep.declined = Some(safe_text(&m)),
                    Err(SaveError::Failed(m)) => rep.rules_error = Some(safe_text(&m)),
                }
                rep.proposed = p;
            }
        }
    }
    rep.record = Some(record);
    rep
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
                None if crate::naming::is_generated_name(slug, rel, &r.var, &key) => catalog
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Mutex;

    use ms_core::SecretBytes;

    /// An in-memory host: records, a vault and rules.
    #[derive(Default)]
    struct Mem {
        projects: RefCell<Vec<ProjectRecord>>,
        keys: Mutex<Vec<(KeyMeta, Vec<u8>)>>,
        rules: RefCell<Rules>,
        saves: RefCell<usize>,
    }

    impl KeyStore for Mem {
        fn list(&self) -> Result<Vec<KeyMeta>, ms_import::Error> {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .iter()
                .map(|(m, _)| m.clone())
                .collect())
        }
        fn put(
            &self,
            name: &KeyName,
            value: SecretBytes,
            meta: KeyMeta,
        ) -> Result<(), ms_import::Error> {
            self.rules
                .borrow_mut()
                .keys
                .insert(name.clone(), KeyRule::new(meta.mode, meta.tier));
            self.keys
                .lock()
                .unwrap()
                .push((meta, value.expose().to_vec()));
            Ok(())
        }
    }

    impl Host for Mem {
        fn projects(&self) -> Result<Vec<(String, PathBuf)>, String> {
            Ok(self
                .projects
                .borrow()
                .iter()
                .map(|p| (p.slug.clone(), PathBuf::from(&p.root)))
                .collect())
        }
        fn record(&self, slug: &str) -> Result<ProjectRecord, String> {
            self.projects
                .borrow()
                .iter()
                .find(|p| p.slug == slug)
                .cloned()
                .ok_or_else(|| "no such project".into())
        }
        fn store(&self) -> &dyn KeyStore {
            self
        }
        fn rules(&self) -> Result<Rules, String> {
            Ok(self.rules.borrow().clone())
        }
        fn save(&self, record: &ProjectRecord, rules: &Rules) -> Result<(), SaveError> {
            *self.saves.borrow_mut() += 1;
            let mut ps = self.projects.borrow_mut();
            ps.retain(|p| p.slug != record.slug);
            ps.push(record.clone());
            for (k, r) in &rules.keys {
                self.rules.borrow_mut().keys.insert(k.clone(), r.clone());
            }
            Ok(())
        }
    }

    const STRIPE: &str = concat!("sk_", "test_", "51HcanaryDIGESTxxxxxxxxxxxxxxxxxxxxxxxx");

    fn project() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap().join("shop");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
        std::fs::write(
            root.join(".env"),
            format!("STRIPE_SECRET_KEY={STRIPE}\nPORT=3000\n"),
        )
        .unwrap();
        (d, root)
    }

    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(root).unwrap().flatten() {
            if e.file_type().unwrap().is_file() {
                out.push((e.path(), std::fs::read(e.path()).unwrap()));
            }
        }
        out.sort();
        out
    }

    // protects=SPEC D-10 / T-109: prepare reads only (no file, vault, record or rule changes) and
    // its digest carries no value; fails_when=prepare writes anything, or the canary shows up in
    // the digest or the plan's debug output of names; no_claim=execute's own checks
    #[test]
    fn prepare_reads_only() {
        let (_d, root) = project();
        let before = snapshot(&root);
        let host = Mem::default();
        let p = prepare(&host, Catalog::builtin(), &root, None).unwrap();
        assert_eq!(snapshot(&root), before);
        assert!(host.keys.lock().unwrap().is_empty());
        assert!(host.projects.borrow().is_empty());
        assert_eq!(*host.saves.borrow(), 0);
        assert_eq!(p.slug, "shop");
        assert_eq!(p.rewrites(), 1);
        assert!(!p.digest().contains(STRIPE));
        assert!(
            p.proposed
                .keys
                .contains_key(&KeyName::new("shop/stripe-secret-key").unwrap()),
            "{:?}",
            p.proposed.keys.keys().collect::<Vec<_>>()
        );
        // execute then does exactly that: the key, the ref, the record and the previewed rules.
        let proposed = p.proposed.clone();
        let rep = execute(&host, Catalog::builtin(), p, 1);
        assert_eq!(rep.found, 1);
        assert!(rep.save_error.is_none() && rep.declined.is_none());
        assert_eq!(
            crate::save::canonical(&rep.proposed),
            crate::save::canonical(&proposed)
        );
        let env = std::fs::read_to_string(root.join(".env")).unwrap();
        assert!(env.contains("STRIPE_SECRET_KEY=ms://shop/stripe-secret-key"));
        assert!(!env.contains(STRIPE));
    }

    // protects=SPEC D-11 / T-109: the digest moves when what would be imported moves (a new
    // secret, a renamed variable) and stays when nothing changed; fails_when=a changed folder
    // keeps the digest a person approved; no_claim=values (they are not in the digest by design)
    #[test]
    fn digest_changes_with_plan() {
        let (_d, root) = project();
        let host = Mem::default();
        let a = prepare(&host, Catalog::builtin(), &root, None)
            .unwrap()
            .digest();
        let b = prepare(&host, Catalog::builtin(), &root, None)
            .unwrap()
            .digest();
        assert_eq!(a, b);
        std::fs::write(
            root.join(".env"),
            format!("STRIPE_SECRET_KEY={STRIPE}\nPORT=3000\nOPENAI_API_KEY=sk-proj-canaryxxxxxxxxxxxxxxxxxxxxxxxx\n"),
        )
        .unwrap();
        let c = prepare(&host, Catalog::builtin(), &root, None)
            .unwrap()
            .digest();
        assert_ne!(a, c);
        std::fs::write(root.join(".env"), format!("STRIPE_KEY={STRIPE}\n")).unwrap();
        let d = prepare(&host, Catalog::builtin(), &root, None)
            .unwrap()
            .digest();
        assert_ne!(c, d);
        assert_ne!(a, d);
    }
}
