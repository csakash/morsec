//! Project records and the one-approval `ProjectSave` (L31 guided-init, SPEC D-2).
//!
//! `ms init` stores a project's values through `PutKey` (each new key allows nothing, as before),
//! then sends `ProjectSave` with the record and the first rules for those keys. msd checks every
//! rule against the record and the catalog (`ms_projects::save::check`), asks one approval for the
//! whole set (bound to the hash of its canonical TOML, carried in the approved argv), and only
//! then applies the rules and writes `projects.toml` (MAC'd, rollback floor in the vault).
//! Refused inside an agent session (in `Daemon::handle`) and while stopped. A tampered
//! `projects.toml` makes the project requests `Denied`; keys and rules keep working.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ms_core::{ApprovalRequest, KeyName, Mode, ReceiptResult, SecretBytes, SessionId, Tier};
use ms_import::catalog::Catalog;
use ms_ipc::{ErrorCode, KeyStatus, ProjectSummary, ResponseBody};
use ms_projects::record::{ProjectRecord, ProjectsFile};
use ms_projects::store::ProjectsStore;
use ms_rules::{KeyRule, Rules, RulesError, RulesStore};
use ms_vault::VaultExt;

use super::{Daemon, daemon_key, lock, reply_err};
use crate::backend::{PROJECTS_HMAC_KEY, PROJECTS_STATE_KEY};

/// The project records file in msd's state directory.
pub const PROJECTS_FILE: &str = "projects.toml";

/// For `msd --init --force` (review R2): a reset replaces `morsec/projects-hmac`, so the old
/// `projects.toml` can never verify again. It is moved aside (`<name>.<tag>`, kept for
/// inspection, like the rules and receipts) and the rollback floor goes back to 0, so the next
/// `ms init` starts a fresh record instead of every project request being `Denied`.
pub fn reset_project_records(
    state: &std::path::Path,
    backend: &crate::backend::Backend,
    tag: &str,
) -> Result<(), String> {
    let file = state.join(PROJECTS_FILE);
    for p in [ms_rules::store::mac_path(&file), file] {
        if p.exists() {
            let mut to = p.as_os_str().to_owned();
            to.push(format!(".{tag}"));
            std::fs::rename(&p, PathBuf::from(&to))
                .map_err(|e| format!("morsec: moving {} aside: {e}", p.display()))?;
        }
    }
    backend
        .put_internal(&key(PROJECTS_STATE_KEY), SecretBytes::new(b"v=0".to_vec()))
        .map_err(|e| format!("morsec: resetting the project records version: {e}"))
}

const TAMPERED: &str = "morsec: the project records failed their integrity check, so they can't be shown or changed. Your keys and rules keep working. Inspect projects.toml in morsec's state directory";

fn key(raw: &str) -> KeyName {
    KeyName::new(raw).unwrap_or_else(|_| unreachable!("constant key name is valid"))
}

pub(super) fn targets(rule: &KeyRule) -> Vec<String> {
    match rule.mode {
        Mode::Run => rule.roots.iter().map(|p| p.display().to_string()).collect(),
        _ => rule.hosts.iter().map(ToString::to_string).collect(),
    }
}

impl Daemon {
    fn projects_store(&self) -> ProjectsStore<'_> {
        ProjectsStore::new(
            self.paths.state.join(PROJECTS_FILE),
            &*self.vault,
            key(PROJECTS_HMAC_KEY),
        )
    }

    /// The rollback floor msd saved in the vault; 0 before the first save.
    fn projects_floor(&self) -> Result<u64, String> {
        match self
            .vault
            .read_with(&key(PROJECTS_STATE_KEY), <[u8]>::to_vec)
        {
            Ok(v) => std::str::from_utf8(&v)
                .ok()
                .and_then(|s| s.strip_prefix("v="))
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| "the saved version is unreadable".to_owned()),
            // No floor and no records: nothing was ever saved. A floor that is gone while records
            // exist fails closed (security review S1), like the rules floor: otherwise an older,
            // validly MAC'd file would load.
            Err(ms_core::Error::NoSuchKey(_)) => {
                let file = self.paths.state.join(PROJECTS_FILE);
                if file.exists() || ms_rules::store::mac_path(&file).exists() {
                    Err("the saved version is missing while project records exist".to_owned())
                } else {
                    Ok(0)
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The verified records, or the `Denied` reply.
    #[allow(clippy::result_large_err)]
    pub(super) fn load_projects(&self) -> Result<(ProjectsFile, u64), ResponseBody> {
        let floor = self.projects_floor().map_err(|e| {
            tracing::error!(error = %e, "project records floor unreadable");
            reply_err(ErrorCode::Denied, TAMPERED)
        })?;
        match self.projects_store().load(floor) {
            Ok(f) => Ok((f, floor)),
            Err(e) => {
                tracing::error!(error = %e, "project records failed to load");
                self.alert("the project records failed their integrity check (ms projects is refused; keys and rules keep working)");
                Err(reply_err(ErrorCode::Denied, TAMPERED))
            }
        }
    }

    pub(super) fn key_statuses(&self, record: &ProjectRecord) -> Vec<KeyStatus> {
        let stored: BTreeSet<KeyName> = self
            .scan_keys()
            .map(|l| l.keys.into_iter().map(|m| m.name).collect())
            .unwrap_or_default();
        let live = self.read_live();
        record
            .keys()
            .into_iter()
            .map(|k| {
                let rule = live.rules.keys.get(&k);
                KeyStatus {
                    mode: rule.map(|r| r.mode),
                    tier: rule.map(|r| r.tier),
                    ready: rule.is_some_and(|r| !r.allows_nothing()) && !live.rules.tampered,
                    targets: rule.map(targets).unwrap_or_default(),
                    stored: stored.contains(&k),
                    key: k,
                }
            })
            .collect()
    }

    /// `ProjectList`.
    pub(super) fn project_list(&self) -> ResponseBody {
        let (file, _) = match self.load_projects() {
            Ok(f) => f,
            Err(r) => return r,
        };
        let projects = file
            .projects
            .iter()
            .map(|p| {
                let keys = self.key_statuses(p);
                let ready = keys.iter().filter(|k| k.ready).count();
                ProjectSummary {
                    slug: p.slug.clone(),
                    display: p.display.clone(),
                    root: p.root.clone(),
                    protected: u32::try_from(ready).unwrap_or(u32::MAX),
                    needs_you: u32::try_from(keys.len() - ready).unwrap_or(u32::MAX),
                    findings: u32::try_from(p.findings.len()).unwrap_or(u32::MAX),
                    stopped_early: p.scan.stopped_early,
                }
            })
            .collect();
        ResponseBody::Projects { projects }
    }

    /// `ProjectGet`.
    pub(super) fn project_get(&self, slug: &str) -> ResponseBody {
        let (file, _) = match self.load_projects() {
            Ok(f) => f,
            Err(r) => return r,
        };
        match file.get(slug) {
            Some(p) => ResponseBody::Project {
                record: p.to_toml(),
                keys: self.key_statuses(p),
            },
            None => reply_err(
                ErrorCode::Invalid,
                format!(
                    "morsec: no project named {}. List them with: ms projects",
                    ms_projects::record::printable(slug)
                ),
            ),
        }
    }

    /// Applies `updates` in one rules save, after `precheck` passes on the rules in force (under
    /// the write lock, so nothing changes in between).
    fn change_many(
        &self,
        updates: &BTreeMap<KeyName, KeyRule>,
        approved: bool,
        precheck: impl FnOnce(&Rules) -> Result<(), String>,
    ) -> Result<Result<u64, String>, RulesError> {
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
        if let Err(e) = precheck(&current) {
            return Ok(Err(e));
        }
        let mut next = current.clone();
        for (k, r) in updates {
            next.keys.insert(k.clone(), r.clone());
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
                tracing::error!(error = %e, "could not save the rules floor in the vault");
                self.alert(format!(
                    "the rules version could not be saved in the vault ({e})"
                ));
            }
        }
        self.rebuild_proxy();
        Ok(Ok(self.rules_version()))
    }

    /// `ProjectSave` from outside every agent session (checked by `handle`).
    pub(super) fn project_save(
        &self,
        session: &SessionId,
        record: &str,
        rules: &str,
    ) -> ResponseBody {
        if self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop), so projects can't be saved. Resume first with: ms start",
            );
        }
        let record = match ProjectRecord::from_toml(record) {
            Ok(r) => r,
            Err(e) => return reply_err(ErrorCode::Invalid, e.to_string()),
        };
        let proposed = match Rules::from_toml(rules, "the proposed rules") {
            Ok(r) => r,
            Err(e) => return reply_err(ErrorCode::Invalid, e.to_string()),
        };
        let _p = lock(&self.projects_write);
        let (file, floor) = match self.load_projects() {
            Ok(f) => f,
            Err(r) => return r,
        };
        let current = {
            let l = self.read_live();
            if l.rules.tampered {
                return self.rules_get(None);
            }
            l.rules.clone()
        };
        let vault_keys: BTreeSet<KeyName> = match self.scan_keys() {
            Ok(l) => l.keys.into_iter().map(|m| m.name).collect(),
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        let root = std::fs::canonicalize(&record.root).ok();
        let catalog = Catalog::builtin();
        if let Err(e) = ms_projects::save::check(
            catalog,
            &record,
            &proposed,
            &current,
            &vault_keys,
            &file,
            root.as_deref(),
        ) {
            return reply_err(ErrorCode::Invalid, e.to_string());
        }

        // One approval for the whole set, bound to the hash of its canonical TOML.
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let token = if proposed.keys.is_empty() {
            None
        } else {
            let argv = ms_projects::save::approval_argv(&record, &proposed);
            let req = ApprovalRequest {
                session: session.clone(),
                key: daemon_key(),
                tier: Tier::Production,
                argv_hash: ms_rules::argv_hash(&argv),
                argv_display: argv,
                cwd: PathBuf::from(&record.root),
                effect: Some(format!(
                    "{} new key(s) of project {} may reach the services listed",
                    proposed.keys.len(),
                    record.slug
                )),
            };
            match self.approve_exact(&req) {
                Ok(t) => Some(t),
                Err(resp) => {
                    let v = self.rules_version();
                    for (k, r) in &proposed.keys {
                        let _ = self.record(
                            session,
                            k,
                            r.mode,
                            "ms init: first rules",
                            v,
                            ReceiptResult::Denied,
                            None,
                        );
                    }
                    return resp;
                }
            }
        };
        if token.is_some()
            && (self.is_stopped()
                || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen)
        {
            return reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran while this project waited for approval, so nothing was applied",
            );
        }

        let mut version = self.rules_version();
        if !proposed.keys.is_empty() {
            let recheck = |now: &Rules| {
                ms_projects::save::check(
                    catalog,
                    &record,
                    &proposed,
                    now,
                    &vault_keys,
                    &file,
                    root.as_deref(),
                )
                .map_err(|e| e.to_string())
            };
            match self.change_many(&proposed.keys, token.is_some(), recheck) {
                Ok(Ok(v)) => version = v,
                Ok(Err(e)) => {
                    return reply_err(
                        ErrorCode::Invalid,
                        format!(
                            "{e}. The rules changed while this waited for approval; run ms init again"
                        ),
                    );
                }
                Err(e @ RulesError::Invalid { .. }) => {
                    return reply_err(ErrorCode::Invalid, e.to_string());
                }
                Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
            }
            if let Some(t) = &token {
                for (k, r) in &proposed.keys {
                    if let Err(e) =
                        self.record_approved(session, k, r.mode, "ms init: first rules", version, t)
                    {
                        tracing::error!(error = %e, "could not record a project rule");
                    }
                }
            }
        }

        let mut next = file.clone();
        match next.projects.iter_mut().find(|p| p.slug == record.slug) {
            Some(p) => *p = record.clone(),
            None => next.projects.push(record.clone()),
        }
        let saved = match self.projects_store().save(&next, floor) {
            Ok(v) => v,
            Err(e) => {
                return reply_err(
                    ErrorCode::Internal,
                    format!(
                        "{e}. The keys' rules were saved; the project record was not (run ms init again)"
                    ),
                );
            }
        };
        if let Err(e) = self.backend.put_internal(
            &key(PROJECTS_STATE_KEY),
            SecretBytes::new(format!("v={saved}").into_bytes()),
        ) {
            tracing::error!(error = %e, "could not save the project records floor");
            self.alert(format!(
                "the project records version could not be saved in the vault ({e})"
            ));
        }
        if let Err(e) = self.record(
            session,
            &daemon_key(),
            Mode::Run,
            &format!("ms init: project {} saved", record.slug),
            version,
            ReceiptResult::Allowed,
            None,
        ) {
            tracing::error!(error = %e, "could not record a project save");
        }
        ResponseBody::Ok {
            message: format!(
                "project {} saved: {} key(s), {} given their services",
                record.slug,
                record.keys().len(),
                proposed.keys.len()
            ),
        }
    }
}
