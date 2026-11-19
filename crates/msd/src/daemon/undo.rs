//! Undo an import, and the key commands with dashboard parity (L33 dash-actions, SPEC D-13,
//! D-21, D-24): `KeyReplace` (`ms set`), `KeyDelete` (`ms rm`) and `ProjectUndo` (`ms undo`).
//!
//! Undo writes values only from the vault into the recorded env file lines
//! (`ms_projects::undo`, which refuses links, other owners, hard links and changed lines): never
//! into a reply, the record, a receipt or a log. It is refused while stopped, inside agent
//! sessions and from sandboxed callers (checked in `Daemon::handle`), and while the project
//! records are unreadable (fails closed). The Touch ID reason names every file that will receive
//! a value.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ms_approve::ApprovalToken;
use ms_core::{ApprovalRequest, KeyName, ReceiptResult, SecretBytes, SessionId, Tier};
use ms_dash::actions::{ActionCode, ActionError, UndoLineView, UndoView};
use ms_ipc::{ErrorCode, ResponseBody, UndoLine, UndoSkip};
use ms_projects::record::ProjectsFile;
use ms_projects::undo::{LineRef, undo_file};
use ms_vault::VaultExt;
use zeroize::Zeroizing;

use super::{Daemon, admin_request, daemon_key, lock, reply_err};
use crate::backend::PROJECTS_STATE_KEY;

fn err(code: ActionCode, m: impl Into<String>) -> ActionError {
    ActionError::new(code, m)
}

/// An IPC error reply for an action error.
pub(super) fn to_reply(e: &ActionError) -> ResponseBody {
    reply_err(
        match e.code {
            ActionCode::TouchIdFailed => ErrorCode::NeedsApproval,
            ActionCode::Busy => ErrorCode::Busy,
            ActionCode::Invalid | ActionCode::Gone | ActionCode::NotText => ErrorCode::Invalid,
            ActionCode::Internal | ActionCode::Unavailable => ErrorCode::Internal,
            _ => ErrorCode::Denied,
        },
        e.message.clone(),
    )
}

/// An `approve_exact` refusal as an action error.
fn from_approval(r: ResponseBody) -> ActionError {
    match r {
        ResponseBody::Error { code, message } => err(
            match code {
                ErrorCode::Busy => ActionCode::Busy,
                ErrorCode::NeedsApproval => ActionCode::TouchIdFailed,
                _ => ActionCode::Refused,
            },
            message,
        ),
        _ => err(ActionCode::Internal, "morsec: unexpected answer"),
    }
}

/// What one Undo touches: per project (slug, root), per file, the recorded lines.
type Targets = Vec<(String, String, Vec<(String, Vec<LineRef>)>)>;

/// How a caller confirms (the dashboard's confirm path, or `ms approve` for the CLI).
pub(super) type Confirm<'a> =
    &'a dyn Fn(&ApprovalRequest, &str) -> Result<ApprovalToken, ActionError>;
/// How a caller writes its receipt for one key.
pub(super) type Receipt<'a> = &'a dyn Fn(&KeyName, ReceiptResult, Option<&ApprovalToken>);

/// Who asked, for the approval card, `ms approve` and the Touch ID sheet: a request from
/// outside every agent session may still come from a detached process an agent started (T-04),
/// so the person sees its program and PID (L33 review S4).
pub(super) fn requester(session: &SessionId) -> String {
    use ms_session::ProcessTable;
    // Read now, while the request is being made, and carried in the request itself: the card
    // shows this record, not a lookup at render time (L33 re-review N6).
    let info = ms_session::OsProcessTable
        .info(session.pid)
        .ok()
        .filter(|i| i.started_unix_ms == session.started_unix_ms);
    let name = info.as_ref().map_or_else(
        || "a program that has exited".to_owned(),
        |i| ms_approve::render::inert(&i.name),
    );
    let path = ms_session::table::exe_path(session.pid)
        .ok()
        .filter(|_| info.is_some())
        .map(|p| format!(" at {}", ms_approve::render::inert(&p.to_string_lossy())))
        .unwrap_or_default();
    format!(
        "requested by {name}{path} (pid {}, started {}), not an agent session",
        session.pid,
        ms_approve::render::utc(session.started_unix_ms)
    )
}

impl Daemon {
    /// The lines an Undo of `slug` (or of every project holding `keys`, without a slug) would
    /// restore, only those of `keys` when given.
    fn undo_targets(
        file: &ProjectsFile,
        slug: Option<&str>,
        keys: Option<&[KeyName]>,
    ) -> Result<Targets, ActionError> {
        if let Some(s) = slug
            && file.get(s).is_none()
        {
            return Err(err(
                ActionCode::Gone,
                format!(
                    "morsec: no project named {}. List them with: ms projects",
                    ms_projects::record::printable(s)
                ),
            ));
        }
        let wanted = |k: &KeyName| keys.is_none_or(|ks| ks.contains(k));
        let mut out = Vec::new();
        for p in file
            .projects
            .iter()
            .filter(|p| slug.is_none_or(|s| p.slug == s))
        {
            let mut files = Vec::new();
            for f in &p.files {
                let lines: Vec<LineRef> = f
                    .secrets
                    .iter()
                    .filter(|s| wanted(&s.key))
                    .map(|s| LineRef {
                        var: s.var.clone(),
                        line: s.line,
                        key: s.key.clone(),
                        quote: s.quote,
                    })
                    .collect();
                if !lines.is_empty() {
                    files.push((f.path.clone(), lines));
                }
            }
            if !files.is_empty() {
                out.push((p.slug.clone(), p.root.clone(), files));
            }
        }
        if out.is_empty() {
            return Err(err(
                ActionCode::Invalid,
                "morsec: nothing to undo: no recorded line holds that key",
            ));
        }
        Ok(out)
    }

    /// Undo (SPEC D-21) for `session`: confirms with `confirm`, restores the lines, deletes keys
    /// nothing refers to any more, removes the agent hint when a whole project goes, and saves
    /// the records. `who` names the receipts' target (`ms undo` or `dashboard: undo`).
    // Each argument is one part of the request (who, what, how to confirm and record).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn undo_run(
        &self,
        session: &SessionId,
        slug: Option<&str>,
        keys: Option<&[KeyName]>,
        confirm: Confirm<'_>,
        receipt: Receipt<'_>,
        argv0: &str,
        requester: Option<&str>,
    ) -> Result<UndoView, ActionError> {
        let refuse_all = |e: ActionError| {
            receipt(
                &keys
                    .and_then(|k| k.first().cloned())
                    .unwrap_or_else(daemon_key),
                match e.code {
                    ActionCode::TouchIdFailed => ReceiptResult::Denied,
                    ActionCode::Stopped => ReceiptResult::Blocked(ms_core::Reason::Stopped),
                    _ => ReceiptResult::Failed("refused".into()),
                },
                None,
            );
            e
        };
        if self.is_stopped() {
            return Err(refuse_all(err(
                ActionCode::Stopped,
                "morsec: morsec is stopped, so no value is written back. Start it first",
            )));
        }
        let unreadable = || {
            err(
                ActionCode::Refused,
                "morsec: the project records failed their integrity check, so Undo is off until they are fixed. Keys and rules keep working (ms doctor)",
            )
        };
        // Read without the records lock: Touch ID can take a while, and ms init must not wait
        // on it (review R4). Everything is read again under the lock after the approval.
        let (file, _) = self.load_projects().map_err(|_| refuse_all(unreadable()))?;
        let targets = Self::undo_targets(&file, slug, keys).map_err(refuse_all)?;

        // The sheet names every file that will receive a value (SPEC D-21).
        let mut files: Vec<String> = Vec::new();
        let mut n = 0usize;
        for (s, _, fs) in &targets {
            for (path, lines) in fs {
                files.push(format!("{s}/{path}"));
                n += lines.len();
            }
        }
        let shown: Vec<String> = files.iter().map(|f| ms_approve::render::inert(f)).collect();
        let reason = format!(
            "write {n} value{} back into {}",
            if n == 1 { "" } else { "s" },
            shown.join(", ")
        );
        let mut argv: Vec<&str> = vec![argv0, "undo"];
        let key_args: Vec<String> = keys
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect();
        argv.push(slug.unwrap_or("-"));
        for k in &key_args {
            argv.push("--key");
            argv.push(k);
        }
        for f in &files {
            argv.push(f);
        }
        if let Some(r) = requester {
            argv.push(r);
        }
        let key = match keys {
            Some([one]) => one.clone(),
            _ => daemon_key(),
        };
        let req = admin_request(session, key, Tier::Production, &argv);
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let reason = match requester {
            Some(r) => format!("{reason}; {r}"),
            None => reason,
        };
        let token = confirm(&req, &reason).map_err(refuse_all)?;
        // From here the approval is spent: every failure still leaves a receipt (review R8).
        let failed = |e: ActionError| {
            receipt(
                &req.key,
                ReceiptResult::Failed(e.message.chars().take(120).collect()),
                Some(&token),
            );
            e
        };
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return Err(failed(err(
                ActionCode::Stopped,
                "morsec: morsec was stopped while Touch ID was up, so nothing was written",
            )));
        }
        let _p = lock(&self.projects_write);
        let (file, floor) = self.load_projects().map_err(|_| failed(unreadable()))?;
        if Self::undo_targets(&file, slug, keys).ok().as_ref() != Some(&targets) {
            return Err(failed(err(
                ActionCode::Gone,
                "morsec: the project records changed while Touch ID was up, so nothing was written. Look again and undo again",
            )));
        }

        let owner = std::fs::metadata(&self.paths.state)
            .map(|m| m.uid())
            .map_err(|e| failed(err(ActionCode::Internal, format!("morsec: {e}"))))?;
        let mut restored: Vec<UndoLineView> = Vec::new();
        let mut skipped: Vec<UndoLineView> = Vec::new();
        // (slug, file, line, var) of every restored line.
        let mut done: BTreeSet<(String, String, u64, String)> = BTreeSet::new();
        for (s, root, fs) in &targets {
            for (path, lines) in fs {
                let mut value = |k: &KeyName| -> Result<Zeroizing<Vec<u8>>, String> {
                    self.vault
                        .read_with(k, |b| Zeroizing::new(b.to_vec()))
                        .map_err(|e| match e {
                            ms_core::Error::NoSuchKey(_) => {
                                "the key is no longer in morsec, so there is no value to put back"
                                    .to_owned()
                            }
                            e => format!("the value could not be read ({e})"),
                        })
                };
                let results = undo_file(Path::new(root), path, lines, owner, &mut value);
                for (l, r) in lines.iter().zip(results) {
                    let v = UndoLineView {
                        project: s.clone(),
                        file: path.clone(),
                        line: l.line,
                        var: l.var.clone(),
                        reason: None,
                    };
                    match r {
                        Ok(()) => {
                            done.insert((s.clone(), path.clone(), l.line, l.var.clone()));
                            restored.push(v);
                        }
                        Err(why) => skipped.push(UndoLineView {
                            reason: Some(why),
                            ..v
                        }),
                    }
                }
            }
        }

        // Keys whose every recorded line, in every project, was restored now: nothing refers to
        // them, so their value and rule go.
        let touched: BTreeSet<KeyName> = targets
            .iter()
            .flat_map(|(_, _, fs)| {
                fs.iter()
                    .flat_map(|(_, ls)| ls.iter().map(|l| l.key.clone()))
            })
            .collect();
        let mut notes: Vec<String> = Vec::new();

        // The records: restored lines leave them; a whole project with nothing skipped goes,
        // with its agent hint block.
        let mut next = file.clone();
        let whole = keys.is_none();
        let mut dropped: Vec<(String, String)> = Vec::new();
        for (s, root, _) in &targets {
            let any_skipped = skipped.iter().any(|x| &x.project == s);
            if whole && !any_skipped {
                next.projects.retain(|p| &p.slug != s);
                dropped.push((s.clone(), root.clone()));
                continue;
            }
            if let Some(p) = next.projects.iter_mut().find(|p| &p.slug == s) {
                for f in &mut p.files {
                    f.secrets.retain(|x| {
                        !done.contains(&(s.clone(), f.path.clone(), x.line, x.var.clone()))
                    });
                }
                p.files.retain(|f| !f.secrets.is_empty());
            }
        }
        let mut saved = true;
        if !done.is_empty() || !dropped.is_empty() {
            #[cfg(test)]
            let injected = self
                .dash_acts
                .fail_next_records_save
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let injected = false;
            let result = if injected {
                Err(ms_projects::Error::Io {
                    context: "saving the records".to_owned(),
                    source: std::io::Error::other("injected failure"),
                })
            } else {
                self.projects_store().save(&next, floor)
            };
            match result {
                Ok(v) => {
                    if let Err(e) = self.backend.put_internal(
                        &KeyName::new(PROJECTS_STATE_KEY)
                            .unwrap_or_else(|_| unreachable!("constant key name")),
                        SecretBytes::new(format!("v={v}").into_bytes()),
                    ) {
                        self.alert(
                            super::AlertKind::FloorNotSaved,
                            format!(
                                "the project records version could not be saved in the vault ({e})"
                            ),
                        );
                    }
                }
                Err(e) => {
                    saved = false;
                    notes.push(format!(
                        "the project records could not be updated ({e}); the files were written, and no key was deleted"
                    ));
                }
            }
            self.rebuild_proxy();
        }
        // Keys go only once the records no longer name them (review R2): a failed save keeps
        // every key, so the records never point at a key that is gone.
        let mut deleted: Vec<KeyName> = Vec::new();
        if saved {
            for k in &touched {
                let all_back = file.projects.iter().all(|p| {
                    p.files.iter().all(|f| {
                        f.secrets.iter().filter(|x| &x.key == k).all(|x| {
                            done.contains(&(p.slug.clone(), f.path.clone(), x.line, x.var.clone()))
                        })
                    })
                });
                if all_back {
                    match self.delete_key(k) {
                        Ok(()) => deleted.push(k.clone()),
                        Err(m) => notes.push(m),
                    }
                }
            }
        }
        for (s, root) in &dropped {
            if !saved {
                break;
            }
            if let Err(e) = ms_projects::hint::remove(Path::new(root), s) {
                notes.push(format!("the agent hint could not be removed ({e})"));
            }
        }

        // One receipt per key touched (names only).
        let restored_keys: BTreeMap<&KeyName, usize> = targets
            .iter()
            .flat_map(|(s, _, fs)| {
                fs.iter()
                    .flat_map(move |(path, ls)| ls.iter().map(move |l| (s, path, l)))
            })
            .filter(|(s, path, l)| {
                done.contains(&((*s).clone(), (*path).clone(), l.line, l.var.clone()))
            })
            .fold(BTreeMap::new(), |mut m, (_, _, l)| {
                *m.entry(&l.key).or_insert(0) += 1;
                m
            });
        for k in &touched {
            if restored_keys.contains_key(k) {
                receipt(k, ReceiptResult::Approved, Some(&token));
            } else {
                receipt(
                    k,
                    ReceiptResult::Failed("left as it was".into()),
                    Some(&token),
                );
            }
        }

        let mut message = format!(
            "Wrote {} value{} back",
            restored.len(),
            if restored.len() == 1 { "" } else { "s" }
        );
        if !skipped.is_empty() {
            message.push_str(&if skipped.len() == 1 {
                "; 1 line left as it was".to_owned()
            } else {
                format!("; {} lines left as they were", skipped.len())
            });
        }
        if !deleted.is_empty() {
            message.push_str(&format!(
                "; deleted {} key{} nothing uses any more",
                deleted.len(),
                if deleted.len() == 1 { "" } else { "s" }
            ));
        }
        for n in notes {
            message.push_str(". ");
            message.push_str(&n);
        }
        Ok(UndoView {
            message,
            restored,
            skipped,
            deleted_keys: deleted.iter().map(ToString::to_string).collect(),
        })
    }

    // ---- IPC (SPEC D-24, D-25) -------------------------------------------------------------

    /// `KeyReplace` (`ms set`), from outside every agent session and sandbox (checked by
    /// `handle`).
    pub(super) fn key_replace(
        &self,
        session: &SessionId,
        key: &KeyName,
        value: SecretBytes,
    ) -> ResponseBody {
        let refuse = |code: ErrorCode, m: String| {
            let _ = self.record(
                session,
                key,
                ms_core::Mode::Run,
                "ms set",
                self.rules_version(),
                ReceiptResult::Denied,
                None,
            );
            reply_err(code, m)
        };
        if self.is_stopped() {
            return refuse(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop), so no value is replaced. Resume first with: ms start".into(),
            );
        }
        if ms_rules::is_reserved(key) {
            return reply_err(
                ErrorCode::Invalid,
                format!("morsec: {key} is one of morsec's own keys"),
            );
        }
        if value.is_empty() {
            return reply_err(
                ErrorCode::Invalid,
                "morsec: the new value is empty; nothing changed",
            );
        }
        let meta = match self.scan_keys() {
            Ok(l) if l.unusable.contains(key) => {
                return reply_err(
                    ErrorCode::Denied,
                    format!("morsec: {}", ms_vault::unusable_hint(key)),
                );
            }
            Ok(l) => match l.keys.into_iter().find(|m| &m.name == key) {
                Some(m) => m,
                None => {
                    return reply_err(
                        ErrorCode::Invalid,
                        format!("morsec: there is no key named {key}. Add it with: ms add {key}"),
                    );
                }
            },
            Err(e) => return reply_err(ErrorCode::Internal, e.to_string()),
        };
        let tier = self
            .read_live()
            .rules
            .keys
            .get(key)
            .map_or(Tier::Production, |r| r.tier);
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        // Bound to the value (an HMAC fingerprint only msd can make) and naming who asked
        // (review S2, S4).
        let Some(fp) = self.value_fingerprint(value.expose()) else {
            return reply_err(
                ErrorCode::Internal,
                "morsec: no randomness to bind the approval to the new value, so nothing changed",
            );
        };
        let fp = format!("new value fingerprint {fp}");
        let who = requester(session);
        let req = admin_request(
            session,
            key.clone(),
            tier,
            &["ms", "set", key.as_str(), &fp, &who],
        );
        let token = match self.approve_admin(&req) {
            Ok(t) => t,
            Err(resp) => {
                let _ = self.record(
                    session,
                    key,
                    meta.mode,
                    "ms set",
                    self.rules_version(),
                    ReceiptResult::Denied,
                    None,
                );
                return resp;
            }
        };
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return refuse(
                ErrorCode::Denied,
                "morsec: ms stop ran while this waited for approval, so nothing changed".into(),
            );
        }
        let mode = meta.mode;
        if let Err(m) = self.replace_value(key, meta, value) {
            return reply_err(ErrorCode::Internal, m);
        }
        if let Err(e) =
            self.record_approved(session, key, mode, "ms set", self.rules_version(), &token)
        {
            tracing::error!(error = %e, "could not record ms set");
        }
        ResponseBody::Ok {
            message: format!("replaced {key}"),
        }
    }

    /// `KeyDelete` (`ms rm`).
    pub(super) fn key_delete(
        &self,
        session: &SessionId,
        key: &KeyName,
        force: bool,
    ) -> ResponseBody {
        if self.is_stopped() {
            return reply_err(
                ErrorCode::Denied,
                "morsec: morsec is stopped (ms stop). Resume first with: ms start",
            );
        }
        if ms_rules::is_reserved(key) {
            return reply_err(
                ErrorCode::Invalid,
                format!("morsec: {key} is one of morsec's own keys"),
            );
        }
        let stored = self
            .scan_keys()
            .map(|l| l.keys.iter().any(|m| &m.name == key))
            .unwrap_or(false);
        if !stored && !self.read_live().rules.keys.contains_key(key) {
            return reply_err(
                ErrorCode::Invalid,
                format!("morsec: there is no key named {key}"),
            );
        }
        if !force {
            match self.references(key) {
                Ok(r) if r.is_empty() => {}
                Ok(r) => {
                    return reply_err(
                        ErrorCode::Denied,
                        format!(
                            "morsec: project files still refer to {key}: {}. Undo it there first (ms undo), or delete it anyway with: ms rm {key} --force",
                            r.join(", ")
                        ),
                    );
                }
                Err(m) => {
                    return reply_err(
                        ErrorCode::Denied,
                        format!(
                            "{m}. morsec can't tell whether a project still uses {key}; delete it anyway with --force only if you are sure"
                        ),
                    );
                }
            }
        }
        let tier = self
            .read_live()
            .rules
            .keys
            .get(key)
            .map_or(Tier::Production, |r| r.tier);
        let who = requester(session);
        let mut argv = vec!["ms", "rm", key.as_str()];
        if force {
            argv.push("--force");
        }
        argv.push(&who);
        let req = admin_request(session, key.clone(), tier, &argv);
        let stops_seen = self.stops.load(std::sync::atomic::Ordering::SeqCst);
        let token = match self.approve_admin(&req) {
            Ok(t) => t,
            Err(resp) => {
                let _ = self.record(
                    session,
                    key,
                    ms_core::Mode::Run,
                    "ms rm",
                    self.rules_version(),
                    ReceiptResult::Denied,
                    None,
                );
                return resp;
            }
        };
        if self.is_stopped() || self.stops.load(std::sync::atomic::Ordering::SeqCst) != stops_seen {
            return reply_err(
                ErrorCode::Denied,
                "morsec: ms stop ran while this waited for approval, so nothing was deleted",
            );
        }
        let mode = self
            .read_live()
            .rules
            .keys
            .get(key)
            .map_or(ms_core::Mode::Run, |r| r.mode);
        if let Err(m) = self.delete_key(key) {
            return reply_err(ErrorCode::Internal, m);
        }
        if let Err(e) =
            self.record_approved(session, key, mode, "ms rm", self.rules_version(), &token)
        {
            tracing::error!(error = %e, "could not record ms rm");
        }
        ResponseBody::Ok {
            message: format!("deleted {key} and its rule"),
        }
    }

    /// `ProjectUndo` (`ms undo`).
    pub(super) fn project_undo(
        &self,
        session: &SessionId,
        slug: &str,
        keys: Option<&[KeyName]>,
    ) -> ResponseBody {
        let confirm =
            |req: &ApprovalRequest, _reason: &str| self.approve_admin(req).map_err(from_approval);
        let receipt = |k: &KeyName, r: ReceiptResult, t: Option<&ApprovalToken>| {
            let mode = self
                .read_live()
                .rules
                .keys
                .get(k)
                .map_or(ms_core::Mode::Run, |x| x.mode);
            let v = self.rules_version();
            let res = match (t, &r) {
                (Some(t), ReceiptResult::Approved) => {
                    self.record_approved(session, k, mode, "ms undo", v, t)
                }
                _ => self.record(session, k, mode, "ms undo", v, r, None),
            };
            if let Err(e) = res {
                tracing::error!(error = %e, "could not record ms undo");
            }
        };
        let who = requester(session);
        match self.undo_run(
            session,
            Some(slug),
            keys,
            &confirm,
            &receipt,
            "ms",
            Some(&who),
        ) {
            Ok(v) => ResponseBody::Undone {
                restored: v
                    .restored
                    .into_iter()
                    .map(|l| UndoLine {
                        project: l.project,
                        file: l.file,
                        line: l.line,
                        var: l.var,
                    })
                    .collect(),
                skipped: v
                    .skipped
                    .into_iter()
                    .map(|l| UndoSkip {
                        project: l.project,
                        file: l.file,
                        line: l.line,
                        var: l.var,
                        reason: l.reason.unwrap_or_default(),
                    })
                    .collect(),
                deleted_keys: v
                    .deleted_keys
                    .iter()
                    .filter_map(|k| KeyName::new(k).ok())
                    .collect(),
            },
            Err(e) => to_reply(&e),
        }
    }
}
