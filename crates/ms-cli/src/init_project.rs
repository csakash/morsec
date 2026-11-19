//! `ms init` in a project (L31 guided-init, design §4.3 to §4.7, SPEC "Project steps").
//!
//! The steps live in `ms_projects::setup` (L35 SPEC D-10), shared with the dashboard's Add
//! project. Here they run over IPC: values go to msd exactly as `ms import` sends them
//! (`IpcStore` → `PutKey`, each new key allowing nothing), then one `ProjectSave` carries the
//! record and the first rules of the new keys, which msd applies after one approval (L31 SPEC
//! D-2). No value is ever printed, put in the record, or in an error.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ms_core::KeyName;
use ms_import::KeyStore;
use ms_import::catalog::Catalog;
use ms_ipc::{Client, ErrorCode, KeyStatus, RequestBody, ResponseBody};
use ms_projects::record::ProjectRecord;
use ms_projects::setup::{self, Host, SaveError};
use ms_rules::Rules;

use crate::import::{IpcStore, now_unix_ms};

/// Debug builds only: append every path the walk opened to this file (the SPEC criterion 1
/// audit the integration tests read).
pub(crate) const WALK_AUDIT_ENV: &str = "MORSEC_TEST_WALK_AUDIT";

/// What project setup did, for the summary: the shared report plus the keys' state from msd.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub s: setup::Report,
    /// Keys of the project and whether each is ready.
    pub keys: Vec<KeyStatus>,
    /// Keys with no known provider (they allow nothing until the user adds a host).
    pub unknown: Vec<KeyName>,
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

/// `ms init`'s side of setup: msd over IPC.
struct IpcHost {
    rt: tokio::runtime::Runtime,
    store: IpcStore,
}

impl Host for IpcHost {
    fn projects(&self) -> Result<Vec<(String, PathBuf)>, String> {
        match ask(&self.rt, RequestBody::ProjectList, None)? {
            ResponseBody::Projects { projects } => Ok(projects
                .into_iter()
                .map(|p| (p.slug, PathBuf::from(p.root)))
                .collect()),
            other => Err(as_error(other)),
        }
    }

    fn record(&self, slug: &str) -> Result<ProjectRecord, String> {
        match ask(
            &self.rt,
            RequestBody::ProjectGet {
                slug: slug.to_owned(),
            },
            None,
        )? {
            ResponseBody::Project { record, .. } => {
                ProjectRecord::from_toml(&record).map_err(|e| e.to_string())
            }
            other => Err(as_error(other)),
        }
    }

    fn store(&self) -> &dyn KeyStore {
        &self.store
    }

    fn rules(&self) -> Result<Rules, String> {
        match ask(&self.rt, RequestBody::RulesGet { key: None }, None)? {
            ResponseBody::Rules { toml, .. } => {
                Rules::from_toml(&toml, "the rules from msd").map_err(|e| e.to_string())
            }
            other => Err(as_error(other)),
        }
    }

    fn save(&self, record: &ProjectRecord, rules: &Rules) -> Result<(), SaveError> {
        let body = RequestBody::ProjectSave {
            record: record.to_toml(),
            rules: ms_projects::save::canonical(rules),
        };
        if rules.keys.is_empty() {
            return match ask(&self.rt, body, None) {
                Ok(ResponseBody::Ok { .. }) => Ok(()),
                Ok(other) => Err(SaveError::Failed(as_error(other))),
                Err(e) => Err(SaveError::Failed(e)),
            };
        }
        let _review = crate::approve::inline_review("ms init");
        match ask(&self.rt, body, Some(crate::approve::APPROVAL_WAIT)) {
            Ok(ResponseBody::Ok { .. }) => Ok(()),
            Ok(ResponseBody::Error {
                code: ErrorCode::NeedsApproval | ErrorCode::Busy | ErrorCode::Denied,
                message,
            }) => Err(SaveError::Declined(message)),
            Ok(ResponseBody::Error { message, .. }) => Err(SaveError::Failed(message)),
            Ok(_) => Err(SaveError::Declined(UNEXPECTED.to_owned())),
            Err(e) => Err(SaveError::Declined(e)),
        }
    }
}

/// Runs the project steps at `root` (canonical, checked by the caller).
pub(crate) fn run(root: &Path, name: Option<&str>) -> Result<Report, String> {
    let host = IpcHost {
        rt: runtime()?,
        store: IpcStore::new().map_err(|e| e.to_string())?,
    };
    let catalog = Catalog::builtin();
    let prepared = setup::prepare(&host, catalog, root, name)?;
    if cfg!(debug_assertions)
        && let Some(p) = std::env::var_os(WALK_AUDIT_ENV).filter(|p| !p.is_empty())
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            for o in &prepared.scan.opened {
                let _ = writeln!(f, "{}", root.join(o).display());
            }
        }
    }
    let s = setup::execute(&host, catalog, prepared, now_unix_ms());
    let mut rep = Report {
        s,
        ..Report::default()
    };

    // The keys' state for the summary.
    rep.keys = match ask(
        &host.rt,
        RequestBody::ProjectGet {
            slug: rep.s.slug.clone(),
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
    if let Some(record) = &rep.s.record {
        rep.unknown = record
            .keys()
            .into_iter()
            .filter(|k| !ready.contains(k) && record.provider_of(k).is_none())
            .collect();
    }
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
        format!("{}  ({})", r.s.display, tilde(&r.s.root, home)),
    ));
    let total = r.keys.len();
    let ready = r.keys.iter().filter(|k| k.ready).count();
    if r.s.found > 0 {
        rows.push((
            "Found".to_owned(),
            format!(
                "{} in {}",
                plural(r.s.found, "secret", "secrets"),
                plural(r.s.files, "file", "files")
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
    if r.s.recovered > 0 {
        rows.push((
            "Recovered".to_owned(),
            format!(
                "{} an earlier run stored but never recorded",
                plural(r.s.recovered, "key", "keys")
            ),
        ));
    }
    if let Some(first) = r.s.missing.first() {
        rows.push((
            "Missing".to_owned(),
            format!(
                "{} no longer in the vault ({first}{}); its lines still hold the ref",
                plural(r.s.missing.len(), "key is", "keys are"),
                if r.s.missing.len() > 1 {
                    " and more"
                } else {
                    ""
                }
            ),
        ));
    }
    if let Some(why) = &r.s.declined {
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
    if let Some(f) = r.s.findings.first() {
        rows.push((
            "In code".to_owned(),
            format!(
                "{} written straight into {}:{}{} (move it into .env, then ms init)",
                plural(r.s.findings.len(), "key", "keys"),
                f.path,
                f.line,
                if r.s.findings.len() > 1 {
                    " and more"
                } else {
                    ""
                }
            ),
        ));
    }
    if r.s.findings_skipped > 0 {
        rows.push((
            "In code".to_owned(),
            format!(
                "{} more not recorded (too many, or a path morsec can't record)",
                r.s.findings_skipped
            ),
        ));
    }
    for (file, n) in &r.s.committed {
        rows.push((
            "Committed".to_owned(),
            format!(
                "{file} is in {}: rotate those keys at each provider",
                plural(*n as usize, "git commit", "git commits")
            ),
        ));
    }
    for (file, why) in &r.s.failed {
        rows.push(("Skipped".to_owned(), format!("{file}: {why}")));
    }
    for file in &r.s.too_large {
        rows.push((
            "Skipped".to_owned(),
            format!("{file}: too large for a .env file"),
        ));
    }
    if let Some(why) = &r.s.stopped_early {
        rows.push((
            "Scan".to_owned(),
            format!("stopped {why}; run ms init --project PATH on a subfolder to cover the rest"),
        ));
    }
    if let Some(e) = &r.s.rules_error {
        rows.push((
            "Rules".to_owned(),
            format!("not saved: {e}. The keys are recorded but can't be used yet"),
        ));
    }
    if let Some(e) = &r.s.save_error {
        rows.push(("Record".to_owned(), format!("not saved: {e}")));
    }
    if !r.s.hints.is_empty() {
        rows.push((
            "Hint".to_owned(),
            format!(
                "added to {}: agents keep the ms:// refs as they are",
                r.s.hints.join(", ")
            ),
        ));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_projects::record::FindingRecord;

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
            s: setup::Report {
                slug: "shop".into(),
                display: "shop".into(),
                root: "/Users/me/code/shop".into(),
                found: 14,
                files: 3,
                findings: vec![FindingRecord {
                    path: "src/lib/stripe.ts".into(),
                    line: 4,
                    provider: "stripe".into(),
                    masked: "sk_live_… (40 bytes)".into(),
                }],
                committed: vec![(".env".into(), 2)],
                ..setup::Report::default()
            },
            keys: vec![k("shop/a", true), k("shop/session-secret", false)],
            unknown: vec![KeyName::new("shop/session-secret").unwrap()],
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
        r.s.found = 0;
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
