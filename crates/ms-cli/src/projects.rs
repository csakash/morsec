//! `ms projects [SLUG]` (L31): the projects `ms init` set up. Names, paths, counts and rules
//! targets only; values are never shown (code findings as the import table masks them).

use std::process::ExitCode;

use clap::Args;
use ms_ipc::{Client, KeyStatus, ProjectSummary, RequestBody, ResponseBody};
use ms_projects::record::ProjectRecord;

use crate::terminal_safe;

/// `ms projects [SLUG]`
#[derive(Debug, Args)]
pub struct ProjectsArgs {
    /// Show this project in full.
    slug: Option<String>,
}

fn ask(body: RequestBody) -> Result<ResponseBody, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: starting the IPC client: {e}"))?
        .block_on(async {
            let path = ms_ipc::default_socket_path()?;
            Client::connect(&path).await?.request(body).await
        })
        .map_err(|e| e.to_string())
}

fn say(s: &str) {
    for line in s.lines() {
        println!("{}", terminal_safe(line));
    }
}

fn fail(s: &str) -> ExitCode {
    eprintln!("{}", terminal_safe(s));
    ExitCode::FAILURE
}

const UNEXPECTED: &str = "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)";

/// One line per project.
pub(crate) fn list_lines(projects: &[ProjectSummary]) -> Vec<String> {
    if projects.is_empty() {
        return vec!["No projects yet. Run ms init inside a project.".into()];
    }
    let w = projects
        .iter()
        .map(|p| p.slug.len())
        .max()
        .unwrap_or(0)
        .max(4);
    let mut out = vec![format!(
        "{:<w$}  PROTECTED  NEEDS YOU  IN CODE  ROOT",
        "NAME"
    )];
    for p in projects {
        out.push(format!(
            "{:<w$}  {:>9}  {:>9}  {:>7}  {}{}",
            p.slug,
            p.protected,
            p.needs_you,
            p.findings,
            p.root,
            if p.stopped_early {
                "  (scan stopped early)"
            } else {
                ""
            }
        ));
    }
    out
}

fn mode(k: &KeyStatus) -> &'static str {
    match k.mode {
        Some(ms_core::Mode::Swap) => "swap",
        Some(ms_core::Mode::Run) => "run",
        Some(ms_core::Mode::Mint) => "mint",
        None => "-",
    }
}

/// One project as a table.
pub(crate) fn detail_lines(r: &ProjectRecord, keys: &[KeyStatus]) -> Vec<String> {
    let mut out = vec![
        format!("Project  {} ({})", r.slug, r.display),
        format!("Root     {}", r.root),
        format!(
            "Scan     {} files and folders{}",
            r.scan.entries,
            if r.scan.stopped_early {
                ", stopped early"
            } else {
                ""
            }
        ),
        String::new(),
        "KEY  MODE  TIER  STATUS  TARGETS".into(),
    ];
    for k in keys {
        let status = match (k.stored, k.ready) {
            (false, _) => "missing from the vault",
            (true, true) => "ready",
            (true, false) => "needs you",
        };
        let tier = match k.tier {
            Some(ms_core::Tier::Test) => "test",
            Some(ms_core::Tier::Production) => "production",
            None => "-",
        };
        out.push(format!(
            "{}  {}  {tier}  {status}  {}",
            k.key,
            mode(k),
            if k.targets.is_empty() {
                "-".to_owned()
            } else {
                k.targets.join(", ")
            }
        ));
    }
    out.push(String::new());
    out.push("FILE  LINE  VARIABLE  KEY".into());
    for f in &r.files {
        for s in &f.secrets {
            out.push(format!("{}  {}  {}  {}", f.path, s.line, s.var, s.key));
        }
        if let Some(n) = f.git_history_commits.filter(|n| *n > 0) {
            out.push(format!(
                "{}  is in {n} git commit(s): rotate its keys at each provider",
                f.path
            ));
        }
    }
    if !r.findings.is_empty() {
        out.push(String::new());
        out.push("Keys written into code (move them into .env, then ms init):".into());
        for f in &r.findings {
            out.push(format!(
                "  {}:{}  {}  {}",
                f.path, f.line, f.provider, f.masked
            ));
        }
    }
    out
}

pub(crate) fn run(a: &ProjectsArgs) -> ExitCode {
    match &a.slug {
        None => match ask(RequestBody::ProjectList) {
            Ok(ResponseBody::Projects { projects }) => {
                for l in list_lines(&projects) {
                    say(&l);
                }
                ExitCode::SUCCESS
            }
            Ok(ResponseBody::Error { message, .. }) => fail(&message),
            Ok(_) => fail(UNEXPECTED),
            Err(e) => fail(&e),
        },
        Some(slug) => match ask(RequestBody::ProjectGet { slug: slug.clone() }) {
            Ok(ResponseBody::Project { record, keys }) => match ProjectRecord::from_toml(&record) {
                Ok(r) => {
                    for l in detail_lines(&r, &keys) {
                        say(&l);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e.to_string()),
            },
            Ok(ResponseBody::Error { message, .. }) => fail(&message),
            Ok(_) => fail(UNEXPECTED),
            Err(e) => fail(&e),
        },
    }
}
