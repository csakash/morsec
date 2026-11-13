//! `ms import [PATH]`: move a .env's secrets into the vault and rewrite it with references.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use ms_core::{KeyMeta, KeyName, Mode, SecretBytes, Tier};
use ms_import::catalog::Catalog;
use ms_import::envfile::{self, EnvFile};
use ms_import::plan::{self, Action, Options, Plan};
use ms_import::{Error, KeyStore};
use ms_ipc::{Client, RequestBody, ResponseBody};

use crate::terminal_safe;
use crate::tty;

/// Exit code for refused input (sysexits-style usage error, like clap).
pub(crate) const EXIT_USAGE: u8 = 2;

#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    /// The file to import.
    #[arg(default_value = ".env")]
    path: PathBuf,
    /// Show the review table and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Do not ask for confirmation (needed when stdin is not a terminal).
    #[arg(long, short = 'y')]
    yes: bool,
    /// Import this variable even if it does not look like a secret.
    #[arg(long, value_name = "VAR")]
    include: Vec<String>,
    /// Never import this variable.
    #[arg(long, value_name = "VAR")]
    exclude: Vec<String>,
    /// Set a variable's tier: VAR=test or VAR=production.
    #[arg(long, value_name = "VAR=TIER", value_parser = parse_tier)]
    tier: Vec<(String, Tier)>,
    /// Set the key a variable is stored under: VAR=stripe/acme-test.
    #[arg(long, value_name = "VAR=KEY", value_parser = parse_name)]
    name: Vec<(String, KeyName)>,
}

fn split_pair(s: &str) -> Result<(&str, &str), String> {
    s.split_once('=')
        .filter(|(v, rest)| !v.is_empty() && !rest.is_empty())
        .ok_or_else(|| "expected VAR=VALUE".to_owned())
}

fn parse_tier(s: &str) -> Result<(String, Tier), String> {
    let (var, t) = split_pair(s)?;
    let tier = match t {
        "test" => Tier::Test,
        "production" | "prod" => Tier::Production,
        _ => return Err("the tier must be test or production".to_owned()),
    };
    Ok((var.to_owned(), tier))
}

fn parse_name(s: &str) -> Result<(String, KeyName), String> {
    let (var, k) = split_pair(s)?;
    let name = KeyName::new(k).map_err(|e| e.to_string())?;
    Ok((var.to_owned(), name))
}

/// Talks to msd for the key store. A fresh connection per call keeps it simple; there are few.
pub(crate) struct IpcStore {
    rt: tokio::runtime::Runtime,
}

impl IpcStore {
    pub(crate) fn new() -> Result<Self, Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Store(format!("starting the IPC client: {e}")))?;
        Ok(Self { rt })
    }

    async fn connect() -> ms_core::Result<Client> {
        Client::connect(&ms_ipc::default_socket_path()?).await
    }
}

fn store_err(e: ms_core::Error) -> Error {
    let msg = terminal_safe(&e.to_string());
    Error::Store(msg.strip_prefix("morsec: ").unwrap_or(&msg).to_owned())
}

/// Any reply other than the expected success is a failure: fail closed.
fn not_acknowledged(resp: ResponseBody, what: &str) -> Error {
    match resp {
        ResponseBody::Error { message, .. } => {
            let msg = terminal_safe(&message);
            Error::Store(msg.strip_prefix("morsec: ").unwrap_or(&msg).to_owned())
        }
        _ => Error::Store(format!(
            "the daemon gave an unexpected reply to {what}; nothing was changed. Make sure ms and msd are the same version (ms --version)"
        )),
    }
}

impl KeyStore for IpcStore {
    fn list(&self) -> Result<Vec<KeyMeta>, Error> {
        let resp = self
            .rt
            .block_on(async { Self::connect().await?.request(RequestBody::ListKeys).await })
            .map_err(store_err)?;
        match resp {
            ResponseBody::Keys { keys } => Ok(keys),
            other => Err(not_acknowledged(other, "the key list")),
        }
    }

    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<(), Error> {
        let resp = self
            .rt
            .block_on(async {
                Self::connect()
                    .await?
                    .put_key(name.clone(), meta, value)
                    .await
            })
            .map_err(store_err)?;
        match resp {
            ResponseBody::Ok { .. } => Ok(()),
            other => Err(not_acknowledged(other, "the stored key")),
        }
    }
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn mode_label(m: Mode) -> &'static str {
    match m {
        Mode::Swap => "swap",
        Mode::Run => "run",
        Mode::Mint => "mint",
    }
}

fn tier_label(t: Tier) -> &'static str {
    match t {
        Tier::Test => "test",
        Tier::Production => "production",
    }
}

/// The review table. Every cell is either from the catalog, a validated name, or a masked value.
fn render(plan: &Plan) -> String {
    let header = [
        "VARIABLE", "LINE", "ACTION", "KEY", "PROVIDER", "MODE", "TIER", "HOSTS", "VALUE",
    ];
    let rows: Vec<[String; 9]> = plan
        .rows
        .iter()
        .map(|r| {
            let hosts = if r.action.rewrites() && r.hosts.is_empty() {
                "none yet (ms rules)".to_owned()
            } else if r.hosts.is_empty() {
                "-".to_owned()
            } else {
                r.hosts.join(",")
            };
            [
                r.var.clone(),
                r.line.to_string(),
                r.action.label().to_owned(),
                r.key
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), ToString::to_string),
                if r.provider_name.is_empty() {
                    "-".to_owned()
                } else {
                    r.provider_name.clone()
                },
                r.mode.map_or("-", mode_label).to_owned(),
                r.tier.map_or("-", tier_label).to_owned(),
                hosts,
                r.masked.clone(),
            ]
        })
        .collect();
    let mut widths = header.map(|h| h.chars().count());
    for r in &rows {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let parts: Vec<String> = cells.zip(widths).map(|(c, w)| format!("{c:<w$}")).collect();
        out.push_str(terminal_safe(parts.join("  ").trim_end()).as_str());
        out.push('\n');
    };
    line(&mut header.iter().copied());
    for r in &rows {
        line(&mut r.iter().map(String::as_str));
    }
    out
}

fn confirm(question: &str) -> io::Result<bool> {
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn fail(e: &Error) -> ExitCode {
    eprintln!("{}", terminal_safe(&e.to_string()));
    match e {
        Error::Usage(_) => ExitCode::from(EXIT_USAGE),
        _ => ExitCode::FAILURE,
    }
}

fn options(a: &ImportArgs) -> Result<Options, Error> {
    let mut o = Options {
        include: a.include.iter().cloned().collect(),
        exclude: a.exclude.iter().cloned().collect(),
        tiers: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    let mut seen = BTreeSet::new();
    for (v, t) in &a.tier {
        if o.tiers.insert(v.clone(), *t).is_some() {
            return Err(Error::Usage(format!("--tier given twice for {v}")));
        }
    }
    for (v, k) in &a.name {
        if !seen.insert(v.clone()) {
            return Err(Error::Usage(format!("--name given twice for {v}")));
        }
        o.names.insert(v.clone(), k.clone());
    }
    Ok(o)
}

pub(crate) fn run(a: &ImportArgs) -> ExitCode {
    let shown = terminal_safe(&a.path.display().to_string());
    let opts = match options(a) {
        Ok(o) => o,
        Err(e) => return fail(&e),
    };
    let file = match EnvFile::read(&a.path, &shown) {
        Ok(f) => f,
        Err(e) => return fail(&e),
    };
    if !a.dry_run && !a.yes && !tty::stdin_is_tty() {
        return fail(&Error::Usage(format!(
            "stdin is not a terminal, so the import can't ask before rewriting {shown}. \
             Review it with --dry-run, then run again with --yes"
        )));
    }
    let store = match IpcStore::new() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let existing = match store.list() {
        Ok(k) => k,
        Err(e) if a.dry_run => {
            eprintln!(
                "note: could not read the vault's keys ({}); key names may change when \
                 they are stored",
                terminal_safe(e.to_string().trim_start_matches("morsec: "))
            );
            Vec::new()
        }
        Err(e) => {
            return fail(&Error::Store(format!(
                "{}. Nothing was stored and {shown} was not changed",
                e.to_string().trim_start_matches("morsec: ")
            )));
        }
    };
    let plan = match plan::plan(Catalog::builtin(), file.entries(), &existing, &opts) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    print!("{}", render(&plan));

    if let Some(n) = envfile::git_history(&a.path).filter(|&n| n > 0) {
        eprintln!(
            "warning: {shown} is in {n} commit(s) of this repository's history. The values in \
             those commits stay readable there: rotate these keys at each provider after importing."
        );
    }
    let changes = plan.rows.iter().filter(|r| r.action.rewrites()).count();
    if changes == 0 {
        println!("Nothing to import in {shown}.");
        return ExitCode::SUCCESS;
    }
    if a.dry_run {
        println!(
            "Dry run: {} key(s) would be stored and {changes} value(s) in {shown} replaced. \
             Nothing was changed.",
            plan.import_count()
        );
        return ExitCode::SUCCESS;
    }
    if !a.yes {
        match confirm(&format!(
            "Import {} key(s) and rewrite {shown}?",
            plan.import_count()
        )) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("Cancelled. Nothing was changed.");
                return ExitCode::FAILURE;
            }
            Err(e) => return fail(&Error::Store(format!("reading the answer: {e}"))),
        }
    }
    match envfile::commit(&file, &plan, &store, now_unix_ms()) {
        Ok(done) => {
            println!(
                "Stored {} key(s); {shown} now holds references instead of {} value(s).",
                done.stored.len(),
                done.rewritten
            );
            if plan
                .rows
                .iter()
                .any(|r| r.action == Action::Import && r.hosts.is_empty())
            {
                println!(
                    "Keys marked \"none yet\" can't be used until you give them hosts or \
                     commands: ms rules <key>"
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_import::dotenv::parse;

    // protects=the table shows masked values only and flags keys with no hosts; fails_when=any
    // value byte beyond the catalog prefix is printed; no_claim=column layout aesthetics
    #[test]
    fn table_is_masked() {
        let entries = parse(
            "STRIPE_SECRET_KEY=sk_live_CANARYxxxxxxxxxxxxxxxx\nSESSION_SECRET=CANARYabc\nPORT=3000\n",
        )
        .unwrap();
        let p = plan::plan(Catalog::builtin(), &entries, &[], &Options::default()).unwrap();
        let t = render(&p);
        assert!(!t.contains("CANARY"), "{t}");
        assert!(!t.contains("3000"), "{t}");
        assert!(t.contains("sk_live_… (30 bytes)"), "{t}");
        assert!(t.contains("none yet (ms rules)"), "{t}");
        assert!(t.contains("api.stripe.com"), "{t}");
    }

    // protects=VAR=VALUE flags parse strictly; fails_when=a malformed pair or bad tier is taken
    #[test]
    fn flag_parsers() {
        assert_eq!(parse_tier("A=test").unwrap(), ("A".into(), Tier::Test));
        assert!(parse_tier("A=staging").is_err());
        assert!(parse_tier("=test").is_err());
        assert!(parse_name("A=Bad Name").is_err());
        assert_eq!(parse_name("A=x/y").unwrap().1.as_str(), "x/y");
    }
}
