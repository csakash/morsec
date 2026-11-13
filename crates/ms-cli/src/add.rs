//! `ms add <name>`: store one secret, typed hidden or piped with `--stdin`. There is no flag that
//! takes the value itself: it would show in `ps` and shell history.

use std::process::ExitCode;

use clap::{Args, ValueEnum};
use ms_core::{KeyMeta, KeyName, Mode, SecretBytes, Tier};
use ms_import::{Error, KeyStore};
use zeroize::Zeroizing;

use crate::import::{EXIT_USAGE, IpcStore, now_unix_ms};
use crate::terminal_safe;
use crate::tty;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TierArg {
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Swap,
    Run,
    Mint,
}

#[derive(Debug, Args)]
pub(crate) struct AddArgs {
    /// Key name, e.g. stripe/test.
    #[arg(value_parser = |s: &str| KeyName::new(s).map_err(|e| e.to_string()))]
    name: KeyName,
    /// Risk tier. Production keys ask before each use.
    #[arg(long, value_enum, default_value = "production")]
    tier: TierArg,
    /// How the key is used.
    #[arg(long, value_enum, default_value = "swap")]
    mode: ModeArg,
    /// Read the value from a pipe instead of typing it.
    #[arg(long)]
    stdin: bool,
}

fn fail(e: &Error) -> ExitCode {
    eprintln!("{}", terminal_safe(&e.to_string()));
    match e {
        Error::Usage(_) => ExitCode::from(EXIT_USAGE),
        _ => ExitCode::FAILURE,
    }
}

fn read_value(a: &AddArgs) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    if a.stdin {
        return tty::read_stdin_value()
            .map(Some)
            .map_err(|e| Error::Store(format!("reading stdin: {e}")));
    }
    let first = tty::read_hidden(&format!("Value for {} (hidden): ", a.name))
        .map_err(|e| Error::Store(format!("reading the terminal: {e}")))?;
    let Some(first) = first else {
        return Ok(None);
    };
    let again = tty::read_hidden("Again: ")
        .map_err(|e| Error::Store(format!("reading the terminal: {e}")))?;
    let Some(again) = again else {
        return Ok(None);
    };
    if *first != *again {
        return Err(Error::Usage(
            "the two values differ. Nothing was stored".into(),
        ));
    }
    Ok(Some(first))
}

pub(crate) fn run(a: &AddArgs) -> ExitCode {
    let tty_in = tty::stdin_is_tty();
    if !a.stdin && !tty_in {
        return fail(&Error::Usage(
            "stdin is not a terminal, so the value can't be typed hidden. Pipe it with --stdin"
                .into(),
        ));
    }
    if a.stdin && tty_in {
        return fail(&Error::Usage(
            "--stdin reads a pipe, and stdin is a terminal (the value would echo). \
             Leave out --stdin to type it hidden"
                .into(),
        ));
    }
    let store = match IpcStore::new() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    // A piped value costs nothing to read first; a typed one is asked for only once the
    // vault is reachable and the name is free.
    let piped = if a.stdin {
        match read_value(a) {
            Ok(v) => v,
            Err(e) => return fail(&e),
        }
    } else {
        None
    };
    if piped.as_ref().is_some_and(|v| v.is_empty()) {
        return fail(&Error::Usage(
            "the value is empty. Nothing was stored".into(),
        ));
    }
    let existing = match store.list() {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    if existing.iter().any(|m| m.name == a.name) {
        return fail(&Error::Usage(format!(
            "a key named {} already exists. Pick another name; replacing keys is not \
             supported yet",
            a.name
        )));
    }
    let value = match piped {
        Some(v) => v,
        None => match read_value(a) {
            Ok(Some(v)) => v,
            Ok(None) => {
                eprintln!("Cancelled. Nothing was stored.");
                return ExitCode::FAILURE;
            }
            Err(e) => return fail(&e),
        },
    };
    if value.is_empty() {
        return fail(&Error::Usage(
            "the value is empty. Nothing was stored".into(),
        ));
    }
    let meta = KeyMeta {
        name: a.name.clone(),
        mode: match a.mode {
            ModeArg::Swap => Mode::Swap,
            ModeArg::Run => Mode::Run,
            ModeArg::Mint => Mode::Mint,
        },
        tier: match a.tier {
            TierArg::Test => Tier::Test,
            TierArg::Production => Tier::Production,
        },
        created_unix_ms: now_unix_ms(),
    };
    let mut value = value;
    let secret = SecretBytes::new(std::mem::take(&mut *value));
    match store.put(&a.name, secret, meta) {
        Ok(()) => {
            println!("Stored {}. Use it as ms://{}", a.name, a.name);
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}
