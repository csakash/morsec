//! `ms set`, `ms rm` and `ms undo` (L33 dash-actions SPEC D-25): the CLI side of the
//! dashboard's Replace, Delete and Undo. Each refuses inside an agent session before asking msd
//! (and before reading a value), then msd asks the person: reviewed on this terminal
//! (`approve::inline_review`), confirmed with Touch ID raised by msd.

use std::process::ExitCode;

use clap::Args;
use ms_core::{KeyName, SecretBytes};
use ms_ipc::{Client, ErrorCode, RequestBody, ResponseBody};
use zeroize::Zeroizing;

use crate::{terminal_safe, tty};

/// Exit code for "refused" (agent session, policy, the person said no), as `ms run`.
const EXIT_REFUSED: u8 = 77;
/// Exit code for a usage error (sysexits EX_USAGE), as `ms rules`.
const EXIT_USAGE: u8 = 64;

fn key_arg(s: &str) -> Result<KeyName, String> {
    KeyName::new(s).map_err(|e| e.to_string())
}

/// `ms set <key>`
#[derive(Debug, Args)]
pub(crate) struct SetArgs {
    /// The key whose value to replace, e.g. shop/stripe-secret-key.
    #[arg(value_parser = key_arg)]
    key: KeyName,
    /// Read the new value from a pipe instead of typing it.
    #[arg(long)]
    stdin: bool,
}

/// `ms rm <key>`
#[derive(Debug, Args)]
pub(crate) struct RmArgs {
    /// The key to delete with its rule, e.g. shop/stripe-secret-key.
    #[arg(value_parser = key_arg)]
    key: KeyName,
    /// Delete it even while a project file still refers to it.
    #[arg(long)]
    force: bool,
}

/// `ms undo <project>`
#[derive(Debug, Args)]
pub(crate) struct UndoArgs {
    /// The project (its name in ms projects).
    project: String,
    /// Only this key's lines (repeatable); without it, the whole project.
    #[arg(long = "key", value_parser = key_arg)]
    keys: Vec<KeyName>,
}

fn fail(msg: &str, code: u8) -> ExitCode {
    eprintln!("{}", terminal_safe(msg));
    ExitCode::from(code)
}

/// Refuses inside an agent session (before any value is read or msd is asked).
fn refuse_in_agent(what: &str) -> Option<ExitCode> {
    crate::connect::inside_agent().map(|who| {
        fail(
            &format!(
                "morsec: {what} runs only in your own terminal, not inside an agent session ({who}). Ask the user to run it"
            ),
            EXIT_REFUSED,
        )
    })
}

/// Sends `body` (with `value` when it carries one), waiting for the person's approval, while
/// this terminal shows the request for review.
fn ask(
    body: RequestBody,
    value: Option<SecretBytes>,
    what: &'static str,
) -> Result<ResponseBody, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: starting the IPC client: {e}"))?;
    let review = crate::approve::inline_review(what);
    let r = rt.block_on(async {
        let path = ms_ipc::default_socket_path()?;
        let mut c = Client::connect(&path).await?;
        match value {
            Some(v) => {
                c.request_with_value(body, v, crate::approve::APPROVAL_WAIT)
                    .await
            }
            None => c.request_within(body, crate::approve::APPROVAL_WAIT).await,
        }
    });
    drop(review);
    r.map_err(|e| e.to_string())
}

fn answer(r: Result<ResponseBody, String>) -> ExitCode {
    match r {
        Ok(ResponseBody::Ok { message }) => {
            println!("{}", terminal_safe(&message));
            ExitCode::SUCCESS
        }
        Ok(ResponseBody::Error { code, message }) => fail(
            &message,
            match code {
                ErrorCode::Invalid => EXIT_USAGE,
                ErrorCode::Denied | ErrorCode::NeedsApproval | ErrorCode::Busy => EXIT_REFUSED,
                _ => 1,
            },
        ),
        Ok(_) => fail(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)",
            1,
        ),
        Err(e) => fail(&e, 1),
    }
}

fn read_value(a: &SetArgs) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    if a.stdin {
        if tty::stdin_is_tty() {
            return Err(
                "morsec: --stdin reads a pipe, and stdin is a terminal (the value would echo). Leave out --stdin to type it hidden"
                    .into(),
            );
        }
        return tty::read_stdin_value()
            .map(Some)
            .map_err(|e| format!("morsec: reading stdin: {e}"));
    }
    if !tty::stdin_is_tty() {
        return Err(
            "morsec: stdin is not a terminal, so the value can't be typed hidden. Pipe it with --stdin"
                .into(),
        );
    }
    let first = tty::read_hidden(&format!("New value for {} (hidden): ", a.key))
        .map_err(|e| format!("morsec: reading the terminal: {e}"))?;
    let Some(first) = first else {
        return Ok(None);
    };
    let again =
        tty::read_hidden("Again: ").map_err(|e| format!("morsec: reading the terminal: {e}"))?;
    let Some(again) = again else {
        return Ok(None);
    };
    if *first != *again {
        return Err("morsec: the two values differ. Nothing was changed".into());
    }
    Ok(Some(first))
}

/// `ms set <key>`: replace a value (Touch ID). Never echoes it.
pub(crate) fn set(a: &SetArgs) -> ExitCode {
    if let Some(code) = refuse_in_agent("ms set") {
        return code;
    }
    let value = match read_value(a) {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("Cancelled. Nothing was changed.");
            return ExitCode::FAILURE;
        }
        Err(e) => return fail(&e, EXIT_USAGE),
    };
    if value.is_empty() {
        return fail(
            "morsec: the value is empty. Nothing was changed",
            EXIT_USAGE,
        );
    }
    let mut value = value;
    let secret = SecretBytes::new(std::mem::take(&mut *value));
    answer(ask(
        RequestBody::KeyReplace { key: a.key.clone() },
        Some(secret),
        "Replacing this value",
    ))
}

/// `ms rm <key> [--force]`: delete a value and its rule (Touch ID).
pub(crate) fn rm(a: &RmArgs) -> ExitCode {
    if let Some(code) = refuse_in_agent("ms rm") {
        return code;
    }
    answer(ask(
        RequestBody::KeyDelete {
            key: a.key.clone(),
            force: a.force,
        },
        None,
        "Deleting this key",
    ))
}

/// `ms undo <project> [--key <key>]`: write values back into the project's files (Touch ID).
pub(crate) fn undo(a: &UndoArgs) -> ExitCode {
    if let Some(code) = refuse_in_agent("ms undo") {
        return code;
    }
    let r = ask(
        RequestBody::ProjectUndo {
            slug: a.project.clone(),
            keys: (!a.keys.is_empty()).then(|| a.keys.clone()),
        },
        None,
        "Undoing this import",
    );
    match r {
        Ok(ResponseBody::Undone {
            restored,
            skipped,
            deleted_keys,
        }) => {
            for l in &restored {
                println!(
                    "restored  {}/{}:{}  {}",
                    terminal_safe(&l.project),
                    terminal_safe(&l.file),
                    l.line,
                    terminal_safe(&l.var)
                );
            }
            for l in &skipped {
                println!(
                    "skipped   {}/{}:{}  {}  ({})",
                    terminal_safe(&l.project),
                    terminal_safe(&l.file),
                    l.line,
                    terminal_safe(&l.var),
                    terminal_safe(&l.reason)
                );
            }
            for k in &deleted_keys {
                println!("deleted   {k} (nothing refers to it any more)");
            }
            println!(
                "{} value{} written back, {} line{} left as they were",
                restored.len(),
                if restored.len() == 1 { "" } else { "s" },
                skipped.len(),
                if skipped.len() == 1 { "" } else { "s" }
            );
            if skipped.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
        other => answer(other),
    }
}
