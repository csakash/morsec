//! `ms approve` (L11): a person reviews the request waiting for approval and answers it.
//!
//! Runs in the user's own terminal, outside every agent process tree (msd refuses it inside one).
//! Every field is shown as inert text (`ms_approve::render`): control, bidi and invisible
//! characters escaped, every argument on its own line, nothing truncated. The answer is read from
//! `/dev/tty` (never stdin, so a pipe can't answer), after discarding anything typed before the
//! prompt. On approve, msd itself raises the Touch ID sheet; `ms` never approves anything alone.
//!
//! `ms start`, a loosening `ms rules` and `ms scan` run the same review inline for the request
//! they created ([`inline_review`]).

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Args;
use ms_approve::render;
use ms_core::AgentKind;
use ms_ipc::{ApprovalScope, Client, ErrorCode, PendingApproval, RequestBody, ResponseBody};

use crate::terminal_safe;

/// How long `ms` waits for a reply that may need a person (msd times out at 120 s).
pub(crate) const APPROVAL_WAIT: Duration = Duration::from_secs(150);
const POLL: Duration = Duration::from_millis(400);

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Keep waiting for more requests after answering one (leave it open in a spare terminal).
    #[arg(long)]
    watch: bool,
}

/// A person's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    Approve(ApprovalScope),
    Deny,
}

/// Parses a typed answer. Anything but `o`/`once`/`s`/`session` is a denial.
pub(crate) fn parse_answer(line: &str) -> Answer {
    match line.trim().to_ascii_lowercase().as_str() {
        "o" | "once" => Answer::Approve(ApprovalScope::Once),
        "s" | "session" => Answer::Approve(ApprovalScope::Session),
        _ => Answer::Deny,
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("morsec: starting the IPC client: {e}"))
}

fn ask(rt: &tokio::runtime::Runtime, body: RequestBody) -> ms_core::Result<ResponseBody> {
    rt.block_on(async {
        let path = ms_ipc::default_socket_path()?;
        Client::connect(&path)
            .await?
            .request_within(body, APPROVAL_WAIT)
            .await
    })
}

fn now_ms() -> u64 {
    ms_session::peer::now_unix_ms()
}

/// The screen for one request: msd's fields, rendered inert.
pub(crate) fn screen(p: &PendingApproval, now_ms: u64) -> Vec<String> {
    let left = p.expires_unix_ms.saturating_sub(now_ms) / 1000;
    let mut l = vec![String::new()];
    l.extend(render::details(&p.request, &p.id, left));
    l.push(String::new());
    l.push(
        "Approving asks for Touch ID (or your login password) in a macOS sheet from msd; check that the sheet shows the same fingerprint."
            .into(),
    );
    l
}

const PROMPT: &str = "Approve? [o] this exact command, once   [s] this exact command for this agent session   [d] deny   (anything else denies): ";

/// Shows `p` on `tty` and reads the answer from it. Typeahead is discarded first, so keys
/// pressed before the request appeared can't answer it.
fn review(tty: &mut File, p: &PendingApproval) -> std::io::Result<Answer> {
    for line in screen(p, now_ms()) {
        writeln!(tty, "{line}")?;
    }
    let _ = rustix::termios::tcflush(tty.as_fd(), rustix::termios::QueueSelector::IFlush);
    write!(tty, "{PROMPT}")?;
    tty.flush()?;
    let mut line = String::new();
    BufReader::new((&*tty).take(32)).read_line(&mut line)?;
    Ok(parse_answer(&line))
}

fn open_tty() -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}

/// Sends the answer; returns msd's message (or the error) for display.
fn decide(rt: &tokio::runtime::Runtime, id: &str, a: Answer) -> Result<String, String> {
    let (approve, scope) = match a {
        Answer::Approve(s) => (true, Some(s)),
        Answer::Deny => (false, None),
    };
    match ask(
        rt,
        RequestBody::ApprovalDecide {
            id: id.to_owned(),
            approve,
            scope,
        },
    ) {
        Ok(ResponseBody::Ok { message }) => Ok(message),
        Ok(ResponseBody::Error { message, .. }) => Err(message),
        Ok(_) => Err("morsec: unexpected reply from the daemon".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The request waiting, `Ok(None)` if none.
fn pending(rt: &tokio::runtime::Runtime) -> Result<Option<PendingApproval>, String> {
    match ask(rt, RequestBody::ApprovalPending) {
        Ok(ResponseBody::Approval { pending }) => Ok(pending),
        Ok(ResponseBody::Error { message, .. }) => Err(message),
        Ok(_) => Err(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)"
                .into(),
        ),
        Err(e) => Err(e.to_string()),
    }
}

/// `ms approve [--watch]`.
pub fn run(a: &ApproveArgs) -> ExitCode {
    let fail = |m: &str| {
        eprintln!("{}", terminal_safe(m));
        ExitCode::FAILURE
    };
    let rt = match runtime() {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let mut tty = match open_tty() {
        Ok(t) => t,
        Err(e) => {
            return fail(&format!(
                "morsec: ms approve needs your own terminal to show the request and read your answer ({e})"
            ));
        }
    };
    let mut said_waiting = false;
    let mut last_id = String::new();
    loop {
        match pending(&rt) {
            Err(m) => return fail(&m),
            Ok(Some(p)) if p.id != last_id => {
                last_id = p.id.clone();
                let answer = match review(&mut tty, &p) {
                    Ok(a) => a,
                    Err(e) => return fail(&format!("morsec: reading your answer: {e}")),
                };
                if let Answer::Approve(_) = answer {
                    let _ = writeln!(tty, "Waiting for Touch ID…");
                }
                let ok = match decide(&rt, &p.id, answer) {
                    Ok(m) => {
                        println!("{}", terminal_safe(&m));
                        true
                    }
                    Err(m) => {
                        eprintln!("{}", terminal_safe(&m));
                        false
                    }
                };
                if !a.watch {
                    // A denial you chose is success; Touch ID failing or the request having
                    // ended is not (review R4).
                    return if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    };
                }
                said_waiting = false;
            }
            Ok(_) => {
                if !said_waiting {
                    println!("Waiting for an approval request… (Ctrl-C to stop)");
                    said_waiting = true;
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

/// True for the request this very `ms` process made: msd records a caller outside every agent
/// tree as `other("terminal")` with the connecting PID, which is ours.
fn is_ours(p: &PendingApproval) -> bool {
    p.request.session.agent == AgentKind::Other("terminal".into())
        && p.request.session.pid == std::process::id()
}

/// Stops the inline review when dropped.
#[derive(Debug)]
pub(crate) struct InlineReview(Arc<AtomicBool>);

impl Drop for InlineReview {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// For a command that may wait for approval (`ms start`, `ms rules`, `ms scan`): reviews, on this
/// terminal, the request this process creates. Without a terminal it says to use `ms approve`
/// elsewhere. Keep the guard alive while the request is in flight.
pub(crate) fn inline_review(what: &'static str) -> InlineReview {
    let done = Arc::new(AtomicBool::new(false));
    let d = done.clone();
    std::thread::spawn(move || {
        let Ok(rt) = runtime() else { return };
        let mut tty = open_tty().ok();
        let mut told = false;
        while !d.load(Ordering::SeqCst) {
            let found = pending(&rt);
            if let Err(m) = &found
                && !told
                && m.contains("inside an agent session")
            {
                // Inside an agent session msd won't show approvals here; the person answers in
                // their own terminal (review R5: only for that refusal, not any IPC error).
                eprintln!(
                    "{what} may need the user's approval: they review it with ms approve in their own terminal"
                );
                told = true;
            }
            if let Ok(Some(p)) = found
                && is_ours(&p)
            {
                let Some(tty) = tty.as_mut() else {
                    eprintln!(
                        "{what} needs your approval: run ms approve in another terminal (not inside an agent) within {}s",
                        p.expires_unix_ms.saturating_sub(now_ms()) / 1000
                    );
                    return;
                };
                let _ = writeln!(tty, "{what} needs your approval.");
                let Ok(answer) = review(tty, &p) else { return };
                if d.load(Ordering::SeqCst) {
                    return;
                }
                if let Answer::Approve(_) = answer {
                    let _ = writeln!(tty, "Waiting for Touch ID…");
                }
                if let Err(m) = decide(&rt, &p.id, answer) {
                    eprintln!("{}", terminal_safe(&m));
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    });
    InlineReview(done)
}

/// "N approval waiting" for `ms status`, or nothing (none, or not allowed to see).
pub(crate) async fn status_hint() -> Option<String> {
    let path = ms_ipc::default_socket_path().ok()?;
    let mut c = Client::connect(&path).await.ok()?;
    match c.request(RequestBody::ApprovalPending).await.ok()? {
        ResponseBody::Approval { pending: Some(_) } => {
            Some("1 approval waiting · run ms approve".into())
        }
        ResponseBody::Error {
            code: ErrorCode::Denied,
            ..
        }
        | ResponseBody::Approval { pending: None } => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{ApprovalRequest, KeyName, SessionId, Tier};

    // protects=only an explicit o/once or s/session approves; Enter, typos and anything else
    // deny; fails_when=an unclear answer approves; no_claim=-
    #[test]
    fn answers() {
        assert_eq!(parse_answer("o\n"), Answer::Approve(ApprovalScope::Once));
        assert_eq!(parse_answer(" ONCE "), Answer::Approve(ApprovalScope::Once));
        assert_eq!(parse_answer("s"), Answer::Approve(ApprovalScope::Session));
        for no in ["", "\n", "d", "y", "yes", "approve", "oo", "\u{1b}[A"] {
            assert_eq!(parse_answer(no), Answer::Deny, "{no:?}");
        }
    }

    // protects=INJ-3 in ms approve's screen: an ANSI, RTL-override and newline payload from the
    // agent shows as escapes, never raw; fails_when=a control or bidi character reaches the
    // terminal; no_claim=the render rules themselves (ms-approve render tests)
    #[test]
    fn screen_is_inert() {
        let p = PendingApproval {
            id: "apr-1".into(),
            request: ApprovalRequest {
                session: SessionId {
                    agent: AgentKind::ClaudeCode,
                    pid: 1,
                    started_unix_ms: 0,
                },
                key: KeyName::new("pg/production").unwrap(),
                tier: Tier::Production,
                argv_display: vec!["psql".into(), "\u{1b}[2Jdrop\u{202e}table\nx".into()],
                argv_hash: [0; 32],
                cwd: "/r".into(),
                effect: Some("\u{1b}]0;t\u{7}".into()),
            },
            requested_unix_ms: 0,
            expires_unix_ms: 60_000,
        };
        let text = screen(&p, 0).join("\n");
        assert!(
            !text
                .chars()
                .any(|c| (c.is_control() && c != '\n') || ('\u{202a}'..='\u{202e}').contains(&c)),
            "{text:?}"
        );
        assert!(
            text.contains(r#"[1] "\e[2Jdrop\u{202e}table\nx""#),
            "{text}"
        );
        assert!(text.contains("expires in     60s"), "{text}");
    }
}
