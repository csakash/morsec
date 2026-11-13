//! `ms scan`: ask msd to search agent transcripts for vault values (L09).
//!
//! The matching runs inside msd; this only prints what it reports: file, line, key name and
//! encoding. There is no path argument: msd picks the transcript directories itself.

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use ms_ipc::{Client, RequestBody, ResponseBody};

use crate::terminal_safe;

/// Exit code when a value was found.
pub(crate) const EXIT_LEAK: u8 = 3;
/// How long to wait for msd (its own budget is 240 s).
const WAIT: Duration = Duration::from_secs(300);

#[derive(Debug, Args)]
#[command(after_help = "\
Searches Claude Code (~/.claude/projects, or $CLAUDE_CONFIG_DIR/projects) and Codex \
(~/.codex/sessions, or $CODEX_HOME/sessions) transcripts, as msd sees them, for every value in \
the vault: raw, JSON-escaped, URL-encoded, hex, base64 and base64url (at any offset inside a \
larger base64 blob). Values shorter than 8 bytes are skipped. Not found: compressed or encrypted \
text, a value split across lines, part of a value.

Prints file:line, the key and the encoding, never the value. Run it from your own terminal; \
msd refuses it inside an agent session.

Exit status: 0 nothing found, 3 a value was found, 1 the scan failed or did not finish.")]
pub(crate) struct ScanArgs {}

/// Renders a reply: (stdout lines, stderr lines, exit code).
pub(crate) fn render(resp: &ResponseBody) -> (Vec<String>, Vec<String>, u8) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let ResponseBody::ScanReport {
        findings,
        files_scanned,
        keys_checked,
        skipped_keys,
        notes,
        complete,
        ..
    } = resp
    else {
        if let ResponseBody::Error { message, .. } = resp {
            err.push(terminal_safe(message));
        } else {
            err.push("morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)".into());
        }
        return (out, err, 1);
    };
    let files = if *files_scanned == 1 { "file" } else { "files" };
    let keys = if *keys_checked == 1 { "key" } else { "keys" };
    if findings.is_empty() {
        out.push(format!(
            "morsec scan: no vault value found in {files_scanned} transcript {files} ({keys_checked} {keys} checked)"
        ));
    } else {
        let n = findings.len();
        out.push(format!(
            "morsec scan: {n} leaked value{} in {files_scanned} transcript {files} ({keys_checked} {keys} checked)",
            if n == 1 { "" } else { "s" }
        ));
        for f in findings {
            out.push(format!(
                "  {}:{}  {}  ({})",
                terminal_safe(&f.file),
                f.line,
                terminal_safe(f.key.as_str()),
                terminal_safe(&f.encoding)
            ));
        }
        let mut leaked: Vec<&str> = findings.iter().map(|f| f.key.as_str()).collect();
        leaked.sort_unstable();
        leaked.dedup();
        out.push(format!(
            "Rotate these keys at their provider, then update them with ms add: {}",
            terminal_safe(&leaked.join(", "))
        ));
    }
    if !skipped_keys.is_empty() {
        let names: Vec<&str> = skipped_keys.iter().map(|k| k.as_str()).collect();
        err.push(format!(
            "note: not searched (value shorter than 8 bytes): {}",
            terminal_safe(&names.join(", "))
        ));
    }
    for n in notes {
        err.push(format!("note: {}", terminal_safe(n)));
    }
    let code = if !findings.is_empty() {
        EXIT_LEAK
    } else if !complete {
        err.push(
            "morsec scan: the scan did not finish, so a leak may have been missed (see the notes above)"
                .into(),
        );
        1
    } else {
        0
    };
    (out, err, code)
}

pub(crate) async fn run(_a: &ScanArgs) -> ExitCode {
    let resp = async {
        let path = ms_ipc::default_socket_path()?;
        Client::connect(&path)
            .await?
            .request_within(RequestBody::Scan, WAIT)
            .await
    }
    .await;
    let (out, err, code) = match resp {
        Ok(r) => render(&r),
        Err(e) => (Vec::new(), vec![terminal_safe(&e.to_string())], 1),
    };
    for l in out {
        println!("{l}");
    }
    for l in err {
        eprintln!("{l}");
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::KeyName;
    use ms_ipc::{ErrorCode, ScanFinding};

    fn report(findings: Vec<ScanFinding>, complete: bool) -> ResponseBody {
        ResponseBody::ScanReport {
            findings,
            files_scanned: 2,
            bytes_scanned: 10,
            keys_checked: 1,
            skipped_keys: vec![KeyName::new("tiny/key").unwrap()],
            notes: vec!["searched /h/.claude/projects".into()],
            complete,
        }
    }

    // protects=exit codes (0 clean, 3 leak, 1 error or incomplete) and that a file name from
    // the transcript tree can't put escape sequences on the terminal; fails_when=an incomplete
    // scan exits 0 or control characters survive
    #[test]
    fn exit_codes_and_terminal_safety() {
        assert_eq!(render(&report(vec![], true)).2, 0);
        assert_eq!(render(&report(vec![], false)).2, 1);
        let f = ScanFinding {
            file: "/h/.claude/projects/p/\u{1b}]0;x\u{7}s.jsonl".into(),
            line: 7,
            key: KeyName::new("stripe/test").unwrap(),
            encoding: "base64".into(),
        };
        let (out, err, code) = render(&report(vec![f], false));
        assert_eq!(code, EXIT_LEAK);
        let all = out.join("\n") + &err.join("\n");
        assert!(!all.chars().any(|c| c.is_control() && c != '\n'), "{all:?}");
        assert!(out[1].contains("s.jsonl:7  stripe/test  (base64)"), "{out:?}");
        assert!(err.iter().any(|l| l.contains("tiny/key")));
        let (_, err, code) = render(&ResponseBody::error(ErrorCode::Denied, "no\u{1b}[2J"));
        assert_eq!(code, 1);
        assert_eq!(err, vec!["no[2J".to_owned()]);
    }
}
