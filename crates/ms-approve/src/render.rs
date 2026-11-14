//! Inert rendering of agent-supplied strings (INJ-3, SPEC D-7).
//!
//! Everything an agent can influence (argv, cwd, effect preview, an agent's process name) is
//! shown through [`inert`]: control, bidi and invisible characters are *escaped*, never dropped,
//! so the person sees that they are there. `ms approve` never truncates; the Touch ID reason has a
//! length cap and says so explicitly when it applies.

use std::fmt::Write as _;

use ms_core::{AgentKind, ApprovalRequest, Tier};
use sha2::{Digest, Sha256};

use crate::token::Scope;

/// Longest Touch ID reason msd builds. Past this the command is cut, with an explicit marker.
pub const REASON_MAX_CHARS: usize = 480;

/// True for characters that change how text around them is displayed, or are invisible:
/// bidi controls, zero-width and other format characters, line/paragraph separators, tags.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}'
        | '\u{180b}'..='\u{180f}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}'
        | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}'
        | '\u{fff0}'..='\u{fffb}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0000}'..='\u{e0fff}')
}

/// `s` as inert text: printable characters as they are; backslash doubled; `\n`, `\r`, `\t`,
/// `\e` for the common controls; every other control, bidi or invisible character as `\u{XXXX}`.
/// The output contains no control character at all and no character that reorders or hides text.
pub fn inert(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{1b}' => out.push_str("\\e"),
            c if c.is_control() || is_invisible_or_bidi(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// `s` inert and in double quotes (a `"` inside is escaped), so spaces and empty strings show.
pub fn quoted(s: &str) -> String {
    format!("\"{}\"", inert(s).replace('"', "\\\""))
}

/// The agent's display name (an `Other` name is a process name: agent-influenced).
pub fn agent_name(a: &AgentKind) -> String {
    match a {
        AgentKind::ClaudeCode => "Claude Code".into(),
        AgentKind::Codex => "Codex".into(),
        AgentKind::Cursor => "Cursor".into(),
        AgentKind::GeminiCli => "Gemini CLI".into(),
        AgentKind::Other(n) => match n.as_str() {
            "terminal" => "your terminal (outside any agent)".into(),
            _ => format!("other: {}", quoted(n)),
        },
    }
}

fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Test => "test",
        Tier::Production => "production",
    }
}

/// Short, stable fingerprint of what is being approved (the binding: session, key, argv hash,
/// cwd), shown both in `ms approve` and in the Touch ID sheet so the two can be matched.
pub fn fingerprint(req: &ApprovalRequest) -> String {
    let mut h = Sha256::new();
    h.update(b"morsec-approval-fp-v1");
    let agent = format!("{:?}", req.session.agent);
    for part in [
        agent.as_bytes(),
        &req.session.pid.to_be_bytes(),
        &req.session.started_unix_ms.to_be_bytes(),
        req.key.as_str().as_bytes(),
        &req.argv_hash,
        req.cwd.as_os_str().as_encoded_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let d = hex::encode(&h.finalize()[..6]);
    format!("{}-{}-{}", &d[0..4], &d[4..8], &d[8..12])
}

/// Unix milliseconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn utc(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// What `ms approve` shows for one pending request: every field, inert, nothing truncated.
pub fn details(req: &ApprovalRequest, id: &str, seconds_left: u64) -> Vec<String> {
    let mut l = vec![
        format!("Approval request {}", inert(id)),
        format!("  agent          {}", agent_name(&req.session.agent)),
        format!(
            "  session        pid {}, started {}",
            req.session.pid,
            utc(req.session.started_unix_ms)
        ),
        format!(
            "  project (cwd)  {}",
            if req.cwd.as_os_str().is_empty() {
                "(none)".to_owned()
            } else {
                quoted(&req.cwd.to_string_lossy())
            }
        ),
        format!(
            "  key            {} ({} tier)",
            inert(req.key.as_str()),
            tier_name(req.tier)
        ),
        format!(
            "  command        {} argument{}, exactly:",
            req.argv_display.len(),
            if req.argv_display.len() == 1 { "" } else { "s" }
        ),
    ];
    for (i, a) in req.argv_display.iter().enumerate() {
        l.push(format!("    [{i}] {}", quoted(a)));
    }
    l.push(format!(
        "  effect         {}",
        req.effect
            .as_deref()
            .map_or_else(|| "(no preview)".to_owned(), quoted)
    ));
    l.push(format!("  argv sha-256   {}", hex::encode(req.argv_hash)));
    l.push(format!("  fingerprint    {}", fingerprint(req)));
    l.push(format!("  expires in     {seconds_left}s"));
    l
}

/// The text msd puts in the Touch ID sheet. Built by msd from the real request; inert; capped at
/// [`REASON_MAX_CHARS`] with an explicit "N more characters not shown" marker when cut.
pub fn touch_id_reason(req: &ApprovalRequest, scope: Scope) -> String {
    let scope = match scope {
        Scope::Once => "this exact command, once",
        Scope::Session => "this exact command for this agent session",
    };
    let cmd = req
        .argv_display
        .iter()
        .map(|a| quoted(a))
        .collect::<Vec<_>>()
        .join(" ");
    let head = format!(
        "approve use of {} ({} key) by {}, {scope} [{}]: ",
        inert(req.key.as_str()),
        tier_name(req.tier),
        agent_name(&req.session.agent),
        fingerprint(req),
    );
    let room = REASON_MAX_CHARS.saturating_sub(head.chars().count());
    let n = cmd.chars().count();
    if n <= room {
        return head + &cmd;
    }
    let marker_room = 80;
    let keep = room.saturating_sub(marker_room);
    let shown: String = cmd.chars().take(keep).collect();
    format!(
        "{head}{shown} … {} more characters not shown; the full command is in ms approve",
        n - keep
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{KeyName, SessionId};
    use std::path::PathBuf;

    fn req(argv: Vec<String>) -> ApprovalRequest {
        ApprovalRequest {
            session: SessionId {
                agent: AgentKind::Other("evil\u{1b}[31mname".into()),
                pid: 42,
                started_unix_ms: 1_763_078_400_000,
            },
            key: KeyName::new("pg/production").unwrap(),
            tier: Tier::Production,
            argv_hash: [7; 32],
            argv_display: argv,
            cwd: PathBuf::from("/repo\u{202e}cod.exe"),
            effect: Some("3 rows\nin orders".into()),
        }
    }

    fn has_dangerous(s: &str) -> bool {
        s.chars().any(|c| c.is_control() || is_invisible_or_bidi(c))
    }

    // protects=INJ-3: ANSI escapes, RTL overrides, newlines, NUL, zero-width and C1 controls in
    // agent-supplied strings render as visible escapes in ms approve and in the Touch ID reason;
    // fails_when=any such character reaches the output raw, or is silently dropped;
    // no_claim=homoglyphs (SPEC D-7)
    #[test]
    fn payloads_render_inert() {
        let payloads = [
            "\u{1b}[2J\u{1b}]0;pwned\u{7}",
            "safe\u{202e}txt.exe",
            "line1\nline2\r\n",
            "nul\0byte",
            "zero\u{200b}width\u{2066}iso\u{2069}",
            "c1\u{9b}31m\u{85}",
            "back\\slash",
        ];
        let argv: Vec<String> = payloads.iter().map(|s| (*s).to_owned()).collect();
        let r = req(argv);
        let lines = details(&r, "id-1", 30);
        for l in &lines {
            assert!(!has_dangerous(l), "{l:?}");
        }
        let text = lines.join("\n");
        assert!(text.contains(r#"[0] "\e[2J\e]0;pwned\u{7}""#), "{text}");
        assert!(text.contains(r#""safe\u{202e}txt.exe""#), "{text}");
        assert!(text.contains(r#""line1\nline2\r\n""#), "{text}");
        assert!(text.contains(r#""nul\u{0}byte""#), "{text}");
        assert!(text.contains(r#""zero\u{200b}width\u{2066}iso\u{2069}""#));
        assert!(text.contains(r#""c1\u{9b}31m\u{85}""#), "{text}");
        assert!(text.contains(r#""back\\slash""#), "{text}");
        assert!(text.contains(r#"other: "evil\e[31mname""#), "{text}");
        assert!(text.contains(r#""/repo\u{202e}cod.exe""#), "{text}");
        assert!(text.contains(r#""3 rows\nin orders""#), "{text}");
        assert!(text.contains("7 arguments, exactly:"));
        let reason = touch_id_reason(&r, Scope::Once);
        assert!(!has_dangerous(&reason), "{reason:?}");
        assert!(reason.contains(r#""safe\u{202e}txt.exe""#), "{reason}");
    }

    // protects=INJ-3 "nothing truncated in a way that hides arguments": ms approve shows every
    // argument in full; a long command in the Touch ID reason is cut with an explicit count of
    // what is not shown; fails_when=an argument is missing from ms approve, or the reason is cut
    // silently or exceeds its cap; no_claim=how macOS lays out the sheet
    #[test]
    fn long_commands_are_never_silently_cut() {
        let long = "x".repeat(2000);
        let r = req(vec![
            "psql".into(),
            "-c".into(),
            long.clone(),
            "--last".into(),
        ]);
        let text = details(&r, "id", 5).join("\n");
        assert!(text.contains(&long));
        assert!(text.contains(r#"[3] "--last""#));
        let reason = touch_id_reason(&r, Scope::Session);
        assert!(
            reason.chars().count() <= REASON_MAX_CHARS + 100,
            "{}",
            reason.len()
        );
        assert!(reason.contains("more characters not shown"), "{reason}");
        assert!(reason.contains(&fingerprint(&r)));
        assert!(reason.contains("for this agent session"));
        let short = touch_id_reason(&req(vec!["ms".into(), "start".into()]), Scope::Once);
        assert!(short.ends_with(r#""ms" "start""#), "{short}");
        assert!(!short.contains("not shown"));
    }

    // protects=the fingerprint shown in ms approve and in the Touch ID sheet changes with every
    // bound field; fails_when=two different bindings share it; no_claim=collision resistance
    // beyond 48 bits (it is for matching by eye, not security)
    #[test]
    fn fingerprint_tracks_the_binding() {
        let a = req(vec!["a".into()]);
        let mut b = a.clone();
        b.argv_hash[0] ^= 1;
        let mut c = a.clone();
        c.cwd = PathBuf::from("/other");
        let mut d = a.clone();
        d.session.pid = 43;
        let fa = fingerprint(&a);
        for o in [&b, &c, &d] {
            assert_ne!(fa, fingerprint(o));
        }
        assert_eq!(fa, fingerprint(&a.clone()));
    }

    #[test]
    fn utc_formats() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_763_078_400_000), "2025-11-14 00:00:00 UTC");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
    }
}
