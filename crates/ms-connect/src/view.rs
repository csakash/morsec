//! A connect or disconnect plan as people see it (L35 dash-connect, SPEC D-1, D-9): the files it
//! touches and their changed lines, redacted, for the terminal (`ms connect`, `ms disconnect`)
//! and the dashboard alike, so the two can't disagree; and the digest that binds an approval to
//! the full content of the plan, not only to the redacted lines shown.
//!
//! Only changed lines are shown, and a string value goes through only when morsec wrote it
//! ([`crate::claude::diff::redact`], [`crate::codex::tedit::redact_line`]): a value of the user's
//! own never leaves the agent's file.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ConfigDiff;
use crate::claude::diff::{Line, changed_lines, significant};

/// Which agent a file belongs to, for redaction: JSON (Claude Code) or TOML (Codex).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// `settings.json`, `~/.claude.json`.
    Json,
    /// `config.toml`.
    Toml,
}

/// One changed line, redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewLine {
    /// `+` added or `-` removed.
    pub sign: char,
    /// 1-based line number (in the new text for `+`, the old for `-`).
    pub n: usize,
    /// The line, with values morsec didn't write shown as `…`.
    pub text: String,
}

/// One file of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewFile {
    /// The file.
    pub path: PathBuf,
    /// `create`, `change`, `remove` (shown line by line) or `write` / `keep` (morsec's own files,
    /// written whole, no lines).
    pub verb: &'static str,
    /// The changed lines; empty for `write` and `keep`.
    pub lines: Vec<ViewLine>,
    /// Too large to show line by line.
    pub too_large: bool,
}

/// `before` → `after` of an agent settings file, redacted against `safe`.
pub fn settings_file(
    path: &Path,
    before: Option<&str>,
    after: Option<&str>,
    syntax: Syntax,
    safe: &[String],
) -> ViewFile {
    let is_safe = |s: &str| safe.iter().any(|x| x == s);
    let verb = match (before, after) {
        (None, Some(_)) => "create",
        (Some(_), None) => "remove",
        _ => "change",
    };
    let red = |t: &str| match syntax {
        Syntax::Json => crate::claude::diff::redact(t, &is_safe),
        Syntax::Toml => crate::codex::tedit::redact_line(t, &is_safe),
    };
    match changed_lines(before.unwrap_or(""), after.unwrap_or("")) {
        Some(lines) => ViewFile {
            path: path.to_owned(),
            verb,
            lines: significant(lines)
                .into_iter()
                .map(|l| match l {
                    Line::Removed(n, t) => ViewLine {
                        sign: '-',
                        n,
                        text: red(t),
                    },
                    Line::Added(n, t) => ViewLine {
                        sign: '+',
                        n,
                        text: red(t),
                    },
                })
                .collect(),
            too_large: false,
        },
        None => ViewFile {
            path: path.to_owned(),
            verb,
            lines: Vec::new(),
            too_large: true,
        },
    }
}

/// A file morsec writes whole (its state, the CA bundle): named, never shown.
pub fn own_file(path: &Path, verb: &'static str) -> ViewFile {
    ViewFile {
        path: path.to_owned(),
        verb,
        lines: Vec::new(),
        too_large: false,
    }
}

/// How a [`ViewFile`] reads in a terminal: `change <path>:` then `  +  12 <text>` lines.
pub fn terminal_lines(f: &ViewFile) -> Vec<String> {
    match f.verb {
        "write" | "keep" | "drop" => return vec![format!("{} {}", f.verb, f.path.display())],
        _ => {}
    }
    let mut out = vec![format!("{} {}:", f.verb, f.path.display())];
    if f.too_large {
        out.push("  (too large to show line by line)".into());
    }
    for l in &f.lines {
        out.push(format!("  {}{:>4} {}", l.sign, l.n, l.text));
    }
    out
}

/// What the digest covers for one file: its path, and its content before and after (`None`:
/// absent). The content is hashed, never shown.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    /// File.
    pub path: &'a Path,
    /// Content now.
    pub before: Option<&'a str>,
    /// Content after.
    pub after: Option<&'a str>,
}

/// SHA-256 over the agent, the action and every change in order (path, before, after, with
/// absence marked). Binds an approval to exactly these writes (SPEC D-1, T-105).
pub fn digest<'a>(
    agent: &str,
    action: &str,
    changes: impl IntoIterator<Item = Change<'a>>,
) -> String {
    let mut h = Sha256::new();
    let mut put = |tag: u8, s: Option<&[u8]>| {
        h.update([tag]);
        match s {
            None => h.update([0u8]),
            Some(b) => {
                h.update([1u8]);
                h.update((b.len() as u64).to_be_bytes());
                h.update(b);
            }
        }
    };
    put(b'v', Some(b"morsec connect plan v1"));
    put(b'g', Some(agent.as_bytes()));
    put(b'a', Some(action.as_bytes()));
    for c in changes {
        put(b'p', Some(c.path.as_os_str().as_encoded_bytes()));
        put(b'b', c.before.map(str::as_bytes));
        put(b'f', c.after.map(str::as_bytes));
    }
    hex::encode(h.finalize())
}

/// The digest of a connect's [`ConfigDiff`].
pub fn connect_digest(agent: &str, diff: &ConfigDiff) -> String {
    digest(
        agent,
        "connect",
        diff.changes.iter().map(|c| Change {
            path: &c.path,
            before: c.before.as_deref(),
            after: Some(&c.after),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileChange;

    const CANARY: &str = concat!("ghp_", "canaryVIEWxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    // protects=SPEC D-9 / T-107: a value of the user's own on a changed line is shown as "…" in
    // JSON and TOML, while what morsec wrote shows as it is; unchanged lines never appear;
    // fails_when=the canary reaches a view line; no_claim=what counts as morsec's (display_safe)
    #[test]
    fn preview_redacts_user_values() {
        let before = format!("{{\n  \"env\": {{\n    \"TOKEN\": \"{CANARY}\"\n  }}\n}}\n");
        let after = format!(
            "{{\n  \"env\": {{\n    \"TOKEN\": \"{CANARY}\",\n    \"HTTPS_PROXY\": \"http://127.0.0.1:7777\"\n  }}\n}}\n"
        );
        let safe = vec!["http://127.0.0.1:7777".to_owned()];
        let f = settings_file(
            Path::new("/h/.claude/settings.json"),
            Some(&before),
            Some(&after),
            Syntax::Json,
            &safe,
        );
        let all: String = terminal_lines(&f).join("\n");
        assert!(all.contains("http://127.0.0.1:7777"), "{all}");
        assert!(!all.contains(CANARY), "{all}");
        // A changed line holding the canary is redacted, not hidden.
        let after2 = before.replace(CANARY, "ms://gh/token");
        let f = settings_file(
            Path::new("/h/.claude/settings.json"),
            Some(&before),
            Some(&after2),
            Syntax::Json,
            &["ms://gh/token".to_owned()],
        );
        let all: String = terminal_lines(&f).join("\n");
        assert!(!all.contains(CANARY) && all.contains("…"), "{all}");
        let tb = format!("[shell_environment_policy.set]\nTOKEN = \"{CANARY}\"\n");
        let ta = format!("{tb}HTTPS_PROXY = \"http://127.0.0.1:7777\"\nX = \"{CANARY}\"\n");
        let f = settings_file(
            Path::new("/h/.codex/config.toml"),
            Some(&tb),
            Some(&ta),
            Syntax::Toml,
            &safe,
        );
        let all: String = terminal_lines(&f).join("\n");
        assert!(
            all.contains("127.0.0.1:7777") && !all.contains(CANARY),
            "{all}"
        );
    }

    // protects=SPEC D-9: the terminal text is built from the same view the page gets (verb, path,
    // signed numbered lines, morsec's own files as one "write" line); fails_when=the two drift;
    // no_claim=colour or width
    #[test]
    fn preview_matches_terminal_lines() {
        let f = settings_file(
            Path::new("/h/s.json"),
            Some("{\n  \"a\": 1\n}\n"),
            Some("{\n  \"a\": 2\n}\n"),
            Syntax::Json,
            &[],
        );
        assert_eq!(
            terminal_lines(&f),
            [
                "change /h/s.json:",
                "  +   2   \"a\": 2",
                "  -   2   \"a\": 1"
            ]
        );
        assert_eq!(
            terminal_lines(&own_file(Path::new("/h/.morsec/ca-bundle.pem"), "write")),
            ["write /h/.morsec/ca-bundle.pem"]
        );
        let new = settings_file(
            Path::new("/h/n.json"),
            None,
            Some("{}\n"),
            Syntax::Json,
            &[],
        );
        assert_eq!(new.verb, "create");
    }

    // protects=SPEC D-1 / T-105: the digest changes with any byte of any file's before or after
    // (lines the preview never shows included), with the path, the action and the agent, and with
    // absence vs empty; fails_when=two different plans share a digest; no_claim=collision
    // resistance beyond SHA-256
    #[test]
    fn digest_covers_full_content() {
        let ch = |p: &'static str, b: Option<&'static str>, a: &'static str| FileChange {
            path: PathBuf::from(p),
            before: b.map(str::to_owned),
            after: a.to_owned(),
        };
        let base = ConfigDiff {
            changes: vec![
                ch("/h/a", Some("x\nsecret-a\n"), "x\ny\n"),
                ch("/h/b", None, "z"),
            ],
        };
        let d = connect_digest("claude-code", &base);
        assert_eq!(d, connect_digest("claude-code", &base.clone()));
        let mut v = base.clone();
        v.changes[0].before = Some("x\nsecret-b\n".into());
        assert_ne!(d, connect_digest("claude-code", &v));
        let mut v = base.clone();
        v.changes[1].before = Some(String::new());
        assert_ne!(d, connect_digest("claude-code", &v));
        let mut v = base.clone();
        v.changes[1].path = PathBuf::from("/h/c");
        assert_ne!(d, connect_digest("claude-code", &v));
        assert_ne!(d, connect_digest("codex", &base));
        let as_remove = digest(
            "claude-code",
            "disconnect",
            base.changes.iter().map(|c| Change {
                path: &c.path,
                before: c.before.as_deref(),
                after: Some(&c.after),
            }),
        );
        assert_ne!(d, as_remove);
    }
}
