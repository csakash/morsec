//! Redaction applied to every agent-supplied string before a receipt is written.
//!
//! Two layers: [`PatternRedactor`] catches secrets by shape (URL passwords, `password=…`,
//! bearer tokens, well-known token prefixes, PEM private keys) without knowing any value, and
//! [`ValueRedactor`] replaces exact values the broker hands it (it has the value in hand while it
//! uses it). Then every field is capped in length. Over-redaction is accepted; a leak is not.

use ms_core::KeyName;

/// Replacement text.
pub const REDACTED: &str = "[redacted]";
/// Marker appended to a capped field.
pub const TRUNCATED: &str = "…[truncated]";

/// Longest `target`, in bytes, before the marker.
pub const MAX_TARGET: usize = 4096;
/// Longest argv element, in bytes, before the marker.
pub const MAX_ARG: usize = 1024;
/// Most argv elements kept; a final element says how many were dropped.
pub const MAX_ARGS: usize = 64;
/// Longest short field (approver, method, token id, failure message, agent name).
pub const MAX_SHORT: usize = 512;

/// Removes secrets from text.
pub trait Redactor: Send + Sync {
    /// Returns `s` with every secret it recognises replaced.
    fn redact(&self, s: &str) -> String;
}

/// Shape-based redaction. Needs no values.
#[derive(Debug, Default, Clone, Copy)]
pub struct PatternRedactor;

/// Assignment names whose value is a secret. Matched case-insensitively.
const SECRET_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "apikey",
    "api_key",
    "api-key",
    "x-api-key",
    "access_key",
    "secret_key",
    "private_key",
    "aws_secret_access_key",
    "aws_session_token",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "signature",
    "sig",
    "sslpassword",
    "pgpassword",
    "key",
    "private-token",
    "proxy-authorization",
    "session",
    "sessionid",
    "cookie",
    "set-cookie",
];

/// Names whose whole value (to the end of the line or closing quote) is a credential, even when
/// it has spaces, as in `Authorization: token abc` or `Cookie: a=1; b=2`.
const WHOLE_VALUE_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Token prefixes that mark a secret by themselves (Stripe, GitHub, Slack, GitLab, npm, Google,
/// OpenAI, Anthropic, AWS). The run after the prefix is redacted when it is long enough.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk_live_", 8),
    ("sk_test_", 8),
    ("rk_live_", 8),
    ("rk_test_", 8),
    ("whsec_", 8),
    ("ghp_", 16),
    ("gho_", 16),
    ("ghu_", 16),
    ("ghs_", 16),
    ("ghr_", 16),
    ("github_pat_", 16),
    ("xoxb-", 8),
    ("xoxp-", 8),
    ("xoxa-", 8),
    ("xoxs-", 8),
    ("xapp-", 8),
    ("glpat-", 12),
    ("npm_", 16),
    ("AIza", 20),
    ("sk-ant-", 16),
    ("sk-proj-", 16),
    ("sk-", 20),
    ("AKIA", 16),
    ("ASIA", 16),
];

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Ends a value in `name=value`: whitespace, separators, quotes. All ASCII, so every cut lands
/// on a char boundary.
fn ends_value(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'`' | b')' | b'}')
}

impl Redactor for PatternRedactor {
    fn redact(&self, s: &str) -> String {
        let s = redact_pem(s);
        let s = redact_url_userinfo(&s);
        let s = redact_auth_schemes(&s);
        let s = redact_assignments(&s);
        redact_prefixed_tokens(&s)
    }
}

/// `-----BEGIN … PRIVATE KEY----- … -----END … PRIVATE KEY-----`, or to the end when unterminated.
fn redact_pem(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("-----BEGIN ") {
        let after = &rest[i..];
        let header_end = after[11..].find("-----").map(|j| j + 11);
        let is_private = header_end.is_some_and(|e| after[11..e].contains("PRIVATE KEY"));
        if !is_private {
            out.push_str(&rest[..i + 11]);
            rest = &rest[i + 11..];
            continue;
        }
        out.push_str(&rest[..i]);
        out.push_str("[redacted private key]");
        match after.find("-----END ") {
            Some(e) => {
                let tail = &after[e + 9..];
                let close = tail.find("-----").map(|c| e + 9 + c + 5);
                rest = close.map_or("", |c| &after[c..]);
            }
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

/// `scheme://user:password@host` → `scheme://user:[redacted]@host`.
fn redact_url_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let auth_start = i + 3;
        out.push_str(&rest[..auth_start]);
        let after = &rest[auth_start..];
        // The authority ends at the first '/', '?', '#' or whitespace.
        let auth_end = after
            .bytes()
            .position(|b| matches!(b, b'/' | b'?' | b'#') || b.is_ascii_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..auth_end];
        match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                match userinfo.find(':') {
                    Some(c) => {
                        out.push_str(&userinfo[..=c]);
                        out.push_str(REDACTED);
                    }
                    None => out.push_str(userinfo),
                }
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &after[auth_end..];
    }
    out.push_str(rest);
    out
}

/// `Bearer xyz`, `Basic xyz`, `Digest xyz` (case-insensitive) → scheme kept, credential redacted.
/// Other schemes are covered by the whole-value rule for `Authorization`.
fn redact_auth_schemes(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let hit = ["bearer ", "basic ", "digest "].iter().find_map(|scheme| {
            let starts = lower[i..].starts_with(scheme);
            let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            (starts && boundary).then_some(scheme.len())
        });
        match hit {
            Some(n) => {
                out.push_str(&s[i..i + n]);
                let mut j = i + n;
                while j < bytes.len() && bytes[j] == b' ' {
                    j += 1;
                }
                let start = j;
                while j < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b'"' {
                    j += 1;
                }
                if j > start {
                    out.push_str(REDACTED);
                }
                i = j;
            }
            None => {
                let ch_len = s[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&s[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

/// `name=value`, `name: value`, `"name":"value"` for every name in [`SECRET_NAMES`], also as
/// the tail of a longer identifier (`DB_PASSWORD=`, `GITHUB_TOKEN=`). A quoted value is redacted
/// to its closing quote; a [`WHOLE_VALUE_NAMES`] value to the end of the line.
fn redact_assignments(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let mut matched = None;
        // `_`, `-` and `.` count as boundaries, so DB_PASSWORD and x.api_key match.
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary {
            for name in SECRET_NAMES {
                if !lower[i..].starts_with(name) {
                    continue;
                }
                let mut j = i + name.len();
                // Optional closing quote of a JSON key, then spaces, then '=' or ':'.
                if j < bytes.len() && matches!(bytes[j], b'"' | b'\'') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j] == b' ' {
                    j += 1;
                }
                if j < bytes.len() && matches!(bytes[j], b'=' | b':') {
                    j += 1;
                    while j < bytes.len() && bytes[j] == b' ' {
                        j += 1;
                    }
                    let quote =
                        (j < bytes.len() && matches!(bytes[j], b'"' | b'\'')).then(|| bytes[j]);
                    if quote.is_some() {
                        j += 1;
                    }
                    let start = j;
                    let whole = WHOLE_VALUE_NAMES.contains(name);
                    while j < bytes.len() {
                        let b = bytes[j];
                        // Inside quotes, a backslash escapes the next byte (`\"`).
                        if quote.is_some() && b == b'\\' {
                            j = (j + 2).min(bytes.len());
                            continue;
                        }
                        let stop = match quote {
                            Some(q) => b == q,
                            None if whole => matches!(b, b'\n' | b'\r' | b'"' | b'\''),
                            None => ends_value(b),
                        };
                        if stop {
                            break;
                        }
                        j += 1;
                    }
                    if j > start {
                        matched = Some((start, j));
                    }
                    break;
                }
            }
        }
        match matched {
            Some((start, end)) => {
                out.push_str(&s[i..start]);
                out.push_str(REDACTED);
                i = end;
            }
            None => {
                let ch_len = s[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&s[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

/// Well-known token prefixes, at a token boundary, followed by enough token characters.
fn redact_prefixed_tokens(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !is_token_char(bytes[i - 1]);
        let mut hit = None;
        if boundary {
            for (prefix, min) in TOKEN_PREFIXES {
                if s[i..].starts_with(prefix) {
                    let start = i + prefix.len();
                    let mut j = start;
                    while j < bytes.len() && is_token_char(bytes[j]) {
                        j += 1;
                    }
                    if j - start >= *min {
                        hit = Some((start, j));
                        break;
                    }
                }
            }
        }
        match hit {
            Some((start, end)) => {
                out.push_str(&s[i..start]);
                out.push_str(REDACTED);
                i = end;
            }
            None => {
                let ch_len = s[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&s[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

/// Replaces secret values the broker holds with their `ms://` reference: literal,
/// percent-encoded, form-encoded, JSON-escaped (in any mix), and base64 / base64url. Borrows the values for one append; it never stores or prints them.
pub struct ValueRedactor<'a> {
    values: Vec<(&'a KeyName, &'a [u8])>,
}

impl std::fmt::Debug for ValueRedactor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValueRedactor")
            .field(
                "keys",
                &self.values.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl<'a> ValueRedactor<'a> {
    /// Redacts each value, in the forms listed on the type, as `ms://<key>`.
    pub fn new(values: Vec<(&'a KeyName, &'a [u8])>) -> Self {
        Self { values }
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Length of the match of `value` at `text[i..]`. Each value byte may appear literally,
/// percent-encoded (`%2D`, `%2d`), as `+` for a space (form encoding), or JSON-escaped (`\/`,
/// `\"`, `\\`, `\n`, `\u002d`), in any mix.
fn match_at(text: &[u8], i: usize, value: &[u8]) -> Option<usize> {
    let at = |k: usize| text.get(k).copied();
    let mut j = i;
    for &b in value {
        if at(j) == Some(b) {
            j += 1;
        } else if at(j) == Some(b'%')
            && at(j + 1)
                .zip(at(j + 2))
                .and_then(|(h, l)| Some(hex_val(h)? << 4 | hex_val(l)?))
                == Some(b)
        {
            j += 3;
        } else if b == b' ' && at(j) == Some(b'+') {
            j += 1;
        } else if at(j) == Some(b'\\') {
            let short = match b {
                b'/' | b'"' | b'\\' => Some(b),
                b'\n' => Some(b'n'),
                b'\r' => Some(b'r'),
                b'\t' => Some(b't'),
                _ => None,
            };
            if short.is_some() && at(j + 1) == short {
                j += 2;
            } else if b < 0x80
                && at(j + 1) == Some(b'u')
                && (2..6).all(|k| at(j + k).and_then(hex_val).is_some())
                && (2..6).fold(0u32, |acc, k| {
                    acc << 4 | u32::from(at(j + k).and_then(hex_val).unwrap_or(0))
                }) == u32::from(b)
            {
                j += 6;
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(j - i)
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 of whole 3-byte groups (no padding).
fn b64(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity(data.len() / 3 * 4);
    for c in data.chunks_exact(3) {
        let n = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            out.push(alphabet[(n >> shift & 63) as usize] as char);
        }
    }
    out
}

/// The parts of `value`'s base64 (standard and URL-safe) that are the same wherever the value
/// sits in a larger base64 blob: one per alignment. Pieces shorter than 8 chars are skipped (too
/// likely to match ordinary text).
fn base64_forms(value: &[u8]) -> Vec<String> {
    let mut forms = Vec::new();
    for offset in 0..3 {
        let Some(rest) = value.get(offset..) else {
            break;
        };
        let whole = &rest[..rest.len() / 3 * 3];
        for alphabet in [B64_STD, B64_URL] {
            let f = b64(whole, alphabet);
            if f.len() >= 8 && !forms.contains(&f) {
                forms.push(f);
            }
        }
    }
    forms
}

/// Replaces every occurrence of `value` in `s`, in any form [`match_at`] accepts.
fn replace_value(s: &str, value: &[u8], reference: &str) -> String {
    let text = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut copied = 0;
    while i < text.len() {
        // Only cut on char boundaries; a match inside a multibyte char is skipped.
        match match_at(text, i, value) {
            Some(n) if s.is_char_boundary(i) && s.is_char_boundary(i + n) => {
                out.push_str(&s[copied..i]);
                out.push_str(reference);
                i += n;
                copied = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&s[copied..]);
    out
}

impl Redactor for ValueRedactor<'_> {
    fn redact(&self, s: &str) -> String {
        let mut out = s.to_owned();
        for (key, value) in &self.values {
            // An empty value matches everywhere. A value that is not UTF-8 can still appear
            // percent-encoded or in base64, so it is not skipped.
            if value.is_empty() {
                continue;
            }
            let reference = format!("ms://{key}");
            out = replace_value(&out, value, &reference);
            for form in base64_forms(value) {
                out = out.replace(&form, &reference);
            }
        }
        out
    }
}

/// Patterns, then the broker's values, then the length cap.
pub(crate) fn clean(s: &str, extra: Option<&dyn Redactor>, cap: usize) -> String {
    // Values first: a pattern could otherwise split a value and leave part of it behind.
    let s = match extra {
        Some(r) => r.redact(s),
        None => s.to_owned(),
    };
    truncate(&PatternRedactor.redact(&s), cap)
}

/// Argv: each element cleaned and capped, flag-separated values (`--password x`) redacted, and
/// at most [`MAX_ARGS`] elements.
pub(crate) fn clean_argv(argv: &[String], extra: Option<&dyn Redactor>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len().min(MAX_ARGS + 1));
    let mut redact_next = false;
    let tool = argv
        .first()
        .and_then(|a| a.rsplit('/').next())
        .unwrap_or_default();
    let is_mysql = matches!(
        tool,
        "mysql" | "mysqldump" | "mysqladmin" | "mariadb" | "mysqlimport"
    );
    for a in argv.iter().take(MAX_ARGS) {
        if redact_next {
            out.push(REDACTED.to_owned());
            redact_next = false;
            continue;
        }
        let flag = a.trim_start_matches('-').to_ascii_lowercase();
        redact_next = a.starts_with('-') && !a.contains('=') && is_secret_flag(&flag);
        if is_mysql && a.len() > 2 && a.starts_with("-p") && !a.starts_with("--") {
            // mysql -pVALUE: the password is glued to the flag.
            out.push(format!("-p{REDACTED}"));
            continue;
        }
        out.push(clean(a, extra, MAX_ARG));
    }
    if argv.len() > MAX_ARGS {
        out.push(format!("…[{} more arguments]", argv.len() - MAX_ARGS));
    }
    out
}

/// A flag whose name is, or ends in, a secret name: `password`, `db-password`, `api_key`.
fn is_secret_flag(flag: &str) -> bool {
    SECRET_NAMES.iter().any(|n| {
        flag == *n
            || flag
                .strip_suffix(n)
                .is_some_and(|head| head.ends_with(['-', '_', '.']))
    })
}

/// Cuts `s` to at most `cap` bytes on a char boundary and marks the cut.
pub(crate) fn truncate(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_owned();
    }
    let mut end = cap;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATED}", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> String {
        PatternRedactor.redact(s)
    }

    // protects=shape-based redaction removes the secret part of each known form; fails_when=any
    // listed secret survives; no_claim=secrets with no recognisable shape (ValueRedactor's job)
    #[test]
    fn patterns_remove_secrets() {
        // Built at runtime so no provider-key-shaped literal sits in the source (ARI-42 GW-1 scan).
        let anthropic_shaped = format!("sk-{}-api03-abcdefghijklmnopqrstu", "ant");
        let cases = [
            ("postgres://app:hunter2@db.internal:5432/x", "hunter2"),
            ("https://u:p4ss@example.com", "p4ss"),
            ("curl -H 'Authorization: Bearer abc.def.ghi'", "abc.def.ghi"),
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            ("PGPASSWORD=s3cr3t psql", "s3cr3t"),
            ("api_key=AAAABBBBCCCC&x=1", "AAAABBBBCCCC"),
            ("{\"token\": \"tok-123456\"}", "tok-123456"),
            ("password: 'correct horse battery'", "horse battery"),
            ("{\"secret\":\"a b c\"}", "b c"),
            ("DB_PASSWORD=hunter2 psql", "hunter2"),
            ("GITHUB_TOKEN=abc123 gh pr list", "abc123"),
            ("STRIPE_SECRET=xyz9 node app", "xyz9"),
            ("MY_API_KEY=plainvalue", "plainvalue"),
            (
                "https://api.example.com/v1?key=abcdef0123456789",
                "abcdef0123456789",
            ),
            ("key=hunter2", "hunter2"),
            (
                "-H 'Authorization: token 0123abcd4567' https://x",
                "0123abcd4567",
            ),
            ("Authorization: SSWS 00abcDEF", "00abcDEF"),
            ("Cookie: sid=s3ss10n; theme=dark", "s3ss10n"),
            ("Authorization: Token LEAKTOK", "LEAKTOK"),
            ("Authorization:Bearer\tTOKLEAK", "TOKLEAK"),
            ("{\"password\":\"ab\\\"cdLEAK\"}", "cdLEAK"),
            ("OPENAI_API_KEY=plainLEAK node", "plainLEAK"),
            ("stripe sk_live_51HxYzAbCdEfGh", "51HxYzAbCdEfGh"),
            ("key=sk_test_CANARY_7f3a9c00", "CANARY"),
            ("ghp_0123456789abcdefABCDEF", "0123456789abcdef"),
            ("aws AKIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"),
            ("x xoxb-1234-5678-abcdef", "1234-5678"),
            (anthropic_shaped.as_str(), "abcdefghijklmnop"),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
                "b3BlbnNzaC1rZXk",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEunterminated",
                "MIIEunterminated",
            ),
        ];
        for (input, secret) in cases {
            let out = r(input);
            assert!(!out.contains(secret), "{input:?} -> {out:?}");
            assert!(out.contains("redacted"), "{input:?} -> {out:?}");
        }
    }

    // protects=ordinary text survives untouched; fails_when=hosts, commands or words that merely
    // contain a name or prefix are mangled; no_claim=every false positive (over-redaction is ok)
    #[test]
    fn leaves_ordinary_text() {
        for s in [
            "api.stripe.com",
            "psql -h db.internal -c select 1",
            "git push origin main",
            "task-runner --disk-size 10",
            "https://example.com/path?q=1",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "passport=1",
            "monkey=1 --key-file=/tmp/k my_tokenizer=x",
            "ünïcode ✓ text",
        ] {
            assert_eq!(r(s), s);
        }
    }

    // protects=exact values, fully or partly percent-encoded, become ms:// refs; fails_when=the
    // value or any percent-encoding of it survives; no_claim=other encodings (base64, hex)
    #[test]
    fn value_redactor() {
        let k = KeyName::new("pg/staging").unwrap();
        let v = b"pa ss/word!";
        let vr = ValueRedactor::new(vec![(&k, v.as_slice())]);
        let out = vr.redact("x=pa ss/word! y=pa%20ss%2Fword%21 z=p%61 ss%2fword! é");
        assert_eq!(
            out,
            "x=ms://pg/staging y=ms://pg/staging z=ms://pg/staging é"
        );
        assert!(!format!("{vr:?}").contains("word"));
        // Form encoding, JSON escapes, base64 at every alignment, and a non-UTF-8 value.
        let v2 = b"pa ss/w+rd";
        let vr2 = ValueRedactor::new(vec![(&k, v2.as_slice())]);
        for leak in [
            "q=pa+ss%2Fw%2Brd",
            "{\"p\":\"pa ss\\/w+rd\"}",
            "{\"p\":\"pa\\u0020ss/w+rd\"}",
            "auth cGEgc3MvdytyZA==",
            "x eHBhIHNzL3crcmQ=",
            "x eHhwYSBzcy93K3Jk",
            "x eHhwYSBzcy93K3Jk".replace('+', "-").as_str(),
        ] {
            let out = vr2.redact(leak);
            assert!(out.contains("ms://pg/staging"), "{leak} -> {out}");
            for part in [
                "ss/w",
                "ss%2F",
                "c3MvdytyZ",
                "BzcyB3",
                "IHNzL3cr",
                "Bzcy93",
                "zcy93",
            ] {
                assert!(!out.contains(part), "{leak} -> {out}");
            }
        }
        let bin = [0xff_u8, 0xfe, b'A', b'B'];
        let vr3 = ValueRedactor::new(vec![(&k, bin.as_slice())]);
        assert_eq!(vr3.redact("q=%FF%FEAB"), "q=ms://pg/staging");
        let empty = ValueRedactor::new(vec![(&k, b"".as_slice())]);
        assert_eq!(empty.redact("abc"), "abc");
    }

    // protects=fields are capped on a char boundary with a visible marker, and argv flag values
    // are redacted; fails_when=a cap splits a char, hides that it cut, or a --password value
    // survives; no_claim=the chosen cap sizes
    #[test]
    fn caps_and_argv() {
        let long = "é".repeat(3000);
        let t = truncate(&long, MAX_TARGET);
        assert!(t.ends_with(TRUNCATED) && t.len() <= MAX_TARGET + TRUNCATED.len());
        let argv: Vec<String> = ["psql", "--password", "hunter2", "-c", "select 1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = clean_argv(&argv, None);
        assert_eq!(out, ["psql", "--password", REDACTED, "-c", "select 1"]);
        let argv: Vec<String> = [
            "/usr/bin/mysql",
            "-pLEAKPW",
            "--db-password",
            "LEAK2",
            "-p",
            "3306",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = clean_argv(&argv, None);
        assert_eq!(
            out,
            [
                "/usr/bin/mysql",
                "-p[redacted]",
                "--db-password",
                REDACTED,
                "-p",
                "3306"
            ]
        );
        let bypass: Vec<String> = ["x", "--bypass", "y"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(clean_argv(&bypass, None), ["x", "--bypass", "y"]);
        let many: Vec<String> = (0..70).map(|i| i.to_string()).collect();
        let out = clean_argv(&many, None);
        assert_eq!(out.len(), MAX_ARGS + 1);
        assert_eq!(out[MAX_ARGS], "…[6 more arguments]");
    }
}
