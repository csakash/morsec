//! A dotenv parser that keeps byte positions, and a rewriter that changes only chosen values.
//!
//! Grammar (one entry per logical line):
//!
//! ```text
//! [spaces] [export <spaces>] NAME [spaces] = [spaces] VALUE [spaces] [# comment]
//! NAME  = [A-Za-z_][A-Za-z0-9_.]*
//! VALUE = 'single, literal, may span lines'
//!       | "double, \n \r \t \" \\ \$ decoded, may span lines"
//!       | `backtick, literal, may span lines`
//!       | unquoted, to end of line or to a '#' that follows a space or tab
//! ```
//!
//! Everything that is not an entry (comments, blank lines, junk) is kept byte for byte. An
//! unterminated quote or text after a closing quote is an error: the import stops rather than
//! guess where a value ends.

use std::fmt;
use std::ops::Range;

use ms_core::SecretBytes;
use zeroize::Zeroizing;

/// Largest `.env` file morsec reads.
pub const MAX_ENV_FILE_BYTES: usize = 1 << 20;

const BOM: &str = "\u{feff}";

/// How a value was quoted in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    /// No quotes.
    None,
    /// `'…'`
    Single,
    /// `"…"`
    Double,
    /// `` `…` ``
    Backtick,
}

impl Quote {
    fn char(self) -> Option<char> {
        match self {
            Quote::None => None,
            Quote::Single => Some('\''),
            Quote::Double => Some('"'),
            Quote::Backtick => Some('`'),
        }
    }
}

/// One `NAME=value` entry.
pub struct Entry {
    /// Variable name.
    pub name: String,
    /// 1-based line where the entry starts.
    pub line: usize,
    /// Byte range of the raw value in the source, quotes included. Empty for `NAME=`.
    pub value_span: Range<usize>,
    /// How the value was quoted.
    pub quote: Quote,
    /// The value uses `${…}` or `$NAME` and is left alone.
    pub interpolated: bool,
    value: SecretBytes,
}

impl Entry {
    /// The decoded value. Broker-internal: never print or log it.
    pub fn value(&self) -> &[u8] {
        self.value.expose()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("line", &self.line)
            .field("value_span", &self.value_span)
            .field("quote", &self.quote)
            .field("interpolated", &self.interpolated)
            .field("value", &self.value)
            .finish()
    }
}

/// Why a file could not be parsed. Carries line numbers only, never file text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// A quoted value never closes.
    #[error("line {line}: the {quote} quote is never closed")]
    Unterminated {
        /// Line of the entry.
        line: usize,
        /// Which quote.
        quote: char,
    },
    /// Text follows a closing quote on the same line.
    #[error("line {line}: unexpected text after the closing quote")]
    TrailingText {
        /// Line of the closing quote.
        line: usize,
    },
}

fn is_hspace(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

/// Index of the `\n` ending the line that contains `i`, or `len`.
fn line_end(b: &[u8], i: usize) -> usize {
    b[i..]
        .iter()
        .position(|&c| c == b'\n')
        .map_or(b.len(), |p| i + p)
}

/// Content end of a line: before a `\r` that precedes `\n`.
fn content_end(b: &[u8], start: usize, end: usize) -> usize {
    if end > start && b[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

/// True when `raw` uses `${…}` or `$NAME`. A backslash escapes the next character.
fn has_interpolation(raw: &[u8], escapes: bool) -> bool {
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'\\' if escapes => i += 2,
            b'$' => {
                if let Some(&n) = raw.get(i + 1)
                    && (n == b'{' || is_name_start(n))
                {
                    return true;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

fn decode_double(raw: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' && i + 1 < raw.len() {
            match raw[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'"' => out.push(b'"'),
                b'\\' => out.push(b'\\'),
                b'$' => out.push(b'$'),
                other => {
                    out.push(b'\\');
                    out.push(other);
                }
            }
            i += 2;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn line_of(b: &[u8], i: usize) -> usize {
    1 + b[..i].iter().filter(|&&c| c == b'\n').count()
}

/// Parses `src`. Values are copied into [`SecretBytes`]; the caller keeps `src` (and should
/// hold it in zeroizing memory).
pub fn parse(src: &str) -> Result<Vec<Entry>, ParseError> {
    let b = src.as_bytes();
    let mut i = if src.starts_with(BOM) { BOM.len() } else { 0 };
    let mut entries = Vec::new();
    while i < b.len() {
        let eol = line_end(b, i);
        let mut j = i;
        while j < eol && is_hspace(b[j]) {
            j += 1;
        }
        // `export ` only counts when a name follows.
        if b[j..eol].starts_with(b"export") {
            let mut k = j + 6;
            if k < eol && is_hspace(b[k]) {
                while k < eol && is_hspace(b[k]) {
                    k += 1;
                }
                if k < eol && is_name_start(b[k]) {
                    j = k;
                }
            }
        }
        if j >= eol || !is_name_start(b[j]) {
            i = eol + 1;
            continue;
        }
        let name_start = j;
        while j < eol && is_name_char(b[j]) {
            j += 1;
        }
        let name_end = j;
        while j < eol && is_hspace(b[j]) {
            j += 1;
        }
        if j >= eol || b[j] != b'=' {
            i = eol + 1;
            continue;
        }
        j += 1;
        let after_eq = j;
        while j < eol && is_hspace(b[j]) {
            j += 1;
        }
        let name = src[name_start..name_end].to_owned();
        let line = line_of(b, name_start);
        let quote = match b.get(j) {
            Some(b'\'') if j < eol => Quote::Single,
            Some(b'"') if j < eol => Quote::Double,
            Some(b'`') if j < eol => Quote::Backtick,
            _ => Quote::None,
        };
        let (span, value, interpolated, next) = match quote.char() {
            Some(q) => {
                let q = q as u8;
                let open = j;
                let mut k = open + 1;
                let close = loop {
                    if k >= b.len() {
                        return Err(ParseError::Unterminated {
                            line,
                            quote: q as char,
                        });
                    }
                    if quote == Quote::Double && b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == q {
                        break k;
                    }
                    k += 1;
                };
                let raw = &b[open + 1..close];
                // Only spaces and an optional comment may follow on the closing line.
                let close_eol = line_end(b, close);
                let tail_end = content_end(b, close + 1, close_eol);
                let mut t = close + 1;
                while t < tail_end && is_hspace(b[t]) {
                    t += 1;
                }
                if t < tail_end && b[t] != b'#' {
                    return Err(ParseError::TrailingText {
                        line: line_of(b, close),
                    });
                }
                let (value, interpolated) = if quote == Quote::Double {
                    (decode_double(raw), has_interpolation(raw, true))
                } else {
                    (Zeroizing::new(raw.to_vec()), false)
                };
                (open..close + 1, value, interpolated, close_eol + 1)
            }
            None => {
                let end = content_end(b, i, eol);
                let start = j.min(end);
                let mut k = start;
                // A '#' starts a comment at the value's start (after a space) or after a space.
                let comment_at_start = start < end && b[start] == b'#' && start > after_eq;
                let mut stop = end;
                if comment_at_start {
                    stop = start;
                } else {
                    while k < end {
                        if b[k] == b'#' && k > start && is_hspace(b[k - 1]) {
                            stop = k;
                            break;
                        }
                        k += 1;
                    }
                }
                let mut ve = stop;
                while ve > start && is_hspace(b[ve - 1]) {
                    ve -= 1;
                }
                let raw = &b[start..ve];
                (
                    start..ve,
                    Zeroizing::new(raw.to_vec()),
                    has_interpolation(raw, false),
                    eol + 1,
                )
            }
        };
        let mut value = value;
        entries.push(Entry {
            name,
            line,
            value_span: span,
            quote,
            interpolated,
            value: SecretBytes::new(std::mem::take(&mut *value)),
        });
        i = next;
    }
    Ok(entries)
}

/// Replaces each value span with `ms://<name>`, written in the entry's original quote style.
/// Every other byte of `src` is kept. `replacements` may be in any order but must not overlap
/// and must be spans returned by [`parse`] for this `src`.
pub fn rewrite(src: &str, replacements: &[(&Entry, String)]) -> Zeroizing<String> {
    let mut sorted: Vec<&(&Entry, String)> = replacements.iter().collect();
    sorted.sort_by_key(|(e, _)| e.value_span.start);
    let mut out = Zeroizing::new(String::with_capacity(src.len()));
    let mut last = 0;
    for (entry, text) in sorted {
        let span = &entry.value_span;
        assert!(
            span.start >= last && span.end <= src.len(),
            "overlapping spans"
        );
        out.push_str(&src[last..span.start]);
        match entry.quote.char() {
            Some(q) => {
                out.push(q);
                out.push_str(text);
                out.push(q);
            }
            None => out.push_str(text),
        }
        last = span.end;
    }
    out.push_str(&src[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn vals(src: &str) -> Vec<(String, String, Quote, bool)> {
        parse(src)
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e.name.clone(),
                    String::from_utf8(e.value().to_vec()).unwrap(),
                    e.quote,
                    e.interpolated,
                )
            })
            .collect()
    }

    fn v(n: &str, val: &str, q: Quote, interp: bool) -> (String, String, Quote, bool) {
        (n.into(), val.into(), q, interp)
    }

    // protects=the documented dotenv forms parse to the values loaders see; fails_when=a quote
    // style, export, comment, CRLF, BOM, escape or multiline value decodes differently;
    // no_claim=behaviour of every third-party dotenv loader (they disagree on edge cases)
    #[test]
    fn golden() {
        let src = "\u{feff}# comment\r\n\
                   A=plain\r\n\
                   export B = 'single # not comment'\n\
                   C=\"dq \\n \\\" \\\\ \\$HOME \\q\"\n\
                   D=`back\ntick`\n\
                   E=value # inline comment\n\
                   F=val#ue\n\
                   G= #only comment\n\
                   H=\n\
                   I=\"multi\nline\"  # c\n\
                   J=${OTHER}/x\n\
                   K=\"$OTHER\"\n\
                   L='$OTHER'\n\
                   not an entry\n\
                   exportM=1\n\
                   export N=2\n\
                   dotted.name=3\n\
                   O=#hash-start\n\
                   P=  spaced  \t\n\
                   Q=last";
        assert_eq!(
            vals(src),
            vec![
                v("A", "plain", Quote::None, false),
                v("B", "single # not comment", Quote::Single, false),
                v("C", "dq \n \" \\ $HOME \\q", Quote::Double, false),
                v("D", "back\ntick", Quote::Backtick, false),
                v("E", "value", Quote::None, false),
                v("F", "val#ue", Quote::None, false),
                v("G", "", Quote::None, false),
                v("H", "", Quote::None, false),
                v("I", "multi\nline", Quote::Double, false),
                v("J", "${OTHER}/x", Quote::None, true),
                v("K", "$OTHER", Quote::Double, true),
                v("L", "$OTHER", Quote::Single, false),
                v("exportM", "1", Quote::None, false),
                v("N", "2", Quote::None, false),
                v("dotted.name", "3", Quote::None, false),
                v("O", "#hash-start", Quote::None, false),
                v("P", "spaced", Quote::None, false),
                v("Q", "last", Quote::None, false),
            ]
        );
        let lines: Vec<usize> = parse(src).unwrap().iter().map(|e| e.line).collect();
        assert_eq!(
            lines,
            [
                2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22
            ]
        );
    }

    // protects=an unclosed quote or junk after a closing quote stops the import with a line
    // number; fails_when=it parses, guesses, or the error echoes file text; no_claim=recovery
    #[test]
    fn errors_fail_closed() {
        assert_eq!(
            parse("A=1\nB=\"sk_live_SECRET\nC=2\n").unwrap_err(),
            ParseError::Unterminated {
                line: 2,
                quote: '"'
            }
        );
        assert_eq!(
            parse("A='x").unwrap_err(),
            ParseError::Unterminated {
                line: 1,
                quote: '\''
            }
        );
        let e = parse("A=\"sk_live_SECRET\"oops\n").unwrap_err();
        assert_eq!(e, ParseError::TrailingText { line: 1 });
        assert!(!e.to_string().contains("SECRET"));
        // An escaped quote at the very end does not close the value.
        assert!(parse("A=\"abc\\\"").is_err());
    }

    // protects=rewriting changes only the chosen spans and keeps quote style, comments, CRLF and
    // the BOM; fails_when=any other byte changes; no_claim=atomicity on disk (see file tests)
    #[test]
    fn rewrite_splices() {
        let src = "\u{feff}# c\r\nA=sk_live_x # keep\r\nB=\"multi\nline\"\nC='lit'\nD=keep\n";
        let entries = parse(src).unwrap();
        let reps = vec![
            (&entries[0], "ms://stripe/production".to_owned()),
            (&entries[1], "ms://env/b".to_owned()),
            (&entries[2], "ms://env/c".to_owned()),
        ];
        let out = rewrite(src, &reps);
        assert_eq!(
            out.as_str(),
            "\u{feff}# c\r\nA=ms://stripe/production # keep\r\nB=\"ms://env/b\"\nC='ms://env/c'\nD=keep\n"
        );
        let again = parse(&out).unwrap();
        assert_eq!(again[0].value(), b"ms://stripe/production");
        assert_eq!(again[1].value(), b"ms://env/b");
    }

    // protects=Debug of an entry never shows its value; fails_when=the canary is printed
    #[test]
    fn entry_debug_redacted() {
        let e = parse("A=sk_test_CANARY123").unwrap();
        let dbg = format!("{e:?}");
        assert!(!dbg.contains("CANARY"), "{dbg}");
    }

    fn arb_env() -> impl Strategy<Value = String> {
        let line = prop_oneof![
            "[A-Z_][A-Z0-9_]{0,6}=[ -~]{0,20}",
            "export [A-Z_]{1,4}=\"[ -~\\n]{0,12}\"",
            "[A-Z]{1,3}='[^']{0,12}'",
            "# [ -~]{0,20}",
            "[ -~]{0,20}",
            "",
        ];
        prop::collection::vec(line, 0..12).prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        // protects=parse never panics on arbitrary input (stable stand-in for the fuzz target);
        // fails_when=any input panics; no_claim=coverage-guided depth (see fuzz/)
        #[test]
        fn never_panics(s in "\\PC{0,200}") {
            let _ = parse(&s);
        }

        // protects=parse never panics on dotenv-shaped input, and an untouched rewrite is the
        // identity; fails_when=a byte changes with no replacements, or spans fall outside src;
        // no_claim=semantic equivalence with other loaders
        #[test]
        fn untouched_rewrite_is_identity(s in arb_env()) {
            if let Ok(entries) = parse(&s) {
                for e in &entries {
                    prop_assert!(e.value_span.end <= s.len());
                    prop_assert!(s.is_char_boundary(e.value_span.start));
                    prop_assert!(s.is_char_boundary(e.value_span.end));
                }
                let same = rewrite(&s, &[]);
                prop_assert_eq!(same.as_str(), s.as_str());
                // Rewriting every entry gives a file whose entries are exactly the refs.
                // (Empty values are never imported, so they are left out here.)
                let reps: Vec<_> = entries
                    .iter()
                    .filter(|e| !e.value().is_empty())
                    .map(|e| (e, "ms://x".to_owned()))
                    .collect();
                let out = rewrite(&s, &reps);
                let again = parse(&out).unwrap();
                prop_assert_eq!(again.len(), entries.len());
                for (old, new) in entries.iter().zip(&again) {
                    let want: &[u8] = if old.value().is_empty() { b"" } else { b"ms://x" };
                    prop_assert_eq!(new.value(), want);
                }
            }
        }
    }
}
