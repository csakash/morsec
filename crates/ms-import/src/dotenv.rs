//! A dotenv parser that keeps byte positions, and a rewriter that changes only chosen values.
//!
//! Grammar (one entry per logical line):
//!
//! ```text
//! [spaces] [export <spaces>] NAME [spaces] ( = | : <space> ) [spaces] VALUE [spaces] [# comment]
//! NAME  = [A-Za-z0-9_.-]+          (what Node's dotenv accepts, so no entry it reads is missed)
//! VALUE = 'single, literal, may span lines'
//!       | "double, \n \r \t \" \\ \$ decoded, may span lines"
//!       | `backtick, literal, may span lines`
//!       | unquoted, to end of line or to a '#' that follows a space or tab
//! ```
//!
//! Comments, blank lines and `export NAME` lines are kept byte for byte. Any other line
//! is an error, as are an unterminated quote and text after a closing quote: a line some loader
//! might read as a secret must never be skipped silently and left in plaintext, so the import
//! stops rather than guess.

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
    /// An unquoted value was cut at ` #`. Some loaders (docker `env_file`) read the comment as
    /// part of the value, so importing it could leave part of a secret behind.
    pub inline_comment: bool,
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
            .field("inline_comment", &self.inline_comment)
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
    /// A carriage return that does not end a line (`\r` alone, outside quotes). Loaders that
    /// treat it as a line end would see different entries than morsec.
    #[error("line {line} has a carriage return that is not part of a CRLF line ending")]
    BareCarriageReturn {
        /// The line.
        line: usize,
    },
    /// A line that is neither a comment, blank, nor a `NAME=value` entry.
    #[error(
        "line {line} is not a NAME=value entry or a # comment, and a loader might still read it as one"
    )]
    NotAnEntry {
        /// The line.
        line: usize,
    },
}

fn is_hspace(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// Start of a shell variable name, for `$NAME` interpolation.
fn is_var_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
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
                    && (n == b'{' || is_var_start(n))
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
        let line_content_end = content_end(b, i, eol);
        // Blank lines and comments are kept, but a comment hiding a bare CR is not: a loader
        // that ends lines at CR would read what follows it as an entry.
        if j < line_content_end && b[j] == b'#' && b[j..line_content_end].contains(&b'\r') {
            return Err(ParseError::BareCarriageReturn {
                line: line_of(b, i),
            });
        }
        if j >= line_content_end || b[j] == b'#' {
            i = eol + 1;
            continue;
        }
        let mut exported = false;
        // `export ` only counts when a name follows.
        if b[j..eol].starts_with(b"export") {
            let mut k = j + 6;
            if k < eol && is_hspace(b[k]) {
                while k < eol && is_hspace(b[k]) {
                    k += 1;
                }
                if k < eol && is_name_char(b[k]) {
                    j = k;
                    exported = true;
                }
            }
        }
        let not_an_entry = ParseError::NotAnEntry {
            line: line_of(b, i),
        };
        if !is_name_char(b[j]) {
            return Err(not_an_entry);
        }
        let name_start = j;
        while j < eol && is_name_char(b[j]) {
            j += 1;
        }
        let name_end = j;
        while j < eol && is_hspace(b[j]) {
            j += 1;
        }
        // `export NAME` holds no value: keep it. A bare word on its own line could be a pasted
        // token, so it is refused like any other unknown line.
        if j >= line_content_end {
            if !exported {
                return Err(not_an_entry);
            }
            i = eol + 1;
            continue;
        }
        match b[j] {
            b'=' => {}
            // `NAME: value` (YAML style, read by Node's dotenv) needs a space or the line end.
            b':' if j + 1 >= line_content_end || is_hspace(b[j + 1]) => {}
            _ => return Err(not_an_entry),
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
        let (span, value, interpolated, inline_comment, next) = match quote.char() {
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
                // A bare CR after the closing quote (even inside its comment) would start a new
                // line for some loaders.
                if b[close + 1..tail_end].contains(&b'\r') {
                    return Err(ParseError::BareCarriageReturn {
                        line: line_of(b, close),
                    });
                }
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
                (open..close + 1, value, interpolated, false, close_eol + 1)
            }
            None => {
                let end = content_end(b, i, eol);
                if b[j.min(end)..end].contains(&b'\r') {
                    return Err(ParseError::BareCarriageReturn { line });
                }
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
                    !comment_at_start && stop < end,
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
            inline_comment,
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
                   export BARE\n\
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

    // protects=the forms Node's dotenv also reads (NAME: value, dashes, leading digits) are
    // entries, and inline comments on unquoted values are flagged; fails_when=one is skipped
    // (it would stay in plaintext) or a flag is wrong; no_claim=every loader's quirks
    #[test]
    fn loader_compatible_forms() {
        let e =
            parse("STRIPE_SECRET_KEY: sk_live_x\nopenai-api-key=sk\n1X=2\nY:\nP=abc #def\nQ=#x\n")
                .unwrap();
        let got: Vec<(&str, &[u8], bool)> = e
            .iter()
            .map(|e| (e.name.as_str(), e.value(), e.inline_comment))
            .collect();
        assert_eq!(
            got,
            vec![
                ("STRIPE_SECRET_KEY", &b"sk_live_x"[..], false),
                ("openai-api-key", b"sk", false),
                ("1X", b"2", false),
                ("Y", b"", false),
                ("P", b"abc", true),
                ("Q", b"#x", false),
            ]
        );
    }

    // protects=a line that is not blank, a comment, a bare name or an entry stops the import with
    // its line number and never its text; fails_when=it is skipped silently (a loader might read a
    // secret from it) or the text is echoed; no_claim=which loader would have read it
    #[test]
    fn unknown_lines_refused() {
        for (src, line) in [
            ("A=1\nsk_live_CANARY_on_its_own\n", 2),
            ("NAME\n", 1),
            ("A=1\n\nKEY:sk_live_CANARY\n", 3),
            ("KEY sk_live_CANARY\n", 1),
            ("  \"QUOTED\"=x\n", 1),
            ("https://x.example/CANARY\n", 1),
        ] {
            let e = parse(src).unwrap_err();
            assert_eq!(e, ParseError::NotAnEntry { line }, "{src:?}");
            assert!(!e.to_string().contains("CANARY"));
        }
        // Blank, comment-only and `export NAME` lines are fine.
        assert!(parse("\n  \n\t# c\n#\nexport NAME\r\n").unwrap().is_empty());
    }

    // protects=a bare CR outside quotes (old Mac endings, stray CRs) stops the import instead of
    // merging lines; fails_when=a following entry is swallowed into a value; no_claim=CRs inside
    // quotes (kept literally)
    #[test]
    fn bare_cr_refused() {
        for (src, line) in [
            ("A_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxx\rB=plain\r", 1),
            ("X=1\nA=foo\r\r\n", 2),
            ("# note\rB=sk_live_CANARY\n", 1),
            ("A=\"x\" # c\rB_SECRET=sk_live_CANARYxxxxxxxxxxxxxx\n", 1),
            ("A='x' #c\rB=y\n", 1),
            ("A=\"multi\nline\"\rB=y\n", 2),
        ] {
            assert_eq!(
                parse(src).unwrap_err(),
                ParseError::BareCarriageReturn { line },
                "{src:?}"
            );
        }
        assert_eq!(parse("A=\"x\ry\"\r\n").unwrap()[0].value(), b"x\ry");
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
            "[a-z0-9-]{1,5}: [ -~]{0,12}",
            "# [ -~]{0,20}",
            "[ -~]{0,20}",
            "\t[A-Z]{1,3}\t=\t[ -~]{0,8}",
            "",
        ];
        let sep = prop_oneof![Just("\n"), Just("\r\n"), Just("\r")];
        prop::collection::vec((line, sep), 0..12).prop_map(|l| {
            l.into_iter().fold(String::new(), |mut acc, (line, sep)| {
                acc.push_str(&line);
                acc.push_str(sep);
                acc
            })
        })
    }

    /// The parse-and-rewrite invariants every fuzz target checks on input it got from anywhere.
    fn check_invariants(s: &str) -> Result<(), TestCaseError> {
        let Ok(entries) = parse(s) else {
            return Ok(());
        };
        for e in &entries {
            prop_assert!(e.value_span.start <= e.value_span.end);
            prop_assert!(e.value_span.end <= s.len());
            prop_assert!(s.is_char_boundary(e.value_span.start));
            prop_assert!(s.is_char_boundary(e.value_span.end));
        }
        let same = rewrite(s, &[]);
        prop_assert_eq!(same.as_str(), s);
        // Rewriting every entry gives a file whose entries are exactly the refs.
        // (Empty values are never imported, so they are left out here.)
        let reps: Vec<_> = entries
            .iter()
            .filter(|e| !e.value().is_empty())
            .map(|e| (e, "ms://x".to_owned()))
            .collect();
        let out = rewrite(s, &reps);
        let again = parse(&out);
        prop_assert!(
            again.is_ok(),
            "a rewritten file must parse: {:?}",
            again.err()
        );
        let again = again.unwrap();
        prop_assert_eq!(again.len(), entries.len());
        for (old, new) in entries.iter().zip(&again) {
            prop_assert_eq!(&old.name, &new.name);
            let want: &[u8] = if old.value().is_empty() {
                b""
            } else {
                b"ms://x"
            };
            prop_assert_eq!(new.value(), want);
        }
        Ok(())
    }

    fn corpus() -> Vec<Vec<u8>> {
        ms_fuzz::seeds("dotenv")
    }

    /// Tokens worth inserting whole into a mutated `.env`.
    const DICT: &[&[u8]] = &[
        b"=",
        b": ",
        b"export ",
        b"#",
        b" #",
        b"'",
        b"\"",
        b"`",
        b"\\",
        b"\\\"",
        b"${",
        b"}",
        b"$X",
        b"\n",
        b"\r\n",
        b"\r",
        b"\t",
        b"\xef\xbb\xbf",
        b"\xc3\xa9",
        b"\xe2\x80\xae",
        b"\0",
    ];

    /// A secret-looking token, unique per index: `TOK<i>x<6 alphanumerics>`.
    fn token(i: usize) -> impl Strategy<Value = String> {
        "[A-Za-z0-9]{6}".prop_map(move |t| format!("TOK{i}x{t}"))
    }

    /// Text that may sit around a token inside a value without changing how it parses.
    fn noise(quote: Quote) -> BoxedStrategy<String> {
        match quote {
            Quote::None => "[a-z0-9_./+-]{0,6}".boxed(),
            Quote::Single => "[a-z0-9 #\"`$\\\n]{0,8}".boxed(),
            Quote::Double => "[a-z0-9 #'`\n]{0,8}".boxed(),
            Quote::Backtick => "[a-z0-9 #'\"$\\\n]{0,8}".boxed(),
        }
    }

    /// One entry line holding `tok` as (part of) its value, in one of the syntaxes loaders read.
    fn entry_line(tok: String) -> impl Strategy<Value = String> {
        let quote = prop_oneof![
            Just(Quote::None),
            Just(Quote::Single),
            Just(Quote::Double),
            Just(Quote::Backtick),
        ];
        (
            quote,
            "[a-z_][a-z0-9_.-]{0,8}",
            prop::bool::ANY,
            prop_oneof![Just("="), Just(" = "), Just("\t=\t"), Just(": ")],
            "[ \t]{0,2}",
            prop_oneof![Just(String::new()), "[ \t]{1,2}#[ -~&&[^A-Z]]{0,10}"],
        )
            .prop_flat_map(move |(q, name, export, sep, lead, comment)| {
                let tok = tok.clone();
                (noise(q), noise(q)).prop_map(move |(a, b)| {
                    let v = match q.char() {
                        None => format!("{a}{tok}{b}"),
                        Some(c) => format!("{c}{a}{tok}{b}{c}"),
                    };
                    let export = if export { "export " } else { "" };
                    // A YAML-style name may not contain '-' or '.' for every loader; keep it
                    // simple and still valid for this parser.
                    format!("{lead}{export}{name}{sep}{v}{comment}")
                })
            })
    }

    /// A `.env` file made of entries that each hold one unique token, plus comments and blanks.
    fn env_with_tokens() -> impl Strategy<Value = (String, usize)> {
        (1usize..8).prop_flat_map(|n| {
            let entries: Vec<_> = (0..n).map(|i| token(i).prop_flat_map(entry_line)).collect();
            (
                entries,
                prop::collection::vec(
                    prop_oneof![
                        Just(String::new()),
                        "#[ -~&&[^A-Z]]{0,20}",
                        "[ \t]{1,3}",
                        "export [a-z]{1,4}"
                    ],
                    n,
                ),
                prop_oneof![Just("\n"), Just("\r\n")],
                prop::bool::ANY,
            )
                .prop_map(move |(entries, fillers, eol, bom)| {
                    let mut s = String::from(if bom { BOM } else { "" });
                    for (e, f) in entries.iter().zip(&fillers) {
                        s.push_str(f);
                        s.push_str(eol);
                        s.push_str(e);
                        s.push_str(eol);
                    }
                    (s, n)
                })
        })
    }

    proptest! {
        #![proptest_config(ms_fuzz::config(2000))]

        // protects=parse never panics on arbitrary input, control characters and line breaks
        // included; fails_when=any input panics; no_claim=coverage-guided depth (see fuzz/)
        #[test]
        fn fuzz_dotenv_never_panics(s in any::<String>()) {
            check_invariants(&s)?;
        }

        // protects=as above, on ASCII-heavy input where dotenv syntax is likely; fails_when=any
        // input panics or breaks an invariant
        #[test]
        fn fuzz_dotenv_never_panics_ascii(s in "[\\x00-\\x7f]{0,200}") {
            check_invariants(&s)?;
        }

        // protects=parse never panics on dotenv-shaped input, spans are in bounds on char
        // boundaries, an untouched rewrite is the identity and a full rewrite re-parses to the
        // same names with only refs; fails_when=any of those breaks; no_claim=semantic
        // equivalence with other loaders
        #[test]
        fn fuzz_dotenv_rewrite_roundtrip(s in arb_env()) {
            check_invariants(&s)?;
        }

        // protects=the same invariants on byte-mutated seeds from the committed corpus
        // (fuzz/corpus/dotenv); fails_when=a mutated real-world file panics or breaks an
        // invariant; no_claim=coverage guidance (proptest, SPEC D1)
        #[test]
        fn fuzz_dotenv_corpus(s in ms_fuzz::mutated_str(corpus(), DICT)) {
            check_invariants(&s)?;
        }

        // protects=fail closed on import: every secret in a value position is either refused
        // with a parse error or found as an entry, and a full ref rewrite leaves none of them in
        // the file; fails_when=a token survives the rewrite or is skipped (left in plaintext);
        // no_claim=interpolated values (left alone by design, see plan.rs)
        #[test]
        fn fuzz_dotenv_no_value_left((s, n) in env_with_tokens()) {
            let entries = parse(&s);
            prop_assert!(entries.is_ok(), "generated file must parse: {:?}\n{s:?}", entries.err());
            let entries = entries.unwrap();
            for i in 0..n {
                let needle = format!("TOK{i}x");
                let holders = entries
                    .iter()
                    .filter(|e| e.value().windows(needle.len()).any(|w| w == needle.as_bytes()))
                    .count();
                prop_assert_eq!(holders, 1, "token {} found in {} entries\n{:?}", i, holders, s);
            }
            let reps: Vec<_> = entries
                .iter()
                .filter(|e| !e.value().is_empty())
                .map(|e| (e, format!("ms://env/{}", e.name)))
                .collect();
            let out = rewrite(&s, &reps);
            for i in 0..n {
                let needle = format!("TOK{i}x");
                prop_assert!(!out.contains(&needle), "a value survived the rewrite:\n{:?}", out.as_str());
            }
        }
    }
}
