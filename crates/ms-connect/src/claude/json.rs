//! A small, strict, order-preserving JSON model for editing agent settings files (SPEC D9).
//!
//! `serde_json` sorts object keys unless its `preserve_order` feature is on, and that feature
//! would unify across the workspace. Settings files are edited in place, so key order, numbers as
//! written and the file's indent must survive. The parser is strict RFC 8259 plus two refusals:
//! a duplicate key anywhere (JSON.parse keeps the last one, a human reads the first) and a string
//! escape that is a lone surrogate (it can't be represented, so it can't be written back).

use std::fmt::Write as _;

/// Deepest nesting accepted.
pub const MAX_DEPTH: usize = 128;

/// A JSON value. Objects keep their key order; numbers keep their exact text.
#[derive(Debug, Clone)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, exactly as written (already validated against the JSON grammar).
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, in key order. Keys are unique.
    Object(Vec<(String, Value)>),
}

impl PartialEq for Value {
    /// Structural equality; object key order does not matter.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.iter().any(|(k2, v2)| k == k2 && v == v2))
            }
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Value {
    /// A string value.
    pub fn str(s: impl Into<String>) -> Self {
        Value::String(s.into())
    }

    /// An empty object.
    pub fn object() -> Self {
        Value::Object(Vec::new())
    }

    /// A number from an integer.
    pub fn int(n: i64) -> Self {
        Value::Number(n.to_string())
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The member `key` of an object, mutable.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Object(m) => m.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Follows `path` through objects.
    pub fn at(&self, path: &[String]) -> Option<&Value> {
        path.iter().try_fold(self, |v, k| v.get(k))
    }

    /// Follows `path` through objects, mutable.
    pub fn at_mut(&mut self, path: &[String]) -> Option<&mut Value> {
        path.iter().try_fold(self, |v, k| v.get_mut(k))
    }

    /// Sets `key` on an object: replaces in place (keeping its position) or appends. Returns the
    /// previous value. No-op returning `None` on a non-object.
    pub fn set(&mut self, key: &str, value: Value) -> Option<Value> {
        let Value::Object(m) = self else {
            return None;
        };
        if let Some((_, v)) = m.iter_mut().find(|(k, _)| k == key) {
            return Some(std::mem::replace(v, value));
        }
        m.push((key.to_owned(), value));
        None
    }

    /// Removes `key` from an object, returning it.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let Value::Object(m) = self else {
            return None;
        };
        let i = m.iter().position(|(k, _)| k == key)?;
        Some(m.remove(i).1)
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// True for an empty object or array.
    pub fn is_empty_container(&self) -> bool {
        match self {
            Value::Object(m) => m.is_empty(),
            Value::Array(a) => a.is_empty(),
            _ => false,
        }
    }

    /// Short type name for messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "a boolean",
            Value::Number(_) => "a number",
            Value::String(_) => "a string",
            Value::Array(_) => "a list",
            Value::Object(_) => "an object",
        }
    }
}

/// A parse error with a 1-based line and column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Line.
    pub line: usize,
    /// Column (characters).
    pub col: usize,
    /// What is wrong.
    pub msg: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}, column {}: {}", self.line, self.col, self.msg)
    }
}

/// Parses a whole document.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        text,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("unexpected text after the JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    text: &'a str,
}

impl Parser<'_> {
    fn err(&self, msg: impl Into<String>) -> ParseError {
        // `i` can sit inside a multi-byte character (an error in the middle of one).
        let mut end = self.i.min(self.text.len());
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        let upto = &self.text[..end];
        let line = upto.matches('\n').count() + 1;
        let col = upto.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        ParseError {
            line,
            col,
            msg: msg.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, ParseError> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err(format!("nested deeper than {MAX_DEPTH} levels")));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of file")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(0xEF) if self.i == 0 => Err(self.err(
                "the file starts with a byte-order mark, which JSON does not allow; remove it",
            )),
            Some(_) => Err(self.err("expected a JSON value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut m: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a key in double quotes"));
            }
            let at = self.i;
            let k = self.string()?;
            if m.iter().any(|(e, _)| *e == k) {
                self.i = at;
                return Err(self.err(format!(
                    "the key \"{}\" appears twice in the same object; remove one so the file means one thing",
                    k.escape_default()
                )));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            m.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                _ => return Err(self.err("expected ',' or '}' (trailing commas are not allowed)")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(a));
        }
        loop {
            self.ws();
            a.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                _ => return Err(self.err("expected ',' or ']' (trailing commas are not allowed)")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while let Some(b'0'..=b'9') = self.peek() {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid number"));
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.i += 1;
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.i += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("invalid number"));
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.i += 1;
            }
        }
        Ok(Value::Number(self.text[start..self.i].to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .and_then(|b| std::str::from_utf8(b).ok())
            .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| self.err("invalid \\u escape"))?;
        self.i += 4;
        Ok(h)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // Input is a &str and we stop only at ASCII bytes, so this is a char boundary.
            out.push_str(&self.text[start..self.i]);
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err("unterminated string"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.s[self.i..].starts_with(b"\\u") {
                                    return Err(self.err("lone surrogate in a \\u escape"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("lone surrogate in a \\u escape"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("lone surrogate in a \\u escape"));
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(cp).ok_or_else(|| self.err("invalid \\u escape"))?,
                            );
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                Some(_) => return Err(self.err("control character inside a string")),
            }
        }
    }
}

/// The indent a file uses: a tab, or 1 to 8 spaces (2 when unknown).
pub fn detect_indent(text: &str) -> String {
    for line in text.lines().skip(1) {
        if line.starts_with('\t') {
            return "\t".into();
        }
        let n = line.len() - line.trim_start_matches(' ').len();
        if n > 0 && line.len() > n {
            return " ".repeat(n.min(8));
        }
    }
    "  ".into()
}

/// Prints like `JSON.stringify(v, null, indent)`.
pub fn print(v: &Value, indent: &str) -> String {
    let mut out = String::new();
    write_value(&mut out, v, indent, 0);
    out
}

/// Prints a document: like [`print`], with a trailing newline when `newline`.
pub fn print_doc(v: &Value, indent: &str, newline: bool) -> String {
    let mut s = print(v, indent);
    if newline {
        s.push('\n');
    }
    s
}

fn write_value(out: &mut String, v: &Value, ind: &str, level: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => write_string(out, s),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(m) if m.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, ind, level + 1);
                write_value(out, e, ind, level + 1);
            }
            newline(out, ind, level);
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, ind, level + 1);
                write_string(out, k);
                out.push_str(": ");
                write_value(out, e, ind, level + 1);
            }
            newline(out, ind, level);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, ind: &str, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str(ind);
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=a settings file written the way Claude Code writes it (JSON.stringify, 2 spaces)
    // prints back byte for byte, so editing one key doesn't reformat the rest; fails_when=key
    // order, number text, escapes or unicode change; no_claim=hand-formatted files (re-printed)
    #[test]
    fn round_trips_stringify_output() {
        let text = "{\n  \"z\": 1,\n  \"a\": [\n    1.50,\n    -0,\n    1e400,\n    12345678901234567890\n  ],\n  \"s\": \"é \\\"q\\\" \\\\ \\n \\u0001 😀 / \\t\",\n  \"e\": {},\n  \"l\": [],\n  \"n\": null,\n  \"b\": false\n}";
        let v = parse(text).unwrap();
        assert_eq!(print(&v, "  "), text);
    }

    // protects=SPEC D8: a duplicate key anywhere is refused (JSON.parse keeps the last one, a
    // reviewer reads the first); fails_when=a duplicate parses; no_claim=duplicates across files
    #[test]
    fn refuses_duplicate_keys() {
        let e = parse(r#"{"a": {"x": 1, "x": 2}}"#).unwrap_err();
        assert!(e.msg.contains("appears twice"), "{e}");
    }

    // protects=strict grammar: trailing commas, comments, BOM, lone surrogates, control chars,
    // bad numbers and over-deep nesting are refused; fails_when=any of them parses
    #[test]
    fn refuses_non_json() {
        for bad in [
            "{\"a\": 1,}",
            "[1,]",
            "// c\n{}",
            "\u{feff}{}",
            r#"{"a": "\ud800"}"#,
            r#"{"a": "\udc00x"}"#,
            "{\"a\": \"x\ny\"}",
            "{\"a\": 01}",
            "{\"a\": 1.}",
            "{\"a\": .5}",
            "{\"a\": tru}",
            "{} {}",
            "",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} parsed");
        }
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn surrogate_pair_decodes() {
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap(), Value::str("😀"));
    }

    #[test]
    fn indent_detection() {
        assert_eq!(detect_indent("{\n    \"a\": 1\n}"), "    ");
        assert_eq!(detect_indent("{\n\t\"a\": 1\n}"), "\t");
        assert_eq!(detect_indent("{\"a\":1}"), "  ");
        assert_eq!(detect_indent("{\n\n  \"a\": 1\n}"), "  ");
    }

    #[test]
    fn object_equality_ignores_order() {
        assert_eq!(
            parse(r#"{"a":1,"b":[1,2]}"#).unwrap(),
            parse(r#"{"b":[1,2],"a":1}"#).unwrap()
        );
        assert_ne!(
            parse(r#"{"b":[2,1]}"#).unwrap(),
            parse(r#"{"b":[1,2]}"#).unwrap()
        );
    }

    mod prop {
        use super::super::*;
        use proptest::prelude::*;

        fn arb_value() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<i64>().prop_map(Value::int),
                any::<String>().prop_map(Value::String),
            ];
            leaf.prop_recursive(4, 32, 6, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                    prop::collection::btree_map(any::<String>(), inner, 0..5)
                        .prop_map(|m| Value::Object(m.into_iter().collect())),
                ]
            })
        }

        proptest! {
            // protects=print/parse are inverse for every value, any indent; fails_when=a string
            // escape, key or nesting round-trips differently; no_claim=byte-identity of input text
            #[test]
            fn print_parse_roundtrip(v in arb_value(), ind in prop_oneof![Just("  "), Just("    "), Just("\t")]) {
                let text = print(&v, ind);
                let back = parse(&text).unwrap();
                prop_assert_eq!(&back, &v);
                prop_assert_eq!(print(&back, ind), text);
            }

            // protects=the parser never panics on arbitrary input; fails_when=it panics
            #[test]
            fn parse_never_panics(s in any::<String>()) {
                let _ = parse(&s);
            }
        }
    }
}
