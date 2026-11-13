//! Key names and `ms://` references.

use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// Longest key name, in bytes, including `/` separators.
pub const MAX_KEY_NAME_LEN: usize = 255;
/// Most `/`-separated segments in a key name.
pub const MAX_SEGMENTS: usize = 8;
/// Longest single segment, in bytes.
pub const MAX_SEGMENT_LEN: usize = 63;

const SCHEME: &str = "ms://";

/// A validated key name such as `stripe/test` or `pg/production`.
///
/// Grammar: 1 to [`MAX_SEGMENTS`] segments joined by `/`; each segment matches
/// `[a-z0-9][a-z0-9-]{0,62}`; at most [`MAX_KEY_NAME_LEN`] bytes in total.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyName(String);

impl KeyName {
    /// Validates `s` as a key name.
    pub fn new(s: &str) -> Result<Self> {
        validate_key_name(s).map_err(|why| Error::InvalidKeyName {
            name: printable(s),
            why,
        })?;
        Ok(Self(s.to_owned()))
    }

    /// The name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_key_name(s: &str) -> std::result::Result<(), &'static str> {
    if s.is_empty() {
        return Err("it is empty");
    }
    if s.len() > MAX_KEY_NAME_LEN {
        return Err("it is longer than 255 bytes");
    }
    let mut segments = 0;
    for seg in s.split('/') {
        segments += 1;
        if segments > MAX_SEGMENTS {
            return Err("it has more than 8 segments");
        }
        if seg.is_empty() {
            return Err("it has an empty segment (leading, trailing or double '/')");
        }
        if seg.len() > MAX_SEGMENT_LEN {
            return Err("a segment is longer than 63 bytes");
        }
        let bytes = seg.as_bytes();
        if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
            return Err("a segment must start with a-z or 0-9");
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err("only a-z, 0-9, '-' and '/' are allowed");
        }
    }
    Ok(())
}

/// Truncates and escapes user input before it goes into an error message.
fn printable(s: &str) -> String {
    let mut out: String = s.chars().take(64).flat_map(char::escape_default).collect();
    if s.chars().count() > 64 {
        out.push('…');
    }
    out
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyName({:?})", self.0)
    }
}

impl TryFrom<&str> for KeyName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl Serialize for KeyName {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        KeyName::new(&s).map_err(serde::de::Error::custom)
    }
}

/// A reference to a vault key: `ms://<key name>`. This is what files and environments hold
/// instead of a secret value.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef {
    name: KeyName,
}

impl SecretRef {
    /// A reference to `name`.
    pub fn new(name: KeyName) -> Self {
        Self { name }
    }

    /// Parses exactly `ms://<key name>`. Other schemes, userinfo, ports, queries and fragments
    /// are rejected because the key-name grammar does not allow `@`, `:`, `?` or `#`.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s.strip_prefix(SCHEME).ok_or_else(|| Error::InvalidRef {
            reference: printable(s),
            why: "it must start with ms://",
        })?;
        let name = KeyName::new(rest).map_err(|_| Error::InvalidRef {
            reference: printable(s),
            why: "the key name after ms:// is not valid",
        })?;
        Ok(Self { name })
    }

    /// The referenced key.
    pub fn name(&self) -> &KeyName {
        &self.name
    }

    /// Finds every valid reference embedded in `haystack`, for example the one in
    /// `postgres://u@h/db?password=ms://pg/staging`.
    ///
    /// A match must not be glued to a preceding scheme character (so `xms://a` is not a match)
    /// or followed by a character the grammar does not allow inside a name (so `ms://abcDEF` is
    /// not a match). Trailing `/` is not part of the name. Candidates that fail validation are
    /// skipped, never partially matched.
    pub fn find_all(haystack: &str) -> Vec<(Range<usize>, SecretRef)> {
        let bytes = haystack.as_bytes();
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(pos) = haystack[from..].find(SCHEME) {
            let start = from + pos;
            from = start + SCHEME.len();
            if start > 0 && is_scheme_char(bytes[start - 1]) {
                continue;
            }
            let name_start = start + SCHEME.len();
            let mut end = name_start;
            while end < bytes.len()
                && (bytes[end].is_ascii_lowercase()
                    || bytes[end].is_ascii_digit()
                    || bytes[end] == b'-'
                    || bytes[end] == b'/')
            {
                end += 1;
            }
            if end < bytes.len() && is_glued_char(bytes[end]) {
                continue;
            }
            let mut name_end = end;
            while name_end > name_start && bytes[name_end - 1] == b'/' {
                name_end -= 1;
            }
            if let Ok(name) = KeyName::new(&haystack[name_start..name_end]) {
                out.push((start..name_end, SecretRef { name }));
                from = name_end;
            }
        }
        out
    }
}

fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-'
}

/// A character that, right after a candidate name, means the candidate is not a whole reference.
/// Includes `@ : ? #` so `find_all` agrees with `parse`, which rejects userinfo, ports, queries
/// and fragments: `ms://user@host` is no reference at all, never `ms://user` plus a tail.
fn is_glued_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(b, b'_' | b'.' | b'@' | b':' | b'?' | b'#')
        || !b.is_ascii()
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.name)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({SCHEME}{})", self.name)
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SecretRef::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // protects=valid names are accepted unchanged; fails_when=a documented valid form is rejected;
    // no_claim=says nothing about names outside this table (see the proptest below)
    #[test]
    fn valid_key_names() {
        for s in [
            "a",
            "stripe/test",
            "pg/production",
            "aws/dev",
            "0",
            "a-b/c-d/e",
            "a/b/c/d/e/f/g/h",
            &"x".repeat(63),
        ] {
            assert_eq!(KeyName::new(s).unwrap().as_str(), s, "{s}");
        }
    }

    // protects=the grammar rejects every listed malformed name; fails_when=any of them is accepted;
    // no_claim=does not enumerate every possible invalid string
    #[test]
    fn invalid_key_names() {
        let long_total = format!(
            "{}/{}/{}/{}/b",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63)
        );
        assert_eq!(long_total.len(), 257);
        let cases: Vec<String> = vec![
            "".into(),
            "Stripe".into(),
            "stripe/Test".into(),
            "..".into(),
            "a/../b".into(),
            ".".into(),
            "a//b".into(),
            "/a".into(),
            "a/".into(),
            "a b".into(),
            " a".into(),
            "a\n".into(),
            "ünicode".into(),
            "-a".into(),
            "a/-b".into(),
            "a_b".into(),
            "a.b".into(),
            "a?x=1".into(),
            "a#frag".into(),
            "user@host".into(),
            "host:5432".into(),
            "x".repeat(64),
            "a/b/c/d/e/f/g/h/i".into(),
            long_total,
        ];
        for s in cases {
            assert!(KeyName::new(&s).is_err(), "accepted invalid name {s:?}");
        }
    }

    // protects=SecretRef::parse accepts exactly ms://<name>; fails_when=another scheme, userinfo,
    // port, query, fragment or bad name is accepted; no_claim=embedded refs (see find_all tests)
    #[test]
    fn parse_refs() {
        let r = SecretRef::parse("ms://stripe/test").unwrap();
        assert_eq!(r.name().as_str(), "stripe/test");
        assert_eq!(r.to_string(), "ms://stripe/test");
        for bad in [
            "stripe/test",
            "MS://stripe/test",
            "ms:/stripe",
            "wd://stripe/test",
            "ms://",
            "ms://user@stripe",
            "ms://stripe:443",
            "ms://stripe/test?x=1",
            "ms://stripe/test#f",
            "ms://stripe/test/",
            " ms://stripe",
            "ms://Stripe",
        ] {
            assert!(SecretRef::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    // protects=refs inside URLs, env values and argv are found with exact byte ranges;
    // fails_when=a ref is missed, mis-bounded, or a glued/invalid candidate is matched;
    // no_claim=does not decide what the shim or proxy does with a match
    #[test]
    fn find_all_embedded() {
        let s = "postgres://u@h/db?password=ms://pg/staging&x=1";
        let found = SecretRef::find_all(s);
        assert_eq!(found.len(), 1);
        assert_eq!(&s[found[0].0.clone()], "ms://pg/staging");

        let s = "Authorization: Bearer ms://stripe/test";
        assert_eq!(SecretRef::find_all(s)[0].1.name().as_str(), "stripe/test");

        let s = "a=ms://a b=ms://b/c/";
        let found: Vec<_> = SecretRef::find_all(s)
            .into_iter()
            .map(|(_, r)| r.to_string())
            .collect();
        assert_eq!(found, ["ms://a", "ms://b/c"]);

        for none in [
            "xms://a",
            "cms://a",
            "ms://abcDEF",
            "ms://a_b",
            "ms://a.b",
            "ms://",
            "ms://-a",
            "ms://ü",
            // Forms parse() rejects must not be half-matched either.
            "ms://user@stripe",
            "ms://stripe:443",
            "ms://stripe/test?x=1",
            "ms://stripe/test#f",
            "postgres://u:ms://pg/x@h/db",
        ] {
            assert!(SecretRef::find_all(none).is_empty(), "matched in {none:?}");
        }
    }

    // protects=the 255-byte limit is exact; fails_when=a 255-byte name is rejected or a 256-byte
    // name accepted (an off-by-one in the length check); no_claim=other limits (see the tables)
    #[test]
    fn length_limit_is_exact() {
        let seg = "a".repeat(63);
        let max = [seg.as_str(); 4].join("/");
        assert_eq!(max.len(), 255);
        assert_eq!(KeyName::new(&max).unwrap().as_str(), max);
        let over = format!("{seg}/{seg}/{seg}/{}/b", "a".repeat(62));
        assert_eq!(over.len(), 256);
        assert!(KeyName::new(&over).is_err());
    }

    // protects=serde never yields an invalid KeyName/SecretRef; fails_when=invalid JSON input
    // deserializes; no_claim=other serde formats
    #[test]
    fn serde_validates() {
        let k: KeyName = serde_json::from_str("\"pg/staging\"").unwrap();
        assert_eq!(k.as_str(), "pg/staging");
        assert!(serde_json::from_str::<KeyName>("\"PG\"").is_err());
        let r: SecretRef = serde_json::from_str("\"ms://pg/staging\"").unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"ms://pg/staging\"");
        assert!(serde_json::from_str::<SecretRef>("\"wd://pg\"").is_err());
    }

    // protects=error text can't smuggle control characters or huge input into logs;
    // fails_when=raw newline/escape bytes or >64 chars appear; no_claim=other error variants
    #[test]
    fn error_text_is_escaped_and_bounded() {
        let msg = KeyName::new(&format!("bad\n\u{1b}[31m{}", "x".repeat(200)))
            .unwrap_err()
            .to_string();
        assert!(!msg.contains('\n') && !msg.contains('\u{1b}'), "{msg}");
        assert!(msg.len() < 400, "{}", msg.len());
    }

    fn segment() -> impl Strategy<Value = String> {
        "[a-z0-9][a-z0-9-]{0,20}"
    }

    proptest! {
        // protects=every grammar-valid name round-trips through KeyName, SecretRef, Display and
        // find_all; fails_when=any valid name is rejected or changed; no_claim=names longer than
        // the generator's bounds (covered by the table tests)
        #[test]
        fn roundtrip(segs in prop::collection::vec(segment(), 1..=8)) {
            let s = segs.join("/");
            let k = KeyName::new(&s).unwrap();
            prop_assert_eq!(k.as_str(), s.as_str());
            let r = SecretRef::new(k.clone());
            let text = r.to_string();
            prop_assert_eq!(SecretRef::parse(&text).unwrap(), r.clone());
            let embedded = format!("x={text}&y=1");
            let found = SecretRef::find_all(&embedded);
            prop_assert_eq!(found.len(), 1);
            prop_assert_eq!(&found[0].1, &r);
        }

        // protects=adding any disallowed character makes the name invalid; fails_when=such a
        // name is accepted; no_claim=multi-character corruptions
        #[test]
        fn one_bad_char_rejects(seg in segment(), bad in "[A-Z_.:@?# \t\n]") {
            let s = format!("{seg}{bad}x");
            prop_assert!(KeyName::new(&s).is_err());
        }
    }
}
