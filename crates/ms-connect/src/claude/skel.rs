//! A value-free record of a settings file's exact bytes (security review S1).
//!
//! `ms disconnect` restores `settings.json` byte for byte. Keeping the original text in the
//! state file would also keep every value in it, such as a plaintext token the user later moves
//! into morsec and deletes from settings, readable by any same-user process. Instead the state
//! keeps a skeleton: the text with every string *value* blanked to `""` (keys, numbers,
//! whitespace and layout kept), plus the SHA-256 of the original. On restore the values are
//! filled back in, in document order, from the settings document with morsec's changes undone,
//! and the result counts as the original only when its hash matches.
//!
//! A value written with escapes `JSON.stringify` would not use (for example `é` for `é`)
//! can't be rebuilt from its decoded text, so its literal is kept; that is the only text of a
//! value the skeleton holds. Such files are rare (editors and Claude Code write canonical
//! escapes).

use sha2::{Digest, Sha256};

use super::json::{self, Value};

/// The skeleton of a settings file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    /// The text with every string value replaced by `""`.
    pub text: String,
    /// (value index, literal) for values whose literal is not the canonical escaping.
    pub literals: Vec<(usize, String)>,
    /// SHA-256 of the original text, hex.
    pub sha256: String,
}

/// SHA-256 of `text`, hex.
pub fn sha256(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Byte ranges of the string literals in `text` that are values (not keys), in order. `text`
/// must be valid JSON.
fn value_literals(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < b.len() && b[i] != b'"' {
            i += if b[i] == b'\\' { 2 } else { 1 };
        }
        let end = (i + 1).min(b.len());
        i = end;
        let rest = text[end..].trim_start_matches([' ', '\t', '\n', '\r']);
        if !rest.starts_with(':') {
            out.push((start, end));
        }
    }
    out
}

/// The string values of `v`, in document order.
fn string_values(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|e| string_values(e, out)),
        Value::Object(m) => m.iter().for_each(|(_, e)| string_values(e, out)),
        _ => {}
    }
}

fn canonical(s: &str) -> String {
    json::print(&Value::String(s.to_owned()), "")
}

/// The skeleton of `text`, which must parse.
pub fn skeletonize(text: &str) -> Skeleton {
    let mut out = String::with_capacity(text.len());
    let mut literals = Vec::new();
    let mut last = 0;
    for (n, (s, e)) in value_literals(text).into_iter().enumerate() {
        let lit = &text[s..e];
        let decoded = json::parse(lit)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        if decoded.as_deref().map(canonical).as_deref() != Some(lit) {
            literals.push((n, lit.to_owned()));
        }
        out.push_str(&text[last..s]);
        out.push_str("\"\"");
        last = e;
    }
    out.push_str(&text[last..]);
    Skeleton {
        text: out,
        literals,
        sha256: sha256(text),
    }
}

/// Rebuilds the original text from its skeleton and `doc` (the same document with morsec's
/// changes undone). `None` when the result is not byte-identical to the original.
pub fn rebuild(sk: &Skeleton, doc: &Value) -> Option<String> {
    let mut values = Vec::new();
    string_values(doc, &mut values);
    let slots = value_literals(&sk.text);
    if slots.len() != values.len() {
        return None;
    }
    let mut out = String::with_capacity(sk.text.len() * 2);
    let mut last = 0;
    for (n, ((s, e), v)) in slots.into_iter().zip(values).enumerate() {
        out.push_str(&sk.text[last..s]);
        match sk.literals.iter().find(|(i, _)| *i == n) {
            Some((_, lit)) => out.push_str(lit),
            None => out.push_str(&canonical(&v)),
        }
        last = e;
    }
    out.push_str(&sk.text[last..]);
    (sha256(&out) == sk.sha256).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=S1: the skeleton holds no canonical string value (a token in env is gone) yet
    // rebuilds the exact bytes, odd layouts included; a different document fails the hash;
    // fails_when=a value survives in the skeleton or a rebuild is accepted that isn't exact
    #[test]
    fn skeleton_has_no_values_and_rebuilds_exactly() {
        for text in [
            "{\n  \"env\": {\n    \"GITHUB_TOKEN\": \"ghp_CANARYsecret\",\n    \"N\": 1\n  },\n  \"l\": [\"a\", \"b:c\"]\n}\n",
            "{\"compact\":\"ghp_CANARYsecret\",\"x\":[\"\",\"q\\\"uote\"]}",
            "{\r\n\t\"crlf\" :  \"ghp_CANARYsecret\"\r\n}\r\n",
        ] {
            let sk = skeletonize(text);
            assert!(!sk.text.contains("CANARY"), "{}", sk.text);
            assert!(sk.literals.iter().all(|(_, l)| !l.contains("CANARY")));
            let doc = json::parse(text).unwrap();
            assert_eq!(rebuild(&sk, &doc).as_deref(), Some(text));
            let mut other = doc.clone();
            if let Value::Object(m) = &mut other {
                m.push(("extra".into(), Value::str("x")));
            }
            assert_eq!(rebuild(&sk, &other), None);
        }
        // A non-canonical escape keeps its literal so the bytes still come back.
        let t = "{\"x\": \"\\u00e9\\/\"}";
        let sk = skeletonize(t);
        assert_eq!(sk.literals.len(), 1);
        assert_eq!(rebuild(&sk, &json::parse(t).unwrap()).as_deref(), Some(t));
    }
}
