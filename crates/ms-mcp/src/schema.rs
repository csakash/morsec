//! A JSON Schema validator for the keyword subset the catalog emits (draft 2020-12 semantics).
//!
//! Supported: `type` (object, string, array, integer, boolean), `properties`, `required`,
//! `additionalProperties: false`, `minLength`, `maxLength` (Unicode scalar values), `pattern`
//! (unanchored search), `not`, `items`, `maxItems`, and the annotations `$schema`, `title`,
//! `description`. Any other keyword makes validation fail: a schema this validator can't fully
//! enforce never passes an instance (fail closed).

use regex::Regex;
use serde_json::Value;

/// Prefix of errors in the schema itself (as opposed to the instance).
const INTERNAL: &str = "internal:";

/// Validates `instance` against `schema`. The error names the failing location.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    check(schema, instance, "arguments")
}

fn check(schema: &Value, v: &Value, at: &str) -> Result<(), String> {
    let Some(s) = schema.as_object() else {
        return Err(format!("internal: the schema at {at} is not an object"));
    };
    for k in s.keys() {
        let known = matches!(
            k.as_str(),
            "$schema"
                | "title"
                | "description"
                | "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "minLength"
                | "maxLength"
                | "pattern"
                | "not"
                | "items"
                | "maxItems"
        );
        if !known {
            return Err(format!(
                "internal: the schema at {at} uses {k:?}, which this validator does not enforce"
            ));
        }
    }
    if let Some(t) = s.get("type") {
        let t = t
            .as_str()
            .ok_or_else(|| format!("internal: the schema at {at} has a non-string type"))?;
        let ok = match t {
            "object" => v.is_object(),
            "string" => v.is_string(),
            "array" => v.is_array(),
            "integer" => v.is_i64() || v.is_u64(),
            "boolean" => v.is_boolean(),
            other => return Err(format!("internal: unsupported type {other:?} at {at}")),
        };
        if !ok {
            return Err(format!("{at} must be of type {t}"));
        }
    }
    if let Some(n) = s.get("not") {
        match check(n, v, at) {
            Ok(()) => {
                return Err(match n.get("pattern").and_then(Value::as_str) {
                    Some(p) if p.contains("://") => {
                        format!("{at} must not contain an ms:// reference")
                    }
                    _ => format!("{at} has a value that is not allowed"),
                });
            }
            // A broken inner schema must not turn into "passes" (fail closed).
            Err(e) if e.starts_with(INTERNAL) => return Err(e),
            Err(_) => {}
        }
    }
    if let Some(text) = v.as_str() {
        let len = text.chars().count() as u64;
        if let Some(max) = s.get("maxLength") {
            let max = uint(max, at)?;
            if len > max {
                return Err(format!("{at} is longer than {max} characters"));
            }
        }
        if let Some(min) = s.get("minLength") {
            let min = uint(min, at)?;
            if len < min {
                return Err(format!("{at} is shorter than {min} characters"));
            }
        }
        if let Some(p) = s.get("pattern") {
            let p = p
                .as_str()
                .ok_or_else(|| format!("internal: non-string pattern at {at}"))?;
            let re = Regex::new(p).map_err(|e| format!("internal: bad pattern at {at}: {e}"))?;
            if !re.is_match(text) {
                return Err(format!("{at} contains a character that is not allowed"));
            }
        }
    }
    if let Some(items) = v.as_array() {
        if let Some(max) = s.get("maxItems") {
            let max = uint(max, at)?;
            if items.len() as u64 > max {
                return Err(format!("{at} has more than {max} items"));
            }
        }
        if let Some(is) = s.get("items") {
            for (i, item) in items.iter().enumerate() {
                check(is, item, &format!("{at}[{i}]"))?;
            }
        }
    }
    if let Some(obj) = v.as_object() {
        let props = match s.get("properties") {
            None => None,
            Some(Value::Object(p)) => Some(p),
            Some(_) => return Err(format!("internal: properties at {at} is not an object")),
        };
        if let Some(req) = s.get("required") {
            let req = req
                .as_array()
                .ok_or_else(|| format!("internal: required at {at} is not an array"))?;
            for r in req {
                let r = r
                    .as_str()
                    .ok_or_else(|| format!("internal: required at {at} holds a non-string"))?;
                if !obj.contains_key(r) {
                    return Err(format!("{at} is missing the required argument {r:?}"));
                }
            }
        }
        match s.get("additionalProperties") {
            None => {}
            Some(Value::Bool(false)) => {
                for k in obj.keys() {
                    if !props.is_some_and(|p| p.contains_key(k)) {
                        return Err(format!(
                            "{at} has an argument this tool does not take: {}",
                            crate::result::inert(&clip(k, 64))
                        ));
                    }
                }
            }
            Some(_) => {
                return Err(format!(
                    "internal: only additionalProperties: false is supported (at {at})"
                ));
            }
        }
        if let Some(p) = props {
            for (k, sub) in p {
                if let Some(x) = obj.get(k) {
                    check(sub, x, &format!("{at}.{k}"))?;
                }
            }
        }
    }
    Ok(())
}

fn uint(v: &Value, at: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("internal: a length or count at {at} is not a whole number"))
}

fn clip(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["arg1"],
            "properties": {
                "arg1": {"type": "string", "maxLength": 5, "pattern": "^[^\\u0000]*$",
                         "not": {"pattern": "[mM][sS]://"}},
                "rest": {"type": "array", "maxItems": 2, "items": {"type": "string", "maxLength": 3}}
            }
        })
    }

    // protects=OUT-1: every keyword the catalog emits is enforced; fails_when=a violating instance
    // passes; no_claim=keywords the catalog does not emit (refused, next test)
    #[test]
    fn enforces_the_subset() {
        let s = schema();
        assert!(validate(&s, &json!({"arg1": "abc"})).is_ok());
        assert!(validate(&s, &json!({"arg1": "abc", "rest": ["x", "yz"]})).is_ok());
        assert!(
            validate(&s, &json!({"arg1": "ééééé"})).is_ok(),
            "length is in chars"
        );
        for bad in [
            json!({}),
            json!([]),
            json!("arg1"),
            json!({"arg1": 1}),
            json!({"arg1": null}),
            json!({"arg1": "abcdef"}),
            json!({"arg1": "a\u{0}b"}),
            json!({"arg1": "ms://x"}),
            json!({"arg1": "MS://x"}),
            json!({"arg1": "a", "key": "other"}),
            json!({"arg1": "a", "session": "s"}),
            json!({"arg1": "a", "rest": "x"}),
            json!({"arg1": "a", "rest": ["a", "b", "c"]}),
            json!({"arg1": "a", "rest": ["abcd"]}),
            json!({"arg1": "a", "rest": [1]}),
        ] {
            assert!(validate(&s, &bad).is_err(), "accepted {bad}");
        }
    }

    // protects=fail closed: a schema keyword the validator doesn't know never lets anything
    // through; fails_when=an unknown keyword is ignored; no_claim=-
    #[test]
    fn unknown_keywords_fail_closed() {
        for s in [
            json!({"type": "string", "format": "email"}),
            json!({"type": "object", "additionalProperties": true}),
            json!({"type": "number"}),
            json!({"oneOf": []}),
            json!(true),
            json!({"not": {"type": "string", "format": "x"}}),
            json!({"not": {"pattern": "("}}),
        ] {
            assert!(validate(&s, &json!("x")).is_err(), "{s}");
        }
    }
}
