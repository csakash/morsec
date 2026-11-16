//! Entry points for the nightly cargo-fuzz harness `fuzz/fuzz_targets/proxy_head.rs` (L24 owns
//! `fuzz/`). Built only with the `fuzzing` feature or in tests; never part of `msd`.
//!
//! [`head`] reads a request head from raw bytes (the target, then `Name: value` lines, then a
//! blank line and the body), runs the swap planner and rewriter against three bindings (Bearer
//! header, Basic password, query parameter), and panics if a property breaks: the value only ever
//! lands in the bound location, and only when the agent put the placeholder there.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use ms_core::KeyName;

use crate::config::{BasicField, Binding, Location};
use crate::rewrite::{Plan, apply, placeholder_in_location, plan};

const HOST: &str = "api.example.com";
const SECRET: &[u8] = b"sk_FUZZ_CANARY_0b1c";

fn binding(key: &str, location: Location) -> Binding {
    Binding {
        key: KeyName::new(key).expect("valid key name"),
        provider: key.replace('/', "-"),
        hosts: vec![HOST.into()],
        port: 443,
        location,
        shaped_placeholder: None,
    }
}

fn bindings() -> [Binding; 3] {
    [
        binding(
            "fz/bearer",
            Location::Header {
                name: "authorization".into(),
                prefix: "Bearer ".into(),
            },
        ),
        binding(
            "fz/basic",
            Location::Basic {
                field: BasicField::Password,
            },
        ),
        binding(
            "fz/query",
            Location::Query {
                param: "key".into(),
            },
        ),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Runs one fuzz input. Inputs that are not a request head are ignored.
///
/// # Panics
/// When a swap property breaks (that is the finding).
pub fn head(data: &[u8]) {
    let Some(split) = data.windows(2).position(|w| w == b"\n\n") else {
        return;
    };
    let (head, body) = (&data[..split], &data[split + 2..]);
    let mut lines = head.split(|&b| b == b'\n');
    let Some(target) = lines.next() else { return };
    let mut req = http::Request::builder();
    match std::str::from_utf8(target)
        .ok()
        .and_then(|t| t.parse::<http::Uri>().ok())
    {
        Some(u) => req = req.uri(u),
        None => return,
    }
    for l in lines {
        let Some(c) = l.iter().position(|&b| b == b':') else {
            continue;
        };
        let (Ok(k), Ok(v)) = (
            HeaderName::from_bytes(&l[..c]),
            HeaderValue::from_bytes(l[c + 1..].trim_ascii()),
        ) else {
            continue;
        };
        req = req.header(k, v);
    }
    let Ok(req) = req.body(()) else { return };
    let (mut parts, ()) = req.into_parts();
    let all = bindings();
    let Plan::Forward(Some(b)) = plan(HOST, 443, &parts, body, &all) else {
        return;
    };
    // A swap only ever follows the binding's own placeholder in the binding's own location.
    assert!(
        placeholder_in_location(&parts, b),
        "swap planned without the placeholder in its location"
    );
    let local: Vec<&Binding> = all.iter().collect();
    if apply(&mut parts, b, &local, SECRET).is_err() {
        return;
    }
    let uri = parts.uri.to_string();
    for (k, v) in &parts.headers {
        let raw = v.as_bytes();
        match &b.location {
            Location::Header { .. } if contains(raw, SECRET) => {
                assert_eq!(k, AUTHORIZATION, "value in {k}");
                assert_eq!(raw, [b"Bearer ".as_slice(), SECRET].concat());
            }
            Location::Basic { .. } => {
                assert!(!contains(raw, SECRET), "raw Basic value in {k}");
                if k == AUTHORIZATION
                    && let Some(enc) = raw.strip_prefix(b"Basic ")
                    && let Ok(pair) = B64.decode(enc)
                {
                    assert!(pair.ends_with(&[b":".as_slice(), SECRET].concat()));
                }
            }
            _ => assert!(!contains(raw, SECRET), "value in {k}"),
        }
    }
    match &b.location {
        Location::Query { .. } => assert!(uri.contains(std::str::from_utf8(SECRET).unwrap())),
        _ => assert!(!contains(uri.as_bytes(), SECRET), "value in the target"),
    }
    let auths = parts.headers.get_all(AUTHORIZATION).iter().count();
    assert!(auths <= 1, "{auths} Authorization headers after the swap");
}

#[cfg(test)]
mod tests {
    // protects=the cargo-fuzz entry point holds its own properties on every committed proxy seed
    // and on hand-written swaps for all three locations, so the nightly harness starts green;
    // fails_when=head() panics on a seed or a legitimate swap; no_claim=fuzzing itself (nightly)
    #[test]
    fn head_entry_point_on_seeds() {
        for name in ["proxy-heads", "proxy-tunnel"] {
            for seed in ms_fuzz::seeds(name) {
                super::head(&seed.replace_crlf());
            }
        }
        super::head(b"/v1\nauthorization: Bearer ms://fz/bearer\nx-api-key: a\n\nbody");
        super::head(b"/v1\nauthorization: Basic dTptczovL2Z6L2Jhc2lj\n\n");
        super::head(b"/v1?key=ms://fz/query&k=2\ncookie: c\n\n");
        super::head(b"/v1?key=ms%3A%2F%2Ffz%2Fquery\n\n");
    }

    trait Crlf {
        fn replace_crlf(&self) -> Vec<u8>;
    }
    impl Crlf for Vec<u8> {
        /// The seeds are HTTP (`\r\n`); `head` reads `\n` lines without the request line's method.
        fn replace_crlf(&self) -> Vec<u8> {
            let s = String::from_utf8_lossy(self).replace("\r\n", "\n");
            let s = s
                .split_once(' ')
                .map_or(s.clone(), |(_, rest)| rest.to_owned());
            s.replacen(" HTTP/1.1", "", 1).into_bytes()
        }
    }
}
