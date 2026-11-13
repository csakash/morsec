//! The pure part of the swap: find placeholders, decide, and rewrite a request head. No I/O, so it
//! is unit-tested and fuzzed directly.

use std::borrow::Cow;
use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Uri};
use ms_core::{KeyName, SecretRef};
use zeroize::Zeroizing;

use crate::config::{BasicField, Binding, Location};

/// Credential headers removed from every request to a bound host. The binding's own header is
/// removed too and re-added with the value.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "cookie",
];

/// Hop-by-hop headers (RFC 9110 §7.6.1) plus the legacy ones. Never forwarded either way.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Percent-decodes `s`, lossily. Used to see placeholders hidden as `ms%3A%2F%2F…`.
pub(crate) fn pct_decode(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn pct_encode_into(out: &mut Vec<u8>, v: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &c in v {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c);
        } else {
            out.extend_from_slice(&[b'%', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
        }
    }
}

/// Every key referenced in `text`: `ms://` refs and shaped placeholders, raw and percent-decoded.
fn refs_in(text: &str, bindings: &[Binding], out: &mut BTreeSet<KeyName>) {
    refs_in_one(text, bindings, out);
    if let Cow::Owned(decoded) = pct_decode(text) {
        refs_in_one(&decoded, bindings, out);
    }
}

fn refs_in_one(t: &str, bindings: &[Binding], out: &mut BTreeSet<KeyName>) {
    for (_, r) in SecretRef::find_all(t) {
        out.insert(r.name().clone());
    }
    for b in bindings {
        if let Some(p) = &b.shaped_placeholder
            && t.contains(p.as_str())
        {
            out.insert(b.key.clone());
        }
    }
}

/// Every key referenced anywhere in the request: target, headers and body.
pub(crate) fn scan(parts: &Parts, body: &[u8], bindings: &[Binding]) -> BTreeSet<KeyName> {
    let mut out = BTreeSet::new();
    refs_in(&parts.uri.to_string(), bindings, &mut out);
    for (name, v) in &parts.headers {
        refs_in(name.as_str(), bindings, &mut out);
        refs_in(&String::from_utf8_lossy(v.as_bytes()), bindings, &mut out);
        if let Some(d) = basic_decoded(v) {
            // `user:password`: split on the separator colon (not the one in `ms://`) so a ref
            // in either half is a whole match for `find_all`.
            let halves = Zeroizing::new(
                d.replace("://", "\0")
                    .replace(':', " ")
                    .replace('\0', "://"),
            );
            refs_in(&halves, bindings, &mut out);
        }
    }
    if !body.is_empty() {
        refs_in(&String::from_utf8_lossy(body), bindings, &mut out);
    }
    out
}

/// What to do with a request to a bound host.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan<'a> {
    /// Refs to keys not bound to this host: refuse, and record one receipt per key.
    Block(Vec<KeyName>),
    /// Placeholders for two different keys of this host in their locations: refuse.
    Ambiguous,
    /// Forward with credentials stripped, swapping `Some` binding's value in.
    Forward(Option<&'a Binding>),
}

/// Decides a request to `host:port`. `bindings` is the full table.
pub(crate) fn plan<'a>(
    host: &str,
    port: u16,
    parts: &Parts,
    body: &[u8],
    bindings: &'a [Binding],
) -> Plan<'a> {
    let local: Vec<&Binding> = bindings.iter().filter(|b| b.serves(host, port)).collect();
    let foreign: Vec<KeyName> = scan(parts, body, bindings)
        .into_iter()
        .filter(|k| !local.iter().any(|b| &b.key == k))
        .collect();
    if !foreign.is_empty() {
        return Plan::Block(foreign);
    }
    let mut placed = local
        .into_iter()
        .filter(|b| placeholder_in_location(parts, b));
    match (placed.next(), placed.next()) {
        (Some(_), Some(_)) => Plan::Ambiguous,
        (one, None) => Plan::Forward(one),
        (None, Some(_)) => unreachable!("iterator yields in order"),
    }
}

fn header_matches(v: &HeaderValue, prefix: &str, b: &Binding) -> bool {
    let Ok(v) = v.to_str() else { return false };
    let v = v.trim();
    match v.get(..prefix.len()) {
        Some(p) if p.eq_ignore_ascii_case(prefix) => b.is_placeholder(&v[prefix.len()..]),
        _ => false,
    }
}

/// The decoded `user:password` of a Basic `Authorization` value.
fn basic_decoded(v: &HeaderValue) -> Option<Zeroizing<String>> {
    let v = v.to_str().ok()?.trim();
    let scheme = v.get(..6)?;
    if !scheme.eq_ignore_ascii_case("basic ") {
        return None;
    }
    let raw = B64.decode(v[6..].trim()).ok()?;
    String::from_utf8(raw).ok().map(Zeroizing::new)
}

/// If `v` is Basic credentials with `b`'s placeholder in `field`, the other half.
///
/// A user name can't contain `:` (RFC 7617) but an `ms://` placeholder does, so the user field is
/// matched as a prefix rather than by splitting on the first colon.
fn basic_match(v: &HeaderValue, b: &Binding, field: BasicField) -> Option<String> {
    let s = basic_decoded(v)?;
    match field {
        BasicField::User => [Some(b.reference()), b.shaped_placeholder.clone()]
            .into_iter()
            .flatten()
            .find_map(|p| {
                s.strip_prefix(p.as_str())?
                    .strip_prefix(':')
                    .map(str::to_owned)
            }),
        BasicField::Password => {
            let (u, p) = s.split_once(':')?;
            b.is_placeholder(p).then(|| u.to_owned())
        }
    }
}

fn query_pairs(uri: &Uri) -> Vec<(String, Option<String>)> {
    uri.query()
        .unwrap_or("")
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
            None => (kv.to_owned(), None),
        })
        .collect()
}

/// True when `b`'s placeholder sits exactly in `b`'s location.
pub(crate) fn placeholder_in_location(parts: &Parts, b: &Binding) -> bool {
    match &b.location {
        Location::Header { name, prefix } => parts
            .headers
            .get_all(name.as_str())
            .iter()
            .any(|v| header_matches(v, prefix, b)),
        Location::Basic { field } => parts
            .headers
            .get_all(AUTHORIZATION)
            .iter()
            .any(|v| basic_match(v, b, *field).is_some()),
        Location::Query { param } => query_pairs(&parts.uri).iter().any(|(k, v)| {
            pct_decode(k) == param.as_str()
                && v.as_deref()
                    .is_some_and(|v| b.is_placeholder(&pct_decode(v)))
        }),
    }
}

/// Removes hop-by-hop headers, every header the `Connection` header names, and `Proxy-*`.
pub(crate) fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
    let proxy: Vec<HeaderName> = h
        .keys()
        .filter(|k| k.as_str().starts_with("proxy-"))
        .cloned()
        .collect();
    for n in proxy {
        h.remove(n);
    }
}

/// Removes every credential the agent supplied for a bound host.
pub(crate) fn strip_credentials(h: &mut HeaderMap, bindings_for_host: &[&Binding]) {
    for n in CREDENTIAL_HEADERS {
        h.remove(*n);
    }
    for b in bindings_for_host {
        if let Location::Header { name, .. } = &b.location {
            h.remove(name.as_str());
        }
    }
}

/// The stored value can't go into the configured location (e.g. it contains a newline).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BadValue;

fn sensitive_value(bytes: Zeroizing<Vec<u8>>) -> Result<HeaderValue, BadValue> {
    // `from_owner` keeps the zeroizing buffer as the backing store, so our copy is wiped when the
    // header is dropped. hyper's own write buffer is outside our control (see SPEC residual risk).
    let mut v = HeaderValue::from_maybe_shared(Bytes::from_owner(bytes)).map_err(|_| BadValue)?;
    v.set_sensitive(true);
    Ok(v)
}

/// Rewrites `parts` for binding `b`: strips agent credentials for the host, then writes `secret`
/// into `b`'s location. Call only after [`plan`] returned `Forward(Some(b))`.
pub(crate) fn apply(
    parts: &mut Parts,
    b: &Binding,
    bindings_for_host: &[&Binding],
    secret: &[u8],
) -> Result<(), BadValue> {
    // Read what we need from the original before stripping.
    let basic_other = match &b.location {
        Location::Basic { field } => Some(
            parts
                .headers
                .get_all(AUTHORIZATION)
                .iter()
                .find_map(|v| basic_match(v, b, *field))
                .map(Zeroizing::new)
                .ok_or(BadValue)?,
        ),
        _ => None,
    };
    strip_credentials(&mut parts.headers, bindings_for_host);
    match &b.location {
        Location::Header { name, prefix } => {
            let mut v = Zeroizing::new(Vec::with_capacity(prefix.len() + secret.len()));
            v.extend_from_slice(prefix.as_bytes());
            v.extend_from_slice(secret);
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| BadValue)?;
            parts.headers.insert(name, sensitive_value(v)?);
        }
        Location::Basic { field } => {
            let other = basic_other.unwrap_or_default();
            let other = other.as_str();
            let mut pair = Zeroizing::new(Vec::with_capacity(secret.len() + other.len() + 1));
            match field {
                BasicField::User => {
                    pair.extend_from_slice(secret);
                    pair.push(b':');
                    pair.extend_from_slice(other.as_bytes());
                }
                BasicField::Password => {
                    pair.extend_from_slice(other.as_bytes());
                    pair.push(b':');
                    pair.extend_from_slice(secret);
                }
            }
            let enc = Zeroizing::new(B64.encode(&*pair));
            let mut v = Zeroizing::new(Vec::with_capacity(6 + enc.len()));
            v.extend_from_slice(b"Basic ");
            v.extend_from_slice(enc.as_bytes());
            parts.headers.insert(AUTHORIZATION, sensitive_value(v)?);
        }
        Location::Query { param } => {
            let mut q = Zeroizing::new(Vec::new());
            for (i, (k, v)) in query_pairs(&parts.uri).into_iter().enumerate() {
                if i > 0 {
                    q.push(b'&');
                }
                q.extend_from_slice(k.as_bytes());
                let swap = pct_decode(&k) == param.as_str()
                    && v.as_deref()
                        .is_some_and(|v| b.is_placeholder(&pct_decode(v)));
                match v {
                    Some(_) if swap => {
                        q.push(b'=');
                        pct_encode_into(&mut q, secret);
                    }
                    Some(v) => {
                        q.push(b'=');
                        q.extend_from_slice(v.as_bytes());
                    }
                    None => {}
                }
            }
            let mut pq = Zeroizing::new(Vec::new());
            pq.extend_from_slice(parts.uri.path().as_bytes());
            pq.push(b'?');
            pq.extend_from_slice(&q);
            let mut up = http::uri::Parts::default();
            up.path_and_query = Some(
                http::uri::PathAndQuery::from_maybe_shared(Bytes::from_owner(pq))
                    .map_err(|_| BadValue)?,
            );
            parts.uri = Uri::from_parts(up).map_err(|_| BadValue)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn binding(key: &str, host: &str, location: Location) -> Binding {
        Binding {
            key: KeyName::new(key).unwrap(),
            provider: key.replace('/', "-"),
            hosts: vec![host.into()],
            port: 443,
            location,
            shaped_placeholder: None,
        }
    }

    fn bearer() -> Location {
        Location::Header {
            name: "authorization".into(),
            prefix: "Bearer ".into(),
        }
    }

    fn parts(uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    const SECRET: &[u8] = b"sk_test_CANARY_7f3a9c";

    // protects=the bearer swap replaces the agent's Authorization and strips other credentials;
    // fails_when=the placeholder survives, a second Authorization appears, or X-Api-Key/Cookie
    // reach upstream; no_claim=transport (see itests)
    #[test]
    fn header_swap_strips_others() {
        let bs = vec![binding("stripe/test", "api.stripe.com", bearer())];
        let mut p = parts(
            "/v1/charges",
            &[
                ("authorization", "Bearer ms://stripe/test"),
                ("x-api-key", "agent-own"),
                ("cookie", "s=1"),
                ("accept", "*/*"),
            ],
        );
        let Plan::Forward(Some(b)) = plan("api.stripe.com", 443, &p, b"", &bs) else {
            panic!()
        };
        apply(&mut p, b, &[b], SECRET).unwrap();
        let auth: Vec<_> = p.headers.get_all("authorization").iter().collect();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].as_bytes(), b"Bearer sk_test_CANARY_7f3a9c");
        assert!(auth[0].is_sensitive());
        assert!(p.headers.get("x-api-key").is_none() && p.headers.get("cookie").is_none());
        assert_eq!(p.headers["accept"], "*/*");
    }

    // protects=Basic user and password positions and query params swap correctly, including a
    // percent-encoded placeholder; fails_when=the wrong half or param changes; no_claim=transport
    #[test]
    fn basic_and_query() {
        let bs = vec![binding(
            "stripe/test",
            "api.stripe.com",
            Location::Basic {
                field: BasicField::User,
            },
        )];
        let enc = B64.encode("ms://stripe/test:");
        let mut p = parts("/", &[("authorization", &format!("basic {enc}"))]);
        let decided = plan("api.stripe.com", 443, &p, b"", &bs);
        let Plan::Forward(Some(b)) = decided else {
            panic!("{decided:?}")
        };
        apply(&mut p, b, &[b], SECRET).unwrap();
        assert_eq!(
            p.headers["authorization"].as_bytes(),
            format!("Basic {}", B64.encode("sk_test_CANARY_7f3a9c:")).as_bytes()
        );

        let bs = vec![binding(
            "tw/test",
            "api.tw.example",
            Location::Basic {
                field: BasicField::Password,
            },
        )];
        let enc = B64.encode("AC123:ms://tw/test");
        let mut p = parts("/", &[("authorization", &format!("Basic {enc}"))]);
        let Plan::Forward(Some(b)) = plan("api.tw.example", 443, &p, b"", &bs) else {
            panic!()
        };
        apply(&mut p, b, &[b], b"pw&=x").unwrap();
        assert_eq!(
            p.headers["authorization"].as_bytes(),
            format!("Basic {}", B64.encode("AC123:pw&=x")).as_bytes()
        );

        let bs = vec![binding(
            "maps/test",
            "maps.example.com",
            Location::Query {
                param: "key".into(),
            },
        )];
        let mut p = parts(
            "/geo?q=a%20b&key=ms%3A%2F%2Fmaps%2Ftest&flag",
            &[("authorization", "Bearer agent")],
        );
        let Plan::Forward(Some(b)) = plan("maps.example.com", 443, &p, b"", &bs) else {
            panic!()
        };
        apply(&mut p, b, &[b], b"AIza/+=").unwrap();
        assert_eq!(p.uri.to_string(), "/geo?q=a%20b&key=AIza%2F%2B%3D&flag");
        assert!(p.headers.get("authorization").is_none());
    }

    // protects=a ref (or shaped placeholder) to a key not bound to the host blocks the request,
    // wherever it hides; fails_when=a foreign ref in path, header, body or encoded form passes;
    // no_claim=receipts (see itests)
    #[test]
    fn foreign_refs_block() {
        let mut aws = binding("aws/prod", "sts.amazonaws.com", bearer());
        aws.shaped_placeholder = Some("AKIA_MS_PLACEHOLDER1".into());
        let bs = vec![binding("stripe/test", "api.stripe.com", bearer()), aws];
        let aws_key = KeyName::new("aws/prod").unwrap();
        let cases = [
            (parts("/x?u=ms://aws/prod", &[]), &b""[..]),
            (parts("/x?u=ms%3A%2F%2Faws%2Fprod", &[]), b""),
            (parts("/", &[("x-forward", "ms://aws/prod")]), b""),
            (parts("/", &[]), b"{\"k\":\"ms://aws/prod\"}"),
            (parts("/", &[]), b"k=AKIA_MS_PLACEHOLDER1"),
            (
                parts(
                    "/",
                    &[(
                        "authorization",
                        &format!("Basic {}", B64.encode("ms://aws/prod:")),
                    )],
                ),
                b"",
            ),
        ];
        for (p, body) in cases {
            assert_eq!(
                plan("api.stripe.com", 443, &p, body, &bs),
                Plan::Block(vec![aws_key.clone()]),
                "{p:?}"
            );
        }
        // An unknown key is foreign everywhere.
        let p = parts("/", &[("authorization", "Bearer ms://pg/prod")]);
        assert!(matches!(
            plan("api.stripe.com", 443, &p, b"", &bs),
            Plan::Block(_)
        ));
        // The right key on the wrong port does not count as bound.
        let p = parts("/", &[("authorization", "Bearer ms://stripe/test")]);
        assert!(matches!(
            plan("api.stripe.com", 8443, &p, b"", &bs),
            Plan::Block(_)
        ));
    }

    // protects=no placeholder means no swap but credentials still stripped; two keys of one host
    // in their locations is refused; fails_when=a swap happens without a placeholder or a
    // two-key request is forwarded; no_claim=policy
    #[test]
    fn no_swap_and_ambiguous() {
        let bs = vec![
            binding("stripe/test", "api.stripe.com", bearer()),
            binding(
                "stripe/live",
                "api.stripe.com",
                Location::Header {
                    name: "x-live".into(),
                    prefix: String::new(),
                },
            ),
        ];
        let p = parts("/", &[("authorization", "Bearer sk_live_REAL")]);
        assert_eq!(
            plan("api.stripe.com", 443, &p, b"", &bs),
            Plan::Forward(None)
        );
        let p = parts(
            "/",
            &[
                ("authorization", "Bearer ms://stripe/test"),
                ("x-live", "ms://stripe/live"),
            ],
        );
        assert_eq!(plan("api.stripe.com", 443, &p, b"", &bs), Plan::Ambiguous);
    }

    // protects=a value with CR/LF can't split headers; fails_when=apply accepts it;
    // no_claim=other invalid bytes beyond control characters
    #[test]
    fn bad_value_refused() {
        let bs = [binding("stripe/test", "api.stripe.com", bearer())];
        let mut p = parts("/", &[("authorization", "Bearer ms://stripe/test")]);
        assert_eq!(
            apply(&mut p, &bs[0], &[&bs[0]], b"a\r\nX-Evil: 1"),
            Err(BadValue)
        );
    }

    // protects=hop-by-hop, Connection-named and Proxy-* headers are removed; fails_when=one
    // survives; no_claim=end-to-end headers
    #[test]
    fn hop_by_hop() {
        let mut p = parts(
            "/",
            &[
                ("connection", "keep-alive, x-secret-hop"),
                ("x-secret-hop", "1"),
                ("proxy-authorization", "Basic eA=="),
                ("proxy-foo", "1"),
                ("te", "trailers"),
                ("upgrade", "h2c"),
                ("accept", "x"),
            ],
        );
        strip_hop_by_hop(&mut p.headers);
        assert_eq!(p.headers.len(), 1, "{:?}", p.headers);
    }

    fn arb_header_value() -> impl Strategy<Value = String> {
        prop_oneof![
            "[ -~]{0,40}",
            Just("Bearer ms://stripe/test".to_string()),
            Just("Basic bXM6Ly9zdHJpcGUvdGVzdDo=".to_string()),
            "Bearer ms://[a-z/]{0,12}",
            "(B|b)asic [A-Za-z0-9+/=]{0,30}",
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        // protects=the head rewriter never panics and only ever writes the value into the
        // configured location; fails_when=any input panics, or the canary appears anywhere but
        // the Authorization header; no_claim=hyper's own parser (see the listener fuzz in itests)
        #[test]
        fn fuzz_rewriter(
            path in "/[ -~&&[^ #]]{0,40}",
            headers in prop::collection::vec(("[a-z-]{1,12}", arb_header_value()), 0..6),
            body in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let bs = [binding("stripe/test", "api.stripe.com", bearer())];
            let mut b = http::Request::builder();
            if let Ok(u) = path.parse::<Uri>() { b = b.uri(u); }
            for (k, v) in &headers {
                if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                    b = b.header(k, v);
                }
            }
            let Ok(req) = b.body(()) else { return Ok(()) };
            let (mut p, ()) = req.into_parts();
            let decided = plan("api.stripe.com", 443, &p, &body, &bs);
            if let Plan::Forward(Some(bind)) = decided {
                apply(&mut p, bind, &[bind], SECRET).unwrap();
                for (k, v) in &p.headers {
                    if v.as_bytes().windows(SECRET.len()).any(|w| w == SECRET) {
                        prop_assert_eq!(k.as_str(), "authorization");
                    }
                }
                prop_assert!(!p.uri.to_string().contains("CANARY"));
            }
        }
    }
}
