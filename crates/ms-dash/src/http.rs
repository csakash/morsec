//! One HTTP request: the checks of design §6.2.4 in order, then the route. Every response, the
//! refusals included, goes through [`finish`], which sets the headers of §6.2.5.

use std::time::Instant;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, ORIGIN};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use ms_core::{KeyName, SessionId};
use serde::Deserialize;

use crate::api::{ExportFormat, parse_activity_query};
use crate::assets;
use crate::auth::Access;
use crate::data::{ApiError, Refusal};
use crate::server::Inner;

/// Largest request body (design §6.2.4).
pub const MAX_BODY: usize = 64 * 1024;
/// The session cookie's name.
pub const COOKIE_NAME: &str = "ms_dash";
/// The CSRF header.
pub const CSRF_HEADER: &str = "x-morsec-csrf";
/// The Content-Security-Policy, exactly as design §6.2.5.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// The response type.
pub type Resp = Response<Full<Bytes>>;

/// The headers every response carries (design §6.2.5).
pub fn security_headers() -> [(&'static str, &'static str); 7] {
    [
        ("content-security-policy", CSP),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ]
}

/// A response with the security headers.
pub fn finish(status: StatusCode, content_type: &str, body: Vec<u8>) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    for (k, v) in security_headers() {
        h.insert(k, HeaderValue::from_static(v));
    }
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(CONTENT_TYPE, v);
    }
    r
}

fn json_error(status: StatusCode, message: &str) -> Resp {
    let body = serde_json::json!({ "error": message })
        .to_string()
        .into_bytes();
    finish(status, "application/json", body)
}

fn json<T: serde::Serialize>(v: &T) -> Resp {
    match serde_json::to_vec(v) {
        Ok(b) => finish(StatusCode::OK, "application/json", b),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "morsec: the answer could not be encoded",
        ),
    }
}

fn from_api_error(e: &ApiError) -> Resp {
    json_error(
        StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        &e.message,
    )
}

fn header(h: &HeaderMap, name: impl http::header::AsHeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// The `ms_dash` cookie's value, if the request has exactly one.
pub fn session_cookie(h: &HeaderMap) -> Option<String> {
    let mut found = None;
    for v in h.get_all(COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some(val) = part.trim().strip_prefix("ms_dash=") {
                if found.is_some() {
                    return None;
                }
                found = Some(val.to_owned());
            }
        }
    }
    found
}

/// Host is `127.0.0.1:<port>` or `localhost:<port>` exactly (DNS rebinding, design §6.2.4).
pub fn host_ok(h: &HeaderMap, port: u16) -> bool {
    let hosts: Vec<_> = h.get_all(HOST).iter().collect();
    if hosts.len() != 1 {
        return false;
    }
    let Ok(host) = hosts[0].to_str() else {
        return false;
    };
    host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

/// `Origin` equals `http://<Host>` (checked after [`host_ok`]).
fn origin_ok(h: &HeaderMap) -> bool {
    match (header(h, ORIGIN), header(h, HOST)) {
        (Some(o), Some(host)) => o == format!("http://{host}"),
        _ => false,
    }
}

/// `Sec-Fetch-Site`, when the browser sends it: POSTs must be `same-origin`; GETs `same-origin`
/// or `none` (typed or opened from `open(1)`). `same-site` is refused too: another port of
/// `127.0.0.1` is the same site.
fn fetch_site_ok(h: &HeaderMap, post: bool) -> bool {
    match header(h, "sec-fetch-site") {
        None => true,
        Some("same-origin") => true,
        Some("none") => !post,
        Some(_) => false,
    }
}

fn is_json(h: &HeaderMap) -> bool {
    header(h, CONTENT_TYPE).is_some_and(|c| {
        let base = c.split(';').next().unwrap_or("").trim();
        base.eq_ignore_ascii_case("application/json")
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReq {
    token: String,
}

/// How long a request body may take to arrive (security review S2).
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Answers a refusal that gets a log line only (throttled), no receipt: a browser's own
/// cross-site fetch, a stale tab's CSRF token, a missing session, a rate limit. Every caller
/// that reaches this point already passed the process check, so it is not an agent session
/// (reviews R1, R3, S4).
fn quiet(inner: &Inner, who: &SessionId, status: StatusCode, why: &str) -> Resp {
    inner.log_refusal(
        &Refusal {
            session: who.clone(),
            why: why.to_owned(),
        },
        false,
    );
    json_error(status, &format!("morsec: refused: {why}"))
}

/// Records a refusal (throttled) and answers it.
async fn refuse(inner: &Inner, who: &SessionId, status: StatusCode, why: &str) -> Resp {
    inner
        .refused(Refusal {
            session: who.clone(),
            why: why.to_owned(),
        })
        .await;
    json_error(status, &format!("morsec: refused: {why}"))
}

/// Handles one request on a connection that passed the process check.
pub async fn handle(
    inner: &Inner,
    port: u16,
    who: &SessionId,
    req: hyper::Request<Incoming>,
) -> Resp {
    let (parts, body) = req.into_parts();
    let h = &parts.headers;
    if !host_ok(h, port) {
        return refuse(
            inner,
            who,
            StatusCode::MISDIRECTED_REQUEST,
            "the Host header is not this dashboard",
        )
        .await;
    }
    let post = match parts.method {
        Method::GET => false,
        Method::POST => true,
        _ => {
            let mut r = json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "morsec: only GET and POST are served",
            );
            r.headers_mut()
                .insert("allow", HeaderValue::from_static("GET, POST"));
            return r;
        }
    };
    if !fetch_site_ok(h, post) {
        return quiet(
            inner,
            who,
            StatusCode::FORBIDDEN,
            "a request from another site",
        );
    }
    let path = parts.uri.path();
    let query = parts.uri.query().unwrap_or("");
    let now = Instant::now();

    // Static page: no data, no session (SPEC D-10).
    if !path.starts_with("/api/") {
        if post {
            return json_error(StatusCode::NOT_FOUND, "morsec: no such page");
        }
        if !inner.take_anon(now) {
            return quiet(
                inner,
                who,
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests",
            );
        }
        return match assets::get(path) {
            Some((ctype, bytes)) => finish(StatusCode::OK, ctype, bytes.to_vec()),
            None => json_error(StatusCode::NOT_FOUND, "morsec: no such page"),
        };
    }

    // Every non-GET: Origin, JSON, bounded body (design §6.2.4).
    let mut body_bytes = Bytes::new();
    if post {
        if !origin_ok(h) {
            return refuse(
                inner,
                who,
                StatusCode::FORBIDDEN,
                "Origin is missing or not this dashboard",
            )
            .await;
        }
        if !is_json(h) {
            return json_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "morsec: send application/json",
            );
        }
        let declared = header(h, CONTENT_LENGTH).and_then(|v| v.parse::<usize>().ok());
        if declared.is_some_and(|n| n > MAX_BODY) {
            return refuse(
                inner,
                who,
                StatusCode::PAYLOAD_TOO_LARGE,
                "body over 64 KiB",
            )
            .await;
        }
        match tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY).collect()).await {
            Ok(Ok(c)) => body_bytes = c.to_bytes(),
            Err(_) => {
                return quiet(
                    inner,
                    who,
                    StatusCode::REQUEST_TIMEOUT,
                    "the body took over 5 s",
                );
            }
            Ok(Err(_)) => {
                return refuse(
                    inner,
                    who,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body over 64 KiB",
                )
                .await;
            }
        }
    }

    if post && path == "/api/session" {
        if !inner.take_anon(now) {
            return quiet(
                inner,
                who,
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests",
            );
        }
        let Ok(r) = serde_json::from_slice::<SessionReq>(&body_bytes) else {
            return json_error(StatusCode::BAD_REQUEST, "morsec: expected {\"token\": …}");
        };
        let existing = session_cookie(h);
        return match inner.start_session(&r.token, existing.as_deref(), now) {
            Ok(Some((cookie, csrf))) => {
                let mut resp = json(&serde_json::json!({ "csrf": csrf }));
                let c = format!(
                    "{COOKIE_NAME}={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
                );
                if let Ok(v) = HeaderValue::from_str(&c) {
                    resp.headers_mut().insert("set-cookie", v);
                }
                resp
            }
            Ok(None) => {
                refuse(
                    inner,
                    who,
                    StatusCode::FORBIDDEN,
                    "the launch token is unknown, used or expired",
                )
                .await
            }
            Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
        };
    }

    // Everything else under /api/: cookie, CSRF (GET too, SPEC D-4), rate.
    let cookie = session_cookie(h);
    let csrf = header(h, CSRF_HEADER);
    match inner.check(cookie.as_deref(), csrf, now) {
        Access::Ok => {}
        // Unauthenticated API requests share the unauthenticated bucket (review R3).
        Access::NoSession if !inner.take_anon(now) => {
            return quiet(
                inner,
                who,
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests",
            );
        }
        Access::NoSession => {
            return quiet(
                inner,
                who,
                StatusCode::UNAUTHORIZED,
                "no dashboard session (open it again with ms dashboard)",
            );
        }
        Access::BadCsrf => {
            return quiet(
                inner,
                who,
                StatusCode::FORBIDDEN,
                "the CSRF token is missing or wrong (the page was opened again in another tab)",
            );
        }
        Access::Limited => {
            return quiet(
                inner,
                who,
                StatusCode::TOO_MANY_REQUESTS,
                "over 20 requests a second",
            );
        }
    }
    if post {
        // L32 is read-only: no action exists (SPEC D-3).
        return json_error(StatusCode::NOT_FOUND, "morsec: no such action");
    }
    route_get(inner, path, query).await
}

/// The read-only API.
async fn route_get(inner: &Inner, path: &str, query: &str) -> Resp {
    let data = inner.data();
    let rest = &path["/api/".len()..];
    let path = rest.to_owned();
    let query = query.to_owned();
    let out = tokio::task::spawn_blocking(move || -> Resp {
        let r = |x: Result<Resp, ApiError>| x.unwrap_or_else(|e| from_api_error(&e));
        match path.as_str() {
            "home" => r(data.home().map(|v| json(&v))),
            "projects" => r(data.projects().map(|v| json(&v))),
            "agents" => r(data.agents().map(|v| json(&v))),
            "scan" => r(data.scan().map(|v| json(&v))),
            "activity" => r(data
                .activity(&parse_activity_query(&query))
                .map(|v| json(&v))),
            "activity/verify" => r(data.verify().map(|v| json(&v))),
            "activity/export" => {
                let q = parse_activity_query(&query);
                let format = if query.split('&').any(|p| p == "format=csv") {
                    ExportFormat::Csv
                } else {
                    ExportFormat::Json
                };
                r(data.export(&q, format).map(|(name, ctype, body)| {
                    let mut resp = finish(StatusCode::OK, ctype, body);
                    let name: String = name
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
                        .collect();
                    if let Ok(v) =
                        HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
                    {
                        resp.headers_mut().insert("content-disposition", v);
                    }
                    resp
                }))
            }
            p => {
                if let Some(slug) = p.strip_prefix("projects/") {
                    if slug.is_empty() || slug.contains('/') {
                        return json_error(StatusCode::NOT_FOUND, "morsec: no such project");
                    }
                    return r(data.project(slug).map(|v| json(&v)));
                }
                if let Some(raw) = p.strip_prefix("keys/") {
                    let Some(Ok(key)) = crate::api::percent_decode(raw).map(|s| KeyName::new(&s))
                    else {
                        return json_error(StatusCode::NOT_FOUND, "morsec: no such key");
                    };
                    return r(data.secret(&key).map(|v| json(&v)));
                }
                json_error(StatusCode::NOT_FOUND, "morsec: no such page")
            }
        }
    })
    .await;
    out.unwrap_or_else(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "morsec: the dashboard failed handling this request",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    // protects=Host must name this port on 127.0.0.1 or localhost, once (DNS rebinding);
    // fails_when=an attacker name, another port, a missing or doubled Host passes;
    // no_claim=the live listener (tests/http.rs)
    #[test]
    fn host_checks() {
        assert!(host_ok(&hm(&[("host", "127.0.0.1:7311")]), 7311));
        assert!(host_ok(&hm(&[("host", "localhost:7311")]), 7311));
        for bad in [
            "evil.example:7311",
            "127.0.0.1:7312",
            "127.0.0.1",
            "localhost",
            "127.0.0.1.nip.io:7311",
            "[::1]:7311",
        ] {
            assert!(!host_ok(&hm(&[("host", bad)]), 7311), "{bad}");
        }
        assert!(!host_ok(&HeaderMap::new(), 7311));
        assert!(!host_ok(
            &hm(&[("host", "127.0.0.1:7311"), ("host", "127.0.0.1:7311")]),
            7311
        ));
    }

    // protects=only same-origin (and, for GET, none) Sec-Fetch-Site values pass, and Origin must
    // equal http://<Host>; fails_when=a cross-site, same-site or null Origin request passes;
    // no_claim=browsers that send neither header (Origin is still required on POST)
    #[test]
    fn origin_and_fetch_site() {
        assert!(fetch_site_ok(&HeaderMap::new(), true));
        assert!(fetch_site_ok(&hm(&[("sec-fetch-site", "none")]), false));
        assert!(!fetch_site_ok(&hm(&[("sec-fetch-site", "none")]), true));
        assert!(!fetch_site_ok(
            &hm(&[("sec-fetch-site", "same-site")]),
            false
        ));
        assert!(!fetch_site_ok(
            &hm(&[("sec-fetch-site", "cross-site")]),
            false
        ));
        let h = |o: &str| hm(&[("host", "127.0.0.1:7311"), ("origin", o)]);
        assert!(origin_ok(&h("http://127.0.0.1:7311")));
        for bad in [
            "null",
            "http://127.0.0.1:3000",
            "http://localhost:7311",
            "https://127.0.0.1:7311",
            "http://evil.example",
        ] {
            assert!(!origin_ok(&h(bad)), "{bad}");
        }
        assert!(!origin_ok(&hm(&[("host", "127.0.0.1:7311")])));
    }

    // protects=exactly one ms_dash cookie is read; fails_when=a second (shadowing) cookie is
    // accepted; no_claim=browser cookie jars
    #[test]
    fn cookie_parsing() {
        assert_eq!(
            session_cookie(&hm(&[("cookie", "a=1; ms_dash=abc; b=2")])).as_deref(),
            Some("abc")
        );
        assert_eq!(
            session_cookie(&hm(&[("cookie", "ms_dash=abc; ms_dash=def")])),
            None
        );
        assert_eq!(session_cookie(&hm(&[("cookie", "x_ms_dash=abc")])), None);
    }
}
