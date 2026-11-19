//! The dashboard's HTTP envelope over a real loopback listener (L32 SPEC criteria 1 to 8): a fake
//! `DashData` stands in for msd, a raw HTTP/1.1 client sets every header by hand.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_core::{AgentKind, KeyName, SessionId};
use ms_dash::api::*;
use ms_dash::{ApiError, Dash, DashConfig, DashData, Refusal};

#[derive(Default)]
struct Fake {
    refuse: Mutex<Option<String>>,
    refused: Mutex<Vec<Refusal>>,
}

fn who() -> SessionId {
    SessionId {
        agent: AgentKind::Other("dashboard".into()),
        pid: 1234,
        started_unix_ms: 1,
    }
}

impl DashData for Fake {
    fn check_connection(&self, _p: SocketAddr, _l: SocketAddr) -> Result<SessionId, Refusal> {
        match self.refuse.lock().unwrap().clone() {
            Some(why) => Err(Refusal {
                session: SessionId {
                    agent: AgentKind::ClaudeCode,
                    pid: 42,
                    started_unix_ms: 1,
                },
                why,
            }),
            None => Ok(who()),
        }
    }
    fn record_refused(&self, r: &Refusal) {
        self.refused.lock().unwrap().push(r.clone());
    }
    fn home(&self) -> Result<HomeView, ApiError> {
        Ok(HomeView {
            running: true,
            keys: 3,
            ..HomeView::default()
        })
    }
    fn projects(&self) -> Result<ProjectsView, ApiError> {
        Ok(ProjectsView::default())
    }
    fn project(&self, slug: &str) -> Result<ProjectView, ApiError> {
        if slug == "shop" {
            Ok(ProjectView {
                slug: slug.into(),
                ..ProjectView::default()
            })
        } else {
            Err(ApiError::not_found("no such project"))
        }
    }
    fn secret(&self, key: &KeyName) -> Result<SecretView, ApiError> {
        Ok(SecretView {
            key: key.to_string(),
            ..SecretView::default()
        })
    }
    fn activity(&self, q: &ActivityQuery) -> Result<ActivityView, ApiError> {
        Ok(ActivityView {
            matched: q.limit.unwrap_or(0),
            ..ActivityView::default()
        })
    }
    fn export(
        &self,
        _q: &ActivityQuery,
        f: ExportFormat,
    ) -> Result<(String, &'static str, Vec<u8>), ApiError> {
        Ok(match f {
            ExportFormat::Csv => ("r\"x.csv".into(), "text/csv", b"a,b\n".to_vec()),
            ExportFormat::Json => ("r.json".into(), "application/json", b"[]".to_vec()),
        })
    }
    fn verify(&self) -> Result<VerifyView, ApiError> {
        Ok(VerifyView {
            ok: true,
            ..VerifyView::default()
        })
    }
    fn agents(&self) -> Result<AgentsView, ApiError> {
        Ok(AgentsView::default())
    }
    fn scan(&self) -> Result<ScanView, ApiError> {
        Ok(ScanView::default())
    }
}

struct T {
    _rt: tokio::runtime::Runtime,
    dash: Dash,
    fake: Arc<Fake>,
}

/// A port below the ephemeral range (macOS: 49152 and up), where client sockets of parallel
/// tests keep landing and leave ports in TIME_WAIT. Bound and returned held.
fn quiet_listener() -> TcpListener {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = std::process::id()
            .wrapping_mul(2_654_435_761)
            .wrapping_add(n * 7919);
        let port = 20_000 + u16::try_from(seed % 25_000).unwrap();
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            return l;
        }
    }
}

fn setup(f: impl FnOnce(&mut DashConfig)) -> T {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut cfg = DashConfig::new(quiet_listener().local_addr().unwrap().port());
    f(&mut cfg);
    let fake = Arc::new(Fake::default());
    let dash = Dash::new(cfg, fake.clone(), rt.handle().clone());
    T {
        _rt: rt,
        dash,
        fake,
    }
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn h(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Sends `head` (request line and headers, no blank line) plus `body`, reads to the end.
fn raw(port: u16, head: &str, body: &str) -> Reply {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let msg = format!(
        "{head}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(msg.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn get(port: u16, path: &str, extra: &str) -> Reply {
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}");
    if !extra.is_empty() {
        head.push_str("\r\n");
        head.push_str(extra);
    }
    raw(port, &head, "")
}

fn post_session(port: u16, token: &str, extra: &str) -> Reply {
    let mut head = format!(
        "POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json"
    );
    if !extra.is_empty() {
        head.push_str("\r\n");
        head.push_str(extra);
    }
    raw(port, &head, &format!("{{\"token\":\"{token}\"}}"))
}

fn origin(port: u16) -> String {
    format!("Origin: http://127.0.0.1:{port}")
}

/// Opens the dashboard and signs in: (port, cookie value, csrf).
fn signed_in(t: &T) -> (u16, String, String) {
    let o = t.dash.open().unwrap();
    let r = post_session(o.port, &o.token, &origin(o.port));
    assert_eq!(r.status, 200, "{r:?}");
    let cookie = r
        .h("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("ms_dash=")
        .unwrap()
        .to_owned();
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    (o.port, cookie, v["csrf"].as_str().unwrap().to_owned())
}

fn auth(cookie: &str, csrf: &str) -> String {
    format!("Cookie: ms_dash={cookie}\r\nX-Morsec-CSRF: {csrf}")
}

const HEADERS: [(&str, &str); 7] = [
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

// protects=design §6.1 and §8 (port squatting): msd binds before it answers and reports the port
// it holds; a taken first port moves it to the next one, and the reported port serves the
// dashboard; fails_when=the reported port is the asked one while something else holds it, or
// nothing of ours listens there; no_claim=what the CLI opens (ms-cli dashboard.rs)
#[test]
fn dash_open_reports_bound_port() {
    let squatter = quiet_listener();
    let base = squatter.local_addr().unwrap().port();
    let t = setup(|c| c.first_port = base);
    let o = t.dash.open().unwrap();
    // Tests run in parallel and grab ports too, so the next free one may be further up.
    assert_ne!(o.port, base, "the squatted port is skipped");
    assert!(o.port > base && o.port < base + 10, "{base} {}", o.port);
    assert_eq!(t.dash.port(), Some(o.port));
    let r = get(o.port, "/", "");
    assert_eq!(r.status, 200);
    assert_eq!(r.h("content-security-policy"), Some(HEADERS[0].1));
    // A second open reuses the listener, with a fresh token.
    let o2 = t.dash.open().unwrap();
    assert_eq!(o2.port, o.port);
    assert_ne!(o2.token, o.token);
    drop(squatter);
}

// protects=criterion 1, every port of the range taken gives a clear error and binds nothing
// else; fails_when=it binds outside its range or answers a port it doesn't hold;
// no_claim=-
#[test]
fn dash_open_fails_when_range_is_full() {
    let (base, _a, _b) = loop {
        let base = quiet_listener().local_addr().unwrap().port();
        if let (Ok(a), Ok(b)) = (
            TcpListener::bind(("127.0.0.1", base)),
            TcpListener::bind(("127.0.0.1", base + 1)),
        ) {
            break (base, a, b);
        }
    };
    let t = setup(|c| {
        c.first_port = base;
        c.span = 2;
    });
    let e = t.dash.open().unwrap_err();
    assert!(e.contains("in use"), "{e}");
    assert_eq!(t.dash.port(), None);
}

// protects=design §6.2.5 and §8 (XSS): the CSP and the other six headers are on every response:
// the page, a 404, refusals (401, 403, 405, 413, 421) and API answers; fails_when=any response
// lacks one or has a different value; no_claim=a connection refused by the process check (it gets
// no bytes at all)
#[test]
fn dash_csp_on_every_response() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let a = auth(&cookie, &csrf);
    let host = format!("Host: 127.0.0.1:{port}");
    let replies = vec![
        get(port, "/", ""),
        get(port, "/dash.js", ""),
        get(port, "/nope", ""),
        get(port, "/api/home", ""),
        get(port, "/api/home", &a),
        get(port, "/api/projects/zzz", &a),
        raw(port, "GET / HTTP/1.1\r\nHost: evil.example", ""),
        raw(port, &format!("PUT / HTTP/1.1\r\n{host}"), ""),
        post_session(port, "00", "Origin: http://evil.example"),
        post_session(port, "00", &origin(port)),
        raw(
            port,
            &format!(
                "POST /api/session HTTP/1.1\r\n{host}\r\n{}\r\nContent-Type: application/json",
                origin(port)
            ),
            &"x".repeat(70 * 1024),
        ),
    ];
    let mut statuses: Vec<u16> = replies.iter().map(|r| r.status).collect();
    statuses.sort_unstable();
    statuses.dedup();
    assert!(statuses.len() >= 7, "a spread of statuses: {statuses:?}");
    for r in &replies {
        assert_ne!(r.status, 0, "{r:?}");
        for (k, v) in HEADERS {
            assert_eq!(r.h(k), Some(v), "{k} on {} {:?}", r.status, r.body);
        }
    }
}

// protects=design §6.2.4 and §8 (DNS rebinding): only Host 127.0.0.1:<port> or localhost:<port>
// is served, even with a valid session, and the refusal is recorded; fails_when=a foreign name or
// another port gets data; no_claim=-
#[test]
fn dash_rejects_foreign_host_header() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let a = auth(&cookie, &csrf);
    for host in [
        "evil.example".to_owned(),
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port + 1),
        "127.0.0.1".to_owned(),
    ] {
        let r = raw(
            port,
            &format!("GET /api/home HTTP/1.1\r\nHost: {host}\r\n{a}"),
            "",
        );
        assert_eq!(r.status, 421, "{host}: {r:?}");
        assert!(!r.body.contains("\"keys\""), "{host}");
    }
    let r = raw(
        port,
        &format!("GET /api/home HTTP/1.1\r\nHost: localhost:{port}\r\n{a}"),
        "",
    );
    assert_eq!(r.status, 200, "localhost:<port> is ours");
    let refused = t.fake.refused.lock().unwrap();
    assert!(
        refused.iter().filter(|r| r.why.contains("Host")).count() >= 4,
        "{refused:?}"
    );
    assert!(refused.iter().all(|r| r.session == who()));
}

// protects=design §6.2.4 and §8 (CSRF): a POST needs Origin equal to this dashboard and
// Sec-Fetch-Site same-origin when sent; a cross-site GET is refused too; a refused POST does not
// consume the launch token; Origin refusals are recorded, Sec-Fetch-Site ones only logged;
// fails_when=a missing, null or foreign Origin, or a cross-site or same-site fetch, gets a
// session or data; no_claim=SameSite enforcement by browsers
#[test]
fn dash_rejects_cross_origin_post() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    let p = o.port;
    for extra in [
        String::new(),
        "Origin: null".to_owned(),
        "Origin: http://evil.example".to_owned(),
        "Origin: http://127.0.0.1:3000".to_owned(),
        format!("{}\r\nSec-Fetch-Site: cross-site", origin(p)),
        format!("{}\r\nSec-Fetch-Site: same-site", origin(p)),
    ] {
        let r = post_session(p, &o.token, &extra);
        assert_eq!(r.status, 403, "{extra}: {r:?}");
        assert!(r.h("set-cookie").is_none());
    }
    // The token survived every refused try.
    let r = post_session(
        p,
        &o.token,
        &format!("{}\r\nSec-Fetch-Site: same-origin", origin(p)),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let cookie = r.h("set-cookie").unwrap().split(';').next().unwrap();
    let csrf: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let csrf = csrf["csrf"].as_str().unwrap();
    let r = get(
        p,
        "/api/home",
        &format!("Cookie: {cookie}\r\nX-Morsec-CSRF: {csrf}\r\nSec-Fetch-Site: cross-site"),
    );
    assert_eq!(r.status, 403, "cross-site GET");
    // Origin refusals get receipts; a browser's own cross-site fetch is only logged (review S4).
    let refused = t.fake.refused.lock().unwrap();
    assert_eq!(refused.len(), 4, "{refused:?}");
    assert!(
        refused.iter().all(|r| r.why.contains("Origin")),
        "{refused:?}"
    );
}

// protects=SPEC D-4 and criterion 6: every API request, GET included, needs the session cookie
// and its CSRF token; fails_when=a cookie alone, a CSRF token alone, another session's token or a
// wrong token reads data; no_claim=-
#[test]
fn api_needs_cookie_and_csrf() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let (_, cookie2, csrf2) = signed_in(&t);
    let cases = [
        (String::new(), 401),
        (format!("Cookie: ms_dash={cookie}"), 403),
        (
            format!("Cookie: ms_dash={cookie}\r\nX-Morsec-CSRF: {csrf2}"),
            403,
        ),
        (format!("Cookie: ms_dash={cookie}\r\nX-Morsec-CSRF: x"), 403),
        (format!("X-Morsec-CSRF: {csrf}"), 401),
        (
            format!("Cookie: ms_dash={csrf}\r\nX-Morsec-CSRF: {csrf}"),
            401,
        ),
        (auth(&cookie, &csrf), 200),
        (auth(&cookie2, &csrf2), 200),
    ];
    for (h, want) in cases {
        let r = get(port, "/api/home", &h);
        assert_eq!(r.status, want, "{h}: {r:?}");
        assert_eq!(r.body.contains("\"keys\":3"), want == 200, "{h}");
    }
}

// protects=design §6.2.2: a launch token works once; fails_when=a replayed token gets a second
// session; no_claim=-
#[test]
fn launch_token_single_use() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    assert_eq!(post_session(o.port, &o.token, &origin(o.port)).status, 200);
    let r = post_session(o.port, &o.token, &origin(o.port));
    assert_eq!(r.status, 403, "{r:?}");
    assert!(r.h("set-cookie").is_none());
    assert_eq!(
        post_session(o.port, &"0".repeat(64), &origin(o.port)).status,
        403
    );
    assert_eq!(t.dash.session_count(), 1);
}

// protects=design §6.2.2: a launch token is good for its ttl only (60 s; 200 ms here);
// fails_when=an expired token gets a session; no_claim=-
#[test]
fn launch_token_expires() {
    let t = setup(|c| c.token_ttl = Duration::from_millis(200));
    let o = t.dash.open().unwrap();
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(post_session(o.port, &o.token, &origin(o.port)).status, 403);
}

// protects=design §6.2.3: the cookie is HttpOnly, SameSite=Strict, Path=/, Max-Age=43200 and both
// it and the CSRF token are 32 random bytes; fails_when=an attribute is missing or a token is
// short or repeated; no_claim=browser behaviour
#[test]
fn session_cookie_attributes() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    let r = post_session(o.port, &o.token, &origin(o.port));
    let c = r.h("set-cookie").unwrap();
    let parts: Vec<&str> = c.split("; ").collect();
    let val = parts[0].strip_prefix("ms_dash=").unwrap();
    assert_eq!(val.len(), 64);
    assert!(val.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        &parts[1..],
        ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"]
    );
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let csrf = v["csrf"].as_str().unwrap();
    assert_eq!(csrf.len(), 64);
    assert_ne!(csrf, val);
    assert_eq!(r.h("content-type"), Some("application/json"));
}

// protects=design §6.2.4: bodies over 64 KiB, other methods, non-JSON posts and any POST but the
// session exchange are refused (L32 has no actions); fails_when=one of them reaches a handler;
// no_claim=-
#[test]
fn body_limit_and_methods() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let host = format!("Host: 127.0.0.1:{port}");
    let a = auth(&cookie, &csrf);
    let o = origin(port);
    let big = "x".repeat(70 * 1024);
    let r = raw(
        port,
        &format!("POST /api/session HTTP/1.1\r\n{host}\r\n{o}\r\nContent-Type: application/json"),
        &big,
    );
    assert_eq!(r.status, 413);
    for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
        let r = raw(
            port,
            &format!("{m} /api/home HTTP/1.1\r\n{host}\r\n{a}"),
            "",
        );
        assert_eq!(r.status, 405, "{m}: {r:?}");
    }
    let r = raw(
        port,
        &format!("POST /api/session HTTP/1.1\r\n{host}\r\n{o}\r\nContent-Type: text/plain"),
        "{}",
    );
    assert_eq!(r.status, 415);
    let r = raw(
        port,
        &format!(
            "POST /api/home HTTP/1.1\r\n{host}\r\n{o}\r\n{a}\r\nContent-Type: application/json"
        ),
        "{}",
    );
    assert_eq!(r.status, 404, "no actions in L32: {r:?}");
}

// protects=design §6.2.6: 20 requests/s per session, and unauthenticated API requests share one
// bucket too (review R3); fails_when=a burst of 40 all pass, or 40 cookie-less requests all get
// 401; no_claim=exact refill timing
#[test]
fn rate_limited_per_session() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let a = auth(&cookie, &csrf);
    let codes: Vec<u16> = (0..40).map(|_| get(port, "/api/home", &a).status).collect();
    let ok = codes.iter().filter(|c| **c == 200).count();
    let limited = codes.iter().filter(|c| **c == 429).count();
    assert!(limited > 0, "{codes:?}");
    assert!((20..40).contains(&ok), "{codes:?}");
    let anon: Vec<u16> = (0..40).map(|_| get(port, "/api/home", "").status).collect();
    assert!(anon.contains(&429) && anon.contains(&401), "{anon:?}");
    // Rate refusals are logged (throttled), not receipts (review R3).
    assert!(t.fake.refused.lock().unwrap().is_empty());
}

// protects=design §6.1: after `idle` without an authenticated request the listener, its sessions
// and its open keep-alive connections close; DashOpen starts it again; fails_when=the port or a
// held connection still answers, or a session survives; no_claim=the 30-minute value itself
// (DashConfig::new)
#[test]
fn dash_closes_when_idle() {
    assert_eq!(DashConfig::new(1).idle, Duration::from_secs(1800));
    let t = setup(|c| c.idle = Duration::from_millis(300));
    let (port, cookie, csrf) = signed_in(&t);
    assert_eq!(get(port, "/api/home", &auth(&cookie, &csrf)).status, 200);
    // A keep-alive connection held open across the close is closed too (review R7).
    let mut held = TcpStream::connect(("127.0.0.1", port)).unwrap();
    held.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    held.write_all(
        format!(
            "GET /api/home HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{}\r\n\r\n",
            auth(&cookie, &csrf)
        )
        .as_bytes(),
    )
    .unwrap();
    let mut buf = [0u8; 4096];
    let n = held.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    std::thread::sleep(Duration::from_millis(900));
    let mut rest = Vec::new();
    let _ = held.read_to_end(&mut rest);
    let after = held
        .write_all(format!("GET /api/home HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes());
    let mut more = [0u8; 64];
    let got = held.read(&mut more).unwrap_or(0);
    assert!(
        after.is_err() || got == 0,
        "the held connection still answers"
    );
    assert_eq!(t.dash.port(), None);
    assert_eq!(t.dash.session_count(), 0);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    let o = t.dash.open().unwrap();
    assert_eq!(get(o.port, "/", "").status, 200);
}

// protects=criterion 2, msd stopping closes the listener and drops every session and token;
// fails_when=a session or the port survives shutdown; no_claim=-
#[test]
fn dash_shutdown_drops_sessions() {
    let t = setup(|_| {});
    let (port, _, _) = signed_in(&t);
    let o = t.dash.open().unwrap();
    t.dash.shutdown();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(t.dash.session_count(), 0);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    let o2 = t.dash.open().unwrap();
    assert_eq!(
        post_session(o2.port, &o.token, &origin(o2.port)).status,
        403,
        "a token minted before the shutdown is gone"
    );
}

// protects=design §6.2.1: a connection the process check refuses is closed before any byte is
// read or written, and the refusal is recorded; fails_when=it gets a response, or no receipt is
// asked for; no_claim=the process check itself (msd dash.rs, ms-cli dashboard.rs)
#[test]
fn refused_connection_gets_no_bytes() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    *t.fake.refuse.lock().unwrap() = Some("agent session".into());
    let r = get(o.port, "/", "");
    assert_eq!(r.status, 0, "{r:?}");
    assert!(r.headers.is_empty() && r.body.is_empty());
    std::thread::sleep(Duration::from_millis(100));
    let refused = t.fake.refused.lock().unwrap();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].session.agent, AgentKind::ClaudeCode);
}

// protects=criterion 9 (L32) and L33 criterion 4 (the new fields), each API route answers its
// view as JSON; keys with `/` are percent-encoded
// in the path; exports come as attachments with a cleaned file name; fails_when=a route is
// missing or a key path is mis-parsed; no_claim=msd's views (msd tests)
#[test]
fn api_views_round_trip() {
    let t = setup(|_| {});
    let (port, cookie, csrf) = signed_in(&t);
    let a = auth(&cookie, &csrf);
    let ok = |p: &str| {
        let r = get(port, p, &a);
        assert_eq!(r.status, 200, "{p}: {r:?}");
        assert_eq!(r.h("content-type"), Some("application/json"), "{p}");
        serde_json::from_str::<serde_json::Value>(&r.body).unwrap()
    };
    let home = ok("/api/home");
    assert_eq!(home["keys"], 3);
    // L33: the warnings, the keys not usable yet and the pending request's shape.
    assert!(home["warnings"].is_array() && home["not_usable"].is_array());
    assert!(home["pending"].is_null());
    assert_eq!(ok("/api/scan")["running"], false);
    assert!(ok("/api/agents")["warnings"].is_array());
    assert!(ok("/api/activity")["projects"].is_array());
    ok("/api/projects");
    assert_eq!(ok("/api/projects/shop")["slug"], "shop");
    assert_eq!(get(port, "/api/projects/nope", &a).status, 404);
    assert_eq!(get(port, "/api/projects/a/b", &a).status, 404);
    assert_eq!(
        ok("/api/keys/shop%2Fstripe-secret-key")["key"],
        "shop/stripe-secret-key"
    );
    assert_eq!(get(port, "/api/keys/Bad%20Key", &a).status, 404);
    assert_eq!(ok("/api/activity?limit=7&since=24h")["matched"], 7);
    assert_eq!(ok("/api/activity/verify")["ok"], true);
    ok("/api/agents");
    ok("/api/scan");
    let r = get(port, "/api/activity/export?format=csv", &a);
    assert_eq!(r.status, 200);
    assert_eq!(r.h("content-type"), Some("text/csv"));
    assert_eq!(
        r.h("content-disposition"),
        Some("attachment; filename=\"rx.csv\"")
    );
    assert_eq!(get(port, "/api/nope", &a).status, 404);
}

// protects=review R1: opening the dashboard again in the same browser (a second launch token,
// sent with the first tab's cookie) joins that session, so the first tab keeps working and no
// receipt is written; fails_when=the first tab's CSRF token stops working or a refusal is
// recorded; no_claim=-
#[test]
fn second_open_keeps_the_first_tab() {
    let t = setup(|_| {});
    let (port, cookie, csrf1) = signed_in(&t);
    let o = t.dash.open().unwrap();
    let r = post_session(
        port,
        &o.token,
        &format!("{}\r\nCookie: ms_dash={cookie}", origin(port)),
    );
    assert_eq!(r.status, 200, "{r:?}");
    let csrf2: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let csrf2 = csrf2["csrf"].as_str().unwrap().to_owned();
    assert_eq!(get(port, "/api/home", &auth(&cookie, &csrf1)).status, 200);
    assert_eq!(get(port, "/api/home", &auth(&cookie, &csrf2)).status, 200);
    assert_eq!(t.dash.session_count(), 1);
    assert!(t.fake.refused.lock().unwrap().is_empty());
}

// protects=security review S2: a POST whose body never finishes is answered 408 after 5 s and
// frees its connection; fails_when=it hangs; no_claim=-
#[test]
fn slow_body_times_out() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", o.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        format!(
            "POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{\"to",
            p = o.port
        )
        .as_bytes(),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 408"));
    assert!(started.elapsed() < Duration::from_secs(8));
}

// protects=L33 SPEC D-1 and criterion 1: the vendored fonts and their licences are served at
// /fonts/<file> without a session, with font/woff2 or text/plain and every security header, the
// exact bytes msd embeds; anything else under /fonts/ is a 404; fails_when=a font is missing, has
// another type or lacks a header, or a path outside the list is served; no_claim=the bytes'
// provenance (assets::fonts_are_pinned)
#[test]
fn fonts_served_with_headers() {
    let t = setup(|_| {});
    let o = t.dash.open().unwrap();
    for (name, ctype, bytes, _) in ms_dash::assets::FONTS {
        let r = get(o.port, &format!("/fonts/{name}"), "");
        assert_eq!(r.status, 200, "{name}");
        assert_eq!(r.h("content-type"), Some(*ctype), "{name}");
        assert_eq!(
            r.h("content-length"),
            Some(bytes.len().to_string().as_str()),
            "{name}"
        );
        for (k, v) in HEADERS {
            assert_eq!(r.h(k), Some(v), "{k} on {name}");
        }
    }
    for bad in [
        "/fonts/",
        "/fonts/SOURCES.txt",
        "/fonts/../dash.js",
        "/fonts/x.woff2",
    ] {
        assert_eq!(get(o.port, bad, "").status, 404, "{bad}");
    }
}
