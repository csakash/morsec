//! The dashboard's action routes over a real loopback listener (L33 SPEC D-22, D-23): a fake
//! `DashData` and `DashActions` stand in for msd, a raw HTTP/1.1 client sets every header.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_core::{AgentKind, KeyName, SecretBytes, SessionId};
use ms_dash::actions::*;
use ms_dash::api::*;
use ms_dash::{ApiError, Dash, DashConfig, DashData, Refusal};

const CANARY: &str = concat!("sk_live_", "DASH_ACTIONS_CANARY_42");

#[derive(Default)]
struct Fake {
    /// The pid the connection check reports from its second call on (0: the browser's).
    later_pid: AtomicU32,
    checks: AtomicU32,
    refused: Mutex<Vec<Refusal>>,
    calls: Mutex<Vec<String>>,
    action_refusals: Mutex<Vec<(Action, String)>>,
    replaced: Mutex<Vec<Vec<u8>>>,
}

fn browser(pid: u32) -> SessionId {
    SessionId {
        agent: AgentKind::Other("dashboard".into()),
        pid,
        started_unix_ms: 1,
    }
}

impl DashData for Fake {
    fn check_connection(&self, _p: SocketAddr, _l: SocketAddr) -> Result<SessionId, Refusal> {
        let n = self.checks.fetch_add(1, Ordering::SeqCst);
        let later = self.later_pid.load(Ordering::SeqCst);
        if n > 0 && later != 0 {
            return Ok(browser(later));
        }
        Ok(browser(1234))
    }
    fn record_refused(&self, r: &Refusal) {
        self.refused.lock().unwrap().push(r.clone());
    }
    fn home(&self) -> Result<HomeView, ApiError> {
        Ok(HomeView::default())
    }
    fn projects(&self) -> Result<ProjectsView, ApiError> {
        Ok(ProjectsView::default())
    }
    fn project(&self, _slug: &str) -> Result<ProjectView, ApiError> {
        Ok(ProjectView::default())
    }
    fn secret(&self, key: &KeyName) -> Result<SecretView, ApiError> {
        Ok(SecretView {
            key: key.to_string(),
            ..SecretView::default()
        })
    }
    fn activity(&self, _q: &ActivityQuery) -> Result<ActivityView, ApiError> {
        Ok(ActivityView::default())
    }
    fn export(
        &self,
        _q: &ActivityQuery,
        _f: ExportFormat,
    ) -> Result<(String, &'static str, Vec<u8>), ApiError> {
        Ok(("r.json".into(), "application/json", b"[]".to_vec()))
    }
    fn verify(&self) -> Result<VerifyView, ApiError> {
        Ok(VerifyView::default())
    }
    fn agents(&self) -> Result<AgentsView, ApiError> {
        Ok(AgentsView::default())
    }
    fn scan(&self) -> Result<ScanView, ApiError> {
        Ok(ScanView::default())
    }
}

impl Fake {
    fn called(&self, what: &str) -> ActionResult {
        self.calls.lock().unwrap().push(what.to_owned());
        Ok(ActionOk::new(format!("did {what}")))
    }
}

impl DashActions for Fake {
    fn stop(&self, _a: &Actor) -> ActionResult {
        self.called("stop")
    }
    fn start(&self, _a: &Actor) -> ActionResult {
        self.called("start")
    }
    fn approve(&self, _a: &Actor, id: &str, _s: bool) -> ActionResult {
        self.called(&format!("approve {id}"))
    }
    fn deny(&self, _a: &Actor, id: &str) -> ActionResult {
        self.called(&format!("deny {id}"))
    }
    fn dismiss(&self, _a: &Actor, id: &str) -> ActionResult {
        self.called(&format!("dismiss {id}"))
    }
    fn recheck(&self, _a: &Actor) -> Result<AgentsView, ActionError> {
        self.calls.lock().unwrap().push("recheck".into());
        Ok(AgentsView::default())
    }
    fn scan_run(&self, _a: &Actor) -> ActionResult {
        self.called("scan")
    }
    fn check_path(&self, _a: &Actor, path: &str) -> Result<PathCheck, ActionError> {
        self.calls.lock().unwrap().push(format!("check {path}"));
        Ok(PathCheck {
            ok: true,
            command: Some(format!("cd '{path}' && ms init")),
            ..PathCheck::default()
        })
    }
    fn rules(&self, _a: &Actor, key: &KeyName, _e: &RuleEdit) -> ActionResult {
        self.called(&format!("rules {key}"))
    }
    fn show(&self, _a: &Actor, key: &KeyName) -> Result<Revealed, ActionError> {
        self.calls.lock().unwrap().push(format!("show {key}"));
        if key.as_str() == "bin/blob" {
            return Ok(Revealed::new(SecretBytes::new(vec![0xff, 0xfe])));
        }
        Ok(Revealed::new(SecretBytes::new(
            format!("{CANARY}\"\\\n\u{2028}").into_bytes(),
        )))
    }
    fn copy(&self, _a: &Actor, key: &KeyName) -> ActionResult {
        // msd writes the pasteboard itself; the browser gets only this message.
        self.called(&format!("copy {key}"))
    }
    fn replace(&self, _a: &Actor, key: &KeyName, value: SecretBytes) -> ActionResult {
        self.replaced.lock().unwrap().push(value.expose().to_vec());
        self.called(&format!("replace {key}"))
    }
    fn add_key(&self, _a: &Actor, new: NewKey) -> ActionResult {
        self.replaced
            .lock()
            .unwrap()
            .push(new.value.expose().to_vec());
        self.called(&format!("add {}", new.key))
    }
    fn delete(&self, _a: &Actor, key: &KeyName, force: bool) -> ActionResult {
        self.called(&format!("delete {key} {force}"))
    }
    fn undo(
        &self,
        _a: &Actor,
        project: Option<&str>,
        key: Option<&KeyName>,
    ) -> Result<UndoView, ActionError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("undo {project:?} {key:?}"));
        Ok(UndoView {
            message: "undone".into(),
            ..UndoView::default()
        })
    }
    fn refused(&self, _a: &Actor, action: Action, _k: Option<&KeyName>, why: &str) {
        self.action_refusals
            .lock()
            .unwrap()
            .push((action, why.to_owned()));
    }
}

struct T {
    _rt: tokio::runtime::Runtime,
    dash: Dash,
    fake: Arc<Fake>,
}

fn quiet_port() -> u16 {
    static N: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = std::process::id()
            .wrapping_mul(2_654_435_761)
            .wrapping_add(n * 7919 + 13);
        let port = 20_000 + u16::try_from(seed % 25_000).unwrap();
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn setup() -> T {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let fake = Arc::new(Fake::default());
    let dash = Dash::with_actions(
        DashConfig::new(quiet_port()),
        fake.clone(),
        Some(fake.clone()),
        rt.handle().clone(),
    );
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
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

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

/// Signed in: (port, cookie, csrf).
fn signed_in(t: &T) -> (u16, String, String) {
    let o = t.dash.open().unwrap();
    let r = raw(
        o.port,
        &format!(
            "POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nContent-Type: application/json",
            p = o.port
        ),
        &format!("{{\"token\":\"{}\"}}", o.token),
    );
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
    (
        o.port,
        cookie,
        r.json()["csrf"].as_str().unwrap().to_owned(),
    )
}

/// A POST from the page: Host, Origin, JSON, cookie, CSRF and `Sec-Fetch-Site: same-origin`;
/// `drop` leaves out headers by name.
fn post(port: u16, cookie: &str, csrf: &str, path: &str, body: &str, drop: &[&str]) -> Reply {
    let mut h = vec![
        format!("POST {path} HTTP/1.1"),
        format!("Host: 127.0.0.1:{port}"),
    ];
    let all = [
        ("origin", format!("Origin: http://127.0.0.1:{port}")),
        ("content-type", "Content-Type: application/json".to_owned()),
        ("cookie", format!("Cookie: ms_dash={cookie}")),
        ("csrf", format!("X-Morsec-CSRF: {csrf}")),
        ("fetch", "Sec-Fetch-Site: same-origin".to_owned()),
    ];
    for (name, line) in all {
        if !drop.contains(&name) {
            h.push(line);
        }
    }
    raw(port, &h.join("\r\n"), body)
}

/// A request for every route in the table, with a body it accepts.
fn sample(pattern: &str, action: Action) -> (String, &'static str) {
    let path = pattern
        .replace("{key}", "shop%2Fstripe-secret-key")
        .replace("{slug}", "shop")
        .replace("{id}", "apr-0123");
    let body = match action {
        Action::CheckPath => "{\"path\":\"/tmp/shop\"}",
        Action::Rules => "{\"edit\":{\"add_host\":\"api.stripe.com\"}}",
        Action::Replace => "{\"value\":\"v\"}",
        Action::AddKey => {
            "{\"key\":\"new/key\",\"value\":\"v\",\"mode\":\"swap\",\"tier\":\"test\"}"
        }
        Action::Approve => "{\"scope\":\"once\"}",
        Action::Delete => "{\"force\":false}",
        _ => "{}",
    };
    (path, body)
}

// protects=SPEC D-22, criterion 18, T-98: every action route in the table is refused without the
// session cookie, without the CSRF token, with a foreign or missing Origin, from another site,
// and (value and destructive routes) without Sec-Fetch-Site: same-origin; with all of them it
// reaches msd; nothing refused reaches msd; fails_when=any route acts on a request missing one
// check; no_claim=the browser's own header behaviour
#[test]
fn every_action_route_checks_envelope() {
    let t = setup();
    for (pattern, action) in ACTION_ROUTES {
        // A session per route: each has its own 30-a-minute action bucket.
        let (port, cookie, csrf) = signed_in(&t);
        let (path, body) = sample(pattern, *action);
        let before = t.fake.calls.lock().unwrap().len();
        let cases: Vec<(&[&str], u16)> =
            vec![(&["cookie"], 401), (&["csrf"], 403), (&["origin"], 403)];
        for (drop, want) in cases {
            let r = post(port, &cookie, &csrf, &path, body, drop);
            assert_eq!(r.status, want, "{pattern} without {drop:?}: {r:?}");
        }
        let foreign = raw(
            port,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\nContent-Type: application/json\r\nCookie: ms_dash={cookie}\r\nX-Morsec-CSRF: {csrf}"
            ),
            body,
        );
        assert_eq!(foreign.status, 403, "{pattern} foreign origin");
        let cross = raw(
            port,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: ms_dash={cookie}\r\nX-Morsec-CSRF: {csrf}\r\nSec-Fetch-Site: cross-site"
            ),
            body,
        );
        assert_eq!(cross.status, 403, "{pattern} cross-site");
        let no_fetch = post(port, &cookie, &csrf, &path, body, &["fetch"]);
        if action.sensitive() {
            assert_eq!(no_fetch.status, 403, "{pattern} without Sec-Fetch-Site");
        }
        assert_eq!(
            t.fake.calls.lock().unwrap().len(),
            before + usize::from(!action.sensitive()),
            "{pattern}: nothing refused reached msd"
        );
        let ok = post(port, &cookie, &csrf, &path, body, &[]);
        assert!(ok.status == 200 || ok.status == 202, "{pattern}: {ok:?}");
        std::thread::sleep(Duration::from_millis(120));
    }
    assert!(
        t.fake
            .action_refusals
            .lock()
            .unwrap()
            .iter()
            .any(|(_, why)| why.contains("Sec-Fetch-Site")),
        "missing Sec-Fetch-Site leaves a receipt"
    );
    // A bad body or parameter is refused with `invalid`, before msd.
    let (port, cookie, csrf) = signed_in(&t);
    let n = t.fake.calls.lock().unwrap().len();
    for (path, body) in [
        ("/api/keys/Bad%20Key/show", "{}"),
        ("/api/stop", "{\"x\":1}"),
        ("/api/keys/a%2Fb/rules", "{\"edit\":{\"rm_rf\":\"/\"}}"),
        ("/api/approvals/a%20b/approve", "{}"),
        ("/api/projects/Bad/undo", "{}"),
    ] {
        let r = post(port, &cookie, &csrf, path, body, &[]);
        assert_eq!(r.status, 400, "{path}: {r:?}");
        assert_eq!(r.json()["code"], "invalid", "{path}");
        std::thread::sleep(Duration::from_millis(60));
    }
    assert_eq!(t.fake.calls.lock().unwrap().len(), n);
    assert_eq!(
        post(port, &cookie, &csrf, "/api/nope", "{}", &[]).status,
        404
    );
}

// protects=SPEC D-22, T-89: the connection's process is checked again at request time; when it
// names another process than the one that connected, the action is refused (403) with a receipt
// and msd never sees it; fails_when=an action runs on a connection whose owner changed;
// no_claim=the OS lookup itself (msd dash.rs)
#[test]
fn action_rechecks_connection_owner() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    // From now on: the browser at accept, another process at the request-time check.
    t.fake.checks.store(0, Ordering::SeqCst);
    t.fake.later_pid.store(999, Ordering::SeqCst);
    let r = post(port, &cookie, &csrf, "/api/stop", "{}", &[]);
    assert_eq!(r.status, 403, "{r:?}");
    assert!(t.fake.calls.lock().unwrap().is_empty());
    assert!(
        t.fake
            .refused
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.why.contains("changed"))
    );
}

// protects=SPEC D-12, D-23, criterion 9, T-91: Show's answer carries the value (JSON-escaped)
// with Cache-Control: no-store and every security header; a value that is not text is 409
// not_text; fails_when=the answer is cacheable, lacks a header, or mis-escapes the value;
// no_claim=what the browser does with it (assets reveal_is_cleared, browser QA)
#[test]
fn reveal_response_is_no_store() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let r = post(port, &cookie, &csrf, "/api/keys/shop%2Fx/show", "{}", &[]);
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.h("cache-control"), Some("no-store"));
    assert!(r.h("content-security-policy").is_some());
    assert_eq!(r.h("x-content-type-options"), Some("nosniff"));
    let v = r.json();
    assert_eq!(v["key"], "shop/x");
    assert_eq!(v["value"], format!("{CANARY}\"\\\n\u{2028}"));
    assert_eq!(v["hide_after_ms"], 15000);
    let r = post(port, &cookie, &csrf, "/api/keys/bin%2Fblob/show", "{}", &[]);
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["code"], "not_text");
}

// protects=SPEC D-12, criterion 10: the HTTP layer turns Copy's answer into {ok, message} and
// adds nothing to it; fails_when=anything from the request reaches the answer; no_claim=msd's
// own copy (msd dash_actions::copy_never_sends_value_to_browser runs it for real)
#[test]
fn copy_answer_holds_no_value() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let r = post(port, &cookie, &csrf, "/api/keys/shop%2Fx/copy", "{}", &[]);
    assert_eq!(r.status, 200, "{r:?}");
    assert!(!r.body.contains(CANARY) && !r.body.contains("sk_live_"));
    assert_eq!(r.json()["ok"], true);
}

// protects=SPEC D-13, criterion 12, T-99: a value posted for Replace or Add reaches msd and is
// never echoed in the answer; fails_when=the posted value comes back; no_claim=hyper's buffers
// (residual)
#[test]
fn replace_never_echoes_value() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let body = format!("{{\"value\":\"{CANARY}\"}}");
    let r = post(
        port,
        &cookie,
        &csrf,
        "/api/keys/shop%2Fx/replace",
        &body,
        &[],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert!(!r.body.contains(CANARY));
    let body = format!(
        "{{\"key\":\"n/k\",\"value\":\"{CANARY}\",\"mode\":\"run\",\"tier\":\"production\"}}"
    );
    let r = post(port, &cookie, &csrf, "/api/keys", &body, &[]);
    assert_eq!(r.status, 200, "{r:?}");
    assert!(!r.body.contains(CANARY));
    assert_eq!(
        *t.fake.replaced.lock().unwrap(),
        [CANARY.as_bytes().to_vec(), CANARY.as_bytes().to_vec()]
    );
}

// protects=SPEC D-22, criterion 11: action routes share a bucket of 30 per minute per session;
// the 31st is 429 rate_limited with a receipt and never reaches msd; reads are not counted;
// fails_when=a 31st action runs; no_claim=the refill rate's exact timing
#[test]
fn action_bucket_per_session() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let mut codes = Vec::new();
    for _ in 0..31 {
        codes.push(post(port, &cookie, &csrf, "/api/agents/recheck", "{}", &[]).status);
        std::thread::sleep(Duration::from_millis(60));
    }
    assert!(codes[..30].iter().all(|c| *c == 200), "{codes:?}");
    assert_eq!(codes[30], 429, "{codes:?}");
    assert_eq!(t.fake.calls.lock().unwrap().len(), 30);
    assert!(
        t.fake
            .action_refusals
            .lock()
            .unwrap()
            .iter()
            .any(|(a, why)| *a == Action::Recheck && why.contains("30 actions"))
    );
}

// protects=SPEC D-18, criterion 15: Run scan answers 202 {"started": true} at once (the scan
// runs on msd's thread) and the Scan view carries `running`; fails_when=the route blocks for the
// scan or answers 200; no_claim=msd's scan (dash_actions tests)
#[test]
fn scan_runs_in_background() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let r = post(port, &cookie, &csrf, "/api/scan/run", "{}", &[]);
    assert_eq!(r.status, 202, "{r:?}");
    assert_eq!(r.json()["started"], true);
    assert_eq!(*t.fake.calls.lock().unwrap(), ["scan"]);
    let v = serde_json::to_value(ScanView::default()).unwrap();
    assert_eq!(v["running"], false);
}

// protects=SPEC D-16, criterion 16: Re-check answers the fresh Agents view and is the only
// thing it asks msd for (no other action, no receipt); fails_when=Re-check triggers another
// action or a refusal receipt; no_claim=msd's checks (recheck_clears_settled_drift)
#[test]
fn recheck_changes_nothing() {
    let t = setup();
    let (port, cookie, csrf) = signed_in(&t);
    let r = post(port, &cookie, &csrf, "/api/agents/recheck", "{}", &[]);
    assert_eq!(r.status, 200, "{r:?}");
    assert!(r.json()["agents"].is_object());
    assert_eq!(*t.fake.calls.lock().unwrap(), ["recheck"]);
    assert!(t.fake.action_refusals.lock().unwrap().is_empty());
    assert!(t.fake.refused.lock().unwrap().is_empty());
}

// protects=L33 review N3: approving, starting, rule changes and the scan need
// Sec-Fetch-Site: same-origin too, like the value and destructive routes; read-only and
// refusing actions don't; fails_when=one of them accepts a request without it;
// no_claim=-
#[test]
fn approving_actions_need_fetch_site() {
    for a in [
        Action::Approve,
        Action::Dismiss,
        Action::Start,
        Action::Rules,
        Action::ScanRun,
        Action::Show,
        Action::Copy,
        Action::Replace,
        Action::AddKey,
        Action::Delete,
        Action::UndoKey,
        Action::UndoProject,
    ] {
        assert!(a.sensitive(), "{a:?}");
    }
    for a in [
        Action::Stop,
        Action::Deny,
        Action::Recheck,
        Action::CheckPath,
    ] {
        assert!(!a.sensitive(), "{a:?}");
    }
}
