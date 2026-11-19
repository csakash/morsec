//! One HTTP request: the checks of design §6.2.4 in order, then the route. Every response, the
//! refusals included, goes through [`finish`], which sets the headers of §6.2.5.

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, ORIGIN};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use ms_core::{KeyName, SessionId};
use serde::Deserialize;

use crate::actions::{
    Action, ActionCode, ActionError, ActionOk, Actor, ModeArg, NewKey, Revealed, RuleEdit, TierArg,
    match_route, valid_id, valid_slug,
};
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

/// The connection a request came on.
#[derive(Debug, Clone, Copy)]
pub struct Conn {
    /// The port the dashboard holds.
    pub port: u16,
    /// The client's address.
    pub peer: SocketAddr,
    /// The listener's address.
    pub local: SocketAddr,
}

/// Handles one request on a connection that passed the process check.
pub async fn handle(
    inner: &Inner,
    conn: Conn,
    who: &SessionId,
    req: hyper::Request<Incoming>,
) -> Resp {
    let port = conn.port;
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
        let Some(cookie) = cookie else {
            return json_error(StatusCode::UNAUTHORIZED, "morsec: no dashboard session");
        };
        return route_action(inner, conn, who, h, path, &cookie, body_bytes, now).await;
    }
    route_get(inner, path, query).await
}

/// An action that did not happen, as `{"error", "code"}` with the code's status.
fn action_error(e: &ActionError) -> Resp {
    let body = serde_json::json!({ "error": e.message, "code": e.code })
        .to_string()
        .into_bytes();
    finish(
        StatusCode::from_u16(e.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        "application/json",
        body,
    )
}

/// `{"ok": true, "message", <extra>}`.
fn action_ok(ok: &ActionOk, extra: Option<(&str, serde_json::Value)>) -> Resp {
    let mut v = serde_json::json!({ "ok": true, "message": ok.message });
    if let (Some((k, x)), Some(m)) = (extra, v.as_object_mut()) {
        m.insert(k.to_owned(), x);
    }
    finish(
        StatusCode::OK,
        "application/json",
        v.to_string().into_bytes(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveReq {
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathReq {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanReq {
    plan: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathPlanReq {
    path: String,
    plan: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesReq {
    edit: RuleEdit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueReq {
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddReq {
    key: String,
    value: String,
    mode: ModeArg,
    tier: TierArg,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteReq {
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoReq {
    #[serde(default)]
    key: Option<String>,
}

/// A parsed action request: the route's parameter and body, checked.
enum Call {
    Stop,
    Start,
    Approve(String, bool),
    Deny(String),
    Dismiss(String),
    Recheck,
    ScanRun,
    CheckPath(String),
    Rules(KeyName, RuleEdit),
    Show(KeyName),
    Copy(KeyName),
    Replace(KeyName, ms_core::SecretBytes),
    Add(NewKey),
    Delete(KeyName, bool),
    UndoKey(KeyName),
    UndoProject(String, Option<KeyName>),
    AgentPreview(String, bool),
    AgentApply(String, bool, String),
    ProjectPreview(String),
    ProjectAdd(String, String),
}

fn key_param(raw: Option<&str>) -> Option<KeyName> {
    raw.and_then(crate::api::percent_decode)
        .and_then(|s| KeyName::new(&s).ok())
}

/// The key the request names, for receipts of refusals.
fn key_of(action: Action, raw: Option<&str>) -> Option<KeyName> {
    match action {
        Action::Rules
        | Action::Show
        | Action::Copy
        | Action::Replace
        | Action::Delete
        | Action::UndoKey => key_param(raw),
        _ => None,
    }
}

fn parse_call(action: Action, raw: Option<&str>, body: &[u8]) -> Result<Call, String> {
    fn body_of<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, String> {
        serde_json::from_slice(b)
            .map_err(|e| format!("morsec: the request body is not as expected ({e})"))
    }
    let key = || key_param(raw).ok_or_else(|| "morsec: that is not a key name".to_owned());
    let agent = || {
        raw.filter(|a| crate::actions::valid_agent(a))
            .map(str::to_owned)
            .ok_or_else(|| "morsec: the dashboard connects claude-code or codex".to_owned())
    };
    let plan = |p: String| {
        if crate::actions::valid_plan(&p) {
            Ok(p)
        } else {
            Err("morsec: that is not a plan from a preview".to_owned())
        }
    };
    let folder = |p: String| {
        if p.is_empty() || p.len() > 4096 {
            Err("morsec: give the folder's full path".to_owned())
        } else {
            Ok(p)
        }
    };
    let id = || {
        raw.filter(|i| valid_id(i))
            .map(str::to_owned)
            .ok_or_else(|| "morsec: that is not a request id".to_owned())
    };
    Ok(match action {
        Action::Stop => body_of::<Empty>(body).map(|_| Call::Stop)?,
        Action::Start => body_of::<Empty>(body).map(|_| Call::Start)?,
        Action::Approve => {
            let r: ApproveReq = body_of(body)?;
            let session = match r.scope.as_deref() {
                None | Some("once") => false,
                Some("session") => true,
                Some(_) => return Err("morsec: scope is once or session".into()),
            };
            Call::Approve(id()?, session)
        }
        Action::Deny => body_of::<Empty>(body).and_then(|_| Ok(Call::Deny(id()?)))?,
        Action::Dismiss => body_of::<Empty>(body).and_then(|_| Ok(Call::Dismiss(id()?)))?,
        Action::Recheck => body_of::<Empty>(body).map(|_| Call::Recheck)?,
        Action::ScanRun => body_of::<Empty>(body).map(|_| Call::ScanRun)?,
        Action::CheckPath => {
            let r: PathReq = body_of(body)?;
            if r.path.is_empty() || r.path.len() > 4096 {
                return Err("morsec: give the folder's full path".into());
            }
            Call::CheckPath(r.path)
        }
        Action::Rules => {
            let r: RulesReq = body_of(body)?;
            Call::Rules(key()?, r.edit)
        }
        Action::Show => body_of::<Empty>(body).and_then(|_| Ok(Call::Show(key()?)))?,
        Action::Copy => body_of::<Empty>(body).and_then(|_| Ok(Call::Copy(key()?)))?,
        Action::Replace => {
            let r: ValueReq = body_of(body)?;
            Call::Replace(key()?, ms_core::SecretBytes::new(r.value.into_bytes()))
        }
        Action::AddKey => {
            let r: AddReq = body_of(body)?;
            let key = KeyName::new(&r.key).map_err(|e| format!("morsec: {e}"))?;
            Call::Add(NewKey {
                key,
                value: ms_core::SecretBytes::new(r.value.into_bytes()),
                mode: r.mode.into(),
                tier: r.tier.into(),
            })
        }
        Action::Delete => {
            let r: DeleteReq = body_of(body)?;
            Call::Delete(key()?, r.force)
        }
        Action::UndoKey => body_of::<Empty>(body).and_then(|_| Ok(Call::UndoKey(key()?)))?,
        Action::UndoProject => {
            let r: UndoReq = body_of(body)?;
            let slug = raw
                .filter(|s| valid_slug(s))
                .ok_or_else(|| "morsec: that is not a project name".to_owned())?;
            let k = match r.key {
                Some(k) => Some(KeyName::new(&k).map_err(|e| format!("morsec: {e}"))?),
                None => None,
            };
            Call::UndoProject(slug.to_owned(), k)
        }
        Action::ConnectPreview | Action::DisconnectPreview => {
            body_of::<Empty>(body)?;
            Call::AgentPreview(agent()?, action == Action::DisconnectPreview)
        }
        Action::Connect | Action::Disconnect => {
            let r: PlanReq = body_of(body)?;
            Call::AgentApply(agent()?, action == Action::Disconnect, plan(r.plan)?)
        }
        Action::ProjectPreview => {
            let r: PathReq = body_of(body)?;
            Call::ProjectPreview(folder(r.path)?)
        }
        Action::ProjectAdd => {
            let r: PathPlanReq = body_of(body)?;
            Call::ProjectAdd(folder(r.path)?, plan(r.plan)?)
        }
    })
}

/// An action request that passed the envelope (L33 SPEC D-22): the action bucket, the
/// `Sec-Fetch-Site` requirement for value and destructive routes, the request-time process
/// re-check, then the call itself on a blocking thread.
#[allow(clippy::too_many_arguments)]
async fn route_action(
    inner: &Inner,
    conn: Conn,
    who: &SessionId,
    h: &HeaderMap,
    path: &str,
    cookie: &str,
    body: Bytes,
    now: Instant,
) -> Resp {
    let Some((action, raw)) = match_route(path) else {
        return json_error(StatusCode::NOT_FOUND, "morsec: no such action");
    };
    let Some(acts) = inner.actions() else {
        return json_error(StatusCode::NOT_FOUND, "morsec: no such action");
    };
    let actor = Actor {
        session: who.clone(),
        peer: conn.peer,
        local: conn.local,
    };
    let key = key_of(action, raw.as_deref());
    if !inner.take_action(cookie, now) {
        inner
            .refused_action(&actor, action, key, "over 30 actions a minute")
            .await;
        return action_error(&ActionError::new(
            ActionCode::RateLimited,
            "morsec: over 30 actions a minute. Wait a minute and try again",
        ));
    }
    if action.sensitive() && header(h, "sec-fetch-site") != Some("same-origin") {
        inner
            .refused_action(
                &actor,
                action,
                key,
                "Sec-Fetch-Site: same-origin is missing",
            )
            .await;
        return action_error(&ActionError::new(
            ActionCode::Refused,
            "morsec: refused: this action is only taken from the dashboard page in a browser",
        ));
    }
    // The connection's process, checked again now (SPEC D-22): an agent that took over the
    // browser's connection, or a reused port, is refused before anything happens.
    let data = inner.data();
    let (peer, local) = (conn.peer, conn.local);
    let again = tokio::task::spawn_blocking(move || data.check_connection(peer, local)).await;
    match again {
        Ok(Ok(now_who))
            if now_who.pid == who.pid && now_who.started_unix_ms == who.started_unix_ms => {}
        Ok(Ok(_)) => {
            return refuse(
                inner,
                who,
                StatusCode::FORBIDDEN,
                "the connection's process changed since it connected",
            )
            .await;
        }
        Ok(Err(r)) => {
            let why = r.why.clone();
            inner.refused(r).await;
            return json_error(StatusCode::FORBIDDEN, &format!("morsec: refused: {why}"));
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "morsec: the dashboard failed handling this request",
            );
        }
    }
    let call = match parse_call(action, raw.as_deref(), &body) {
        Ok(c) => c,
        Err(m) => {
            inner
                .refused_action(&actor, action, key, "invalid request")
                .await;
            return action_error(&ActionError::new(ActionCode::Invalid, m));
        }
    };
    drop(body);
    let out = tokio::task::spawn_blocking(move || -> Resp {
        let done = |r: Result<ActionOk, ActionError>| match r {
            Ok(ok) => action_ok(&ok, None),
            Err(e) => action_error(&e),
        };
        let a = &actor;
        match call {
            Call::Stop => done(acts.stop(a)),
            Call::Start => done(acts.start(a)),
            Call::Approve(id, session) => done(acts.approve(a, &id, session)),
            Call::Deny(id) => done(acts.deny(a, &id)),
            Call::Dismiss(id) => done(acts.dismiss(a, &id)),
            Call::Recheck => match acts.recheck(a) {
                Ok(v) => action_ok(
                    &ActionOk::new("checked again"),
                    serde_json::to_value(&v).ok().map(|v| ("agents", v)),
                ),
                Err(e) => action_error(&e),
            },
            Call::ScanRun => match acts.scan_run(a) {
                Ok(ok) => {
                    let mut r = action_ok(&ok, Some(("started", serde_json::Value::Bool(true))));
                    *r.status_mut() = StatusCode::ACCEPTED;
                    r
                }
                Err(e) => action_error(&e),
            },
            Call::CheckPath(p) => match acts.check_path(a, &p) {
                Ok(c) => action_ok(
                    &ActionOk::new(if c.ok {
                        "Checked"
                    } else {
                        "That folder can't be set up as a project"
                    }),
                    serde_json::to_value(&c).ok().map(|v| ("check", v)),
                ),
                Err(e) => action_error(&e),
            },
            Call::Rules(k, e) => done(acts.rules(a, &k, &e)),
            Call::Show(k) => match acts.show(a, &k) {
                Ok(v) => reveal_response(&k, v),
                Err(e) => action_error(&e),
            },
            Call::Copy(k) => done(acts.copy(a, &k)),
            Call::Replace(k, v) => done(acts.replace(a, &k, v)),
            Call::Add(n) => done(acts.add_key(a, n)),
            Call::Delete(k, force) => done(acts.delete(a, &k, force)),
            Call::UndoKey(k) => undo_answer(acts.undo(a, None, Some(&k))),
            Call::UndoProject(slug, k) => undo_answer(acts.undo(a, Some(&slug), k.as_ref())),
            Call::AgentPreview(agent, off) => match acts.agent_preview(a, &agent, off) {
                Ok(v) => action_ok(
                    &ActionOk::new(if v.nothing_to_do {
                        "Nothing to change"
                    } else {
                        "Review the changes"
                    }),
                    serde_json::to_value(&v).ok().map(|v| ("preview", v)),
                ),
                Err(e) => action_error(&e),
            },
            Call::AgentApply(agent, off, plan) => done(acts.agent_apply(a, &agent, off, &plan)),
            Call::ProjectPreview(path) => match acts.project_preview(a, &path) {
                Ok(v) => action_ok(
                    &ActionOk::new(if v.ok {
                        "Review what will be set up"
                    } else {
                        "That folder can't be set up as a project"
                    }),
                    serde_json::to_value(&v).ok().map(|v| ("preview", v)),
                ),
                Err(e) => action_error(&e),
            },
            Call::ProjectAdd(path, plan) => match acts.project_add(a, &path, &plan) {
                Ok(v) => action_ok(
                    &ActionOk::new(v.message.clone()),
                    serde_json::to_value(&v).ok().map(|v| ("setup", v)),
                ),
                Err(e) => action_error(&e),
            },
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

fn undo_answer(r: Result<crate::actions::UndoView, ActionError>) -> Resp {
    match r {
        Ok(v) => action_ok(
            &ActionOk::new(v.message.clone()),
            serde_json::to_value(&v).ok().map(|v| ("undo", v)),
        ),
        Err(e) => action_error(&e),
    }
}

/// Appends `s` to `out` as the inside of a JSON string.
fn push_json_str(out: &mut Vec<u8>, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                let code = c as u32;
                let hex = b"0123456789abcdef";
                out.extend_from_slice(b"\\u");
                for shift in [12, 8, 4, 0] {
                    out.push(hex[((code >> shift) & 0xf) as usize]);
                }
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

/// Owns the response body of a Show and wipes it when hyper drops the body.
struct WipedBody(zeroize::Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for WipedBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The one place a value is written into a response (SPEC D-12, D-23): `{"key", "value",
/// "hide_after_ms": 15000}`, built by hand into a buffer that is zeroized when hyper drops the
/// body (reserved up front so it never reallocates and leaves a copy behind), with
/// `Cache-Control: no-store` like every response. A value that is not UTF-8 is refused (409).
pub fn reveal_response(key: &KeyName, v: Revealed) -> Resp {
    let Ok(text) = std::str::from_utf8(v.0.expose()) else {
        return action_error(&ActionError::new(
            ActionCode::NotText,
            "morsec: this value is not text, so it can't be shown. Use it through morsec as it is",
        ));
    };
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(
        text.len() * 6 + key.as_str().len() * 6 + 64,
    ));
    out.extend_from_slice(b"{\"key\":\"");
    push_json_str(&mut out, key.as_str());
    out.extend_from_slice(b"\",\"value\":\"");
    push_json_str(&mut out, text);
    out.extend_from_slice(b"\",\"hide_after_ms\":15000}");
    drop(v);
    let body = Bytes::from_owner(WipedBody(out));
    let mut r = Response::new(Full::new(body));
    *r.status_mut() = StatusCode::OK;
    let h = r.headers_mut();
    for (k, v) in security_headers() {
        h.insert(k, HeaderValue::from_static(v));
    }
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
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
