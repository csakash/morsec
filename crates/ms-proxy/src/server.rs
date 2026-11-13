//! The listener and request handling.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::request::Parts;
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ms_approve::ApprovalOutcome;
use ms_core::{
    Decision, KeyName, Mode, Reason, ReceiptEvent, ReceiptResult, Request as PolicyRequest,
    SessionId,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::config::{Binding, ProxyConfig};
use crate::deps::{BlockEvent, BlockKind, Deps};
use crate::error::ProxyError;
use crate::idle::{Activity, IdleIo, until_idle};
use crate::rewrite::{self, Plan};
use crate::ssrf::{self, Checked};
use crate::upstream::{self, Cache, UpstreamError};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Body type the proxy returns to the agent.
pub(crate) type Body = BoxBody<Bytes, BoxError>;

/// A bound, not yet serving, swap proxy.
#[derive(Debug)]
pub struct Proxy {
    listener: TcpListener,
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    cfg: ProxyConfig,
    deps: Deps,
    client_tls: Arc<rustls::ClientConfig>,
    /// Bytes (in KiB) that inspected request bodies may hold in memory at once.
    body_budget: Arc<Semaphore>,
    #[cfg(test)]
    loopback_ok: bool,
}

/// How long a request waits for room in the body budget before `503`.
const BUDGET_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A request body read by the proxy, with the budget it holds.
#[derive(Debug)]
struct Collected {
    bytes: Bytes,
    overflow: bool,
    _budget: OwnedSemaphorePermit,
}

/// One terminated CONNECT tunnel to a bound host.
#[derive(Debug)]
struct Tunnel {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
    session: SessionId,
    upstream: Cache,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Escapes and truncates agent-supplied text before it goes into a message or log.
fn printable(s: &str) -> String {
    s.chars().take(253).flat_map(char::escape_default).collect()
}

fn text(status: StatusCode, msg: impl Into<String>) -> Response<Body> {
    let mut body = msg.into();
    body.push('\n');
    let mut r = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *r.status_mut() = status;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r.headers_mut()
        .insert("x-morsec", http::HeaderValue::from_static("refused"));
    r
}

/// `host` lowercased without a trailing dot or IPv6 brackets, and the port.
fn split_authority(a: &http::uri::Authority, default_port: u16) -> (String, u16) {
    let host = a
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (host, a.port_u16().unwrap_or(default_port))
}

fn proxy_user(parts: &Parts) -> Option<String> {
    let v = parts
        .headers
        .get(http::header::PROXY_AUTHORIZATION)?
        .to_str()
        .ok()?;
    let b64 = v.get(..6).filter(|s| s.eq_ignore_ascii_case("basic "))?;
    let _ = b64;
    let raw = B64.decode(v[6..].trim()).ok()?;
    let s = String::from_utf8(raw).ok()?;
    Some(s.split_once(':').map_or(s.clone(), |(u, _)| u.to_owned()))
}

impl Proxy {
    /// Validates `cfg` against the CA and binds the listener.
    pub async fn bind(cfg: ProxyConfig, deps: Deps) -> Result<Self, ProxyError> {
        cfg.validate(deps.ca.hosts())?;
        let client_tls = crate::tls::client_config(&cfg.upstream_roots)?;
        let budget_kib = cfg
            .limits
            .max_buffered_bytes
            .div_ceil(1024)
            .min(Semaphore::MAX_PERMITS);
        let listener = TcpListener::bind(cfg.listen)
            .await
            .map_err(|source| ProxyError::Io {
                context: "bind",
                source,
            })?;
        Ok(Self {
            listener,
            inner: Arc::new(Inner {
                cfg,
                deps,
                client_tls,
                body_budget: Arc::new(Semaphore::new(budget_kib)),
                #[cfg(test)]
                loopback_ok: false,
            }),
        })
    }

    /// Lets the in-crate tests reach upstream servers on 127.0.0.1.
    #[cfg(test)]
    pub(crate) fn allow_loopback_upstreams_for_tests(&mut self) {
        Arc::get_mut(&mut self.inner)
            .expect("not serving yet")
            .loopback_ok = true;
    }

    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.listener.local_addr().map_err(|source| ProxyError::Io {
            context: "local_addr",
            source,
        })
    }

    /// Serves until `shutdown` resolves. In-flight connections finish on their own.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let sem = Arc::new(Semaphore::new(self.inner.cfg.limits.max_connections));
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                p = sem.clone().acquire_owned() => match p { Ok(p) => p, Err(_) => break },
                () = &mut shutdown => break,
            };
            let accepted = tokio::select! {
                a = self.listener.accept() => a,
                () = &mut shutdown => break,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    let inner = self.inner.clone();
                    // The permit travels into any tunnel this connection becomes, so CONNECT
                    // tunnels count against max_connections for as long as they live.
                    let permit = Arc::new(permit);
                    tokio::spawn(inner.connection(tcp, peer, permit));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "morsec proxy accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
}

impl Inner {
    fn loopback_ok(&self) -> bool {
        #[cfg(test)]
        {
            self.loopback_ok
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn block(&self, session: Option<&SessionId>, host: &str, port: u16, kind: BlockKind) {
        self.deps.egress.blocked(&BlockEvent {
            session: session.cloned(),
            host: printable(host),
            port,
            kind,
        });
    }

    fn receipt(
        &self,
        session: &SessionId,
        key: &KeyName,
        host: &str,
        result: ReceiptResult,
        approval_id: Option<String>,
        rule_version: u64,
    ) -> ms_core::Result<()> {
        self.deps
            .receipts
            .append(ReceiptEvent {
                time_unix_ms: now_ms(),
                session: session.clone(),
                key: key.clone(),
                mode: Mode::Swap,
                target: printable(host),
                argv_hash: None,
                rule_version,
                approval_id,
                result,
            })
            .map(drop)
    }

    /// Records one `Blocked(HostNotAllowed)` receipt per key, then refuses.
    fn refuse_refs(&self, session: &SessionId, keys: &[KeyName], host: &str) -> Response<Body> {
        for k in keys {
            if let Err(e) = self.receipt(
                session,
                k,
                host,
                ReceiptResult::Blocked(Reason::HostNotAllowed),
                None,
                self.deps.policy.version(),
            ) {
                tracing::error!(error = %e, "morsec proxy could not record a block receipt");
            }
        }
        let names: Vec<String> = keys.iter().map(|k| format!("ms://{k}")).collect();
        text(
            StatusCode::FORBIDDEN,
            format!(
                "morsec: blocked. {} is not bound to {}; nothing was sent. If this host should get the key, bind it with: ms rules",
                names.join(", "),
                printable(host)
            ),
        )
    }

    async fn connection(
        self: Arc<Self>,
        tcp: TcpStream,
        peer: SocketAddr,
        permit: Arc<OwnedSemaphorePermit>,
    ) {
        let limits = &self.cfg.limits;
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let permit = permit.clone();
            async move { Ok::<_, Infallible>(me.front(req, peer, permit).await) }
        });
        let mut b = hyper::server::conn::http1::Builder::new();
        b.timer(TokioTimer::new())
            .header_read_timeout(limits.header_read_timeout)
            .max_buf_size(limits.max_head_bytes.max(8192));
        let _ = b
            .serve_connection(TokioIo::new(tcp), svc)
            .with_upgrades()
            .await;
    }

    /// A request on the proxy port: CONNECT, absolute-form `http://`, or base-URL mode.
    async fn front(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let user = proxy_user(&parts);
        let Some(session) = self.deps.sessions.resolve(peer, user.as_deref()) else {
            let host = parts.uri.host().unwrap_or("").to_owned();
            self.block(None, &host, 0, BlockKind::NoSession);
            return text(
                StatusCode::FORBIDDEN,
                "morsec: this connection is not from a known agent session, so nothing was forwarded. Start the agent through a morsec connector (ms connect)",
            );
        };
        if parts.method == Method::CONNECT {
            let req = Request::from_parts(parts, body);
            return self.connect(req, session, permit).await;
        }
        if parts.uri.scheme().is_some() {
            return self.plain(parts, body, session).await;
        }
        if let Some(rest) = parts.uri.path().strip_prefix("/p/") {
            let rest = rest.to_owned();
            return self.base_url(parts, body, session, &rest).await;
        }
        text(
            StatusCode::BAD_REQUEST,
            "morsec: this is the morsec swap proxy. Set HTTPS_PROXY to it, or use a base URL of the form /p/<provider>/…",
        )
    }

    async fn check(
        &self,
        host: &str,
        port: u16,
        session: &SessionId,
    ) -> Result<Vec<SocketAddr>, Response<Body>> {
        match ssrf::check(&*self.deps.resolver, host, port, self.loopback_ok()).await {
            Ok(Checked::Ok(a)) => Ok(a),
            Ok(Checked::Refused(ip, why)) => {
                self.block(Some(session), host, port, BlockKind::NonPublicAddress);
                Err(text(
                    StatusCode::FORBIDDEN,
                    format!(
                        "morsec: blocked. {} resolves to {ip} ({why:?}), which is not a public address. The proxy never connects to private, loopback, link-local or metadata addresses",
                        printable(host)
                    ),
                ))
            }
            Ok(Checked::NoAddress) | Err(_) => Err(text(
                StatusCode::BAD_GATEWAY,
                format!(
                    "morsec: could not resolve {}. Check the host name",
                    printable(host)
                ),
            )),
        }
    }

    fn bound(&self, host: &str, port: u16) -> Vec<&Binding> {
        self.cfg
            .bindings
            .iter()
            .filter(|b| b.serves(host, port))
            .collect()
    }

    fn is_bound_host(&self, host: &str) -> bool {
        self.cfg
            .bindings
            .iter()
            .any(|b| b.hosts.iter().any(|h| h == host))
    }

    async fn connect(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        session: SessionId,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<Body> {
        let Some(auth) = req.uri().authority().cloned() else {
            return text(StatusCode::BAD_REQUEST, "morsec: CONNECT needs host:port");
        };
        let (host, port) = split_authority(&auth, 443);
        let bound = !self.bound(&host, port).is_empty();
        if !bound && !self.cfg.allowed(&host) {
            self.block(Some(&session), &host, port, BlockKind::NotAllowed);
            return text(
                StatusCode::FORBIDDEN,
                format!(
                    "morsec: blocked. {}:{port} is not on the egress allowlist and no key is bound to it. Allow it with: ms rules",
                    printable(&host)
                ),
            );
        }
        let addrs = match self.check(&host, port, &session).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let upgrade = hyper::upgrade::on(&mut req);
        if bound {
            let tunnel = Arc::new(Tunnel {
                host,
                port,
                addrs,
                session,
                upstream: Cache::default(),
            });
            let me = self.clone();
            tokio::spawn(async move {
                if let Ok(up) = upgrade.await {
                    me.mitm(up, tunnel).await;
                }
                drop(permit);
            });
        } else {
            let mut up_tcp =
                match upstream::tcp(&addrs, self.cfg.limits.upstream_connect_timeout).await {
                    Ok(s) => s,
                    Err(UpstreamError(e)) => {
                        return text(
                            StatusCode::BAD_GATEWAY,
                            format!("morsec: could not reach {}: {e}", printable(&host)),
                        );
                    }
                };
            let idle = self.cfg.limits.tunnel_idle_timeout;
            tokio::spawn(async move {
                if let Ok(up) = upgrade.await {
                    let act = Activity::new();
                    let mut agent = IdleIo::new(TokioIo::new(up), act.clone());
                    let pipe = tokio::io::copy_bidirectional(&mut agent, &mut up_tcp);
                    until_idle(pipe, act, idle).await;
                }
                drop(permit);
            });
        }
        Response::new(
            http_body_util::Empty::new()
                .map_err(|never| match never {})
                .boxed(),
        )
    }

    async fn mitm(self: Arc<Self>, up: hyper::upgrade::Upgraded, t: Arc<Tunnel>) {
        let limits = &self.cfg.limits;
        let act = Activity::new();
        let acceptor = tokio_rustls::LazyConfigAcceptor::new(
            rustls::server::Acceptor::default(),
            IdleIo::new(TokioIo::new(up), act.clone()),
        );
        let Ok(Ok(start)) = timeout(limits.header_read_timeout, acceptor).await else {
            return;
        };
        let sni = start
            .client_hello()
            .server_name()
            .map(str::to_ascii_lowercase);
        if sni
            .as_deref()
            .is_some_and(|s| s.trim_end_matches('.') != t.host)
        {
            self.block(
                Some(&t.session),
                sni.as_deref().unwrap_or(""),
                t.port,
                BlockKind::Protocol,
            );
            return;
        }
        let cfg = match self.deps.ca.server_config(&t.host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "morsec proxy could not issue a leaf");
                return;
            }
        };
        let Ok(Ok(tls)) = timeout(limits.header_read_timeout, start.into_stream(cfg)).await else {
            return;
        };
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let t = t.clone();
            async move { Ok::<_, Infallible>(me.inspected(req, t).await) }
        });
        let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        b.http1()
            .timer(TokioTimer::new())
            .header_read_timeout(limits.header_read_timeout)
            .max_buf_size(limits.max_head_bytes.max(8192));
        b.http2()
            .timer(TokioTimer::new())
            .max_header_list_size(limits.max_head_bytes.try_into().unwrap_or(u32::MAX))
            .max_concurrent_streams(32)
            .keep_alive_interval(Some(std::time::Duration::from_secs(30)))
            .keep_alive_timeout(std::time::Duration::from_secs(20));
        // Boxed with an explicit output type: hyper-util's connection future otherwise trips a
        // higher-ranked `From` inference inside `tokio::spawn`.
        let conn: std::pin::Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + '_>> =
            Box::pin(b.serve_connection(TokioIo::new(tls), svc));
        until_idle(conn, act, limits.tunnel_idle_timeout).await;
    }

    /// A request inside a terminated tunnel to a bound host.
    async fn inspected(self: Arc<Self>, req: Request<Incoming>, t: Arc<Tunnel>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let named = parts.uri.authority().cloned().or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.parse().ok())
        });
        let ok = named.is_some_and(|a| {
            let (h, p) = split_authority(&a, t.port);
            h == t.host && p == t.port
        });
        if !ok {
            self.block(Some(&t.session), &t.host, t.port, BlockKind::Protocol);
            return text(
                StatusCode::MISDIRECTED_REQUEST,
                format!(
                    "morsec: the request names a different host than the tunnel to {}; open a new connection for it",
                    t.host
                ),
            );
        }
        self.swap_and_send(
            parts,
            body,
            &t.session,
            &t.host,
            t.port,
            Some(&t.addrs),
            Some(&t.upstream),
        )
        .await
    }

    async fn base_url(
        self: Arc<Self>,
        mut parts: Parts,
        body: Incoming,
        session: SessionId,
        rest: &str,
    ) -> Response<Body> {
        let (provider, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(b) = self.cfg.bindings.iter().find(|b| b.provider == provider) else {
            return text(
                StatusCode::NOT_FOUND,
                format!(
                    "morsec: no provider named {}. List bound keys with: ms rules",
                    printable(provider)
                ),
            );
        };
        let host = b.hosts[0].clone();
        let port = b.port;
        let pq = match parts.uri.query() {
            Some(q) => format!("/{tail}?{q}"),
            None => format!("/{tail}"),
        };
        match pq.parse() {
            Ok(u) => parts.uri = u,
            Err(_) => return text(StatusCode::BAD_REQUEST, "morsec: bad base-URL path"),
        }
        parts.headers.remove(http::header::HOST);
        self.swap_and_send(parts, body, &session, &host, port, None, None)
            .await
    }

    /// Reads up to `max_body_bytes` of `body`, holding that much of the global buffer budget.
    /// Never fails on size: `overflow` says the body was longer and only a prefix was kept.
    async fn collect(
        &self,
        parts: &Parts,
        mut body: Incoming,
    ) -> Result<Collected, Response<Body>> {
        let max = self.cfg.limits.max_body_bytes;
        let declared = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok());
        let reserve = declared.unwrap_or(max).min(max);
        let kib = u32::try_from(reserve.div_ceil(1024).max(1)).unwrap_or(u32::MAX);
        let budget = match timeout(
            BUDGET_WAIT,
            self.body_budget.clone().acquire_many_owned(kib),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => {
                return Err(text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "morsec: too many large requests in flight; nothing was sent. Retry shortly",
                ));
            }
        };
        let mut buf = Vec::with_capacity(reserve.min(64 * 1024));
        let mut overflow = false;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                return Err(text(
                    StatusCode::BAD_REQUEST,
                    "morsec: could not read the request body",
                ));
            };
            if let Ok(data) = frame.into_data() {
                let room = reserve.saturating_sub(buf.len());
                if data.len() > room {
                    buf.extend_from_slice(&data[..room]);
                    overflow = true;
                    break;
                }
                buf.extend_from_slice(&data);
            }
        }
        Ok(Collected {
            bytes: Bytes::from(buf),
            overflow,
            _budget: budget,
        })
    }

    fn too_large(&self) -> Response<Body> {
        text(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "morsec: request body is over the {} byte limit for requests the proxy inspects; nothing was sent",
                self.cfg.limits.max_body_bytes
            ),
        )
    }

    /// Decides, swaps and forwards one request to a bound host.
    #[allow(clippy::too_many_arguments)]
    async fn swap_and_send(
        &self,
        mut parts: Parts,
        body: Incoming,
        session: &SessionId,
        host: &str,
        port: u16,
        addrs: Option<&Vec<SocketAddr>>,
        cache: Option<&Cache>,
    ) -> Response<Body> {
        let collected = match self.collect(&parts, body).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        if collected.overflow {
            return self.too_large();
        }
        let body = collected.bytes.clone();
        let local = self.bound(host, port);
        let binding = match rewrite::plan(host, port, &parts, &body, &self.cfg.bindings) {
            Plan::Block(keys) => return self.refuse_refs(session, &keys, host),
            Plan::Ambiguous => {
                return text(
                    StatusCode::FORBIDDEN,
                    "morsec: blocked. The request carries placeholders for two keys of this host; send one per request",
                );
            }
            Plan::Forward(b) => b,
        };
        rewrite::strip_hop_by_hop(&mut parts.headers);
        let addrs = match addrs {
            Some(a) => a.clone(),
            None => match self.check(host, port, session).await {
                Ok(a) => a,
                Err(r) => return r,
            },
        };
        let mut result = ReceiptResult::Allowed;
        let mut approval_id = None;
        match binding {
            None => rewrite::strip_credentials(&mut parts.headers, &local),
            Some(b) => {
                let preq = PolicyRequest::Swap {
                    key: b.key.clone(),
                    host: host.to_owned(),
                };
                let (decision, version) = self.deps.policy.decide(session, &preq);
                let rule_version = version;
                match decision {
                    Decision::Allow => {}
                    Decision::Deny { reason } => {
                        let _ = self.receipt(
                            session,
                            &b.key,
                            host,
                            ReceiptResult::Blocked(reason.clone()),
                            None,
                            rule_version,
                        );
                        return text(
                            StatusCode::FORBIDDEN,
                            format!(
                                "morsec: blocked by your rules ({reason:?}): ms://{} to {host}. See: ms rules",
                                b.key
                            ),
                        );
                    }
                    Decision::NeedsApproval { request } => {
                        let outcome = match self.deps.approver.clone() {
                            Some(a) => {
                                let t = self.cfg.limits.approval_timeout;
                                tokio::task::spawn_blocking(move || a.ask(&request, t))
                                    .await
                                    .unwrap_or(ApprovalOutcome::Denied)
                            }
                            None => ApprovalOutcome::Denied,
                        };
                        match outcome {
                            ApprovalOutcome::Approved(tok) => {
                                result = ReceiptResult::Approved;
                                approval_id = Some(tok.id);
                            }
                            ApprovalOutcome::Denied | ApprovalOutcome::TimedOut => {
                                let _ = self.receipt(
                                    session,
                                    &b.key,
                                    host,
                                    ReceiptResult::Denied,
                                    None,
                                    rule_version,
                                );
                                return text(
                                    StatusCode::FORBIDDEN,
                                    format!(
                                        "morsec: ms://{} needs approval for {host} and it was not given; nothing was sent",
                                        b.key
                                    ),
                                );
                            }
                        }
                    }
                }
                let vault = self.deps.vault.clone();
                let b2 = b.clone();
                let local2: Vec<Binding> = local.iter().map(|b| (*b).clone()).collect();
                let joined = tokio::task::spawn_blocking(move || {
                    let refs: Vec<&Binding> = local2.iter().collect();
                    let mut applied = Err(rewrite::BadValue);
                    let r = vault.with_secret(&b2.key, &mut |v| {
                        applied = rewrite::apply(&mut parts, &b2, &refs, v);
                    });
                    (parts, r, applied)
                })
                .await;
                let Ok((p, read, applied)) = joined else {
                    return text(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "morsec: internal error; nothing was sent",
                    );
                };
                parts = p;
                if let Err(e) = read {
                    let _ = self.receipt(
                        session,
                        &b.key,
                        host,
                        ReceiptResult::Failed("no value".into()),
                        None,
                        rule_version,
                    );
                    return text(StatusCode::BAD_GATEWAY, format!("{e}; nothing was sent"));
                }
                if applied.is_err() {
                    return text(
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "morsec: the stored value for ms://{} can't be placed in this request (bad characters); nothing was sent. Re-add it with: ms add",
                            b.key
                        ),
                    );
                }
                if let Err(e) =
                    self.receipt(session, &b.key, host, result, approval_id, rule_version)
                {
                    tracing::error!(error = %e, "morsec proxy could not record a receipt");
                    return text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "morsec: could not write the receipt, so nothing was sent. Check: ms log --verify",
                    );
                }
            }
        }
        let req = Request::from_parts(parts, Full::new(body));
        match upstream::send_tls(
            &self.client_tls,
            cache,
            host,
            port,
            &addrs,
            self.cfg.limits.upstream_connect_timeout,
            req,
        )
        .await
        {
            Ok(resp) => relay(resp),
            Err(UpstreamError(e)) => text(
                StatusCode::BAD_GATEWAY,
                format!("morsec: could not reach {host}: {e}"),
            ),
        }
    }

    /// Absolute-form `http://` through the proxy. Keys never travel over cleartext.
    async fn plain(&self, mut parts: Parts, body: Incoming, session: SessionId) -> Response<Body> {
        if parts.uri.scheme_str() != Some("http") {
            return text(StatusCode::BAD_REQUEST, "morsec: use CONNECT for https");
        }
        let Some(auth) = parts.uri.authority().cloned() else {
            return text(StatusCode::BAD_REQUEST, "morsec: missing host");
        };
        let (host, port) = split_authority(&auth, 80);
        // Scan the head and as much body as the limit allows; refs found here are blocked.
        let collected = match self.collect(&parts, body).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let body = collected.bytes.clone();
        let refs: Vec<KeyName> = rewrite::scan(&parts, &body, &self.cfg.bindings)
            .into_iter()
            .collect();
        if !refs.is_empty() {
            return self.refuse_refs(&session, &refs, &host);
        }
        if self.is_bound_host(&host) {
            return text(
                StatusCode::FORBIDDEN,
                format!(
                    "morsec: {host} gets a key, so it is reachable over https only. Use https://{host}"
                ),
            );
        }
        if !self.cfg.allowed(&host) {
            self.block(Some(&session), &host, port, BlockKind::NotAllowed);
            return text(
                StatusCode::FORBIDDEN,
                format!(
                    "morsec: blocked. {} is not on the egress allowlist. Allow it with: ms rules",
                    printable(&host)
                ),
            );
        }
        if collected.overflow {
            return self.too_large();
        }
        let addrs = match self.check(&host, port, &session).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        rewrite::strip_hop_by_hop(&mut parts.headers);
        let req = Request::from_parts(parts, Full::new(body));
        match upstream::send_plain(
            &host,
            port,
            &addrs,
            self.cfg.limits.upstream_connect_timeout,
            req,
        )
        .await
        {
            Ok(resp) => relay(resp),
            Err(UpstreamError(e)) => text(
                StatusCode::BAD_GATEWAY,
                format!("morsec: could not reach {}: {e}", printable(&host)),
            ),
        }
    }
}

/// Streams an upstream response back. Redirects are relayed, never followed.
fn relay(resp: Response<Incoming>) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    rewrite::strip_hop_by_hop(&mut parts.headers);
    parts.version = http::Version::HTTP_11;
    Response::from_parts(parts, body.map_err(|e| Box::new(e) as BoxError).boxed())
}
