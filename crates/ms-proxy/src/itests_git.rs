//! L30 end to end with real git: `git push` / `git fetch` over HTTPS through the proxy to a local
//! `git http-backend` behind TLS. Only the proxy trusts the server's CA; git trusts only the
//! morsec CA (`GIT_SSL_CAINFO`). git holds `ms://git/test`; the proxy puts the token in the
//! Basic-auth password on the way out.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ms_core::{
    AgentKind, Decision, KeyMeta, KeyName, Mode, Reason, ReceiptResult, Request as PolicyRequest,
    SecretBytes, SessionId, Tier,
};
use ms_receipts::memory::MemorySink;
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;

use crate::ssrf::{BoxFuture, Resolve};
use crate::*;

const TOKEN: &str = "ghp_GITCANARY_5d1e0b7c2a";
const OTHER_TOKEN: &str = "ghp_OTHERCANARY_93ab";
const GIT_HOST: &str = "git.test";
const OTHER_HOST: &str = "other.test";
const REF: &str = "ms://git/test";

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = BoxBody<Bytes, BoxError>;

#[derive(Debug)]
struct AllowAll;
impl Policy for AllowAll {
    fn decide(&self, _: &SessionId, _: &PolicyRequest) -> (Decision, u64) {
        (Decision::Allow, 3)
    }
    fn version(&self) -> u64 {
        3
    }
}

#[derive(Debug)]
struct OneSession;
impl SessionResolver for OneSession {
    fn resolve(&self, _: SocketAddr, _: SocketAddr, _: Option<&str>) -> Option<SessionId> {
        Some(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 77,
            started_unix_ms: 1,
        })
    }
}

#[derive(Debug)]
struct Loopback;
impl Resolve for Loopback {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<SocketAddr>>> {
        let v = if host == GIT_HOST || host == OTHER_HOST {
            vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)]
        } else {
            vec![]
        };
        Box::pin(async move { Ok(v) })
    }
}

/// What the git server saw: every Authorization header, decoded.
#[derive(Debug, Default)]
struct Seen(Mutex<Vec<String>>);

/// `git http-backend` as CGI, behind Basic auth that accepts exactly `x-access-token:<token>`.
async fn backend(
    req: Request<Incoming>,
    root: PathBuf,
    token: &'static str,
    seen: Arc<Seen>,
) -> Result<Response<TestBody>, Infallible> {
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| B64.decode(b).ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    if let Some(a) = &auth {
        seen.0.lock().unwrap().push(a.clone());
    }
    let reply = |status: StatusCode, extra: Option<(&str, &str)>, body: Vec<u8>| {
        let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed());
        *r.status_mut() = status;
        if let Some((k, v)) = extra {
            r.headers_mut().insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        r
    };
    if auth.as_deref() != Some(&format!("x-access-token:{token}")) {
        return Ok(reply(
            StatusCode::UNAUTHORIZED,
            Some(("www-authenticate", "Basic realm=\"git\"")),
            Vec::new(),
        ));
    }
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let ctype = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let gzip = req
        .headers()
        .get("content-encoding")
        .is_some_and(|v| v == "gzip");
    let mut body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
    if gzip {
        let mut d = Command::new("gunzip")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        d.stdin.take().unwrap().write_all(&body).unwrap();
        body = d.wait_with_output().unwrap().stdout;
    }
    let out = tokio::task::spawn_blocking(move || {
        let mut c = Command::new("git")
            .arg("http-backend")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_PROJECT_ROOT", &root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("REMOTE_USER", "x-access-token")
            .env("REQUEST_METHOD", method)
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("CONTENT_TYPE", ctype)
            .env("CONTENT_LENGTH", body.len().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(&body).unwrap();
        c.wait_with_output().unwrap().stdout
    })
    .await
    .unwrap();
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let split = split.or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)));
    let (head, rest) = match split {
        Some((i, n)) => (&out[..i], out[i + n..].to_vec()),
        None => (&out[..], Vec::new()),
    };
    let mut r = Response::new(Full::new(Bytes::from(rest)).map_err(|n| match n {}).boxed());
    for line in String::from_utf8_lossy(head).lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("status") {
            *r.status_mut() = StatusCode::from_u16(v[..3].parse().unwrap()).unwrap();
        } else if let (Ok(k), Ok(v)) = (
            http::HeaderName::from_bytes(k.trim().as_bytes()),
            v.parse::<http::HeaderValue>(),
        ) {
            r.headers_mut().insert(k, v);
        }
    }
    Ok(r)
}

fn pki(
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

/// A git server on 127.0.0.1 serving `root`; returns its port and its CA root.
async fn git_server(
    root: PathBuf,
    token: &'static str,
    seen: Arc<Seen>,
) -> (u16, CertificateDer<'static>) {
    let (ca, chain, key) = pki(&[GIT_HOST, OTHER_HOST]);
    let mut cfg = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            let (root, seen) = (root.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |r| backend(r, root.clone(), token, seen.clone()));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, ca)
}

fn git(dir: &Path, env: &[(&str, String)], args: &[&str]) -> Output {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn ok(o: &Output) -> String {
    let s = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "git failed: {s}");
    s
}

fn put(vault: &MemoryVault, key: &str, value: &str) {
    let name = KeyName::new(key).unwrap();
    vault
        .put(
            &name,
            SecretBytes::from(value.to_owned()),
            KeyMeta {
                name: name.clone(),
                mode: Mode::Swap,
                tier: Tier::Test,
                created_unix_ms: 0,
            },
        )
        .unwrap();
}

/// Every file under `dir`, for the leak scan.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() && !p.is_symlink() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

// protects=L30 Verify 3: git push and fetch over HTTPS land through the proxy with the token
// swapped into the Basic password, git never holds the token (environment, config, files,
// output), and a git host bound to another key refuses the placeholder with a receipt;
// fails_when=the push fails, the server sees the placeholder, the token reaches git's side, or the
// foreign host gets anything but a 403; no_claim=msd's rules → bindings (msd tests) and the
// connectors' GIT_SSL_CAINFO (ms-connect tests)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn git_push_and_fetch_through_the_swap() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let base = d.path().canonicalize().unwrap();
    let srv = base.join("srv");
    let work = base.join("work");
    std::fs::create_dir_all(&srv).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    ok(&git(
        &srv,
        &[],
        &["init", "-q", "--bare", "-b", "main", "repo.git"],
    ));
    ok(&git(
        &srv,
        &[],
        &["init", "-q", "--bare", "-b", "main", "other.git"],
    ));
    // The server enables receive-pack for authenticated users (REMOTE_USER); say so explicitly.
    for r in ["repo.git", "other.git"] {
        ok(&git(
            &srv.join(r),
            &[],
            &["config", "http.receivepack", "true"],
        ));
    }

    let seen = Arc::new(Seen::default());
    let (port, up_root) = git_server(srv.clone(), TOKEN, seen.clone()).await;

    let vault = Arc::new(MemoryVault::new());
    put(&vault, "git/test", TOKEN);
    put(&vault, "other/test", OTHER_TOKEN);
    let ca = Arc::new(Ca::generate([GIT_HOST, OTHER_HOST]).unwrap());
    let receipts = Arc::new(MemorySink::new());
    let basic = Location::Basic {
        field: BasicField::Password,
    };
    let mut cfg = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.bindings = vec![
        Binding {
            key: KeyName::new("git/test").unwrap(),
            provider: "git-test-git".into(),
            hosts: vec![GIT_HOST.into()],
            port,
            location: basic.clone(),
            shaped_placeholder: None,
        },
        Binding {
            key: KeyName::new("other/test").unwrap(),
            provider: "other-test-git".into(),
            hosts: vec![OTHER_HOST.into()],
            port,
            location: basic,
            shaped_placeholder: None,
        },
    ];
    cfg.upstream_roots = UpstreamRoots::Only(vec![up_root]);
    let mut deps = Deps::new(
        vault,
        Arc::new(AllowAll),
        receipts.clone(),
        Arc::new(OneSession),
        ca.clone(),
    );
    deps.resolver = Arc::new(Loopback);
    let mut proxy = Proxy::bind(cfg, deps).await.unwrap();
    proxy.allow_loopback_upstreams_for_tests();
    let paddr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve(std::future::pending()));

    // git trusts only the morsec CA, and reaches the server only through the proxy.
    let ca_file = base.join("morsec-ca.pem");
    std::fs::write(&ca_file, ca.cert_pem()).unwrap();
    let global = base.join("gitconfig");
    // A global helper with the person's own credentials: the recipe's reset must keep it out.
    std::fs::write(
        &global,
        "[credential]\n\thelper = \"!f() { echo username=me; echo password=PERSONAL-TOKEN; }; f\"\n",
    )
    .unwrap();
    let env: Vec<(&str, String)> = vec![
        ("HTTPS_PROXY", format!("http://{paddr}")),
        ("GIT_SSL_CAINFO", ca_file.display().to_string()),
        ("GIT_CONFIG_GLOBAL", global.display().to_string()),
    ];
    let url = |host: &str, repo: &str| format!("https://{host}:{port}/{repo}");

    let w = |a: &[&str]| git(&work, &env, a);
    ok(&w(&["init", "-q", "-b", "main"]));
    std::fs::write(work.join("README"), "hello\n").unwrap();
    ok(&w(&["add", "README"]));
    ok(&w(&["commit", "-qm", "first"]));
    for host in [GIT_HOST, OTHER_HOST] {
        let h = format!("credential.https://{host}:{port}.helper");
        ok(&w(&["config", &h, ""]));
        ok(&w(&[
            "config",
            "--add",
            &h,
            &format!("!f() {{ echo username=x-access-token; echo password={REF}; }}; f"),
        ]));
    }
    ok(&w(&["remote", "add", "origin", &url(GIT_HOST, "repo.git")]));
    let mut outputs = Vec::new();

    // Push lands on the server.
    let o = w(&["push", "-q", "origin", "main"]);
    outputs.push(ok(&o));
    let head = ok(&w(&["rev-parse", "HEAD"]));
    let remote = ok(&git(&srv.join("repo.git"), &[], &["rev-parse", "main"]));
    assert_eq!(head.trim(), remote.trim());

    // Fetch (and ls-remote) see a commit pushed by someone else.
    let other_clone = base.join("seed");
    ok(&git(
        &base,
        &[],
        &[
            "clone",
            "-q",
            &srv.join("repo.git").display().to_string(),
            "seed",
        ],
    ));
    std::fs::write(other_clone.join("NEW"), "x\n").unwrap();
    ok(&git(&other_clone, &[], &["add", "NEW"]));
    ok(&git(&other_clone, &[], &["commit", "-qm", "second"]));
    ok(&git(&other_clone, &[], &["push", "-q", "origin", "main"]));
    let o = w(&["fetch", "-q", "origin"]);
    outputs.push(ok(&o));
    let fetched = ok(&w(&["rev-parse", "origin/main"]));
    let server = ok(&git(&srv.join("repo.git"), &[], &["rev-parse", "main"]));
    assert_eq!(fetched.trim(), server.trim());
    outputs.push(ok(&w(&["ls-remote", "origin"])));

    // The server saw only the real token, never the placeholder or the personal one.
    let seen_auth = seen.0.lock().unwrap().clone();
    assert!(!seen_auth.is_empty());
    assert!(
        seen_auth
            .iter()
            .all(|a| a == &format!("x-access-token:{TOKEN}")),
        "{seen_auth:?}"
    );

    // The placeholder for git/test sent to other.test (bound to other/test) is refused.
    let o = w(&["push", "-q", &url(OTHER_HOST, "other.git"), "main"]);
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        !o.status.success(),
        "push to the foreign host landed: {msg}"
    );
    assert!(msg.contains("403"), "{msg}");
    outputs.push(msg);
    assert!(
        git(
            &srv.join("other.git"),
            &[],
            &["rev-parse", "--verify", "-q", "main"]
        )
        .stdout
        .is_empty(),
        "the foreign repository got a branch"
    );

    let ev = receipts.events();
    let allowed: Vec<_> = ev
        .iter()
        .filter(|e| e.result == ReceiptResult::Allowed)
        .collect();
    assert!(!allowed.is_empty());
    assert!(
        allowed
            .iter()
            .all(|e| e.key.as_str() == "git/test" && e.target == GIT_HOST)
    );
    assert!(
        ev.iter().any(|e| e.key.as_str() == "git/test"
            && e.target == OTHER_HOST
            && e.result == ReceiptResult::Blocked(Reason::HostNotAllowed)),
        "{ev:?}"
    );

    // git's side never held the token: environment, every file it can see, and all output.
    for (_, v) in &env {
        assert!(!v.contains(TOKEN));
    }
    for o in &outputs {
        assert!(!o.contains(TOKEN) && !o.contains(OTHER_TOKEN), "{o}");
    }
    let mut all = Vec::new();
    files(&work, &mut all);
    files(&other_clone, &mut all);
    all.extend([ca_file.clone(), global.clone()]);
    let mut scanned: HashMap<PathBuf, bool> = HashMap::new();
    for f in all {
        let bytes = std::fs::read(&f).unwrap_or_default();
        let hit = bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes());
        scanned.insert(f, hit);
    }
    let hits: Vec<_> = scanned
        .iter()
        .filter(|(_, h)| **h)
        .map(|(p, _)| p)
        .collect();
    assert!(hits.is_empty(), "token found in {hits:?}");
    assert!(scanned.len() > 10);
}
