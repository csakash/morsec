//! Upstream connections: always to an address the SSRF guard checked, TLS verified against the
//! configured roots, h2 or http/1.1 by ALPN.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, Version};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// A ready connection to one upstream.
pub(crate) enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::H1(_) => "Sender::H1",
            Self::H2(_) => "Sender::H2",
        })
    }
}

/// Why an upstream request failed. The text is safe to show the agent.
#[derive(Debug)]
pub(crate) struct UpstreamError(pub(crate) String);

/// Connection reused for requests inside one agent tunnel (all to the same host).
pub(crate) type Cache = Mutex<Option<Sender>>;

pub(crate) async fn tcp(addrs: &[SocketAddr], t: Duration) -> Result<TcpStream, UpstreamError> {
    let mut last = String::from("no address");
    for a in addrs {
        match timeout(t, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "connect timed out".into(),
        }
    }
    Err(UpstreamError(last))
}

async fn dial_tls(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    addrs: &[SocketAddr],
    t: Duration,
) -> Result<Sender, UpstreamError> {
    let tcp = tcp(addrs, t).await?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| UpstreamError(format!("{host} is not a valid TLS server name")))?;
    let stream = timeout(
        t,
        tokio_rustls::TlsConnector::from(tls.clone()).connect(name, tcp),
    )
    .await
    .map_err(|_| UpstreamError("TLS handshake timed out".into()))?
    .map_err(|e| UpstreamError(format!("TLS: {e}")))?;
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(stream);
    if h2 {
        let (s, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| UpstreamError(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Sender::H2(s))
    } else {
        let (s, conn) = http1::handshake(io)
            .await
            .map_err(|e| UpstreamError(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Sender::H1(s))
    }
}

/// Plain-HTTP upstream (allowlisted `http://` only; never carries a key).
pub(crate) async fn dial_plain(
    addrs: &[SocketAddr],
    t: Duration,
) -> Result<http1::SendRequest<Full<Bytes>>, UpstreamError> {
    let tcp = tcp(addrs, t).await?;
    let (s, conn) = http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(|e| UpstreamError(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(s)
}

fn authority(host: &str, port: u16, default: u16) -> String {
    if port == default {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// Shapes `req` for h1 (origin-form + `Host`) or h2 (absolute URI, no `Host`).
fn shape(req: &mut Request<Full<Bytes>>, h2: bool, host: &str, port: u16, scheme: &str) {
    let default = if scheme == "https" { 443 } else { 80 };
    let auth = authority(host, port, default);
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());
    req.headers_mut().remove(http::header::HOST);
    req.headers_mut().remove(http::header::CONTENT_LENGTH);
    if h2 {
        *req.version_mut() = Version::HTTP_2;
        if let Ok(u) = format!("{scheme}://{auth}{pq}").parse() {
            *req.uri_mut() = u;
        }
    } else {
        *req.version_mut() = Version::HTTP_11;
        if let Ok(u) = pq.parse() {
            *req.uri_mut() = u;
        }
        if let Ok(v) = HeaderValue::from_str(&auth) {
            req.headers_mut().insert(http::header::HOST, v);
        }
    }
}

/// Sends `req` over TLS to `host` at one of `addrs`, reusing `cache` when it can.
pub(crate) async fn send_tls(
    tls: &Arc<rustls::ClientConfig>,
    cache: Option<&Cache>,
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    connect_timeout: Duration,
    req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, UpstreamError> {
    let reused = match cache {
        Some(c) => {
            let mut g = c.lock().await;
            match g.take() {
                Some(Sender::H2(s)) if !s.is_closed() => {
                    let clone = s.clone();
                    *g = Some(Sender::H2(s));
                    Some(Sender::H2(clone))
                }
                Some(Sender::H1(s)) if s.is_ready() => Some(Sender::H1(s)),
                _ => None,
            }
        }
        None => None,
    };
    let was_reused = reused.is_some();
    let sender = match reused {
        Some(s) => s,
        None => dial_tls(tls, host, addrs, connect_timeout).await?,
    };
    match send_on(sender, cache, req, host, port).await {
        Ok(resp) => Ok(resp),
        // A reused connection the upstream closed while idle: the request was never written,
        // so send it once more on a fresh connection.
        Err(Retry::Unsent(req, _)) if was_reused => {
            let fresh = dial_tls(tls, host, addrs, connect_timeout).await?;
            send_on(fresh, cache, *req, host, port)
                .await
                .map_err(Retry::into_error)
        }
        Err(e) => Err(e.into_error()),
    }
}

enum Retry {
    Unsent(Box<Request<Full<Bytes>>>, hyper::Error),
    Failed(hyper::Error),
}

impl Retry {
    fn into_error(self) -> UpstreamError {
        match self {
            Self::Unsent(_, e) | Self::Failed(e) => UpstreamError(e.to_string()),
        }
    }
}

fn retry(mut e: hyper::client::conn::TrySendError<Request<Full<Bytes>>>) -> Retry {
    match e.take_message() {
        Some(req) => Retry::Unsent(Box::new(req), e.into_error()),
        None => Retry::Failed(e.into_error()),
    }
}

async fn send_on(
    sender: Sender,
    cache: Option<&Cache>,
    mut req: Request<Full<Bytes>>,
    host: &str,
    port: u16,
) -> Result<Response<Incoming>, Retry> {
    match sender {
        Sender::H2(mut s) => {
            shape(&mut req, true, host, port, "https");
            if let Some(c) = cache {
                let mut g = c.lock().await;
                if g.is_none() {
                    *g = Some(Sender::H2(s.clone()));
                }
            }
            s.try_send_request(req).await.map_err(retry)
        }
        Sender::H1(mut s) => {
            shape(&mut req, false, host, port, "https");
            if let Err(e) = s.ready().await {
                return Err(Retry::Unsent(Box::new(req), e));
            }
            let resp = s.try_send_request(req).await.map_err(retry)?;
            if let Some(c) = cache {
                let mut g = c.lock().await;
                if g.is_none() {
                    *g = Some(Sender::H1(s));
                }
            }
            Ok(resp)
        }
    }
}

/// Sends `req` over plain HTTP/1.1.
pub(crate) async fn send_plain(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    connect_timeout: Duration,
    mut req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, UpstreamError> {
    let mut s = dial_plain(addrs, connect_timeout).await?;
    shape(&mut req, false, host, port, "http");
    s.send_request(req)
        .await
        .map_err(|e| UpstreamError(e.to_string()))
}
