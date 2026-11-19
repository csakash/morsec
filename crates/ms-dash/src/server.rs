//! The listener: bound on demand by [`Dash::open`] on the first free port of its range on
//! `127.0.0.1`, closed after `idle` without an authenticated request or by [`Dash::shutdown`].
//! Every accepted connection passes [`DashData::check_connection`] before hyper reads a byte.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener as StdListener};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use ms_core::SessionId;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, watch};

use crate::auth::{Access, Auth, RateLog, Throttle};
use crate::data::{DashData, Refusal};
use crate::{DEFAULT_PORT, PORT_SPAN};

/// Listener settings.
#[derive(Debug, Clone)]
pub struct DashConfig {
    /// First port tried.
    pub first_port: u16,
    /// Ports tried, from `first_port` on.
    pub span: u16,
    /// Closes after this long without an authenticated request (design §6.1: 30 min).
    pub idle: Duration,
    /// A launch token's life (design §6.2.2: 60 s).
    pub token_ttl: Duration,
    /// Requests per second per session, and for unauthenticated requests together (§6.2.6: 20).
    pub rate: u32,
    /// Most connections open at once.
    pub max_connections: usize,
}

impl DashConfig {
    /// The design's values, starting at `first_port`.
    pub fn new(first_port: u16) -> Self {
        Self {
            first_port,
            span: PORT_SPAN,
            idle: Duration::from_secs(30 * 60),
            token_ttl: Duration::from_secs(60),
            rate: 20,
            max_connections: 32,
        }
    }
}

impl Default for DashConfig {
    fn default() -> Self {
        Self::new(DEFAULT_PORT)
    }
}

/// What [`Dash::open`] gives msd. The token goes to the browser opener and nowhere else: never
/// over IPC (SPEC D-12), never into a log (its `Debug` hides it).
#[derive(Clone, PartialEq, Eq)]
pub struct Opened {
    /// The port msd holds.
    pub port: u16,
    /// A single-use launch token (hex).
    pub token: String,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("port", &self.port)
            .field("token", &"[hidden]")
            .finish()
    }
}

impl Opened {
    /// The sign-in URL: the token only in the fragment, on 127.0.0.1 and this port. `view` must
    /// already be checked ([`valid_view`]).
    pub fn url(&self, view: Option<&str>) -> String {
        match view {
            Some(v) => format!("http://127.0.0.1:{}/#t={}&v={v}", self.port, self.token),
            None => format!("http://127.0.0.1:{}/#t={}", self.port, self.token),
        }
    }
}

/// `project/<slug>` with a slug of `a-z0-9-` (64 bytes at most): the only view a URL may name.
pub fn valid_view(v: &str) -> bool {
    v.strip_prefix("project/").is_some_and(|slug| {
        !slug.is_empty()
            && slug.len() <= 64
            && slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

struct Running {
    port: u16,
    stop: watch::Sender<bool>,
}

struct State {
    running: Option<Running>,
    auth: Auth,
    last_auth: Instant,
    throttle: Throttle,
    log: RateLog,
}

/// Shared by the listener, its connections and [`Dash`].
pub struct Inner {
    cfg: DashConfig,
    data: Arc<dyn DashData>,
    rt: Handle,
    state: Mutex<State>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").field("cfg", &self.cfg).finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Inner {
    pub(crate) fn data(&self) -> Arc<dyn DashData> {
        self.data.clone()
    }

    pub(crate) fn take_anon(&self, now: Instant) -> bool {
        lock(&self.state).auth.take_anon(now)
    }

    /// Cookie and CSRF check; an `Ok` counts as an authenticated request (idle timer).
    pub(crate) fn check(&self, cookie: Option<&str>, csrf: Option<&str>, now: Instant) -> Access {
        let mut st = lock(&self.state);
        let a = st.auth.check(cookie, csrf, now);
        if a == Access::Ok {
            st.last_auth = now;
        }
        a
    }

    /// Trades a launch token for a session (joining `existing` when that cookie is live):
    /// `Ok(None)` when the token is not good.
    pub(crate) fn start_session(
        &self,
        token: &str,
        existing: Option<&str>,
        now: Instant,
    ) -> Result<Option<(String, String)>, String> {
        let mut st = lock(&self.state);
        if !st.auth.take_launch(token, now) {
            return Ok(None);
        }
        st.last_auth = now;
        st.auth
            .start_session(now, existing)
            .map(Some)
            .map_err(|e| format!("morsec: no randomness for a session: {e}"))
    }

    /// Logs a refusal: the first per caller and reason per minute, then a count (review R3).
    pub(crate) fn log_refusal(&self, r: &Refusal, receipt: bool) {
        let key = format!("{:?}/{}:{}", r.session.agent, r.session.pid, r.why);
        if let Some(quiet) = lock(&self.state).log.allow(&key, Instant::now()) {
            tracing::warn!(
                pid = r.session.pid,
                why = %r.why,
                receipt,
                similar_skipped = quiet,
                "dashboard refused"
            );
        }
    }

    /// Records a refusal with a receipt: at most 30 a minute per agent session, and 30 for
    /// every other caller together (SPEC D-9, review S3).
    pub(crate) async fn refused(&self, r: Refusal) {
        let allowed = lock(&self.state).throttle.allow(&r.session, Instant::now());
        self.log_refusal(&r, allowed);
        if allowed {
            let data = self.data.clone();
            let _ = tokio::task::spawn_blocking(move || data.record_refused(&r)).await;
        }
    }

    /// Closes the dashboard if no authenticated request came within `idle`; checked and done
    /// under one lock, so a request can't slip in between (review R6). True when it closed.
    fn shutdown_if_idle(&self) -> bool {
        let mut st = lock(&self.state);
        if st.last_auth.elapsed() < self.cfg.idle {
            return false;
        }
        if let Some(r) = st.running.take() {
            let _ = r.stop.send(true);
            tracing::info!(port = r.port, "dashboard idle; closed");
        }
        st.auth.clear();
        true
    }

    fn shutdown(&self) {
        let mut st = lock(&self.state);
        if let Some(r) = st.running.take() {
            let _ = r.stop.send(true);
            tracing::info!(port = r.port, "dashboard closed");
        }
        st.auth.clear();
    }
}

/// The dashboard. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Dash {
    inner: Arc<Inner>,
}

impl Dash {
    /// A dashboard that is not listening yet. `rt` runs the listener.
    pub fn new(cfg: DashConfig, data: Arc<dyn DashData>, rt: Handle) -> Self {
        Self {
            inner: Arc::new(Inner {
                cfg,
                data,
                rt,
                state: Mutex::new(State {
                    running: None,
                    auth: Auth::new(20),
                    last_auth: Instant::now(),
                    throttle: Throttle::default(),
                    log: RateLog::default(),
                }),
            }),
        }
    }

    /// `DashOpen`: starts the listener if needed and mints a launch token. Synchronous (msd calls
    /// it from its blocking pool); must not be called on a runtime worker thread of `rt` that
    /// can't block, though it never waits on the runtime.
    pub fn open(&self) -> Result<Opened, String> {
        let inner = &self.inner;
        let mut st = lock(&inner.state);
        if st.running.is_none() {
            let (listener, port) = bind_first(inner.cfg.first_port, inner.cfg.span)?;
            let (tx, rx) = watch::channel(false);
            let _g = inner.rt.enter();
            let listener = TcpListener::from_std(listener)
                .map_err(|e| format!("morsec: the dashboard listener failed: {e}"))?;
            // Only now is it running (review R5).
            st.auth = Auth::new(inner.cfg.rate);
            st.running = Some(Running { port, stop: tx });
            inner
                .rt
                .spawn(accept_loop(inner.clone(), listener, port, rx.clone()));
            inner.rt.spawn(idle_watch(inner.clone(), rx));
            tracing::info!(port, "dashboard listening on 127.0.0.1");
        }
        let now = Instant::now();
        st.last_auth = now;
        let port = st.running.as_ref().map_or(0, |r| r.port);
        let token = st
            .auth
            .mint_launch(now, inner.cfg.token_ttl)
            .map_err(|e| format!("morsec: no randomness for a launch token: {e}"))?;
        Ok(Opened { port, token })
    }

    /// The port it listens on, if it does.
    pub fn port(&self) -> Option<u16> {
        lock(&self.inner.state).running.as_ref().map(|r| r.port)
    }

    /// Closes the listener and every connection; drops sessions and tokens.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Sessions open (tests).
    pub fn session_count(&self) -> usize {
        lock(&self.inner.state).auth.session_count()
    }
}

/// Binds `127.0.0.1:<p>` for the first free `p` of `first..first+span`.
fn bind_first(first: u16, span: u16) -> Result<(StdListener, u16), String> {
    let mut last = None;
    for i in 0..span {
        let Some(port) = first.checked_add(i) else {
            break;
        };
        match StdListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
            Ok(l) => {
                l.set_nonblocking(true)
                    .map_err(|e| format!("morsec: the dashboard listener failed: {e}"))?;
                // Report what the kernel gave, never what was asked.
                let got = l
                    .local_addr()
                    .map_err(|e| format!("morsec: the dashboard listener failed: {e}"))?
                    .port();
                return Ok((l, got));
            }
            Err(e) => last = Some(e),
        }
    }
    Err(format!(
        "morsec: every dashboard port from {first} to {} is in use{}. Free one, or stop what holds them",
        first.saturating_add(span.saturating_sub(1)),
        last.map(|e| format!(" ({e})")).unwrap_or_default()
    ))
}

async fn idle_watch(inner: Arc<Inner>, mut stop: watch::Receiver<bool>) {
    let tick = (inner.cfg.idle / 4).clamp(Duration::from_millis(20), Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(tick) => {}
        }
        if inner.shutdown_if_idle() {
            return;
        }
    }
}

async fn accept_loop(
    inner: Arc<Inner>,
    listener: TcpListener,
    port: u16,
    mut stop: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(inner.cfg.max_connections));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            r = listener.accept() => {
                let Ok((stream, peer)) = r else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let (inner, stop) = (inner.clone(), stop.clone());
                tokio::spawn(async move {
                    connection(inner, stream, peer, port, stop).await;
                    drop(permit);
                });
            }
        }
    }
}

async fn connection(
    inner: Arc<Inner>,
    stream: TcpStream,
    peer: SocketAddr,
    port: u16,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(local) = stream.local_addr() else {
        return;
    };
    // The process check, before any byte is read (design §6.2.1).
    let data = inner.data.clone();
    let verdict = tokio::task::spawn_blocking(move || data.check_connection(peer, local)).await;
    let who: SessionId = match verdict {
        Ok(Ok(who)) => who,
        Ok(Err(refusal)) => {
            drop(stream);
            inner.refused(refusal).await;
            return;
        }
        Err(_) => return,
    };
    let svc_inner = inner.clone();
    let svc = service_fn(move |req| {
        let (inner, who) = (svc_inner.clone(), who.clone());
        async move { Ok::<_, Infallible>(crate::http::handle(&inner, port, &who, req).await) }
    });
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(stream), svc);
    tokio::select! {
        _ = conn => {}
        _ = stop.changed() => {}
    }
}
