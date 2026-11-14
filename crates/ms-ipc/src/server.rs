//! Daemon side: a Unix socket in a private directory, a peer check on every connection, and a
//! handler per request.
//!
//! Connection limits (L07, open item S6 from L00): a same-user process must not be able to starve
//! the kill switch by holding connections open. So the accept loop never waits; a general pool
//! serves ordinary clients, a few reserved control slots serve only `Status` and `Stop` when the
//! general pool is full, each peer process may hold only a few connections, and every connection
//! has a total lifetime and request cap besides the idle timeout. See [`ServerLimits`].

use std::collections::HashMap;
use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_core::{Error, Result, SecretBytes};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::frame::{read_frame, read_secret_frame, write_frame};
use crate::protocol::{ErrorCode, RequestBody, ResponseBody, decode, encode};

/// How long a connection may sit between frames before it is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Most connections in the general pool (see [`ServerLimits::general`]).
pub const MAX_CONNECTIONS: usize = 64;

/// How long a reserved control connection may wait between frames.
const CONTROL_FIRST_FRAME: Duration = Duration::from_secs(1);

/// Connection limits. The defaults suit `msd`; tests change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// Connections served for any request.
    pub general: usize,
    /// Extra connections used only when the general pool is full. They serve only `Status` and
    /// `Stop`, so the kill switch stays reachable.
    pub reserved: usize,
    /// Most open connections per peer process (by kernel PID).
    pub per_peer: usize,
    /// Longest gap between frames.
    pub idle: Duration,
    /// Longest total life of a general connection, whatever it is doing.
    pub lifetime: Duration,
    /// Longest total life of a reserved (control) connection.
    pub control_lifetime: Duration,
    /// Most requests on one connection.
    pub max_requests: u32,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            general: MAX_CONNECTIONS,
            reserved: 8,
            per_peer: 8,
            idle: IDLE_TIMEOUT,
            lifetime: Duration::from_secs(600),
            control_lifetime: Duration::from_secs(10),
            max_requests: 1024,
        }
    }
}

/// Credentials of the connecting process, from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    /// Effective user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Process id, when the platform reports it.
    pub pid: Option<i32>,
    /// When the daemon accepted the connection, Unix milliseconds (L07). A process that started
    /// after this is not the peer (PID reuse), so identity checks made later in the connection
    /// must compare against this, not the current time.
    pub accepted_unix_ms: u64,
}

/// Wall-clock now, Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

/// Decides whether a peer may talk to the daemon. L06 replaces [`SameUid`] with session identity.
pub trait PeerCheck: Send + Sync + 'static {
    /// `Err` closes the connection with `peer_rejected`.
    fn check(&self, peer: &PeerInfo) -> Result<()>;
}

/// Accepts only processes running as `uid`.
#[derive(Debug, Clone, Copy)]
pub struct SameUid {
    /// The only uid allowed.
    pub uid: u32,
}

impl PeerCheck for SameUid {
    fn check(&self, peer: &PeerInfo) -> Result<()> {
        if peer.uid == self.uid {
            Ok(())
        } else {
            Err(Error::PeerRejected(format!(
                "uid {} is not the daemon's user",
                peer.uid
            )))
        }
    }
}

/// Handles one request. `value` is present only for requests that carry one (`PutKey`).
pub trait Handler: Send + Sync + 'static {
    /// Produces the response.
    fn handle(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> impl Future<Output = ResponseBody> + Send;

    /// Serves a streaming request (`RunStream`, L12). Chunks sent on `io.output` reach the
    /// client as they come; the returned body is the stream's last frame, after which the
    /// connection closes. The future is dropped (cancelled) when the client goes away or the
    /// connection's lifetime runs out, so anything it started must stop on drop.
    ///
    /// The default answers `not_implemented`.
    fn handle_stream(
        &self,
        peer: &PeerInfo,
        request: RequestBody,
        io: StreamIo,
    ) -> impl Future<Output = ResponseBody> + Send {
        let _ = (peer, io);
        let owner = request.owner_loop();
        async move {
            ResponseBody::error(
                ErrorCode::NotImplemented,
                format!("morsec: this request is not built yet (planned in loop {owner})"),
            )
        }
    }
}

/// Stdin from a streaming client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinEvent {
    /// Bytes.
    Data(Vec<u8>),
    /// The client's stdin ended.
    End,
}

/// The two directions of a stream (L12). `input` closes without [`StdinEvent::End`] only when
/// the client is gone.
#[derive(Debug)]
pub struct StreamIo {
    /// Stdin from the client.
    pub input: tokio::sync::mpsc::Receiver<StdinEvent>,
    /// Frames to the client (`RunOutput`). Bounded: a slow client slows the producer.
    pub output: tokio::sync::mpsc::Sender<ResponseBody>,
}

/// Frames queued in each direction of a stream.
const STREAM_QUEUE: usize = 16;
/// How often a stream whose stdin queue is full checks whether the client hung up.
const STDIN_POLL: Duration = Duration::from_millis(50);

/// A bound daemon socket. Removes the socket file when dropped.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    owner_uid: u32,
    limits: ServerLimits,
}

fn socket_err(msg: String) -> Error {
    Error::Socket(msg)
}

/// Opens `dir` itself (never a symlink in its place) and returns the handle with its metadata.
fn open_dir(dir: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let m = f.metadata()?;
    Ok((f, m))
}

fn same_inode(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

impl Server {
    /// Binds `path` and sets the socket to 0600.
    ///
    /// A missing directory is created with mode 0700. An existing directory is never modified: it
    /// must already be private (no group or other bits) or `bind` refuses, so pointing `--socket`
    /// at `~/` or `/tmp/` can't silently change those directories. Also refuses when another
    /// daemon answers on `path`, when `path` exists and is not a socket, or when the directory
    /// belongs to another user. A stale socket left by a crashed daemon is removed.
    ///
    /// The directory is checked through a descriptor opened with `O_NOFOLLOW` (so a symlink in
    /// its place is refused), and after binding the path is checked to still name that same
    /// directory and a socket we own (L07, open item S3 from L00). Because the directory is
    /// private to us, nobody else can reach the socket between `bind` and `chmod`.
    pub fn bind(path: &Path) -> Result<Self> {
        Self::bind_with(path, ServerLimits::default())
    }

    /// [`Server::bind`] with explicit limits.
    pub fn bind_with(path: &Path, limits: ServerLimits) -> Result<Self> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                socket_err(format!(
                    "socket path {} has no directory; pass a path like ~/Library/Application Support/morsec/msd.sock",
                    path.display()
                ))
            })?;
        if limits.general == 0 || limits.per_peer == 0 || limits.max_requests == 0 {
            return Err(socket_err(
                "server limits must allow at least one connection and request".into(),
            ));
        }
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(socket_err(format!(
                    "{} is a symbolic link; point the socket at a real private directory",
                    dir.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|e| Error::io(format!("creating {}", dir.display()), e))?;
            }
            Err(e) => return Err(Error::io(format!("checking {}", dir.display()), e)),
        }
        let (dir_fd, dir_meta) = open_dir(dir).map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
                socket_err(format!(
                    "{} is not a directory (or is a symbolic link); choose another socket path",
                    dir.display()
                ))
            } else {
                Error::io(format!("opening {}", dir.display()), e)
            }
        })?;
        if dir_meta.permissions().mode() & 0o077 != 0 {
            return Err(socket_err(format!(
                "{} is readable or writable by other users (mode {:o}); use a private directory, or run: chmod 700 {}",
                dir.display(),
                dir_meta.permissions().mode() & 0o7777,
                dir.display()
            )));
        }

        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(socket_err(format!(
                        "another msd is already running on {}. Stop it first, or pass --socket",
                        path.display()
                    )));
                }
                std::fs::remove_file(path).map_err(|e| {
                    Error::io(format!("removing stale socket {}", path.display()), e)
                })?;
            }
            Ok(_) => {
                return Err(socket_err(format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(format!("checking {}", path.display()), e)),
        }

        let listener = UnixListener::bind(path)
            .map_err(|e| Error::io(format!("binding {}", path.display()), e))?;
        // From here on, dropping `server` removes whatever is at `path`. Do the identity checks
        // before taking ownership, so a refused bind never deletes a file we didn't create.
        let sock_meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::io(format!("checking {}", path.display()), e))?;
        let dir_now = std::fs::symlink_metadata(dir)
            .map_err(|e| Error::io(format!("checking {}", dir.display()), e))?;
        let dir_after = dir_fd
            .metadata()
            .map_err(|e| Error::io(format!("checking {}", dir.display()), e))?;
        if !same_inode(&dir_now, &dir_meta) || !sock_meta.file_type().is_socket() {
            return Err(socket_err(format!(
                "{} changed while the socket was being created; refusing to use it",
                dir.display()
            )));
        }
        let owner_uid = sock_meta.uid();
        let server = Server {
            listener,
            path: path.to_owned(),
            owner_uid,
            limits,
        };
        if dir_after.uid() != owner_uid {
            return Err(socket_err(format!(
                "{} belongs to another user; choose a socket directory you own",
                dir.display()
            )));
        }
        if dir_after.permissions().mode() & 0o077 != 0 {
            return Err(socket_err(format!(
                "{} became accessible to other users while binding; refusing to use it",
                dir.display()
            )));
        }
        // The directory is ours and private (checked through the descriptor, and the path still
        // names it), so nobody else can swap the socket before this chmod.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(format!("restricting {} to 0600", path.display()), e))?;
        Ok(server)
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The uid that owns the socket, which is this process's effective uid. Use it for
    /// [`SameUid`].
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// The limits this server applies.
    pub fn limits(&self) -> ServerLimits {
        self.limits
    }

    /// Accepts connections until `shutdown` resolves.
    pub async fn serve<H: Handler, P: PeerCheck>(
        self,
        handler: Arc<H>,
        check: Arc<P>,
        shutdown: impl Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        let limits = self.limits;
        let general = Arc::new(Semaphore::new(limits.general));
        let reserved = Arc::new(Semaphore::new(limits.reserved));
        // Connections refused with a `busy` reply are written in the background; cap those too.
        let refusing = Arc::new(Semaphore::new(16));
        let peers = Arc::new(PeerCounts::default());
        loop {
            // Never wait for a slot before accepting: a full pool must not stop `Stop` from
            // reaching a reserved slot.
            let accepted = tokio::select! {
                () = &mut shutdown => break,
                a = self.listener.accept() => a,
            };
            let stream = match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    // EMFILE and friends: back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let slot = if let Ok(p) = general.clone().try_acquire_owned() {
                Slot::General(p)
            } else if let Ok(p) = reserved.clone().try_acquire_owned() {
                Slot::Control(p)
            } else {
                if let Ok(p) = refusing.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        refuse_busy(stream).await;
                        drop(p);
                    });
                }
                // Otherwise the stream is dropped, which closes it.
                continue;
            };
            let (h, c, pc) = (handler.clone(), check.clone(), peers.clone());
            tokio::spawn(async move {
                serve_conn(stream, h, c, pc, limits, slot, now_unix_ms()).await;
            });
        }
    }
}

/// Which pool a connection's slot came from. The permit is released when the connection ends.
#[derive(Debug)]
enum Slot {
    General(#[allow(dead_code)] OwnedSemaphorePermit),
    Control(#[allow(dead_code)] OwnedSemaphorePermit),
}

impl Slot {
    fn control_only(&self) -> bool {
        matches!(self, Slot::Control(_))
    }
}

/// Open connections per peer PID.
#[derive(Debug, Default)]
struct PeerCounts(Mutex<HashMap<i32, usize>>);

/// Holds one of a peer's connection counts; gives it back on drop.
#[derive(Debug)]
struct PeerGuard {
    counts: Arc<PeerCounts>,
    pid: i32,
}

impl PeerCounts {
    fn enter(self: &Arc<Self>, pid: i32, cap: usize) -> Option<PeerGuard> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(pid).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(PeerGuard {
            counts: self.clone(),
            pid,
        })
    }
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut m = self.counts.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.pid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.pid);
            }
        }
    }
}

const BUSY_MESSAGE: &str = "morsec: the daemon is at its connection limit, so only ms status and ms stop are served right now. Try again shortly; if it persists, a process is holding connections open: run ms stop";

async fn refuse_busy(mut stream: UnixStream) {
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        send(
            &mut stream,
            0,
            &ResponseBody::error(ErrorCode::Busy, BUSY_MESSAGE),
        ),
    )
    .await;
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn send(stream: &mut UnixStream, id: u64, body: &ResponseBody) -> bool {
    match encode(id, body) {
        Ok(bytes) => write_frame(stream, &bytes).await.is_ok(),
        Err(_) => false,
    }
}

async fn serve_conn<H: Handler, P: PeerCheck>(
    mut stream: UnixStream,
    handler: Arc<H>,
    check: Arc<P>,
    peers: Arc<PeerCounts>,
    limits: ServerLimits,
    slot: Slot,
    accepted_unix_ms: u64,
) {
    let lifetime = if slot.control_only() {
        limits.control_lifetime
    } else {
        limits.lifetime
    };
    // The total lifetime bounds everything, including a slow handler or a client trickling bytes.
    let _ = tokio::time::timeout(
        lifetime,
        conn_body(
            &mut stream,
            handler,
            check,
            peers,
            limits,
            slot.control_only(),
            accepted_unix_ms,
        ),
    )
    .await;
    drop(slot);
}

async fn conn_body<H: Handler, P: PeerCheck>(
    stream: &mut UnixStream,
    handler: Arc<H>,
    check: Arc<P>,
    peers: Arc<PeerCounts>,
    limits: ServerLimits,
    control_only: bool,
    accepted_unix_ms: u64,
) {
    let peer = match stream.peer_cred() {
        Ok(c) => PeerInfo {
            uid: c.uid(),
            gid: c.gid(),
            pid: c.pid(),
            accepted_unix_ms,
        },
        // A client that connects and hangs up at once (such as `bind`'s liveness probe) has no
        // credentials left to read. That is not an attack signal, so it is not a warning.
        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
            tracing::debug!("client left before sending anything");
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, "no peer credentials; closing");
            return;
        }
    };
    if let Err(e) = check.check(&peer) {
        tracing::warn!(uid = peer.uid, pid = ?peer.pid, "peer rejected");
        send(
            stream,
            0,
            &ResponseBody::error(ErrorCode::PeerRejected, e.to_string()),
        )
        .await;
        return;
    }
    // A peer without a PID (not expected on macOS or Linux) shares one bucket.
    let Some(_guard) = peers.enter(peer.pid.unwrap_or(-1), limits.per_peer) else {
        tracing::warn!(pid = ?peer.pid, "peer holds too many connections");
        send(
            stream,
            0,
            &ResponseBody::error(
                ErrorCode::Busy,
                "morsec: this process already holds the most connections the daemon allows; close some and retry",
            ),
        )
        .await;
        return;
    };
    let mut served: u32 = 0;
    loop {
        // A reserved control slot must not be parked on: its client gets one second to send.
        let wait = if control_only {
            limits.idle.min(CONTROL_FIRST_FRAME)
        } else {
            limits.idle
        };
        let frame = match tokio::time::timeout(wait, read_frame(stream)).await {
            Err(_) | Ok(Ok(None)) => return,
            Ok(Ok(Some(f))) => f,
            Ok(Err(e)) => {
                send(
                    stream,
                    0,
                    &ResponseBody::error(ErrorCode::Protocol, e.to_string()),
                )
                .await;
                return;
            }
        };
        let env = match decode::<RequestBody>(&frame) {
            Ok(env) => env,
            Err((id, code, message)) => {
                send(stream, id, &ResponseBody::error(code, message)).await;
                return;
            }
        };
        if served >= limits.max_requests {
            send(
                stream,
                env.id,
                &ResponseBody::error(
                    ErrorCode::Busy,
                    "morsec: this connection has served its request limit; reconnect",
                ),
            )
            .await;
            return;
        }
        if control_only && !env.body.is_control() {
            send(
                stream,
                env.id,
                &ResponseBody::error(ErrorCode::Busy, BUSY_MESSAGE),
            )
            .await;
            return;
        }
        let value = if env.body.carries_value() {
            match tokio::time::timeout(limits.idle, read_secret_frame(stream)).await {
                Ok(Ok(v)) => Some(v),
                Ok(Err(e)) => {
                    send(
                        stream,
                        env.id,
                        &ResponseBody::error(ErrorCode::Protocol, e.to_string()),
                    )
                    .await;
                    return;
                }
                Err(_) => return,
            }
        } else {
            None
        };
        served += 1;
        if env.body.is_stream() {
            serve_stream(stream, &*handler, &peer, env.id, env.body).await;
            return;
        }
        let response = handler.handle(&peer, env.body, value).await;
        if !send(stream, env.id, &response).await {
            return;
        }
    }
}

/// Runs one stream: client frames feed `StreamIo::input`, `StreamIo::output` is written as it
/// comes, and the handler's result is the last frame. Ends the connection afterwards. If the
/// client disconnects, sends a bad frame or stops reading, the handler future is dropped, which
/// cancels the run.
async fn serve_stream<H: Handler>(
    stream: &mut UnixStream,
    handler: &H,
    peer: &PeerInfo,
    id: u64,
    body: RequestBody,
) {
    let (mut rd, mut wr) = stream.split();
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(STREAM_QUEUE);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(STREAM_QUEUE);
    let io = StreamIo {
        input: in_rx,
        output: out_tx,
    };
    // Reads client frames until the client goes away. Only stdin frames are valid here.
    let reader = async move {
        let mut ended = false;
        loop {
            let frame = match read_frame(&mut rd).await {
                Ok(Some(f)) => f,
                Ok(None) | Err(_) => return,
            };
            let event = match decode::<RequestBody>(&frame) {
                Ok(e) => match e.body {
                    RequestBody::RunInput { data } if !ended => match crate::b64_decode(&data) {
                        Some(bytes) => StdinEvent::Data(bytes),
                        None => return,
                    },
                    RequestBody::RunInputEnd if !ended => {
                        ended = true;
                        StdinEvent::End
                    }
                    _ => return,
                },
                Err(_) => return,
            };
            // While the stdin queue is full (the child isn't reading), keep watching the socket:
            // a client that hangs up must still cancel the run.
            let mut event = Some(event);
            while let Some(e) = event.take() {
                tokio::select! {
                    permit = in_tx.reserve() => {
                        // Err: the handler stopped reading stdin; drop the bytes.
                        if let Ok(p) = permit {
                            p.send(e);
                        }
                    }
                    ready = rd.ready(tokio::io::Interest::READABLE) => {
                        match ready {
                            Ok(r) if !r.is_read_closed() => {
                                // More frames wait behind this one. Hand it over the moment a
                                // slot frees; otherwise look for a hang-up again shortly.
                                tokio::select! {
                                    permit = in_tx.reserve() => {
                                        if let Ok(p) = permit {
                                            p.send(e);
                                        }
                                    }
                                    () = tokio::time::sleep(STDIN_POLL) => event = Some(e),
                                }
                            }
                            _ => return,
                        }
                    }
                }
            }
        }
    };
    let work = async move {
        let run = handler.handle_stream(peer, body, io);
        tokio::pin!(run);
        let last = loop {
            tokio::select! {
                biased;
                Some(frame) = out_rx.recv() => {
                    if !send_half(&mut wr, id, &frame).await {
                        return;
                    }
                }
                last = &mut run => break last,
            }
        };
        // Output the handler queued before finishing comes first.
        while let Ok(frame) = out_rx.try_recv() {
            if !send_half(&mut wr, id, &frame).await {
                return;
            }
        }
        let _ = send_half(&mut wr, id, &last).await;
    };
    tokio::select! {
        () = work => {}
        () = reader => {}
    }
}

async fn send_half<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    id: u64,
    body: &ResponseBody,
) -> bool {
    match encode(id, body) {
        Ok(bytes) => write_frame(w, &bytes).await.is_ok(),
        Err(_) => false,
    }
}
