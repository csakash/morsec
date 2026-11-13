//! Daemon side: a Unix socket in a private directory, a peer check on every connection, and a
//! handler per request.

use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ms_core::{Error, Result, SecretBytes};
use tokio::net::{UnixListener, UnixStream};

use crate::frame::{read_frame, read_secret_frame, write_frame};
use crate::protocol::{ErrorCode, RequestBody, ResponseBody, decode, encode};

/// How long a connection may sit between frames before it is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Most connections served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// Credentials of the connecting process, from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    /// Effective user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Process id, when the platform reports it.
    pub pid: Option<i32>,
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
}

/// A bound daemon socket. Removes the socket file when dropped.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    owner_uid: u32,
}

impl Server {
    /// Binds `path` and sets the socket to 0600.
    ///
    /// A missing directory is created with mode 0700. An existing directory is never modified: it
    /// must already be private (no group or other bits) or `bind` refuses, so pointing `--socket`
    /// at `~/` or `/tmp/` can't silently change those directories. Also refuses when another
    /// daemon answers on `path`, when `path` exists and is not a socket, or when the directory
    /// belongs to another user. A stale socket left by a crashed daemon is removed.
    pub fn bind(path: &Path) -> Result<Self> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                Error::Socket(format!(
                    "socket path {} has no directory; pass a path like ~/Library/Application Support/morsec/msd.sock",
                    path.display()
                ))
            })?;
        match std::fs::metadata(dir) {
            Ok(m) if !m.is_dir() => {
                return Err(Error::Socket(format!(
                    "{} is not a directory; choose another socket path",
                    dir.display()
                )));
            }
            Ok(m) if m.permissions().mode() & 0o077 != 0 => {
                return Err(Error::Socket(format!(
                    "{} is readable or writable by other users (mode {:o}); use a private directory, or run: chmod 700 {}",
                    dir.display(),
                    m.permissions().mode() & 0o7777,
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
        let dir_meta = std::fs::metadata(dir)
            .map_err(|e| Error::io(format!("checking {}", dir.display()), e))?;

        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(Error::Socket(format!(
                        "another msd is already running on {}. Stop it first, or pass --socket",
                        path.display()
                    )));
                }
                std::fs::remove_file(path).map_err(|e| {
                    Error::io(format!("removing stale socket {}", path.display()), e)
                })?;
            }
            Ok(_) => {
                return Err(Error::Socket(format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(format!("checking {}", path.display()), e)),
        }

        let listener = UnixListener::bind(path)
            .map_err(|e| Error::io(format!("binding {}", path.display()), e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(format!("restricting {} to 0600", path.display()), e))?;
        let owner_uid = std::fs::metadata(path)
            .map_err(|e| Error::io(format!("checking {}", path.display()), e))?
            .uid();
        let server = Server {
            listener,
            path: path.to_owned(),
            owner_uid,
        };
        if dir_meta.uid() != owner_uid {
            // Dropping `server` removes the socket.
            return Err(Error::Socket(format!(
                "{} belongs to another user; choose a socket directory you own",
                dir.display()
            )));
        }
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

    /// Accepts connections until `shutdown` resolves.
    pub async fn serve<H: Handler, P: PeerCheck>(
        self,
        handler: Arc<H>,
        check: Arc<P>,
        shutdown: impl Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        loop {
            // At most MAX_CONNECTIONS at once; further clients wait in the listen backlog.
            let permit = tokio::select! {
                () = &mut shutdown => break,
                p = slots.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break, // semaphore closed: never happens, but don't spin
                },
            };
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let (h, c) = (handler.clone(), check.clone());
                        tokio::spawn(async move {
                            serve_conn(stream, h, c).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        // EMFILE and friends: back off instead of spinning.
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    }
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
) {
    let peer = match stream.peer_cred() {
        Ok(c) => PeerInfo {
            uid: c.uid(),
            gid: c.gid(),
            pid: c.pid(),
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
            &mut stream,
            0,
            &ResponseBody::error(ErrorCode::PeerRejected, e.to_string()),
        )
        .await;
        return;
    }
    loop {
        let frame = match tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut stream)).await {
            Err(_) | Ok(Ok(None)) => return,
            Ok(Ok(Some(f))) => f,
            Ok(Err(e)) => {
                send(
                    &mut stream,
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
                send(&mut stream, id, &ResponseBody::error(code, message)).await;
                return;
            }
        };
        let value = if env.body.carries_value() {
            match tokio::time::timeout(IDLE_TIMEOUT, read_secret_frame(&mut stream)).await {
                Ok(Ok(v)) => Some(v),
                Ok(Err(e)) => {
                    send(
                        &mut stream,
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
        let response = handler.handle(&peer, env.body, value).await;
        if !send(&mut stream, env.id, &response).await {
            return;
        }
    }
}
