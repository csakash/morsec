//! Client side, used by `ms`, the shim and `ms mcp`.

use std::path::Path;
use std::time::Duration;

use ms_core::{Error, KeyMeta, KeyName, Result, SecretBytes};
use tokio::net::UnixStream;

use crate::frame::{read_frame, read_secret_frame, write_frame};
use crate::peer_verify::PeerIdentity;
use crate::protocol::{OutStream, RequestBody, ResponseBody, decode, encode};
use tokio::io::AsyncReadExt;

/// How long to wait for the daemon to accept.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait for a response.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// A connection to `msd`.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    next_id: u64,
    identity: PeerIdentity,
}

impl Client {
    /// Connects to the daemon at `path`. Any failure is [`Error::DaemonUnavailable`]: nothing
    /// falls back to anything else.
    pub async fn connect(path: &Path) -> Result<Self> {
        let unavailable = |detail: String| Error::DaemonUnavailable { detail };
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(path))
            .await
            .map_err(|_| unavailable(format!("no answer on {} within 2s", path.display())))?
            .map_err(|e| unavailable(format!("{}: {e}", path.display())))?;
        // Authenticate the server before sending anything (a key value, in put_key): it must
        // run as this user. Another user's socket at the same path is not our daemon.
        let server_uid = stream
            .peer_cred()
            .map_err(|e| {
                unavailable(format!(
                    "can't identify the server on {}: {e}",
                    path.display()
                ))
            })?
            .uid();
        check_server_uid(server_uid, own_uid()?, path)?;
        // T-03: the uid says nothing about *which* same-user process answers. Before the first
        // frame, check the connected peer's code signature (see `peer_verify`).
        let identity = verify_server(&stream)
            .await
            .map_err(|detail| Error::DaemonNotVerified { detail })?;
        Ok(Self {
            stream,
            next_id: 1,
            identity,
        })
    }

    /// What was established about the daemon when this connection was made (`ms doctor`).
    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Sends a request and waits for its response. Use [`Client::put_key`] for `PutKey`.
    pub async fn request(&mut self, body: RequestBody) -> Result<ResponseBody> {
        if body.carries_value() {
            return Err(Error::Protocol(
                "PutKey must be sent with Client::put_key".into(),
            ));
        }
        self.request_within(body, RESPONSE_TIMEOUT).await
    }

    /// Like [`Client::request`], waiting up to `timeout` for the response (`Scan`, which reads
    /// every transcript, can take longer than the default).
    pub async fn request_within(
        &mut self,
        body: RequestBody,
        timeout: Duration,
    ) -> Result<ResponseBody> {
        if body.carries_value() {
            return Err(Error::Protocol(
                "PutKey must be sent with Client::put_key".into(),
            ));
        }
        let id = self.send(&body).await?;
        self.receive(id, timeout).await
    }

    /// Sends a request whose reply may be followed by raw value frames (L34 `DevStart`), waiting
    /// up to `timeout` for the reply. After a `DevStarted`, reads one value per name in its `env`
    /// straight into [`SecretBytes`]; any other reply comes back with no values.
    pub async fn request_with_values(
        &mut self,
        body: RequestBody,
        timeout: Duration,
    ) -> Result<(ResponseBody, Vec<SecretBytes>)> {
        if !body.returns_values() {
            return Err(Error::Protocol(
                "request_with_values needs a DevStart request".into(),
            ));
        }
        let id = self.send(&body).await?;
        let reply = self.receive(id, timeout).await?;
        let n = match &reply {
            ResponseBody::DevStarted { env, .. } => env.len(),
            _ => 0,
        };
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            let v = tokio::time::timeout(RESPONSE_TIMEOUT, read_secret_frame(&mut self.stream))
                .await
                .map_err(|_| Error::Protocol("the daemon stopped sending values".into()))??;
            values.push(v);
        }
        Ok((reply, values))
    }

    /// Stores a key. The value goes in its own raw frame and never through serde.
    pub async fn put_key(
        &mut self,
        name: KeyName,
        meta: KeyMeta,
        value: SecretBytes,
    ) -> Result<ResponseBody> {
        let id = self.send(&RequestBody::PutKey { name, meta }).await?;
        write_frame(&mut self.stream, value.expose()).await?;
        drop(value);
        self.receive(id, RESPONSE_TIMEOUT).await
    }

    /// Runs a command as a stream (`RunStream`, L12): once the daemon answers `RunStarted`,
    /// forwards `stdin` (or an immediate end when `None`), hands each redacted output chunk to
    /// `on_output`, and returns the last frame (`RunExit` or `Error`). If the daemon refuses
    /// first, `stdin` is never read. Consumes the connection: the daemon closes it after a stream.
    pub async fn run_stream<R, F>(
        mut self,
        request: RequestBody,
        stdin: Option<R>,
        mut on_output: F,
    ) -> Result<ResponseBody>
    where
        R: tokio::io::AsyncRead + Unpin,
        F: FnMut(OutStream, &[u8]),
    {
        if !request.is_stream() {
            return Err(Error::Protocol(
                "run_stream needs a RunStream request".into(),
            ));
        }
        let id = self.send(&request).await?;
        let (mut rd, mut wr) = self.stream.split();
        // Nothing of stdin is read until the daemon says the run starts.
        let started = read_frame(&mut rd)
            .await?
            .ok_or_else(|| Error::Protocol("the daemon closed the run".into()))?;
        match decode::<ResponseBody>(&started)
            .map_err(|(_, _, m)| Error::Protocol(m))?
            .body
        {
            ResponseBody::RunStarted => {}
            ResponseBody::RunOutput { .. } => {
                return Err(Error::Protocol(
                    "the daemon sent output before the run started".into(),
                ));
            }
            last => return Ok(last),
        }
        let pump = async move {
            if let Some(mut input) = stdin {
                let mut buf = vec![0u8; STDIN_CHUNK];
                loop {
                    let n = match input.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let frame = RequestBody::RunInput {
                        data: crate::b64_encode(&buf[..n]),
                    };
                    if !send_on(&mut wr, id, &frame).await {
                        return std::future::pending().await;
                    }
                }
            }
            let _ = send_on(&mut wr, id, &RequestBody::RunInputEnd).await;
            std::future::pending::<()>().await
        };
        let reader = async move {
            loop {
                let frame = read_frame(&mut rd)
                    .await?
                    .ok_or_else(|| Error::Protocol("the daemon closed the run".into()))?;
                let env = decode::<ResponseBody>(&frame).map_err(|(_, _, m)| Error::Protocol(m))?;
                match env.body {
                    ResponseBody::RunOutput { stream, data } => {
                        let bytes = crate::b64_decode(&data).ok_or_else(|| {
                            Error::Protocol("the daemon sent malformed output".into())
                        })?;
                        on_output(stream, &bytes);
                    }
                    last => return Ok(last),
                }
            }
        };
        tokio::select! {
            r = reader => r,
            () = pump => unreachable!("the stdin pump never finishes"),
        }
    }

    async fn send(&mut self, body: &RequestBody) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = encode(id, body)?;
        write_frame(&mut self.stream, &bytes).await?;
        Ok(id)
    }

    async fn receive(&mut self, id: u64, timeout: Duration) -> Result<ResponseBody> {
        let frame = tokio::time::timeout(timeout, read_frame(&mut self.stream))
            .await
            .map_err(|_| {
                Error::Protocol(format!(
                    "no response from the daemon within {}s",
                    timeout.as_secs()
                ))
            })??
            .ok_or_else(|| Error::Protocol("the daemon closed the connection".into()))?;
        let env = decode::<ResponseBody>(&frame).map_err(|(_, _, m)| Error::Protocol(m))?;
        // id 0 is the daemon's "this connection is being closed" error.
        if env.id != id && env.id != 0 {
            return Err(Error::Protocol(format!(
                "response id {} does not match request {id}",
                env.id
            )));
        }
        Ok(env.body)
    }
}

/// Applies the peer-verification policy to a fresh connection. The signature check can poll for
/// up to 2 s, so it runs off the async workers (a long-lived `ms mcp` connects per tool call),
/// on its own descriptor for the same socket. The dev opt-out and refusals decide at once.
///
/// If the caller drops the connect future, the blocking check still runs to its end (at most
/// 2 s) holding that descriptor, so msd counts the connection toward its per-process limit
/// until then. Nothing is ever sent on it (review R10, accepted).
async fn verify_server(stream: &UnixStream) -> std::result::Result<PeerIdentity, String> {
    use crate::peer_verify::{Trust, apply, current_trust, verify_peer};
    let trust = current_trust();
    if !matches!(trust, Trust::Verify { .. }) {
        return apply(trust, |_| Err("no signature check in this mode".into()));
    }
    let fd = {
        use std::os::fd::AsFd;
        stream
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| format!("can't duplicate the connection for the check: {e}"))?
    };
    tokio::task::spawn_blocking(move || apply(trust, |req| verify_peer(&fd, req)))
        .await
        .map_err(|e| format!("the check did not finish: {e}"))?
}

/// Stdin bytes per `RunInput` frame.
const STDIN_CHUNK: usize = 32 * 1024;

async fn send_on<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, id: u64, body: &RequestBody) -> bool {
    match encode(id, body) {
        Ok(bytes) => write_frame(w, &bytes).await.is_ok(),
        Err(_) => false,
    }
}

/// This process's effective uid, read from the kernel through a socket pair (no `unsafe`):
/// the peer of our own pair is us.
fn own_uid() -> Result<u32> {
    let (a, _b) = UnixStream::pair().map_err(|e| Error::io("creating a socket pair", e))?;
    Ok(a.peer_cred()
        .map_err(|e| Error::io("reading own credentials", e))?
        .uid())
}

fn check_server_uid(server_uid: u32, own: u32, path: &Path) -> Result<()> {
    if server_uid == own {
        Ok(())
    } else {
        Err(Error::DaemonUnavailable {
            detail: format!(
                "the socket {} belongs to uid {server_uid}, not to you; refusing to talk to it",
                path.display()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=a server running as another user is refused before anything is sent, with the
    // DaemonUnavailable fix text; fails_when=a mismatched uid is accepted; no_claim=a live
    // second-user server (needs two uids; the comparison is what this pins)
    #[test]
    fn other_users_server_is_refused() {
        let p = Path::new("/tmp/x.sock");
        assert!(check_server_uid(501, 501, p).is_ok());
        let err = check_server_uid(0, 501, p).unwrap_err();
        assert!(matches!(err, Error::DaemonUnavailable { .. }));
        assert!(
            err.to_string().contains("belongs to uid 0") && err.to_string().contains("ms start"),
            "{err}"
        );
    }

    // protects=own_uid returns this process's uid, matching the owner of a file it creates;
    // fails_when=it returns another uid; no_claim=setuid processes
    #[tokio::test]
    async fn own_uid_matches_created_file() {
        use std::os::unix::fs::MetadataExt;
        let f = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            own_uid().unwrap(),
            std::fs::metadata(f.path()).unwrap().uid()
        );
    }
}
