//! Client side, used by `ms`, the shim and `ms mcp`.

use std::path::Path;
use std::time::Duration;

use ms_core::{Error, KeyMeta, KeyName, Result, SecretBytes};
use tokio::net::UnixStream;

use crate::frame::{read_frame, write_frame};
use crate::protocol::{RequestBody, ResponseBody, decode, encode};

/// How long to wait for the daemon to accept.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait for a response.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// A connection to `msd`.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    next_id: u64,
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
        Ok(Self { stream, next_id: 1 })
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
