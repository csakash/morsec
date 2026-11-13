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
        Ok(Self { stream, next_id: 1 })
    }

    /// Sends a request and waits for its response. Use [`Client::put_key`] for `PutKey`.
    pub async fn request(&mut self, body: RequestBody) -> Result<ResponseBody> {
        if body.carries_value() {
            return Err(Error::Protocol(
                "PutKey must be sent with Client::put_key".into(),
            ));
        }
        let id = self.send(&body).await?;
        self.receive(id).await
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
        self.receive(id).await
    }

    async fn send(&mut self, body: &RequestBody) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = encode(id, body)?;
        write_frame(&mut self.stream, &bytes).await?;
        Ok(id)
    }

    async fn receive(&mut self, id: u64) -> Result<ResponseBody> {
        let frame = tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(&mut self.stream))
            .await
            .map_err(|_| Error::Protocol("no response from the daemon within 30s".into()))??
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
