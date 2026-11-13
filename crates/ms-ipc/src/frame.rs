//! Length-prefixed frames.

use ms_core::{Error, Result, SecretBytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::MAX_FRAME;

async fn read_len<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<usize>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r
            .read(&mut len[got..])
            .await
            .map_err(|e| Error::io("reading frame length", e))?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(Error::Protocol(
                    "connection closed inside a frame header".into(),
                ))
            };
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(Error::Protocol("empty frame".into()));
    }
    if len > MAX_FRAME {
        return Err(Error::Protocol(format!(
            "frame of {len} bytes exceeds the 1 MiB limit"
        )));
    }
    Ok(Some(len))
}

/// Reads one frame. `Ok(None)` means the peer closed cleanly between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let Some(len) = read_len(r).await? else {
        return Ok(None);
    };
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| Error::io("reading frame body", e))?;
    Ok(Some(buf))
}

/// Reads one frame straight into [`SecretBytes`], for `PutKey` values. A clean close here is a
/// protocol error: the value was promised.
pub async fn read_secret_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<SecretBytes> {
    let len = read_len(r)
        .await?
        .ok_or_else(|| Error::Protocol("connection closed before the key value".into()))?;
    // Read into a zeroizing buffer so a partial read on an error path is wiped, then move the
    // allocation into SecretBytes (no copy).
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)
        .await
        .map_err(|e| Error::io("reading key value", e))?;
    Ok(SecretBytes::new(std::mem::take(&mut *buf)))
}

/// Writes one frame. Rejects empty and oversized payloads before writing anything.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(Error::Protocol("refusing to send an empty frame".into()));
    }
    if payload.len() > MAX_FRAME {
        return Err(Error::Protocol(format!(
            "refusing to send a frame of {} bytes (limit 1 MiB)",
            payload.len()
        )));
    }
    let len =
        u32::try_from(payload.len()).map_err(|_| Error::Protocol("frame too large".into()))?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::io("writing frame", e))?;
    w.write_all(payload)
        .await
        .map_err(|e| Error::io("writing frame", e))?;
    w.flush().await.map_err(|e| Error::io("writing frame", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=frames round-trip and the limits hold on both sides; fails_when=an empty or
    // >1 MiB frame is read or written; no_claim=socket behaviour (see tests/ipc.rs)
    #[tokio::test]
    async fn limits() {
        let (mut a, mut b) = tokio::io::duplex(4 << 20);
        write_frame(&mut a, b"hello").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"hello");

        assert!(write_frame(&mut a, b"").await.is_err());
        assert!(
            write_frame(&mut a, &vec![1u8; MAX_FRAME + 1])
                .await
                .is_err()
        );
        write_frame(&mut a, &vec![1u8; MAX_FRAME]).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap().len(), MAX_FRAME);

        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(read_frame(&mut b).await, Err(Error::Protocol(m)) if m.contains("empty")));
        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(read_frame(&mut b).await, Err(Error::Protocol(m)) if m.contains("1 MiB")));

        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    // protects=a value frame arrives intact as SecretBytes; fails_when=bytes differ or a missing
    // value frame is accepted; no_claim=memory wiping of intermediate buffers
    #[tokio::test]
    async fn secret_frame() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"sk_CANARY").await.unwrap();
        assert_eq!(
            read_secret_frame(&mut b).await.unwrap().expose(),
            b"sk_CANARY"
        );
        drop(a);
        assert!(read_secret_frame(&mut b).await.is_err());
    }
}
