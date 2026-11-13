//! Idle timeouts for tunnels: an IO wrapper that records activity, and a watchdog that ends a
//! future once nothing has moved for the configured time.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Last time any wrapped stream moved bytes, as milliseconds since `start`.
#[derive(Debug, Clone)]
pub(crate) struct Activity {
    start: Instant,
    last_ms: Arc<AtomicU64>,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        let now = self.start.elapsed().as_millis() as u64;
        self.last_ms.store(now, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = self.last_ms.load(Ordering::Relaxed);
        self.start
            .elapsed()
            .saturating_sub(Duration::from_millis(last))
    }
}

/// Wraps a stream so every read or write that moves bytes counts as activity.
#[derive(Debug)]
pub(crate) struct IdleIo<T> {
    inner: T,
    activity: Activity,
}

impl<T> IdleIo<T> {
    pub(crate) fn new(inner: T, activity: Activity) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.touch();
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Runs `fut` until it finishes or `activity` has been idle for `idle`; the future is dropped
/// (closing its connections) in the second case.
pub(crate) async fn until_idle<F: Future>(fut: F, activity: Activity, idle: Duration) {
    let watchdog = async {
        loop {
            let left = idle.saturating_sub(activity.idle_for());
            if left.is_zero() {
                return;
            }
            tokio::time::sleep(left).await;
        }
    };
    tokio::select! {
        _ = fut => {}
        () = watchdog => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // protects=an idle tunnel is ended after the idle time while an active one keeps going;
    // fails_when=an idle future runs forever or an active one is cut; no_claim=real sockets
    #[tokio::test]
    async fn idle_watchdog() {
        let (a, mut b) = tokio::io::duplex(64);
        let act = Activity::new();
        let mut io = IdleIo::new(a, act.clone());
        let started = Instant::now();
        let reader = async move {
            let mut buf = [0u8; 8];
            while io.read(&mut buf).await.map(|n| n > 0).unwrap_or(false) {}
        };
        let writer = async move {
            for _ in 0..5 {
                b.write_all(b"x").await.unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            // then go quiet without closing
            std::future::pending::<()>().await;
        };
        until_idle(
            async {
                tokio::join!(reader, writer);
            },
            act,
            Duration::from_millis(150),
        )
        .await;
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(300),
            "{took:?}: cut while active"
        );
        assert!(took < Duration::from_secs(2), "{took:?}: idle never ended");
    }
}
