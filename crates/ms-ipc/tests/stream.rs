//! `RunStream` over a real socket (L12): stdin frames reach the handler, output frames reach the
//! client in order, the last frame ends the stream, a client that leaves cancels the handler, and
//! a handler without streaming answers `not_implemented`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ms_core::SecretBytes;
use ms_ipc::{
    Client, ErrorCode, Handler, OutStream, PeerInfo, RequestBody, ResponseBody, SameUid, Server,
    StdinEvent, StreamIo,
};
use tokio::sync::oneshot;

/// Echoes stdin to stdout upper-cased, then exits with the number of bytes read.
#[derive(Default)]
struct Echo {
    dropped: Arc<AtomicBool>,
}

struct SetOnDrop(Arc<AtomicBool>);
impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Handler for Echo {
    async fn handle(&self, _: &PeerInfo, _: RequestBody, _: Option<SecretBytes>) -> ResponseBody {
        ResponseBody::error(ErrorCode::Invalid, "x")
    }

    async fn handle_stream(
        &self,
        _: &PeerInfo,
        req: RequestBody,
        mut io: StreamIo,
    ) -> ResponseBody {
        let _guard = SetOnDrop(self.dropped.clone());
        let RequestBody::RunStream { argv, .. } = req else {
            return ResponseBody::error(ErrorCode::Protocol, "not a stream");
        };
        if argv.first().map(String::as_str) == Some("refuse") {
            return ResponseBody::error(ErrorCode::Denied, "no");
        }
        let _ = io.output.send(ResponseBody::RunStarted).await;
        if argv.first().map(String::as_str) == Some("deaf") {
            // Never reads stdin.
            std::future::pending::<()>().await;
        }
        if argv.first().map(String::as_str) == Some("hang") {
            std::future::pending::<()>().await;
        }
        let mut n = 0;
        while let Some(StdinEvent::Data(d)) = io.input.recv().await {
            n += d.len();
            let up = String::from_utf8_lossy(&d).to_uppercase();
            let _ = io
                .output
                .send(ResponseBody::RunOutput {
                    stream: OutStream::Stdout,
                    data: ms_ipc::b64_encode(up.as_bytes()),
                })
                .await;
        }
        ResponseBody::RunExit {
            code: Some(i32::try_from(n).unwrap()),
            signal: None,
        }
    }
}

/// A handler that only implements `handle`.
struct Plain;
impl Handler for Plain {
    async fn handle(&self, _: &PeerInfo, _: RequestBody, _: Option<SecretBytes>) -> ResponseBody {
        ResponseBody::error(ErrorCode::Invalid, "x")
    }
}

async fn serve<H: Handler>(
    h: Arc<H>,
) -> (tempfile::TempDir, std::path::PathBuf, oneshot::Sender<()>) {
    let dir = tempfile::Builder::new()
        .prefix("msstr")
        .tempdir_in("/tmp")
        .unwrap();
    let path = dir.path().join("s/msd.sock");
    let server = Server::bind(&path).unwrap();
    let check = Arc::new(SameUid {
        uid: server.owner_uid(),
    });
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(server.serve(h, check, async {
        let _ = rx.await;
    }));
    (dir, path, tx)
}

fn stream_req(cmd: &str) -> RequestBody {
    RequestBody::RunStream {
        argv: vec![cmd.into()],
        cwd: "/".into(),
        env: vec![],
    }
}

// protects=stdin bytes reach the handler, output frames arrive in order before the last frame,
// and the last frame is the handler's result; fails_when=bytes are lost, reordered or the exit is
// wrong; no_claim=the runner (ms-run tests)
#[tokio::test]
async fn round_trip() {
    let (_d, path, _stop) = serve(Arc::new(Echo::default())).await;
    let client = Client::connect(&path).await.unwrap();
    let input: &[u8] = b"hello stream";
    let mut got = Vec::new();
    let last = client
        .run_stream(stream_req("echo"), Some(input), |s, b| {
            assert_eq!(s, OutStream::Stdout);
            got.extend_from_slice(b);
        })
        .await
        .unwrap();
    assert_eq!(got, b"HELLO STREAM");
    assert_eq!(
        last,
        ResponseBody::RunExit {
            code: Some(12),
            signal: None
        }
    );

    // No stdin: an immediate end of input.
    let client = Client::connect(&path).await.unwrap();
    let last = client
        .run_stream(stream_req("echo"), None::<&[u8]>, |_, _| {})
        .await
        .unwrap();
    assert_eq!(
        last,
        ResponseBody::RunExit {
            code: Some(0),
            signal: None
        }
    );
}

// protects=R1: a refusal before RunStarted leaves the caller's stdin unread, so the shim can still
// pass it to the real tool; fails_when=any stdin byte is consumed; no_claim=-
#[tokio::test]
async fn refusal_leaves_stdin_unread() {
    let (_d, path, _stop) = serve(Arc::new(Echo::default())).await;
    let client = Client::connect(&path).await.unwrap();
    let mut input: &[u8] = b"keep me";
    let last = client
        .run_stream(stream_req("refuse"), Some(&mut input), |_, _| {})
        .await
        .unwrap();
    assert!(matches!(
        last,
        ResponseBody::Error {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert_eq!(input, b"keep me");
}

// protects=a client that disconnects mid-stream cancels the handler (its future is dropped, which
// is what kills the child in msd); fails_when=the handler keeps running; no_claim=-
#[tokio::test]
async fn disconnect_cancels() {
    let h = Arc::new(Echo::default());
    let (_d, path, _stop) = serve(h.clone()).await;
    let client = Client::connect(&path).await.unwrap();
    let run = client.run_stream(stream_req("hang"), Some(tokio::io::empty()), |_, _| {});
    let _ = tokio::time::timeout(Duration::from_millis(300), run).await;
    for _ in 0..100 {
        if h.dropped.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the stream handler was not cancelled when the client left");
}

// protects=a handler without streaming answers not_implemented naming L12; stdin frames outside
// a stream are not requests; fails_when=either is served; no_claim=-
#[tokio::test]
async fn default_and_stray_frames() {
    let (_d, path, _stop) = serve(Arc::new(Plain)).await;
    let client = Client::connect(&path).await.unwrap();
    let last = client
        .run_stream(stream_req("x"), None::<&[u8]>, |_, _| {})
        .await
        .unwrap();
    assert!(
        matches!(&last, ResponseBody::Error { code: ErrorCode::NotImplemented, message } if message.contains("L12")),
        "{last:?}"
    );
    assert!(!RequestBody::RunInputEnd.is_stream());
    assert!(RequestBody::RunInputEnd.owner_loop().contains("L12"));
}

/// Endless stdin.
struct Zeros;
impl tokio::io::AsyncRead for Zeros {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = buf.remaining().min(8192);
        buf.put_slice(&vec![0u8; n]);
        std::task::Poll::Ready(Ok(()))
    }
}

// protects=R4: with the stdin queue full (the handler never reads stdin) a client that hangs up
// still cancels the run; fails_when=the handler keeps running; no_claim=-
#[tokio::test]
async fn disconnect_cancels_under_stdin_backpressure() {
    let h = Arc::new(Echo::default());
    let (_d, path, _stop) = serve(h.clone()).await;
    let client = Client::connect(&path).await.unwrap();
    let run = client.run_stream(stream_req("deaf"), Some(Zeros), |_, _| {});
    let _ = tokio::time::timeout(Duration::from_millis(500), run).await;
    for _ in 0..100 {
        if h.dropped.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("a client that left during stdin backpressure did not cancel the run");
}
