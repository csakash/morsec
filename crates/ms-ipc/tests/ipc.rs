//! Socket-level tests for the IPC server and client.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_core::{Error, KeyMeta, KeyName, Mode, SecretBytes, Tier};
use ms_ipc::frame::{read_frame, write_frame};
use ms_ipc::protocol::{Envelope, decode, encode};
use ms_ipc::{
    Client, ErrorCode, Handler, MAX_FRAME, PeerCheck, PeerInfo, RequestBody, ResponseBody, SameUid,
    Server,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::oneshot;

const CANARY: &str = "sk_live_CANARY_c0ffee_DO_NOT_LEAK";

/// Records what it received; answers Status, otherwise not_implemented.
#[derive(Default)]
struct Recorder {
    values: Mutex<Vec<Vec<u8>>>,
}

impl Handler for Recorder {
    async fn handle(
        &self,
        _peer: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        if let Some(v) = value {
            self.values.lock().unwrap().push(v.expose().to_vec());
        }
        match request {
            RequestBody::Status => ResponseBody::Status {
                daemon: "test".into(),
                version: "0".into(),
                mode: "test".into(),
            },
            other => ResponseBody::error(
                ErrorCode::NotImplemented,
                format!("planned in loop {}", other.owner_loop()),
            ),
        }
    }
}

struct Running {
    path: PathBuf,
    handler: Arc<Recorder>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Running {
    async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap();
    }
}

/// Short base dir: Unix socket paths are limited to ~104 bytes on macOS.
fn tmpdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("msipc")
        .tempdir_in("/tmp")
        .unwrap()
}

async fn start_with<P: PeerCheck>(check: impl FnOnce(&Server) -> P) -> Running {
    let dir = tmpdir();
    let path = dir.path().join("sub/msd.sock");
    let server = Server::bind(&path).unwrap();
    let check = Arc::new(check(&server));
    let handler = Arc::new(Recorder::default());
    let (tx, rx) = oneshot::channel();
    let h = handler.clone();
    let task = tokio::spawn(async move {
        server
            .serve(h, check, async {
                let _ = rx.await;
            })
            .await;
    });
    Running {
        path,
        handler,
        stop: Some(tx),
        task,
        _dir: dir,
    }
}

async fn start() -> Running {
    start_with(|s| SameUid { uid: s.owner_uid() }).await
}

async fn raw(path: &Path) -> UnixStream {
    UnixStream::connect(path).await.unwrap()
}

async fn read_response(s: &mut UnixStream) -> Option<Envelope<ResponseBody>> {
    let f = tokio::time::timeout(Duration::from_secs(5), read_frame(s))
        .await
        .unwrap()
        .unwrap()?;
    Some(decode::<ResponseBody>(&f).unwrap())
}

// protects=a Status request round-trips with the matching id; fails_when=the response is missing,
// wrong, or the connection can't be reused; no_claim=the real daemon's status content (L07)
#[tokio::test]
async fn status_round_trip() {
    let r = start().await;
    let mut c = Client::connect(&r.path).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            c.request(RequestBody::Status).await.unwrap(),
            ResponseBody::Status {
                daemon: "test".into(),
                version: "0".into(),
                mode: "test".into()
            }
        );
    }
    r.shutdown().await;
}

// protects=socket 0600 and directory 0700, and the socket is removed on shutdown;
// fails_when=group/other can reach the socket or a stale socket is left; no_claim=ACLs or macOS
// sandbox profiles
#[tokio::test]
async fn socket_permissions() {
    let r = start().await;
    let sock = std::fs::metadata(&r.path).unwrap().permissions().mode() & 0o777;
    let dir = std::fs::metadata(r.path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!((sock, dir), (0o600, 0o700));
    let path = r.path.clone();
    r.shutdown().await;
    assert!(!path.exists(), "socket left behind");
}

// protects=a frame over 1 MiB is refused and the connection closed without reading the body;
// fails_when=the server answers normally or keeps the connection; no_claim=memory use under many
// concurrent oversized clients
#[tokio::test]
async fn oversized_frame_rejected() {
    let r = start().await;
    let mut s = raw(&r.path).await;
    s.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    let resp = read_response(&mut s).await.unwrap();
    assert!(
        matches!(resp.body, ResponseBody::Error { code: ErrorCode::Protocol, ref message } if message.contains("1 MiB"))
    );
    assert!(
        read_response(&mut s).await.is_none(),
        "connection not closed"
    );
    r.shutdown().await;
}

// protects=a zero-length frame is refused and the connection closed; fails_when=it is accepted;
// no_claim=other malformed headers
#[tokio::test]
async fn zero_frame_rejected() {
    let r = start().await;
    let mut s = raw(&r.path).await;
    s.write_all(&0u32.to_be_bytes()).await.unwrap();
    let resp = read_response(&mut s).await.unwrap();
    assert!(matches!(
        resp.body,
        ResponseBody::Error {
            code: ErrorCode::Protocol,
            ..
        }
    ));
    assert!(read_response(&mut s).await.is_none());
    r.shutdown().await;
}

// protects=an unknown protocol version gets unsupported_version with its id, then close;
// fails_when=the server tries to handle it; no_claim=future version negotiation
#[tokio::test]
async fn unknown_version_rejected() {
    let r = start().await;
    let mut s = raw(&r.path).await;
    write_frame(&mut s, br#"{"v":2,"id":42,"body":{"type":"status"}}"#)
        .await
        .unwrap();
    let resp = read_response(&mut s).await.unwrap();
    assert_eq!(resp.id, 42);
    assert!(
        matches!(resp.body, ResponseBody::Error { code: ErrorCode::UnsupportedVersion, ref message } if message.contains("ms --version"))
    );
    assert!(read_response(&mut s).await.is_none());
    r.shutdown().await;
}

// protects=malformed JSON and unknown request types are protocol errors, then close;
// fails_when=either is handled; no_claim=fuzz coverage (L24)
#[tokio::test]
async fn malformed_rejected() {
    let r = start().await;
    for bad in [
        &b"not json"[..],
        br#"{"v":1,"id":1,"body":{"type":"get_secret","key":"a"}}"#,
    ] {
        let mut s = raw(&r.path).await;
        write_frame(&mut s, bad).await.unwrap();
        let resp = read_response(&mut s).await.unwrap();
        assert!(
            matches!(
                resp.body,
                ResponseBody::Error {
                    code: ErrorCode::Protocol,
                    ..
                }
            ),
            "{resp:?}"
        );
        assert!(read_response(&mut s).await.is_none());
    }
    r.shutdown().await;
}

// protects=a missing daemon is DaemonUnavailable whose message tells the user to run ms start;
// fails_when=another error kind or no fix text; no_claim=a daemon that accepts then hangs
#[tokio::test]
async fn missing_daemon_is_unavailable() {
    let dir = tmpdir();
    let err = Client::connect(&dir.path().join("none.sock"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::DaemonUnavailable { .. }), "{err:?}");
    assert!(err.to_string().contains("ms start"), "{err}");
}

// protects=a peer that fails the check gets peer_rejected and nothing is handled;
// fails_when=the request reaches the handler; no_claim=real uid separation (one uid in tests)
#[tokio::test]
async fn rejected_peer() {
    let r = start_with(|s| SameUid {
        uid: s.owner_uid().wrapping_add(1),
    })
    .await;
    let mut c = Client::connect(&r.path).await.unwrap();
    let resp = c.request(RequestBody::Status).await.unwrap();
    assert!(
        matches!(
            resp,
            ResponseBody::Error {
                code: ErrorCode::PeerRejected,
                ..
            }
        ),
        "{resp:?}"
    );
    r.shutdown().await;
}

// protects=a second daemon can't take over a live socket, and a non-socket file is never
// replaced; fails_when=bind succeeds in either case; no_claim=races between two simultaneous binds
#[tokio::test]
async fn bind_refuses_live_socket_and_regular_file() {
    let r = start().await;
    assert!(Server::bind(&r.path).is_err());
    let dir = tmpdir();
    let file = dir.path().join("x.sock");
    std::fs::write(&file, b"keep me").unwrap();
    assert!(Server::bind(&file).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    r.shutdown().await;
}

// protects=a PutKey value travels only in its raw frame: it reaches the handler intact, and no
// JSON message on the wire (request or response) contains it; also every Request/Response variant
// serializes without it; fails_when=the canary appears in any JSON; no_claim=memory wiping
#[tokio::test]
async fn value_never_in_json() {
    let r = start().await;
    let name = KeyName::new("stripe/live").unwrap();
    let meta = KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 1,
    };

    // Over a real client: the handler gets the value and the response doesn't echo it.
    let mut c = Client::connect(&r.path).await.unwrap();
    let resp = c
        .put_key(
            name.clone(),
            meta.clone(),
            SecretBytes::from(CANARY.to_owned()),
        )
        .await
        .unwrap();
    assert!(!format!("{resp:?}").contains("CANARY"));
    assert_eq!(
        r.handler.values.lock().unwrap().as_slice(),
        [CANARY.as_bytes().to_vec()]
    );

    // The JSON frame the client sends for PutKey, byte for byte.
    let put_json = encode(
        1,
        &RequestBody::PutKey {
            name: name.clone(),
            meta: meta.clone(),
        },
    )
    .unwrap();
    let all_requests = [
        RequestBody::Status,
        RequestBody::PutKey {
            name: name.clone(),
            meta,
        },
        RequestBody::ListKeys,
        RequestBody::Run {
            argv: vec!["psql".into(), "ms://pg/staging".into()],
            cwd: "/tmp".into(),
        },
        RequestBody::Mint {
            key: name.clone(),
            scope: "read".into(),
        },
        RequestBody::RulesGet {
            key: Some(name.clone()),
        },
        RequestBody::RulesProposeLoosen { key: name },
        RequestBody::Stop,
        RequestBody::Start,
        RequestBody::LogQuery { limit: 10 },
        RequestBody::DoctorProbe,
    ];
    let all_responses = [
        ResponseBody::Status {
            daemon: "msd".into(),
            version: "0".into(),
            mode: "dev-stub".into(),
        },
        ResponseBody::error(ErrorCode::Internal, "x"),
    ];
    let mut blobs = vec![put_json];
    for (i, b) in all_requests.iter().enumerate() {
        let bytes = encode(i as u64, b).unwrap();
        assert_eq!(
            decode::<RequestBody>(&bytes).unwrap().body,
            *b,
            "round trip"
        );
        blobs.push(bytes);
    }
    for b in &all_responses {
        blobs.push(encode(0, b).unwrap());
    }
    for blob in blobs {
        let s = String::from_utf8(blob).unwrap();
        assert!(!s.contains("CANARY"), "{s}");
    }
    r.shutdown().await;
}

// protects=unimplemented requests answer not_implemented naming their loop; fails_when=a request
// is silently accepted; no_claim=the real handlers
#[tokio::test]
async fn unimplemented_names_loop() {
    let r = start().await;
    let mut c = Client::connect(&r.path).await.unwrap();
    let resp = c.request(RequestBody::Stop).await.unwrap();
    assert!(
        matches!(resp, ResponseBody::Error { code: ErrorCode::NotImplemented, ref message } if message.contains("L07 daemon"))
    );
    assert!(
        c.request(RequestBody::PutKey {
            name: KeyName::new("a").unwrap(),
            meta: KeyMeta {
                name: KeyName::new("a").unwrap(),
                mode: Mode::Swap,
                tier: Tier::Test,
                created_unix_ms: 0
            }
        })
        .await
        .is_err()
    );
    r.shutdown().await;
}
