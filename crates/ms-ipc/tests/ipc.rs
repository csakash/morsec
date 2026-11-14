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
    Server, ServerLimits,
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
            RequestBody::Status => ResponseBody::status("test", "0", "test"),
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
    start_limited(ServerLimits::default(), check).await
}

async fn start_limited<P: PeerCheck>(
    limits: ServerLimits,
    check: impl FnOnce(&Server) -> P,
) -> Running {
    let dir = tmpdir();
    let path = dir.path().join("sub/msd.sock");
    let server = Server::bind_with(&path, limits).unwrap();
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
            ResponseBody::status("test", "0", "test")
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

/// Frames seen by the relay: (client-to-server?, bytes).
type Wire = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

async fn pump(
    mut from: tokio::net::unix::OwnedReadHalf,
    mut to: tokio::net::unix::OwnedWriteHalf,
    upstream: bool,
    log: Wire,
) {
    while let Ok(Some(f)) = read_frame(&mut from).await {
        log.lock().unwrap().push((upstream, f.clone()));
        if write_frame(&mut to, &f).await.is_err() {
            break;
        }
    }
}

/// A byte-recording relay between one client and the server, so a test sees exactly what
/// crossed the socket in each direction.
fn relay(listen: &Path, target: PathBuf, log: Wire) -> tokio::task::JoinHandle<()> {
    let l = tokio::net::UnixListener::bind(listen).unwrap();
    tokio::spawn(async move {
        let (client, _) = l.accept().await.unwrap();
        let server = UnixStream::connect(&target).await.unwrap();
        let (cr, cw) = client.into_split();
        let (sr, sw) = server.into_split();
        let up = tokio::spawn(pump(cr, sw, true, log.clone()));
        let down = tokio::spawn(pump(sr, cw, false, log));
        let _ = tokio::join!(up, down);
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// protects=on the real wire, a PutKey value crosses exactly once, as its own raw frame
// right after the PutKey JSON; every other frame in both directions is JSON without the value;
// and the handler receives it intact; fails_when=the client also puts the value in a JSON frame,
// the server echoes it, or the value frame is missing or altered; no_claim=memory wiping, or
// other transports
#[tokio::test]
async fn value_crosses_the_wire_only_as_raw_frame() {
    let r = start().await;
    let relay_dir = tmpdir();
    let relay_path = relay_dir.path().join("relay.sock");
    let wire: Wire = Arc::default();
    let relay_task = relay(&relay_path, r.path.clone(), wire.clone());

    let name = KeyName::new("stripe/live").unwrap();
    let meta = KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 1,
    };
    let mut c = Client::connect(&relay_path).await.unwrap();
    let resp = c
        .put_key(name, meta, SecretBytes::from(CANARY.to_owned()))
        .await
        .unwrap();
    assert!(matches!(
        resp,
        ResponseBody::Error {
            code: ErrorCode::NotImplemented,
            ..
        }
    ));
    // A second exchange on the same connection: the stream stays in sync after the value frame.
    assert!(matches!(
        c.request(RequestBody::Status).await.unwrap(),
        ResponseBody::Status { .. }
    ));
    drop(c);
    relay_task.await.unwrap();

    assert_eq!(
        r.handler.values.lock().unwrap().as_slice(),
        [CANARY.as_bytes().to_vec()]
    );
    let frames = wire.lock().unwrap().clone();
    let dirs: Vec<bool> = frames.iter().map(|(up, _)| *up).collect();
    assert_eq!(
        dirs,
        [true, true, false, true, false],
        "unexpected frame sequence"
    );
    for (i, (up, bytes)) in frames.iter().enumerate() {
        if i == 1 {
            assert!(*up);
            assert_eq!(bytes.as_slice(), CANARY.as_bytes(), "value frame altered");
            continue;
        }
        assert!(
            !contains(bytes, CANARY.as_bytes()),
            "value in frame {i}: {}",
            String::from_utf8_lossy(bytes)
        );
        assert!(!contains(bytes, b"CANARY"), "partial value in frame {i}");
        serde_json::from_slice::<serde_json::Value>(bytes)
            .unwrap_or_else(|e| panic!("frame {i} is not JSON: {e}"));
    }
    r.shutdown().await;
}

// protects=every Request and Response variant round-trips through encode/decode; fails_when=a
// variant fails to encode, decode or changes; no_claim=that secrets can't enter a message (that is
// a type guarantee: SecretBytes has no Serialize) or what goes over a socket (see the relay test)
#[test]
fn every_variant_round_trips() {
    let name = KeyName::new("stripe/live").unwrap();
    let meta = KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 1,
    };
    let meta2 = meta.clone();
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
        RequestBody::RulesGet { key: None },
        RequestBody::RulesProposeLoosen {
            key: name.clone(),
            rule: None,
            at_terminal: false,
        },
        RequestBody::RulesProposeLoosen {
            key: name.clone(),
            rule: Some("version = 1\n[keys.\"stripe/live\"]\nmode = \"swap\"\n".into()),
            at_terminal: true,
        },
        RequestBody::Stop,
        RequestBody::Start { at_terminal: false },
        RequestBody::Start { at_terminal: true },
        RequestBody::LogQuery { limit: 10 },
        RequestBody::DoctorProbe {
            nonce: None,
            report: None,
        },
        RequestBody::DoctorProbe {
            nonce: Some("0123456789abcdef0123456789abcdef".into()),
            report: Some(ms_ipc::ProbeReport {
                proxy_reached: true,
                direct_open: false,
                detail: "x".into(),
            }),
        },
    ];
    let all_responses = [
        ResponseBody::status("msd", "0", "dev-stub"),
        ResponseBody::Status {
            daemon: "msd".into(),
            version: "0".into(),
            mode: "keychain".into(),
            running: Some(false),
            keys: Some(3),
            proxy_port: Some(7277),
            alerts: vec!["drift".into()],
            ca_pem: Some("-----BEGIN CERTIFICATE-----".into()),
            ca_hosts: vec!["api.stripe.com".into()],
        },
        ResponseBody::Ok {
            message: "stored".into(),
        },
        ResponseBody::Keys {
            keys: vec![meta2.clone()],
        },
        ResponseBody::Rules {
            version: 4,
            toml: "version = 4\n".into(),
            notes: vec!["n".into()],
        },
        ResponseBody::error(ErrorCode::Internal, "x"),
        ResponseBody::error(ErrorCode::Busy, "x"),
        ResponseBody::error(ErrorCode::Denied, "x"),
        ResponseBody::error(ErrorCode::NeedsApproval, "x"),
        ResponseBody::error(ErrorCode::NotInitialized, "x"),
        ResponseBody::error(ErrorCode::Invalid, "x"),
        ResponseBody::Probe {
            canaries: vec![],
            reports: vec![],
        },
        ResponseBody::Probe {
            canaries: vec![ms_ipc::ProbeSighting {
                session: None,
                seen_unix_ms: 1,
            }],
            reports: vec![(
                ms_ipc::ProbeReport {
                    proxy_reached: false,
                    direct_open: true,
                    detail: String::new(),
                },
                ms_ipc::ProbeSighting {
                    session: Some(ms_core::SessionId {
                        agent: ms_core::AgentKind::Codex,
                        pid: 9,
                        started_unix_ms: 2,
                    }),
                    seen_unix_ms: 3,
                },
            )],
        },
    ];
    for (i, b) in all_requests.iter().enumerate() {
        let bytes = encode(i as u64, b).unwrap();
        let env = decode::<RequestBody>(&bytes).unwrap();
        assert_eq!((env.id, &env.body), (i as u64, b), "round trip");
    }
    for b in &all_responses {
        let bytes = encode(7, b).unwrap();
        assert_eq!(&decode::<ResponseBody>(&bytes).unwrap().body, b);
    }
}

// protects=bind never changes a directory it did not create: an existing group/other-accessible
// directory is refused with a chmod hint and left exactly as it was; an existing private directory
// is used as is; fails_when=the mode changes or bind succeeds in an open directory;
// no_claim=directories owned by another user (needs a second uid)
#[tokio::test]
async fn bind_leaves_existing_directories_alone() {
    let d = tmpdir();
    let open = d.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = Server::bind(&open.join("msd.sock")).unwrap_err();
    assert!(
        matches!(err, Error::Socket(ref m) if m.contains("chmod 700")),
        "{err}"
    );
    let mode = std::fs::metadata(&open).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "bind changed an existing directory");
    assert!(!open.join("msd.sock").exists());

    let private = d.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let s = Server::bind(&private.join("msd.sock")).unwrap();
    assert_eq!(
        std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o700
    );
    drop(s);
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

// protects=old-to-new compatibility of IPC v1 after L07's additions: messages written by a pre-L07
// client or daemon (no new fields) still parse in this build, with the new fields at their safe
// defaults; fails_when=a new field is required or defaults to something permissive (at_terminal
// true); no_claim=new-to-old (a pre-L07 ms can't parse a new msd's extended Status or new
// variants; ms and msd ship together)
#[test]
fn pre_l07_messages_still_parse() {
    let old = [
        (
            r#"{"v":1,"id":1,"body":{"type":"start"}}"#,
            RequestBody::Start { at_terminal: false },
        ),
        (
            r#"{"v":1,"id":1,"body":{"type":"rules_get","key":null}}"#,
            RequestBody::RulesGet { key: None },
        ),
        (
            r#"{"v":1,"id":1,"body":{"type":"rules_propose_loosen","key":"a/b"}}"#,
            RequestBody::RulesProposeLoosen {
                key: KeyName::new("a/b").unwrap(),
                rule: None,
                at_terminal: false,
            },
        ),
    ];
    for (text, want) in old {
        let env = decode::<RequestBody>(text.as_bytes()).unwrap();
        assert_eq!(env.body, want, "{text}");
    }
    let status =
        r#"{"v":1,"id":1,"body":{"type":"status","daemon":"msd","version":"0","mode":"dev-stub"}}"#;
    let env = decode::<ResponseBody>(status.as_bytes()).unwrap();
    assert_eq!(env.body, ResponseBody::status("msd", "0", "dev-stub"));
    // Defaults are not written, so a new daemon's plain status is byte-identical to the old one.
    let bytes = encode(1, &ResponseBody::status("msd", "0", "dev-stub")).unwrap();
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), status);
    let start = encode(1, &RequestBody::Start { at_terminal: false }).unwrap();
    assert_eq!(
        std::str::from_utf8(&start).unwrap(),
        r#"{"v":1,"id":1,"body":{"type":"start"}}"#
    );
}

async fn send_req(s: &mut UnixStream, id: u64, body: &RequestBody) {
    write_frame(s, &encode(id, body).unwrap()).await.unwrap();
}

/// Opens `n` connections and makes sure each is accepted and served (one Status each), then
/// leaves them open.
async fn hold(path: &Path, n: usize) -> Vec<UnixStream> {
    let mut held = Vec::new();
    for i in 0..n {
        let mut s = raw(path).await;
        send_req(&mut s, i as u64 + 1, &RequestBody::Status).await;
        let r = read_response(&mut s).await.expect("held connection served");
        assert!(
            matches!(r.body, ResponseBody::Status { .. }),
            "{:?}",
            r.body
        );
        held.push(s);
    }
    held
}

fn open_limits() -> ServerLimits {
    // One test process stands in for many: lift the per-peer cap for the starvation tests.
    ServerLimits {
        per_peer: 10_000,
        ..ServerLimits::default()
    }
}

// protects=S6: 64 connections held open by one process do not starve the kill switch: Stop and
// Status still answer within a second through the reserved control slots; fails_when=Stop waits
// for a general slot or is refused; no_claim=many processes each holding connections under the
// per-peer cap (residual: an attacker with enough processes can also fill the reserved slots)
#[tokio::test]
async fn held_connections_do_not_delay_stop() {
    let r = start_limited(open_limits(), |s| SameUid { uid: s.owner_uid() }).await;
    let held = hold(&r.path, 64).await;
    let started = std::time::Instant::now();
    let mut c = Client::connect(&r.path).await.unwrap();
    let resp = c.request(RequestBody::Stop).await.unwrap();
    assert!(
        matches!(
            resp,
            ResponseBody::Error {
                code: ErrorCode::NotImplemented,
                ..
            }
        ),
        "Stop reached the handler: {resp:?}"
    );
    let mut c2 = Client::connect(&r.path).await.unwrap();
    assert!(matches!(
        c2.request(RequestBody::Status).await.unwrap(),
        ResponseBody::Status { .. }
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    drop(held);
    r.shutdown().await;
}

// protects=S6: a reserved control slot serves only Status and Stop; anything else gets `busy` and
// the connection closes; fails_when=a non-control request runs while the general pool is full;
// no_claim=fairness between control clients
#[tokio::test]
async fn reserved_slots_refuse_other_requests() {
    let limits = ServerLimits {
        general: 2,
        reserved: 1,
        ..open_limits()
    };
    let r = start_limited(limits, |s| SameUid { uid: s.owner_uid() }).await;
    let held = hold(&r.path, 2).await;
    let mut s = raw(&r.path).await;
    send_req(&mut s, 9, &RequestBody::ListKeys).await;
    let resp = read_response(&mut s).await.unwrap();
    assert!(
        matches!(resp.body, ResponseBody::Error { code: ErrorCode::Busy, ref message } if message.contains("ms stop")),
        "{:?}",
        resp.body
    );
    assert!(
        read_response(&mut s).await.is_none(),
        "connection left open"
    );
    // Reserved slot back: a third client with the general pool full, and the reserved slot held,
    // is refused busy at once instead of hanging.
    let mut ctl = raw(&r.path).await;
    send_req(&mut ctl, 1, &RequestBody::Status).await;
    assert!(matches!(
        read_response(&mut ctl).await.unwrap().body,
        ResponseBody::Status { .. }
    ));
    let mut extra = raw(&r.path).await;
    let resp = read_response(&mut extra).await.unwrap();
    assert!(matches!(
        resp.body,
        ResponseBody::Error {
            code: ErrorCode::Busy,
            ..
        }
    ));
    drop((held, ctl));
    r.shutdown().await;
}

// protects=S6 per-peer cap: one process can't hold more than `per_peer` connections; the next is
// told `busy` and closed, and a slot frees when one closes; fails_when=the cap is not enforced or
// not released; no_claim=PID reuse across the cap (a dead process's PID has no open connections)
#[tokio::test]
async fn per_peer_cap() {
    let limits = ServerLimits {
        per_peer: 2,
        ..ServerLimits::default()
    };
    let r = start_limited(limits, |s| SameUid { uid: s.owner_uid() }).await;
    let mut held = hold(&r.path, 2).await;
    let mut s = raw(&r.path).await;
    let resp = read_response(&mut s).await.unwrap();
    assert!(matches!(
        resp.body,
        ResponseBody::Error {
            code: ErrorCode::Busy,
            ..
        }
    ));
    drop(held.pop());
    // The server notices the close asynchronously.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut c = Client::connect(&r.path).await.unwrap();
        match c.request(RequestBody::Status).await.unwrap() {
            ResponseBody::Status { .. } => break,
            other => assert!(std::time::Instant::now() < deadline, "{other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(held);
    r.shutdown().await;
}

// protects=S6 per-connection caps: a connection is closed after `max_requests` requests and after
// its total lifetime even while it keeps sending; fails_when=a connection lives or serves forever;
// no_claim=the exact timing
#[tokio::test]
async fn request_and_lifetime_caps() {
    let limits = ServerLimits {
        max_requests: 2,
        lifetime: Duration::from_millis(400),
        ..ServerLimits::default()
    };
    let r = start_limited(limits, |s| SameUid { uid: s.owner_uid() }).await;
    let mut s = raw(&r.path).await;
    for id in 1..=2 {
        send_req(&mut s, id, &RequestBody::Status).await;
        assert!(matches!(
            read_response(&mut s).await.unwrap().body,
            ResponseBody::Status { .. }
        ));
    }
    send_req(&mut s, 3, &RequestBody::Status).await;
    let resp = read_response(&mut s).await.unwrap();
    assert!(matches!(
        resp.body,
        ResponseBody::Error {
            code: ErrorCode::Busy,
            ..
        }
    ));

    let mut t = raw(&r.path).await;
    let started = std::time::Instant::now();
    send_req(&mut t, 1, &RequestBody::Status).await;
    assert!(read_response(&mut t).await.is_some());
    // Keep the connection idle-but-alive: it is still closed at the lifetime.
    assert!(read_response(&mut t).await.is_none());
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_secs(3),
        "{took:?}"
    );
    r.shutdown().await;
}

// protects=S3: bind refuses a socket directory that is a symbolic link (even to a private
// directory we own) and leaves nothing behind; fails_when=bind follows the link;
// no_claim=a swap of an ancestor directory mid-bind (the post-bind inode check covers the parent)
#[tokio::test]
async fn bind_refuses_symlinked_directory() {
    let d = tmpdir();
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = Server::bind(&link.join("msd.sock")).unwrap_err();
    assert!(
        matches!(err, Error::Socket(ref m) if m.contains("symbolic link")),
        "{err}"
    );
    assert!(!real.join("msd.sock").exists());
}

// protects=S3: the bound socket is 0600 and owned by us, inside a 0700 directory bind created;
// fails_when=the mode is wider; no_claim=umask races in other threads
#[tokio::test]
async fn bound_socket_is_private() {
    use std::os::unix::fs::MetadataExt;
    let d = tmpdir();
    let path = d.path().join("new/dir/msd.sock");
    let s = Server::bind(&path).unwrap();
    let m = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(m.mode() & 0o777, 0o600);
    assert_eq!(m.uid(), s.owner_uid());
    let dm = std::fs::metadata(path.parent().unwrap()).unwrap();
    assert_eq!(dm.mode() & 0o777, 0o700);
    drop(s);
    assert!(!path.exists());
}

// protects=L17 additive change to the frozen v1 DoctorProbe: the pre-L17 unit form
// {"type":"doctor_probe"} still parses (as a lookup with no nonce); fails_when=the old wire form
// is rejected; no_claim=what msd answers
#[test]
fn doctor_probe_old_wire_form_parses() {
    let env = decode::<RequestBody>(br#"{"v":1,"id":4,"body":{"type":"doctor_probe"}}"#).unwrap();
    assert_eq!(
        env.body,
        RequestBody::DoctorProbe {
            nonce: None,
            report: None
        }
    );
}
