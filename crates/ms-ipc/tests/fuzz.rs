//! Fuzz targets for IPC framing, message decoding and the live server (hardening loop, SPEC S2).
//!
//! proptest on stable (SPEC D1). `MORSEC_FUZZ_CASES` sets the case count; seeds come from
//! `fuzz/corpus/ipc-frames` (raw byte streams) and `fuzz/corpus/ipc-messages` (JSON envelopes).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use ms_core::{KeyMeta, KeyName, Mode, SecretBytes, Tier};
use ms_ipc::frame::{read_frame, read_secret_frame, write_frame};
use ms_ipc::protocol::{Envelope, Header, decode, encode};
use ms_ipc::{
    ApprovalScope, ErrorCode, Handler, MAX_FRAME, PeerInfo, ProbeReport, RequestBody, ResponseBody,
    RunEnv, SameUid, Server, StdinEvent, StreamIo,
};
use proptest::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::UnixStream;

const CANARY: &[u8] = b"sk_live_CANARY_c0ffee_DO_NOT_LEAK";

fn corpus(name: &str) -> Vec<Vec<u8>> {
    ms_fuzz::seeds(&format!("ipc-{name}"))
}

/// Tokens worth inserting whole into a mutated message.
const JSON_DICT: &[&[u8]] = &[
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b",",
    b":",
    b"null",
    b"true",
    b"-1",
    b"1e999",
    b"18446744073709551616",
    b"\"v\":1",
    b"\"v\":2",
    b"\"id\":",
    b"\"type\":",
    b"\"put_key\"",
    b"\"run_stream\"",
    b"\"mcp_call\"",
    b"\"approval_decide\"",
    b"\\u0000",
    b"\\ud800",
    b"\\\"",
    b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
];

/// Tokens worth inserting whole into a mutated frame stream.
const FRAME_DICT: &[&[u8]] = &[
    b"\0\0\0\0",
    b"\0\0\0\x01",
    b"\0\x10\0\0",
    b"\0\x10\0\x01",
    b"\xff\xff\xff\xff",
    b"\x7f\xff\xff\xff",
];

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

// ---------- framing ----------

/// An `AsyncRead` that hands out `data` in chunks of the given sizes (cycled), then EOF. Models a
/// socket that delivers a frame in arbitrary pieces.
struct Chunked {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    k: usize,
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let left = this.data.len() - this.pos;
        if left == 0 {
            return Poll::Ready(Ok(()));
        }
        let want = this.sizes[this.k % this.sizes.len()].max(1);
        this.k += 1;
        let n = want.min(left).min(buf.remaining());
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, PartialEq)]
enum Got {
    Frame(Vec<u8>),
    Closed,
    Error,
}

/// The framing rules, written out plainly: 4-byte big-endian length, then that many bytes; a
/// zero or >1 MiB length, or a stream that ends inside a header or a body, is an error.
fn model(data: &[u8]) -> Vec<Got> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        if rest.is_empty() {
            out.push(Got::Closed);
            return out;
        }
        if rest.len() < 4 {
            out.push(Got::Error);
            return out;
        }
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        if len == 0 || len > MAX_FRAME || rest.len() - 4 < len {
            out.push(Got::Error);
            return out;
        }
        out.push(Got::Frame(rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
}

async fn real(data: Vec<u8>, sizes: Vec<usize>) -> Vec<Got> {
    let mut r = Chunked {
        data,
        pos: 0,
        sizes,
        k: 0,
    };
    let mut out = Vec::new();
    loop {
        match read_frame(&mut r).await {
            Ok(Some(f)) => out.push(Got::Frame(f)),
            Ok(None) => {
                out.push(Got::Closed);
                return out;
            }
            Err(_) => {
                out.push(Got::Error);
                return out;
            }
        }
    }
}

/// A frame stream: a mutated seed, raw bytes, or well-formed frames with optional damage.
fn frame_stream() -> impl Strategy<Value = Vec<u8>> {
    let built = prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 0..6).prop_map(
        |frames| {
            let mut v = Vec::new();
            for f in frames {
                v.extend_from_slice(&(f.len() as u32).to_be_bytes());
                v.extend_from_slice(&f);
            }
            v
        },
    );
    prop_oneof![
        3 => ms_fuzz::mutated(corpus("frames"), FRAME_DICT),
        2 => built,
        1 => prop::collection::vec(any::<u8>(), 0..64),
    ]
}

fn chunk_sizes() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(1usize..9, 1..6)
}

proptest! {
    #![proptest_config(ms_fuzz::config(256))]

    // protects=read_frame agrees with the framing rules on any byte stream delivered in any
    // chunking (no panic, no frame invented, none lost, limits and truncation refused);
    // fails_when=the reader and the model disagree; no_claim=socket timeouts (tests/ipc.rs)
    #[test]
    fn fuzz_frame_model(data in frame_stream(), sizes in chunk_sizes()) {
        let want = model(&data);
        let got = rt().block_on(real(data, sizes));
        prop_assert_eq!(got, want);
    }

    // protects=read_secret_frame reads exactly the first frame or fails, and a clean close is an
    // error (the value was promised); fails_when=it disagrees with the model or panics;
    // no_claim=wiping of the buffer (tests in frame.rs)
    #[test]
    fn fuzz_frame_secret_model(data in frame_stream(), sizes in chunk_sizes()) {
        let want = match model(&data).into_iter().next() {
            Some(Got::Frame(f)) => Some(f),
            _ => None,
        };
        let got = rt().block_on(async {
            let mut r = Chunked { data, pos: 0, sizes, k: 0 };
            read_secret_frame(&mut r).await.ok().map(|v| v.expose().to_vec())
        });
        prop_assert_eq!(got, want);
    }

    // protects=write_frame then read_frame round-trips any payload sequence in any chunking, and
    // write_frame refuses empty payloads before writing anything; fails_when=bytes differ or an
    // empty frame reaches the wire; no_claim=payloads near 1 MiB (frame.rs limits test)
    #[test]
    fn fuzz_frame_roundtrip(
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..2048), 0..6),
        sizes in chunk_sizes(),
    ) {
        let (wire, sent) = rt().block_on(async {
            let mut wire = Vec::new();
            let mut sent = Vec::new();
            for p in &payloads {
                let before = wire.len();
                let r = write_frame(&mut wire, p).await;
                if p.is_empty() {
                    assert!(r.is_err());
                    assert_eq!(wire.len(), before, "nothing written for a refused frame");
                } else {
                    r.unwrap();
                    sent.push(Got::Frame(p.clone()));
                }
            }
            sent.push(Got::Closed);
            (wire, sent)
        });
        prop_assert_eq!(rt().block_on(real(wire, sizes)), sent);
    }
}

// ---------- message decoding ----------

fn key_name() -> impl Strategy<Value = KeyName> {
    "[a-z][a-z0-9_-]{0,10}(/[a-z0-9_.-]{1,10}){0,2}"
        .prop_filter_map("valid key name", |s| KeyName::new(&s).ok())
}

fn json_value() -> impl Strategy<Value = serde_json::Value> {
    use serde_json::Value;
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(any::<String>(), inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn request_body() -> impl Strategy<Value = RequestBody> {
    let argv = prop::collection::vec(any::<String>(), 0..4);
    let cwd = any::<String>().prop_map(PathBuf::from);
    let env = prop::collection::vec(
        (any::<String>(), any::<String>()).prop_map(|(name, value)| RunEnv { name, value }),
        0..3,
    );
    prop_oneof![
        Just(RequestBody::Status),
        Just(RequestBody::ListKeys),
        Just(RequestBody::RunInputEnd),
        Just(RequestBody::Stop),
        Just(RequestBody::Scan),
        Just(RequestBody::ApprovalPending),
        (key_name(), any::<bool>(), any::<u64>()).prop_map(|(name, prod, t)| {
            RequestBody::PutKey {
                meta: KeyMeta {
                    name: name.clone(),
                    mode: Mode::Swap,
                    tier: if prod { Tier::Production } else { Tier::Test },
                    created_unix_ms: t,
                },
                name,
            }
        }),
        (argv.clone(), cwd.clone(), env.clone()).prop_map(|(argv, cwd, env)| RequestBody::Run {
            argv,
            cwd,
            env
        }),
        (argv, cwd.clone(), env).prop_map(|(argv, cwd, env)| RequestBody::RunStream {
            argv,
            cwd,
            env
        }),
        (any::<String>(), any::<u64>(), cwd, json_value()).prop_map(
            |(tool, rules_version, cwd, arguments)| RequestBody::McpCall {
                tool,
                rules_version,
                cwd,
                arguments,
            }
        ),
        any::<String>().prop_map(|data| RequestBody::RunInput { data }),
        (key_name(), any::<String>()).prop_map(|(key, scope)| RequestBody::Mint { key, scope }),
        prop::option::of(key_name()).prop_map(|key| RequestBody::RulesGet { key }),
        (key_name(), prop::option::of(any::<String>()), any::<bool>()).prop_map(
            |(key, rule, at_terminal)| RequestBody::RulesProposeLoosen {
                key,
                rule,
                at_terminal
            }
        ),
        any::<bool>().prop_map(|at_terminal| RequestBody::Start { at_terminal }),
        any::<u32>().prop_map(|limit| RequestBody::LogQuery { limit }),
        (
            prop::option::of("[0-9a-f]{32}"),
            prop::option::of((any::<bool>(), any::<bool>(), any::<String>()).prop_map(
                |(proxy_reached, direct_open, detail)| ProbeReport {
                    proxy_reached,
                    direct_open,
                    detail,
                }
            )),
        )
            .prop_map(|(nonce, report)| RequestBody::DoctorProbe { nonce, report }),
        (
            any::<String>(),
            any::<bool>(),
            prop::option::of(prop_oneof![
                Just(ApprovalScope::Once),
                Just(ApprovalScope::Session)
            ]),
        )
            .prop_map(|(id, approve, scope)| RequestBody::ApprovalDecide {
                id,
                approve,
                scope
            }),
    ]
}

/// Bytes a peer might send as a message: mutated seeds, mutated encodings, or raw text.
fn message_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => ms_fuzz::mutated(corpus("messages"), JSON_DICT),
        1 => any::<String>().prop_map(String::into_bytes),
        1 => prop::collection::vec(any::<u8>(), 0..64),
    ]
}

/// Checks what `decode` did with `bytes` against what the header says.
fn check_decode<T>(bytes: &[u8]) -> Result<(), TestCaseError>
where
    T: serde::de::DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
{
    let header = serde_json::from_slice::<Header>(bytes);
    match (decode::<T>(bytes), header) {
        (Ok(env), Ok(h)) => {
            prop_assert_eq!(env.v, 1);
            prop_assert_eq!(env.id, h.id);
            // What the daemon accepted re-encodes to something it reads back the same way.
            let again =
                encode(env.id, &env.body).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let back: Envelope<T> = decode(&again).map_err(|e| TestCaseError::fail(e.2))?;
            prop_assert_eq!(back, env);
        }
        (Ok(_), Err(e)) => prop_assert!(false, "decoded without a header: {e}"),
        (Err((id, code, _)), Ok(h)) if h.v != 1 => {
            prop_assert_eq!(code, ErrorCode::UnsupportedVersion);
            prop_assert_eq!(id, h.id);
        }
        (Err((id, code, _)), Ok(h)) => {
            prop_assert_eq!(code, ErrorCode::Protocol);
            prop_assert_eq!(id, h.id);
        }
        (Err((id, code, _)), Err(_)) => {
            prop_assert_eq!(code, ErrorCode::Protocol);
            prop_assert_eq!(id, 0);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ms_fuzz::config(1024))]

    // protects=decode never panics on arbitrary or mutated messages, answers a wrong version with
    // UnsupportedVersion and the sender's id, anything else bad with Protocol, and whatever it
    // accepts round-trips; fails_when=a panic, a wrong code or id, or an accepted message that
    // does not re-encode to itself; no_claim=handler semantics
    #[test]
    fn fuzz_decode_request(bytes in message_bytes()) {
        check_decode::<RequestBody>(&bytes)?;
    }

    // protects=as above for responses the client decodes; fails_when=as above
    #[test]
    fn fuzz_decode_response(bytes in message_bytes()) {
        check_decode::<ResponseBody>(&bytes)?;
    }

    // protects=every request a client can build encodes to a frame-sized message that decodes to
    // exactly itself (escaping of control characters, surrogates, nested JSON arguments);
    // fails_when=any field changes in transit; no_claim=messages over 1 MiB (refused by framing)
    #[test]
    fn fuzz_decode_roundtrip(id in any::<u64>(), body in request_body()) {
        let bytes = encode(id, &body).unwrap();
        let back = decode::<RequestBody>(&bytes).map_err(|e| TestCaseError::fail(e.2))?;
        prop_assert_eq!(back.id, id);
        prop_assert_eq!(back.body, body);
    }
}

// ---------- live server ----------

/// Answers Status; counts value frames; drains stream stdin and answers when it ends.
#[derive(Default)]
struct Sink {
    values: AtomicUsize,
}

impl Handler for Sink {
    async fn handle(
        &self,
        _: &PeerInfo,
        request: RequestBody,
        value: Option<SecretBytes>,
    ) -> ResponseBody {
        if value.is_some() {
            self.values.fetch_add(1, Ordering::SeqCst);
        }
        match request {
            RequestBody::Status => ResponseBody::status("fuzz", "0", "fuzz"),
            other => ResponseBody::error(
                ErrorCode::NotImplemented,
                format!("planned in loop {}", other.owner_loop()),
            ),
        }
    }

    async fn handle_stream(&self, _: &PeerInfo, _: RequestBody, mut io: StreamIo) -> ResponseBody {
        while let Some(e) = io.input.recv().await {
            if e == StdinEvent::End {
                break;
            }
        }
        ResponseBody::status("fuzz", "0", "stream")
    }
}

struct Live {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

fn live() -> &'static Live {
    static L: OnceLock<Live> = OnceLock::new();
    L.get_or_init(|| {
        rt().block_on(async {
            // Short base dir: Unix socket paths are limited to ~104 bytes on macOS.
            let dir = tempfile::Builder::new()
                .prefix("msfz")
                .tempdir_in("/tmp")
                .unwrap();
            let path = dir.path().join("s/msd.sock");
            let server = Server::bind(&path).unwrap();
            let check = Arc::new(SameUid {
                uid: server.owner_uid(),
            });
            tokio::spawn(server.serve(Arc::new(Sink::default()), check, std::future::pending()));
            Live { path, _dir: dir }
        })
    })
}

/// Sends `bytes`, closes the write half, and returns every frame the server answered with
/// (`None` if it did not finish within 10 s).
async fn exchange(path: &std::path::Path, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut s = UnixStream::connect(path).await.unwrap();
    let _ = s.write_all(bytes).await;
    let _ = s.shutdown().await;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .ok()
        .map(|_| out)
}

/// A frame stream built from real messages: requests (valid, mutated, PutKey with or without a
/// value frame, a stream with stdin frames) plus damage.
fn session_bytes() -> impl Strategy<Value = Vec<u8>> {
    let frame = |b: &[u8]| {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    };
    let piece = prop_oneof![
        request_body().prop_map(move |b| frame(&encode(1, &b).unwrap())),
        message_bytes().prop_map(move |b| frame(&b)),
        Just(frame(CANARY)),
        Just(frame(&encode(2, &RequestBody::RunInputEnd).unwrap())),
        prop::collection::vec(any::<u8>(), 0..8),
    ];
    prop_oneof![
        3 => prop::collection::vec(piece, 0..6).prop_map(|v| v.concat()),
        2 => ms_fuzz::mutated(corpus("frames"), FRAME_DICT),
    ]
}

proptest! {
    #![proptest_config(ms_fuzz::config(64))]

    // protects=a live server survives any frame sequence (value frames, streams, stdin outside a
    // stream, damage): it answers only well-formed responses, never echoes a value frame, ends
    // the exchange on its own, and still serves a new Status connection; fails_when=a response
    // frame does not decode, contains the canary, the server hangs, or stops answering;
    // no_claim=msd's real handler (tests in crates/msd)
    #[test]
    fn fuzz_server_sequences(bytes in session_bytes()) {
        // Start the server outside block_on: its first use starts it on the same runtime.
        let path = &live().path;
        let out = rt().block_on(exchange(path, &bytes));
        prop_assert!(out.is_some(), "server did not finish the exchange");
        let out = out.unwrap();
        prop_assert!(!out.windows(CANARY.len()).any(|w| w == CANARY), "value echoed");
        let mut frames = model(&out);
        prop_assert_eq!(frames.pop(), Some(Got::Closed), "server sent a broken frame");
        for f in frames {
            let Got::Frame(f) = f else { unreachable!() };
            prop_assert!(decode::<ResponseBody>(&f).is_ok(), "undecodable response");
        }
        let status = rt().block_on(async {
            let mut c = ms_ipc::Client::connect(path).await.unwrap();
            c.request(RequestBody::Status).await
        });
        prop_assert_eq!(status.unwrap(), ResponseBody::status("fuzz", "0", "fuzz"));
    }
}
