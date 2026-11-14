//! IPC between `ms`, the shim, `ms mcp` and `msd`.
//!
//! Frames are a 4-byte big-endian length followed by UTF-8 JSON, at most [`MAX_FRAME`] bytes.
//! Messages are `{"v":1,"id":<u64>,"body":{...}}`. There is deliberately no request that returns
//! a secret value, and [`ms_core::SecretBytes`] has no `Serialize`, so no message can carry one.
//! `PutKey` sends its value in a separate raw frame that the server reads straight into
//! `SecretBytes`.

pub mod client;
pub mod frame;
pub mod paths;
pub mod protocol;
pub mod server;

pub use client::Client;
pub use paths::default_socket_path;
pub use protocol::{
    ErrorCode, OutStream, PROTOCOL_VERSION, RequestBody, ResponseBody, RunEnv, ScanFinding,
};
pub use server::{
    Handler, PeerCheck, PeerInfo, SameUid, Server, ServerLimits, StdinEvent, StreamIo, now_unix_ms,
};

/// Largest frame accepted, in bytes (1 MiB).
pub const MAX_FRAME: usize = 1 << 20;

/// Encodes stream bytes for `RunInput` / `RunOutput` / `RunResult` (standard base64).
pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes [`b64_encode`]'s output. `None` for anything else.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}
