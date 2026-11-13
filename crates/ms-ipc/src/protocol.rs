//! Protocol v1 messages.

use std::path::PathBuf;

use ms_core::{Error, KeyMeta, KeyName, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// The only protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Every message on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Protocol version.
    pub v: u32,
    /// Request id; a response carries its request's id.
    pub id: u64,
    /// Payload.
    pub body: T,
}

/// Just the version and id, parsed before the body so an unknown version gets a clear error.
#[derive(Debug, Deserialize)]
pub struct Header {
    /// Protocol version.
    pub v: u32,
    /// Request id.
    pub id: u64,
}

/// Requests to the daemon. In L00 only `Status` is handled; the rest answer `not_implemented`
/// naming the loop that builds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestBody {
    /// Daemon status.
    Status,
    /// Store a key. The value follows in the next frame, raw.
    PutKey {
        /// Key name.
        name: KeyName,
        /// Its metadata.
        meta: KeyMeta,
    },
    /// List key metadata.
    ListKeys,
    /// Run a command (from the shim or `ms run`). Non-UTF-8 arguments are refused by the client.
    Run {
        /// Exact argv.
        argv: Vec<String>,
        /// Working directory.
        cwd: PathBuf,
    },
    /// Mint a short-lived credential.
    Mint {
        /// Key.
        key: KeyName,
        /// Requested scope.
        scope: String,
    },
    /// Show rules (all, or one key).
    RulesGet {
        /// Key, or all.
        key: Option<KeyName>,
    },
    /// Propose a looser rule; needs an approval.
    RulesProposeLoosen {
        /// Key.
        key: KeyName,
    },
    /// Kill switch.
    Stop,
    /// Resume after a stop; needs an approval.
    Start,
    /// Query receipts.
    LogQuery {
        /// Most records to return.
        limit: u32,
    },
    /// `ms doctor --probe` report from inside an agent.
    DoctorProbe,
}

impl RequestBody {
    /// True when a raw value frame follows this request.
    pub fn carries_value(&self) -> bool {
        matches!(self, RequestBody::PutKey { .. })
    }

    /// The loop that implements this request, for `not_implemented` answers.
    pub fn owner_loop(&self) -> &'static str {
        match self {
            RequestBody::Status => "L00 foundation",
            RequestBody::PutKey { .. } | RequestBody::ListKeys => "L07 daemon",
            RequestBody::Run { .. } => "L12 run-core",
            RequestBody::Mint { .. } => "L18 mint-aws",
            RequestBody::RulesGet { .. } | RequestBody::RulesProposeLoosen { .. } => {
                "L03 rules-policy"
            }
            RequestBody::Stop | RequestBody::Start => "L07 daemon",
            RequestBody::LogQuery { .. } => "L02 receipts",
            RequestBody::DoctorProbe => "L17 doctor",
        }
    }
}

/// Machine-readable error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request is planned but not built.
    NotImplemented,
    /// The client speaks another protocol version.
    UnsupportedVersion,
    /// Malformed frame or message.
    Protocol,
    /// The client is not allowed to talk to this daemon.
    PeerRejected,
    /// The daemon failed.
    Internal,
}

/// Responses from the daemon. No variant can hold a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseBody {
    /// Daemon status.
    Status {
        /// Daemon name.
        daemon: String,
        /// Daemon version.
        version: String,
        /// `dev-stub` until L07.
        mode: String,
    },
    /// An error; `message` is shown to people as is.
    Error {
        /// Kind.
        code: ErrorCode,
        /// Text, including the fix.
        message: String,
    },
}

impl ResponseBody {
    /// An error response.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        ResponseBody::Error {
            code,
            message: message.into(),
        }
    }
}

/// Serializes an envelope to the bytes of one frame.
pub fn encode<T: Serialize>(id: u64, body: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&Envelope {
        v: PROTOCOL_VERSION,
        id,
        body,
    })
    .map_err(|e| Error::Protocol(format!("encoding message: {e}")))
}

/// Parses a frame: first the header (so an unknown version is reported as such), then the body.
pub fn decode<T: DeserializeOwned>(
    bytes: &[u8],
) -> std::result::Result<Envelope<T>, (u64, ErrorCode, String)> {
    let header: Header = serde_json::from_slice(bytes).map_err(|e| {
        (
            0,
            ErrorCode::Protocol,
            format!("morsec: malformed message: {e}"),
        )
    })?;
    if header.v != PROTOCOL_VERSION {
        return Err((
            header.id,
            ErrorCode::UnsupportedVersion,
            format!(
                "morsec: protocol version {} is not supported (this build speaks {PROTOCOL_VERSION}). Make sure ms and msd are the same version (ms --version)",
                header.v
            ),
        ));
    }
    serde_json::from_slice(bytes).map_err(|e| {
        (
            header.id,
            ErrorCode::Protocol,
            format!("morsec: malformed message: {e}"),
        )
    })
}
