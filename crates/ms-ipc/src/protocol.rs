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

/// Requests to the daemon. A request that is planned but not built answers `not_implemented`
/// naming the loop that builds it.
///
/// Fields added after v1 was frozen are optional (`#[serde(default)]`), so older clients' messages
/// still parse (L07).
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
    /// Propose a change to one key's rule. The daemon classifies it: tightening is saved at
    /// once, loosening needs an approval.
    RulesProposeLoosen {
        /// Key.
        key: KeyName,
        /// The proposed rule for `key`, as a rules file (`rules.toml` format) holding only that
        /// key; its `version` is ignored. Absent: remove the key's rule (L07).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        /// Pre-L11 recovery path: the user confirmed at their own terminal (L07 SPEC D-A).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        at_terminal: bool,
    },
    /// Kill switch.
    Stop,
    /// Resume after a stop; needs an approval.
    Start {
        /// Pre-L11 recovery path: the user confirmed at their own terminal (L07 SPEC D-A).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        at_terminal: bool,
    },
    /// Query receipts.
    LogQuery {
        /// Most records to return.
        limit: u32,
    },
    /// `ms doctor --probe` report from inside an agent.
    DoctorProbe,
}

impl RequestBody {
    /// True for the kill-switch requests that may use a reserved control slot when every
    /// general connection slot is taken (L07, S6).
    pub fn is_control(&self) -> bool {
        matches!(self, RequestBody::Status | RequestBody::Stop)
    }

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
            RequestBody::RulesGet { .. } | RequestBody::RulesProposeLoosen { .. } => "L07 daemon",
            RequestBody::Stop | RequestBody::Start { .. } => "L07 daemon",
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
    /// The daemon is at its connection limit; only `Status` and `Stop` are served (L07).
    Busy,
    /// Policy or a person refused (L07).
    Denied,
    /// The change needs an approval that was not given (L07).
    NeedsApproval,
    /// morsec is not set up yet: run `ms init` (L07).
    NotInitialized,
    /// The request was well formed but its content is not acceptable (L07).
    Invalid,
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
        /// `keychain`, or `dev-memory` for an ephemeral dev daemon (`dev-stub` before L07).
        mode: String,
        /// False after `ms stop` (L07). Absent from pre-L07 daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        running: Option<bool>,
        /// Number of keys in the vault, morsec's own keys excluded (L07).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keys: Option<u32>,
        /// The swap proxy's loopback port (L07).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proxy_port: Option<u16>,
        /// Things the user should look at: tampered rules, connector settings drift (L07).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alerts: Vec<String>,
        /// The swap proxy's CA certificate (PEM, public), as msd loaded and checked it against
        /// the key in the vault; absent while no host is bound (L07). `ms init --trust` trusts
        /// this, never the file on disk, which any same-user process can replace.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_pem: Option<String>,
        /// The hosts that CA may sign for (its name constraints) (L07).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ca_hosts: Vec<String>,
    },
    /// Success; `message` is shown to people as is (L07).
    Ok {
        /// What was done.
        message: String,
    },
    /// Key metadata, never values (`ListKeys`, L07).
    Keys {
        /// One entry per key.
        keys: Vec<KeyMeta>,
    },
    /// The user rules, MAC-verified by the daemon (`RulesGet`, L07). The client merges a
    /// project `.morsec.toml` itself, so the daemon never reads a path a client names. ms-ipc does not depend on ms-rules, so the rules
    /// travel as the rules file's TOML.
    Rules {
        /// Rules version.
        version: u64,
        /// The rules, in the `rules.toml` format.
        toml: String,
        /// Notes from the project merge and integrity state, for display.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
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
    /// A status reply with only the pre-L07 fields set.
    pub fn status(
        daemon: impl Into<String>,
        version: impl Into<String>,
        mode: impl Into<String>,
    ) -> Self {
        ResponseBody::Status {
            daemon: daemon.into(),
            version: version.into(),
            mode: mode.into(),
            running: None,
            keys: None,
            proxy_port: None,
            alerts: Vec::new(),
            ca_pem: None,
            ca_hosts: Vec::new(),
        }
    }

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
