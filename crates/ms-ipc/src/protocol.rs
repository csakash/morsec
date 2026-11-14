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
    /// Run a command and answer once with its (capped, redacted) output: [`ResponseBody::RunResult`].
    /// No stdin. Non-UTF-8 arguments are refused by the client.
    Run {
        /// Exact argv.
        argv: Vec<String>,
        /// Working directory.
        cwd: PathBuf,
        /// The caller's environment variables whose value holds an `ms://` ref, and only those
        /// (L12). Refs only: a client never has a value to send.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        env: Vec<RunEnv>,
    },
    /// Run a command with streamed stdin and output (L12; the shim and `ms run`). The daemon
    /// answers either one [`ResponseBody::Error`] (refused, `not_run`…), or
    /// [`ResponseBody::RunStarted`], then [`ResponseBody::RunOutput`] frames, then one
    /// [`ResponseBody::RunExit`] or `Error`; then it closes the connection. After `RunStarted`
    /// the client sends [`RequestBody::RunInput`] / [`RequestBody::RunInputEnd`]. Closing the
    /// connection early cancels the run.
    RunStream {
        /// Exact argv.
        argv: Vec<String>,
        /// Working directory.
        cwd: PathBuf,
        /// As in `Run`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        env: Vec<RunEnv>,
    },
    /// Call an `ms mcp` tool (L14). msd rebuilds the tool catalog from its own rules, refuses
    /// the call when `rules_version` is not the version in force, validates `arguments` against
    /// the tool's JSON Schema, builds the argv and environment from the tool (the key is the
    /// tool's, never an argument) and runs it like `Run`. Answered with
    /// [`ResponseBody::RunResult`] or [`ResponseBody::Error`]; every call leaves a receipt.
    McpCall {
        /// Tool name, as the agent sent it.
        tool: String,
        /// The rules version the caller's tool list was built from.
        rules_version: u64,
        /// Working directory of the `ms mcp` process.
        cwd: PathBuf,
        /// The tool arguments, as the agent sent them (unvalidated).
        #[serde(default)]
        arguments: serde_json::Value,
    },
    /// Stdin bytes for the running `RunStream` (base64). Only valid inside a stream.
    RunInput {
        /// Standard base64.
        data: String,
    },
    /// Stdin is at its end. Only valid inside a stream.
    RunInputEnd,
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
    /// Search the agent transcripts msd knows about for vault values (`ms scan`, L09). No
    /// fields: msd picks the directories itself, so a client can't point it at a file.
    Scan,
    /// The approval waiting for a person, if any (`ms approve`, L11). Refused inside an agent
    /// session.
    ApprovalPending,
    /// A person's answer to the waiting approval (L11). Refused inside an agent session. Before
    /// approving anything msd itself asks for Touch ID, with a reason it builds from the request.
    ApprovalDecide {
        /// The pending request's id (from `ApprovalPending`).
        id: String,
        /// Approve (Touch ID follows) or deny (no Touch ID).
        approve: bool,
        /// What an approval covers; absent = this exact command, once.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<ApprovalScope>,
    },
}

/// What an approval covers (L11, PRD §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// This exact command, once (the default).
    Once,
    /// This exact command, for this agent session.
    Session,
}

/// The approval waiting for a person (`ApprovalPending`, L11). Every string in `request` is
/// agent-influenced: render it with `ms_approve::render`, never raw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingApproval {
    /// Id a decision must name.
    pub id: String,
    /// The exact request, as msd will carry it out.
    pub request: ms_core::ApprovalRequest,
    /// When it was asked, Unix ms.
    pub requested_unix_ms: u64,
    /// When it times out, Unix ms.
    pub expires_unix_ms: u64,
}

impl RequestBody {
    /// True for the kill-switch requests that may use a reserved control slot when every
    /// general connection slot is taken (L07, S6).
    pub fn is_control(&self) -> bool {
        matches!(self, RequestBody::Status | RequestBody::Stop)
    }

    /// True for `RunStream`, which turns the connection into a stream (L12).
    pub fn is_stream(&self) -> bool {
        matches!(self, RequestBody::RunStream { .. })
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
            RequestBody::Run { .. }
            | RequestBody::RunStream { .. }
            | RequestBody::RunInput { .. }
            | RequestBody::RunInputEnd => "L12 run-core",
            RequestBody::McpCall { .. } => "L14 mcp-server",
            RequestBody::Mint { .. } => "L18 mint-aws",
            RequestBody::RulesGet { .. } | RequestBody::RulesProposeLoosen { .. } => "L07 daemon",
            RequestBody::Stop | RequestBody::Start { .. } => "L07 daemon",
            RequestBody::LogQuery { .. } => "L02 receipts",
            RequestBody::DoctorProbe => "L17 doctor",
            RequestBody::Scan => "L09 e2e-canary",
            RequestBody::ApprovalPending | RequestBody::ApprovalDecide { .. } => {
                "L11 approvals-macos"
            }
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
    /// A run request referenced no run-mode key, so the broker has nothing to do: the shim runs
    /// the real tool unchanged (L12).
    NotRun,
}

/// One environment variable a client forwards with a run request: its value holds an `ms://`
/// ref (L12). The daemon resolves run-mode refs in it for the child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEnv {
    /// Variable name.
    pub name: String,
    /// Its value as the caller has it, refs and all.
    pub value: String,
}

/// Which output stream a [`ResponseBody::RunOutput`] chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Where a vault value was found (`ScanReport`, L09). Location and key name only: there is no
/// field that could carry the value or the text around it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFinding {
    /// The transcript file (lossy UTF-8).
    pub file: String,
    /// 1-based line number.
    pub line: u64,
    /// The key whose value was found.
    pub key: KeyName,
    /// How it appeared: `raw`, `json-escaped`, `url-encoded`, `hex`, `base64`, `base64url`.
    pub encoding: String,
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
    /// The result of a transcript scan (`Scan`, L09).
    ScanReport {
        /// Every place a value was found, sorted by file and line.
        findings: Vec<ScanFinding>,
        /// Transcript files read.
        files_scanned: u64,
        /// Bytes read.
        bytes_scanned: u64,
        /// Keys searched for.
        keys_checked: u32,
        /// Keys not searched for because their values are too short to match reliably.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        skipped_keys: Vec<KeyName>,
        /// The directories searched, and anything else worth showing.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
        /// False when the scan stopped early (time budget, file cap, unreadable files).
        complete: bool,
    },
    /// The run passed every check and is starting (L12, `RunStream`): the first frame of a stream
    /// that runs. A client sends stdin only after it, so a refusal or a `not_run` answer never
    /// consumes the caller's input.
    RunStarted,
    /// A chunk of a running command's output, already redacted (L12, `RunStream`).
    RunOutput {
        /// Which stream.
        stream: OutStream,
        /// The bytes, standard base64.
        data: String,
    },
    /// How a streamed run ended (L12). The last frame of a `RunStream`.
    RunExit {
        /// Exit code, when the command exited.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        /// Signal number, when a signal ended it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    /// A buffered run's result (L12, `Run`). Output is redacted and capped.
    RunResult {
        /// Exit code, when the command exited.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        /// Signal number, when a signal ended it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
        /// Standard output, standard base64.
        stdout: String,
        /// Standard error, standard base64.
        stderr: String,
        /// True when either stream was cut at the cap.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        truncated: bool,
    },
    /// The approval waiting for a person, if any (`ApprovalPending`, L11).
    Approval {
        /// The request, or none.
        pending: Option<PendingApproval>,
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
