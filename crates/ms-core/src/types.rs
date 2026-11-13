//! Policy, session and receipt types. None of these can hold a secret value.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::key::KeyName;

/// How a key is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// A local proxy swaps a placeholder for the real key on the way out (HTTP APIs).
    Swap,
    /// The broker runs the command itself and returns redacted output.
    Run,
    /// The broker creates a short-lived, narrow credential per session.
    Mint,
}

/// Risk tier of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Never prompts.
    Test,
    /// Needs an approval bound to the exact request.
    Production,
}

/// Which coding agent a session belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Claude Code (terminal, desktop app, IDE extensions).
    ClaudeCode,
    /// Codex (CLI, app, IDE extension).
    Codex,
    /// Cursor.
    Cursor,
    /// Gemini CLI.
    GeminiCli,
    /// Anything else, by process name.
    Other(String),
}

/// One agent session: the agent's root process, identified by PID and start time so a reused
/// PID is a new session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    /// The agent.
    pub agent: AgentKind,
    /// PID of the agent's root process.
    pub pid: u32,
    /// Start time of that process, Unix milliseconds.
    pub started_unix_ms: u64,
}

/// Metadata about a stored key. Never includes the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMeta {
    /// Key name.
    pub name: KeyName,
    /// How the key is used.
    pub mode: Mode,
    /// Risk tier.
    pub tier: Tier,
    /// When the key was added, Unix milliseconds.
    pub created_unix_ms: u64,
}

/// A request to use a key, as seen by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// Swap the key into a request to `host`.
    Swap {
        /// Key.
        key: KeyName,
        /// Destination host.
        host: String,
    },
    /// Run a command with the key.
    Run {
        /// Key.
        key: KeyName,
        /// SHA-256 over the exact argv.
        argv_hash: [u8; 32],
        /// Working directory.
        cwd: PathBuf,
    },
    /// Mint a credential from the key.
    Mint {
        /// Key.
        key: KeyName,
        /// Requested scope, as the minter understands it.
        scope: String,
    },
}

/// Why policy denied a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Policy is not built yet; everything is denied (L00 stub, replaced by L03).
    NotImplemented,
    /// The key is not allowed to go to this host.
    HostNotAllowed,
    /// The key is not allowed for this command.
    CommandNotAllowed,
    /// `ms stop` is in effect.
    Stopped,
    /// No such key.
    NoSuchKey,
    /// The rules file failed its integrity check.
    RulesTampered,
}

/// What a person sees and approves. Built by the broker from the real request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Who is asking.
    pub session: SessionId,
    /// Which key.
    pub key: KeyName,
    /// Its tier.
    pub tier: Tier,
    /// The exact command, one element per argument, for display.
    pub argv_display: Vec<String>,
    /// SHA-256 over the exact argv; the approval is bound to it.
    pub argv_hash: [u8; 32],
    /// Working directory.
    pub cwd: PathBuf,
    /// Effect preview, e.g. "3 rows in orders", when one can be computed safely.
    pub effect: Option<String>,
}

/// Policy outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Go ahead.
    Allow,
    /// Refuse.
    Deny {
        /// Why.
        reason: Reason,
    },
    /// Ask a person first.
    NeedsApproval {
        /// What to show them.
        request: ApprovalRequest,
    },
}

/// Outcome recorded in a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptResult {
    /// Allowed by rules.
    Allowed,
    /// Approved by a person.
    Approved,
    /// Blocked by rules.
    Blocked(Reason),
    /// Denied by a person or timed out.
    Denied,
    /// Failed while executing.
    Failed(String),
}

/// One use of a key. L02 adds the hash chain and HMAC around this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEvent {
    /// Unix milliseconds.
    pub time_unix_ms: u64,
    /// Who.
    pub session: SessionId,
    /// Which key.
    pub key: KeyName,
    /// How.
    pub mode: Mode,
    /// Host, or the command as displayed (already redacted).
    pub target: String,
    /// SHA-256 over the exact argv, for run mode.
    pub argv_hash: Option<[u8; 32]>,
    /// Version of the rules that decided.
    pub rule_version: u64,
    /// Approval token id, when a person approved.
    pub approval_id: Option<String>,
    /// Outcome.
    pub result: ReceiptResult,
}
