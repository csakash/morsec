//! Run mode: the broker runs a command with a secret and returns redacted output.
//!
//! L00 froze [`RunAdapter`] and the plan types. L12 (this crate) builds on them:
//!
//! - [`input`]: checks a request (argv shape, the forwarded ref-bearing environment).
//! - [`cwd`]: the working directory must be inside the key's project roots.
//! - [`resolve`]: programs come from a trusted search path, never the agent's `PATH`.
//! - [`redact`]: Aho–Corasick redaction of every encoding of a value, across chunk boundaries.
//! - [`generic`]: the fallback adapter for allowlisted CLIs (values through the environment
//!   only).
//! - [`runner`]: adapter selection, exec plans, and running the child (process group, minimal
//!   environment, stdin forwarding, redacted output, exit status).
//! - [`client`]: the client side shared by `ms-shim` and `ms run`.
//!
//! Policy (rules, approvals, receipts) lives in msd (`crates/msd/src/daemon/run.rs`), which
//! calls [`runner::Runner::plan`] only with the keys it allowed.
//!
//! # Writing an adapter (L15, L16)
//!
//! Implement [`RunAdapter`] and register it with [`runner::Runner::register`]; adapters are
//! tried in order before the generic one. `plan` must return an absolute `program` (resolve
//! names with [`runner::Runner::resolver`]; the runner re-checks it), an argv array, the call's
//! `cwd` unchanged, and any variables of its own in `env` (the runner adds `PATH`, the base set
//! and the forwarded ref variables). Refuse with [`error::adapter_refuse`] /
//! [`error::adapter_invalid`] so the agent gets the right code. Values an adapter reads from the
//! vault are redacted from output only if they are among the call's keys.

pub mod client;
pub mod cwd;
pub mod error;
pub mod generic;
pub mod input;
pub mod redact;
pub mod resolve;
pub mod runner;

pub use error::{RunError, RunErrorKind};
pub use input::RunInput;
pub use runner::{ExecIo, Exit, Prepared, Runner, RunnerConfig};

/// Truncates and escapes agent-supplied text before it goes into a message.
pub(crate) fn printable(s: &str) -> String {
    let mut out: String = s.chars().take(80).flat_map(char::escape_default).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    out
}

use std::ffi::OsString;
use std::path::PathBuf;

use ms_core::{Result, SecretBytes, SessionId};
use ms_vault::Vault;

/// A command an agent asked the broker to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCall {
    /// Exact argv, `argv[0]` first.
    pub argv: Vec<OsString>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Who asked.
    pub session: SessionId,
}

/// One environment variable for the child.
#[derive(Debug)]
pub enum EnvValue {
    /// Plain value.
    Plain(OsString),
    /// Secret value: wiped after the child starts.
    Secret(SecretBytes),
}

/// What the runner executes. The program is an absolute path and arguments are an array: no shell.
#[derive(Debug)]
pub struct ExecPlan {
    /// Absolute path of the binary.
    pub program: PathBuf,
    /// Arguments after the program.
    pub args: Vec<OsString>,
    /// The child's complete environment (nothing is inherited).
    pub env: Vec<(OsString, EnvValue)>,
    /// Working directory.
    pub cwd: PathBuf,
}

/// A safe preview of what a command will change, shown in the approval dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectPreview {
    /// For example "3 rows in orders".
    pub summary: String,
}

/// Turns a call into an exec plan for one family of tools.
pub trait RunAdapter: Send + Sync {
    /// True when this adapter handles `argv`.
    fn matches(&self, argv: &[OsString]) -> bool;
    /// Builds the exec plan, reading secrets from `vault` as needed.
    fn plan(&self, call: &RunCall, vault: &dyn Vault) -> Result<ExecPlan>;
    /// A preview of the effect, when one can be computed without side effects.
    fn preview(&self, call: &RunCall) -> Option<EffectPreview>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{AgentKind, KeyMeta, KeyName, Mode, Tier};
    use ms_vault::VaultExt;
    use ms_vault::memory::MemoryVault;

    struct Echo;
    impl RunAdapter for Echo {
        fn matches(&self, argv: &[OsString]) -> bool {
            argv.first().is_some_and(|a| a == "echo")
        }
        fn plan(&self, call: &RunCall, vault: &dyn Vault) -> Result<ExecPlan> {
            let k = KeyName::new("t").unwrap();
            let secret = vault.read_with(&k, |b| SecretBytes::from(b.to_vec()))?;
            Ok(ExecPlan {
                program: "/bin/echo".into(),
                args: call.argv[1..].to_vec(),
                env: vec![("TOKEN".into(), EnvValue::Secret(secret))],
                cwd: call.cwd.clone(),
            })
        }
        fn preview(&self, _call: &RunCall) -> Option<EffectPreview> {
            None
        }
    }

    // protects=RunAdapter is object-safe and plan() can read through &dyn Vault; the plan's Debug
    // output hides the secret; fails_when=either stops compiling or the value prints;
    // no_claim=the runner (L12)
    #[test]
    fn adapter_through_dyn() {
        let v = MemoryVault::new();
        let k = KeyName::new("t").unwrap();
        v.put(
            &k,
            SecretBytes::from("CANARY".to_owned()),
            KeyMeta {
                name: k.clone(),
                mode: Mode::Run,
                tier: Tier::Test,
                created_unix_ms: 0,
            },
        )
        .unwrap();
        let a: &dyn RunAdapter = &Echo;
        let call = RunCall {
            argv: vec!["echo".into(), "hi".into()],
            cwd: "/tmp".into(),
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 1,
                started_unix_ms: 1,
            },
        };
        assert!(a.matches(&call.argv));
        let plan = a.plan(&call, &v).unwrap();
        assert!(!format!("{plan:?}").contains("CANARY"));
        assert!(a.preview(&call).is_none());
    }
}
