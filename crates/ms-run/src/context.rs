//! Context-aware adapters (L15 SPEC D1): an additive hook beside the frozen [`RunAdapter`].
//!
//! The frozen trait gets only the call. Some adapters need more: the rule facts of the keys the
//! call uses (read-only, tier), the vault while computing a preview, a way to clean up after the
//! run (a passfile), and values of their own to redact (a password taken out of a URL). msd
//! builds a [`CallContext`] for each call from the effective rules and passes it to
//! [`crate::Runner::plan_in`], [`crate::Runner::preview_in`] and
//! [`crate::Runner::needs_approval`].
//!
//! Contextual adapters are tried before the frozen ones. When the old entry points
//! ([`crate::Runner::plan`], [`crate::Runner::preview`]) reach one, it gets an empty context and
//! must refuse (fail closed): no facts means "don't know what the rule allows".
//!
//! [`RunAdapter`]: crate::RunAdapter

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use ms_core::{KeyName, Result, Tier};
use ms_vault::Vault;
use zeroize::Zeroizing;

use crate::{EffectPreview, ExecPlan, RunCall};

/// What the effective rule says about one key, for adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFacts {
    /// The key's tier.
    pub tier: Tier,
    /// The rule requires read-only access.
    pub read_only: bool,
}

/// Per-call context: the vault and the facts of every run-mode key the call uses (refs in argv
/// and in forwarded variables).
pub struct CallContext<'a> {
    /// The vault, for adapters that read a key's value (to rewrite or probe a connection).
    pub vault: &'a dyn Vault,
    /// Facts per run-mode key of this call. Empty when the caller gave none.
    pub keys: BTreeMap<KeyName, KeyFacts>,
    /// The run-mode keys the call forwards through environment variables (the rest are in
    /// argv). [`crate::Runner::plan_in`] fills this from the checked input itself.
    pub env_keys: BTreeSet<KeyName>,
}

impl std::fmt::Debug for CallContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallContext")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl<'a> CallContext<'a> {
    /// A context with no facts: contextual adapters refuse it.
    pub fn empty(vault: &'a dyn Vault) -> Self {
        Self {
            vault,
            keys: BTreeMap::new(),
            env_keys: BTreeSet::new(),
        }
    }
}

/// Something kept alive until the run ends, then dropped (for example a passfile that its
/// `Drop` removes).
pub trait RunGuard: Send + Sync + std::fmt::Debug {}

/// What a contextual adapter returns.
#[derive(Debug)]
pub struct AdapterPlan {
    /// The exec plan, with the same contract as [`crate::RunAdapter::plan`]'s.
    pub exec: ExecPlan,
    /// Values to redact from the output besides the call's keys' values, each labelled with the
    /// key it came from (for example a password taken out of a URL).
    pub secrets: Vec<(KeyName, Zeroizing<Vec<u8>>)>,
    /// Dropped when the run ends, or when the plan is dropped without running.
    pub guard: Option<Box<dyn RunGuard>>,
}

/// An adapter that sees the call's rule facts. See the module docs.
pub trait ContextAdapter: Send + Sync {
    /// True when this adapter handles `argv`.
    fn matches(&self, argv: &[OsString]) -> bool;
    /// Builds the plan. Must refuse when `ctx` lacks facts for a key the call uses.
    fn plan(&self, call: &RunCall, ctx: &CallContext<'_>) -> Result<AdapterPlan>;
    /// A preview of the effect, for an approval prompt. Only called when an approval is asked.
    fn preview(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<EffectPreview>;
    /// `Some(why)` when this call needs a person's approval even though the key's tier alone
    /// wouldn't ask for one (for example a schema migration).
    fn needs_approval(&self, call: &RunCall, ctx: &CallContext<'_>) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::Resolver;
    use crate::{RunInput, Runner, RunnerConfig};
    use ms_core::{AgentKind, SessionId};
    use ms_vault::memory::MemoryVault;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct Flag(Arc<AtomicBool>);
    impl RunGuard for Flag {}
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct EchoSecret(Arc<AtomicBool>);
    impl ContextAdapter for EchoSecret {
        fn matches(&self, argv: &[OsString]) -> bool {
            argv.first().is_some_and(|a| a == "echo")
        }
        fn plan(&self, call: &RunCall, ctx: &CallContext<'_>) -> Result<AdapterPlan> {
            let k = KeyName::new("t").unwrap();
            if !ctx.keys.contains_key(&k) {
                return Err(crate::error::adapter_refuse("no facts"));
            }
            Ok(AdapterPlan {
                exec: ExecPlan {
                    program: "/bin/echo".into(),
                    args: vec!["pw=S3CRET-x91".into()],
                    env: Vec::new(),
                    cwd: call.cwd.clone(),
                },
                secrets: vec![(k, Zeroizing::new(b"S3CRET-x91".to_vec()))],
                guard: Some(Box::new(Flag(self.0.clone()))),
            })
        }
        fn preview(&self, _: &RunCall, _: &CallContext<'_>) -> Option<EffectPreview> {
            None
        }
        fn needs_approval(&self, _: &RunCall, _: &CallContext<'_>) -> Option<String> {
            Some("always".into())
        }
    }

    // protects=SPEC D1: a contextual adapter is chosen before the generic one, its extra secrets
    // are redacted from output, its guard lives until the run ends, its approval escalation is
    // reported, and the old entry point (no facts) is refused; fails_when=an adapter's own secret
    // reaches the output, the guard is dropped early or never, or `plan` without facts runs;
    // no_claim=the pg adapters (live tests)
    #[test]
    fn contextual_adapter_contract() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut r = Runner::new(RunnerConfig {
            resolver: Resolver::new(vec!["/bin".into()], Vec::new()),
            base_env: Vec::new(),
            max_runtime: std::time::Duration::from_secs(10),
        });
        r.register_contextual(Box::new(EchoSecret(dropped.clone())));
        let v = MemoryVault::new();
        let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let input = RunInput::new(vec!["echo".into()], cwd.clone(), Vec::new()).unwrap();
        let call = Runner::call(
            &input,
            cwd,
            SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 1,
                started_unix_ms: 1,
            },
        );
        let none = BTreeSet::new();
        assert!(r.plan(&input, &call, &none, &v).is_err());
        assert!(r.preview(&call).is_none());
        let mut ctx = CallContext::empty(&v);
        ctx.keys.insert(
            KeyName::new("t").unwrap(),
            KeyFacts {
                tier: Tier::Test,
                read_only: false,
            },
        );
        assert_eq!(r.needs_approval(&call, &ctx).as_deref(), Some("always"));
        let p = r.plan_in(&input, &call, &none, &ctx).unwrap();
        assert!(!dropped.load(Ordering::SeqCst));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_, out, _, _) = rt.block_on(r.execute_buffered(p, 4096)).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.contains("S3CRET-x91") && out.contains("pw=[redacted"),
            "{out}"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "guard not dropped after the run"
        );
    }
}
