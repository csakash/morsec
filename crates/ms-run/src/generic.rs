//! The generic adapter for allowlisted CLIs: cloud CLIs, deploy tools (SPEC D4).
//!
//! It runs `argv[0]` resolved from the trusted search path with the remaining arguments as an
//! array. It never takes a value through an argument: a ref in argv is refused, because argv is
//! visible to every user on the machine through `ps`. Values reach the child only through the
//! environment variables the caller forwarded, which the [`crate::Runner`] fills in. It is the
//! fallback: it matches every call, so it is consulted last.

use std::ffi::OsString;

use ms_core::{Result, SecretRef};
use ms_vault::Vault;

use crate::error::adapter_refuse;
use crate::resolve::Resolver;
use crate::{EffectPreview, ExecPlan, RunAdapter, RunCall};

/// See the module docs.
#[derive(Debug, Clone)]
pub struct GenericAdapter {
    resolver: Resolver,
}

impl GenericAdapter {
    /// An adapter that resolves programs with `resolver`.
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }
}

impl RunAdapter for GenericAdapter {
    fn matches(&self, _argv: &[OsString]) -> bool {
        true
    }

    fn plan(&self, call: &RunCall, _vault: &dyn Vault) -> Result<ExecPlan> {
        let argv: Vec<&str> = call
            .argv
            .iter()
            .map(|a| a.to_str())
            .collect::<Option<_>>()
            .ok_or_else(|| crate::error::adapter_invalid("an argument is not valid UTF-8"))?;
        let Some((first, rest)) = argv.split_first() else {
            return Err(crate::error::adapter_invalid("the command is empty"));
        };
        if argv.iter().any(|a| !SecretRef::find_all(a).is_empty()) {
            return Err(adapter_refuse(
                "a reference in a command argument would be visible to every process on this machine (ps), so morsec doesn't put values there. Put it in an environment variable instead, e.g. TOKEN=ms://… tool",
            ));
        }
        let program = self
            .resolver
            .resolve(first)
            .map_err(|e| adapter_refuse(e.message.trim_start_matches("morsec: ")))?;
        Ok(ExecPlan {
            program,
            args: rest.iter().map(OsString::from).collect(),
            env: Vec::new(),
            cwd: call.cwd.clone(),
        })
    }

    fn preview(&self, _call: &RunCall) -> Option<EffectPreview> {
        None
    }
}
