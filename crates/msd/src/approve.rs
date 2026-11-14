//! msd's approver (L11, CLI only).
//!
//! A request that needs a person waits in [`ms_approve::HumanApprover`]; the person reviews it
//! with `ms approve` in their own terminal and msd itself raises the Touch ID sheet
//! ([`ms_approve::macos::TouchId`]) before anything is approved. There is no flag or environment
//! variable that skips Touch ID in a release build. A *debug* build started with the ephemeral
//! memory vault accepts `--test-touch-id allow|deny` for the end-to-end tests; it replaces only the
//! Touch ID step (SPEC D-10).

use std::sync::Arc;

use ms_approve::HumanApprover;
use ms_approve::auth::Authenticator;

/// The test-only stand-in for Touch ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TestTouchId {
    /// Every Touch ID check succeeds.
    Allow,
    /// Every Touch ID check fails.
    Deny,
}

/// The real authenticator for this platform.
fn platform() -> Arc<dyn Authenticator> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(ms_approve::macos::TouchId)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(ms_approve::auth::Unavailable)
    }
}

/// The authenticator msd uses. `test` is honoured only in a debug build with the memory vault;
/// anything else is refused, so a release msd always uses Touch ID.
pub fn authenticator(
    test: Option<TestTouchId>,
    memory_vault: bool,
) -> Result<Arc<dyn Authenticator>, String> {
    match test {
        None => Ok(platform()),
        Some(_) if !cfg!(debug_assertions) => {
            Err("morsec: --test-touch-id exists only in debug builds".into())
        }
        Some(_) if !memory_vault => Err(
            "morsec: --test-touch-id only works with --vault memory (an ephemeral dev vault)"
                .into(),
        ),
        Some(TestTouchId::Allow) => {
            tracing::warn!("TEST BUILD: Touch ID is replaced by --test-touch-id allow");
            Ok(Arc::new(
                ms_approve::auth::fake::FakeAuthenticator::approve(),
            ))
        }
        Some(TestTouchId::Deny) => Ok(Arc::new(ms_approve::auth::fake::FakeAuthenticator::deny(
            "--test-touch-id deny",
        ))),
    }
}

/// The approver msd runs with.
pub fn approver(
    test: Option<TestTouchId>,
    memory_vault: bool,
) -> Result<Arc<HumanApprover>, String> {
    let auth = authenticator(test, memory_vault)?;
    HumanApprover::new(auth)
        .map(Arc::new)
        .map_err(|e| format!("morsec: no randomness for approval tokens: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D-10: the Touch ID stand-in is refused with the keychain vault (and absent
    // from release builds), so a real vault always gets Touch ID; fails_when=--test-touch-id is
    // accepted with the keychain vault; no_claim=the release-build branch (tests run debug)
    #[test]
    fn test_touch_id_needs_the_memory_vault() {
        assert!(authenticator(Some(TestTouchId::Allow), false).is_err());
        assert!(authenticator(Some(TestTouchId::Deny), false).is_err());
        assert!(authenticator(Some(TestTouchId::Allow), true).is_ok());
        assert!(authenticator(None, false).is_ok());
    }
}
