//! Minting short-lived credentials.
//!
//! L00 freezes [`Minter`] and ships [`fake::FakeMinter`]. AWS (L18), GitHub (L19) and Postgres
//! (L20) implement it.

use ms_core::{KeyName, Result, SecretBytes, SessionId};

/// A credential minted for one session. The agent receives `token`; it is weak and expires.
#[derive(Debug)]
pub struct MintedCred {
    /// The credential handed to the agent.
    pub token: SecretBytes,
    /// Expiry, Unix milliseconds.
    pub expires_unix_ms: u64,
}

/// Creates and revokes short-lived credentials.
pub trait Minter: Send + Sync {
    /// Mints a credential for `session` from the long-lived key `key`, narrowed to `scope`.
    fn mint(&self, key: &KeyName, session: &SessionId, scope: &str) -> Result<MintedCred>;
    /// Revokes everything this minter has issued (kill switch).
    fn revoke_all(&self) -> Result<()>;
}

/// Fake minter for tests.
pub mod fake {
    use std::sync::Mutex;

    use ms_core::{KeyName, Result, SecretBytes, SessionId};

    use crate::{MintedCred, Minter};

    /// Issues `fake-<n>` tokens with a fixed lifetime and counts revocations.
    #[derive(Debug, Default)]
    pub struct FakeMinter {
        state: Mutex<(u64, u64)>, // (issued, revoke_all calls)
    }

    impl FakeMinter {
        /// A fresh fake.
        pub fn new() -> Self {
            Self::default()
        }

        /// How many times `revoke_all` ran.
        pub fn revocations(&self) -> u64 {
            self.state.lock().unwrap_or_else(|e| e.into_inner()).1
        }
    }

    impl Minter for FakeMinter {
        fn mint(&self, _key: &KeyName, _session: &SessionId, _scope: &str) -> Result<MintedCred> {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.0 += 1;
            Ok(MintedCred {
                token: SecretBytes::from(format!("fake-{}", s.0)),
                expires_unix_ms: 15 * 60 * 1000,
            })
        }

        fn revoke_all(&self) -> Result<()> {
            self.state.lock().unwrap_or_else(|e| e.into_inner()).1 += 1;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeMinter;
    use super::*;
    use ms_core::AgentKind;

    // protects=the fake mints distinct tokens and counts revocations through &dyn Minter;
    // fails_when=tokens repeat or revocation isn't counted; no_claim=any real provider
    #[test]
    fn mints_and_revokes() {
        let f = FakeMinter::new();
        let d: &dyn Minter = &f;
        let k = KeyName::new("aws/dev").unwrap();
        let s = SessionId {
            agent: AgentKind::Codex,
            pid: 2,
            started_unix_ms: 3,
        };
        let a = d.mint(&k, &s, "read").unwrap();
        let b = d.mint(&k, &s, "read").unwrap();
        assert_ne!(a.token.expose(), b.token.expose());
        assert!(!format!("{a:?}").contains("fake-1"));
        d.revoke_all().unwrap();
        assert_eq!(f.revocations(), 1);
    }
}
