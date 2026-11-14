//! The bound approval token (SPEC D-5, D-6).
//!
//! `mac = HMAC-SHA256(k, "morsec-approval-v1" ‖ len-prefixed fields)` over the token id (which
//! carries the scope), the scope, the session (agent, pid, start), the key, the argv hash, the
//! cwd and the expiry. `k` is random per [`TokenIssuer`] (per msd process) and is replaced by
//! [`TokenIssuer::revoke_all`], which invalidates every outstanding token at once.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use hmac::{Hmac, Mac};
use ms_core::{ApprovalRequest, KeyName, SessionId};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::ApprovalToken;

/// How long a once token stays usable after approval: long enough for the executor to act.
pub const ONCE_TTL: Duration = Duration::from_secs(60);
/// Longest a session grant lasts (also ends at `ms stop` and when msd exits).
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

const DOMAIN: &[u8] = b"morsec-approval-v1";

/// What an approval covers (PRD §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// This exact command, once (the default).
    Once,
    /// This exact command, any number of times, for this agent session.
    Session,
}

impl Scope {
    fn prefix(self) -> &'static str {
        match self {
            Scope::Once => "once-",
            Scope::Session => "sess-",
        }
    }

    /// The scope a token id says it has.
    pub fn of_id(id: &str) -> Option<Scope> {
        let rest_ok = |r: &str| r.len() == 32 && r.bytes().all(|b| b.is_ascii_hexdigit());
        if let Some(r) = id.strip_prefix("once-") {
            rest_ok(r).then_some(Scope::Once)
        } else if let Some(r) = id.strip_prefix("sess-") {
            rest_ok(r).then_some(Scope::Session)
        } else {
            None
        }
    }
}

/// Exactly what a token is bound to: the request the executor is about to carry out.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Binding {
    /// The agent session.
    pub session: SessionId,
    /// The key.
    pub key: KeyName,
    /// SHA-256 over the exact argv.
    pub argv_hash: [u8; 32],
    /// Working directory.
    pub cwd: PathBuf,
}

impl Binding {
    /// The binding of an approval request.
    pub fn of(req: &ApprovalRequest) -> Self {
        Self {
            session: req.session.clone(),
            key: req.key.clone(),
            argv_hash: req.argv_hash,
            cwd: req.cwd.clone(),
        }
    }
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Not a token this daemon issued, or for a different request (any bound field changed).
    #[error("the approval does not match this exact request")]
    Mismatch,
    /// Past its expiry.
    #[error("the approval has expired")]
    Expired,
    /// A once token that was already used.
    #[error("the approval was for one use and has been used")]
    Used,
}

/// 32 random bytes from the kernel.
pub fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// Issues and checks tokens.
pub struct TokenIssuer {
    key: Mutex<Zeroizing<[u8; 32]>>,
    /// Once tokens already used: id → expiry (pruned when expired).
    used: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenIssuer { key: [redacted] }")
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl TokenIssuer {
    /// An issuer with a fresh random key.
    pub fn random() -> std::io::Result<Self> {
        Ok(Self::with_key(random_bytes()?))
    }

    /// An issuer with `key` (tests).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: Mutex::new(Zeroizing::new(key)),
            used: Mutex::default(),
        }
    }

    fn mac(&self, id: &str, scope: Scope, b: &Binding, expires: u64) -> Hmac<Sha256> {
        let key = lock(&self.key);
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("any key length");
        let agent = format!("{:?}", b.session.agent);
        let scope_tag: &[u8] = match scope {
            Scope::Once => b"once",
            Scope::Session => b"session",
        };
        m.update(DOMAIN);
        for part in [
            id.as_bytes(),
            scope_tag,
            agent.as_bytes(),
            &b.session.pid.to_be_bytes(),
            &b.session.started_unix_ms.to_be_bytes(),
            b.key.as_str().as_bytes(),
            &b.argv_hash,
            b.cwd.as_os_str().as_encoded_bytes(),
            &expires.to_be_bytes(),
        ] {
            m.update(&(part.len() as u64).to_be_bytes());
            m.update(part);
        }
        m
    }

    /// Issues a token for `b` with `scope`, valid from `now_ms`.
    pub fn issue(&self, b: &Binding, scope: Scope, now_ms: u64) -> std::io::Result<ApprovalToken> {
        let id = format!("{}{}", scope.prefix(), hex::encode(random_bytes::<16>()?));
        let ttl = match scope {
            Scope::Once => ONCE_TTL,
            Scope::Session => SESSION_TTL,
        };
        let expires = now_ms.saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let mac = self.mac(&id, scope, b, expires).finalize().into_bytes();
        Ok(ApprovalToken {
            id,
            mac: mac.into(),
            expires_unix_ms: expires,
        })
    }

    /// Checks `t` against `b` without using it up.
    pub fn check(&self, t: &ApprovalToken, b: &Binding, now_ms: u64) -> Result<Scope, TokenError> {
        let scope = Scope::of_id(&t.id).ok_or(TokenError::Mismatch)?;
        self.mac(&t.id, scope, b, t.expires_unix_ms)
            .verify_slice(&t.mac)
            .map_err(|_| TokenError::Mismatch)?;
        if now_ms >= t.expires_unix_ms {
            return Err(TokenError::Expired);
        }
        if scope == Scope::Once && lock(&self.used).contains_key(&t.id) {
            return Err(TokenError::Used);
        }
        Ok(scope)
    }

    /// The executor's check, right before it acts: `t` must be for exactly `b`, unexpired, and
    /// (for a once token) unused. A once token is used up by this call.
    pub fn verify(&self, t: &ApprovalToken, b: &Binding, now_ms: u64) -> Result<Scope, TokenError> {
        let scope = self.check(t, b, now_ms)?;
        if scope == Scope::Once {
            let mut used = lock(&self.used);
            used.retain(|_, exp| *exp > now_ms);
            if used.insert(t.id.clone(), t.expires_unix_ms).is_some() {
                return Err(TokenError::Used);
            }
        }
        Ok(scope)
    }

    /// Invalidates every token issued so far (new key).
    pub fn revoke_all(&self) -> std::io::Result<()> {
        let fresh = random_bytes()?;
        *lock(&self.key) = Zeroizing::new(fresh);
        lock(&self.used).clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::AgentKind;

    fn binding() -> Binding {
        Binding {
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 100,
                started_unix_ms: 5,
            },
            key: KeyName::new("pg/production").unwrap(),
            argv_hash: ms_core_argv_hash(&["psql", "-c", "select 1"]),
            cwd: PathBuf::from("/repo"),
        }
    }

    fn ms_core_argv_hash(argv: &[&str]) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for a in argv {
            h.update((a.len() as u64).to_be_bytes());
            h.update(a.as_bytes());
        }
        h.finalize().into()
    }

    // protects=AUTH-3 binding: a token approved for one exact request is refused for any other
    // (one argument changed, another cwd, key, session pid/start or agent), and editing its id,
    // scope, expiry or MAC breaks it; fails_when=any changed field still verifies;
    // no_claim=the human step (broker tests)
    #[test]
    fn any_change_after_approval_is_refused() {
        let iss = TokenIssuer::with_key([3; 32]);
        let b = binding();
        let t = iss.issue(&b, Scope::Once, 1_000).unwrap();

        let mut changed = Vec::new();
        let mut x = b.clone();
        x.argv_hash = ms_core_argv_hash(&["psql", "-c", "select 2"]);
        changed.push(x);
        let mut x = b.clone();
        x.cwd = PathBuf::from("/repo2");
        changed.push(x);
        let mut x = b.clone();
        x.key = KeyName::new("pg/staging").unwrap();
        changed.push(x);
        let mut x = b.clone();
        x.session.pid = 101;
        changed.push(x);
        let mut x = b.clone();
        x.session.started_unix_ms = 6;
        changed.push(x);
        let mut x = b.clone();
        x.session.agent = AgentKind::Codex;
        changed.push(x);
        for c in &changed {
            assert_eq!(iss.verify(&t, c, 1_001), Err(TokenError::Mismatch), "{c:?}");
        }

        let mut forged = t.clone();
        forged.expires_unix_ms += 1_000_000;
        assert_eq!(iss.check(&forged, &b, 1_001), Err(TokenError::Mismatch));
        let mut forged = t.clone();
        forged.id = forged.id.replacen("once-", "sess-", 1);
        assert_eq!(iss.check(&forged, &b, 1_001), Err(TokenError::Mismatch));
        let mut forged = t.clone();
        forged.mac[0] ^= 1;
        assert_eq!(iss.check(&forged, &b, 1_001), Err(TokenError::Mismatch));
        // Another daemon's key.
        let other = TokenIssuer::with_key([4; 32]);
        assert_eq!(other.check(&t, &b, 1_001), Err(TokenError::Mismatch));

        // The real binding still works, exactly once.
        assert_eq!(iss.verify(&t, &b, 1_001), Ok(Scope::Once));
        assert_eq!(iss.verify(&t, &b, 1_002), Err(TokenError::Used));
    }

    // protects=expiry and revocation: tokens stop working at expiry and after revoke_all (ms
    // stop); session tokens are reusable until then; fails_when=an expired or revoked token
    // verifies, or a session token is used up; no_claim=wall-clock skew
    #[test]
    fn expiry_reuse_and_revocation() {
        let iss = TokenIssuer::with_key([5; 32]);
        let b = binding();
        let once = iss.issue(&b, Scope::Once, 0).unwrap();
        let ttl = u64::try_from(ONCE_TTL.as_millis()).unwrap();
        assert_eq!(once.expires_unix_ms, ttl);
        assert_eq!(iss.check(&once, &b, ttl), Err(TokenError::Expired));
        let sess = iss.issue(&b, Scope::Session, 0).unwrap();
        for now in [1, 2, 3] {
            assert_eq!(iss.verify(&sess, &b, now), Ok(Scope::Session));
        }
        iss.revoke_all().unwrap();
        assert_eq!(iss.verify(&sess, &b, 4), Err(TokenError::Mismatch));
        assert!(format!("{iss:?}").contains("redacted"));
    }

    #[test]
    fn scope_ids() {
        assert_eq!(
            Scope::of_id(&format!("once-{}", "a".repeat(32))),
            Some(Scope::Once)
        );
        assert_eq!(
            Scope::of_id(&format!("sess-{}", "0".repeat(32))),
            Some(Scope::Session)
        );
        assert_eq!(Scope::of_id("once-xyz"), None);
        assert_eq!(Scope::of_id("other"), None);
    }
}
