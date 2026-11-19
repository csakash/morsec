//! Launch tokens, sessions, CSRF tokens, rate limits and the refusal-receipt throttle. All in
//! msd's memory: a restart (or the idle close) signs everyone out.
//!
//! Tokens are 32 random bytes from the kernel, hex. msd keeps only their SHA-256, so a memory
//! dump of the maps holds nothing that can be replayed, and lookups compare hashes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ms_core::SessionId;
use sha2::{Digest, Sha256};

/// Most launch tokens outstanding; minting another drops the oldest.
pub const MAX_LAUNCH_TOKENS: usize = 16;
/// Most sessions; a new one drops the oldest.
pub const MAX_SESSIONS: usize = 8;
/// How long a session lives (the cookie's `Max-Age`).
pub const SESSION_TTL: Duration = Duration::from_secs(43_200);
/// Refusal receipts per session per minute (SPEC D-9).
pub const REFUSALS_PER_MINUTE: u32 = 30;
/// Sessions the refusal throttle remembers.
const THROTTLE_SESSIONS: usize = 1024;

/// A fresh token: 32 random bytes, hex.
pub fn new_token() -> std::io::Result<String> {
    Ok(hex::encode(ms_approve::token::random_bytes::<32>()?))
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Equal in time that depends only on the length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A token bucket: `rate` per second, burst `rate`.
#[derive(Debug, Clone)]
pub struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// A full bucket.
    pub fn new(rate: u32) -> Self {
        Self {
            rate: f64::from(rate),
            tokens: f64::from(rate),
            last: Instant::now(),
        }
    }

    /// Takes one token if there is one.
    pub fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// One signed-in page.
#[derive(Debug)]
struct Session {
    csrf: String,
    created: Instant,
    bucket: Bucket,
}

/// What a request's cookie and CSRF header add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Signed in, CSRF matches, within the rate.
    Ok,
    /// No cookie, or one msd doesn't know (or expired): 401.
    NoSession,
    /// A known cookie with a missing or wrong CSRF header: 403.
    BadCsrf,
    /// Over the session's rate: 429.
    Limited,
}

/// The in-memory auth state.
#[derive(Debug)]
pub struct Auth {
    launch: HashMap<[u8; 32], Instant>,
    sessions: HashMap<[u8; 32], Session>,
    anon: Bucket,
    rate: u32,
}

impl Auth {
    /// Empty, with `rate` requests/s per session and for unauthenticated requests together.
    pub fn new(rate: u32) -> Self {
        Self {
            launch: HashMap::new(),
            sessions: HashMap::new(),
            anon: Bucket::new(rate),
            rate,
        }
    }

    /// Mints a launch token valid until `now + ttl`.
    pub fn mint_launch(&mut self, now: Instant, ttl: Duration) -> std::io::Result<String> {
        self.launch.retain(|_, exp| *exp > now);
        while self.launch.len() >= MAX_LAUNCH_TOKENS {
            let oldest = self.launch.iter().min_by_key(|(_, e)| **e).map(|(k, _)| *k);
            match oldest {
                Some(k) => self.launch.remove(&k),
                None => break,
            };
        }
        let t = new_token()?;
        self.launch.insert(digest(&t), now + ttl);
        Ok(t)
    }

    /// Uses a launch token: true once, while it is valid. A used or expired token is gone.
    pub fn take_launch(&mut self, token: &str, now: Instant) -> bool {
        if token.len() != 64 {
            return false;
        }
        matches!(self.launch.remove(&digest(token)), Some(exp) if exp > now)
    }

    /// Starts a session: (cookie value, CSRF token).
    pub fn start_session(&mut self, now: Instant) -> std::io::Result<(String, String)> {
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.created) < SESSION_TTL);
        while self.sessions.len() >= MAX_SESSIONS {
            let oldest = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => self.sessions.remove(&k),
                None => break,
            };
        }
        let (cookie, csrf) = (new_token()?, new_token()?);
        self.sessions.insert(
            digest(&cookie),
            Session {
                csrf: csrf.clone(),
                created: now,
                bucket: Bucket::new(self.rate),
            },
        );
        Ok((cookie, csrf))
    }

    /// Checks a request's cookie value and CSRF header, and takes one from its rate bucket.
    pub fn check(&mut self, cookie: Option<&str>, csrf: Option<&str>, now: Instant) -> Access {
        let Some(cookie) = cookie.filter(|c| c.len() == 64) else {
            return Access::NoSession;
        };
        let Some(s) = self.sessions.get_mut(&digest(cookie)) else {
            return Access::NoSession;
        };
        if now.saturating_duration_since(s.created) >= SESSION_TTL {
            self.sessions.remove(&digest(cookie));
            return Access::NoSession;
        }
        if !csrf.is_some_and(|c| ct_eq(c.as_bytes(), s.csrf.as_bytes())) {
            return Access::BadCsrf;
        }
        if !s.bucket.take(now) {
            return Access::Limited;
        }
        Access::Ok
    }

    /// Takes one from the shared bucket for unauthenticated requests (SPEC D-10).
    pub fn take_anon(&mut self, now: Instant) -> bool {
        self.anon.take(now)
    }

    /// Drops every token and session (idle close, shutdown).
    pub fn clear(&mut self) {
        self.launch.clear();
        self.sessions.clear();
        self.anon = Bucket::new(self.rate);
    }

    /// Sessions open (tests).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// At most [`REFUSALS_PER_MINUTE`] refusal receipts per session per minute.
#[derive(Debug, Default)]
pub struct Throttle {
    seen: HashMap<SessionId, (Instant, u32)>,
}

impl Throttle {
    /// True when this refusal should get a receipt.
    pub fn allow(&mut self, s: &SessionId, now: Instant) -> bool {
        if self.seen.len() >= THROTTLE_SESSIONS && !self.seen.contains_key(s) {
            self.seen
                .retain(|_, (t, _)| now.saturating_duration_since(*t) < Duration::from_secs(60));
            if self.seen.len() >= THROTTLE_SESSIONS {
                return false;
            }
        }
        let e = self.seen.entry(s.clone()).or_insert((now, 0));
        if now.saturating_duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        if e.1 >= REFUSALS_PER_MINUTE {
            return false;
        }
        e.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::AgentKind;

    // protects=a launch token works once, only before it expires, and only the exact token;
    // fails_when=a token is reused, outlives its ttl, or a prefix/other token is accepted;
    // no_claim=the HTTP path (tests/http.rs)
    #[test]
    fn launch_tokens() {
        let mut a = Auth::new(20);
        let now = Instant::now();
        let t = a.mint_launch(now, Duration::from_secs(60)).unwrap();
        assert_eq!(t.len(), 64);
        assert!(!a.take_launch(&t[..63], now));
        assert!(a.take_launch(&t, now));
        assert!(!a.take_launch(&t, now), "single use");
        let t = a.mint_launch(now, Duration::from_secs(60)).unwrap();
        assert!(!a.take_launch(&t, now + Duration::from_secs(61)), "expired");
        assert!(!a.take_launch(&t, now), "an expired try still consumes it");
    }

    // protects=a session needs its own cookie and its own CSRF token, and is rate limited;
    // fails_when=a wrong CSRF passes, or more than the rate passes in one instant;
    // no_claim=cookie attributes (tests/http.rs)
    #[test]
    fn sessions_csrf_and_rate() {
        let mut a = Auth::new(5);
        let now = Instant::now();
        let (c, x) = a.start_session(now).unwrap();
        assert_eq!(a.check(Some(&c), Some("nope"), now), Access::BadCsrf);
        assert_eq!(a.check(Some(&c), None, now), Access::BadCsrf);
        assert_eq!(a.check(Some(&x), Some(&x), now), Access::NoSession);
        assert_eq!(a.check(None, Some(&x), now), Access::NoSession);
        let ok = (0..10)
            .filter(|_| a.check(Some(&c), Some(&x), now) == Access::Ok)
            .count();
        assert_eq!(ok, 5);
        assert_eq!(a.check(Some(&c), Some(&x), now), Access::Limited);
        assert_eq!(
            a.check(Some(&c), Some(&x), now + Duration::from_secs(1)),
            Access::Ok
        );
        assert_eq!(
            a.check(Some(&c), Some(&x), now + SESSION_TTL),
            Access::NoSession
        );
        a.clear();
        assert_eq!(a.session_count(), 0);
    }

    // protects=SPEC D-9, an agent looping requests can't write more than 30 refusal receipts a
    // minute per session; fails_when=the 31st in a minute is allowed, or the next minute is
    // still blocked; no_claim=the receipt itself (msd)
    #[test]
    fn refusal_throttle() {
        let mut t = Throttle::default();
        let s = SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 7,
            started_unix_ms: 1,
        };
        let now = Instant::now();
        let n = (0..100).filter(|_| t.allow(&s, now)).count();
        assert_eq!(n, REFUSALS_PER_MINUTE as usize);
        assert!(t.allow(&s, now + Duration::from_secs(61)));
    }
}
