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
/// CSRF tokens one session keeps: one per page that signed in with its cookie (review R1).
pub const CSRF_PER_SESSION: usize = 4;

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
    /// Newest last; a page holds one of them.
    csrf: Vec<String>,
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

    /// Starts a session, or joins `existing` when that cookie names a live one (a second
    /// `ms dashboard` in the same browser: cookies are not port-scoped, so a new cookie would
    /// sign the first tab out; review R1). Returns (cookie value, a new CSRF token).
    pub fn start_session(
        &mut self,
        now: Instant,
        existing: Option<&str>,
    ) -> std::io::Result<(String, String)> {
        if let Some(c) = existing.filter(|c| c.len() == 64)
            && let Some(s) = self.sessions.get_mut(&digest(c))
            && now.saturating_duration_since(s.created) < SESSION_TTL
        {
            let csrf = new_token()?;
            s.csrf.push(csrf.clone());
            if s.csrf.len() > CSRF_PER_SESSION {
                s.csrf.remove(0);
            }
            return Ok((c.to_owned(), csrf));
        }
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
                csrf: vec![csrf.clone()],
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
        // Every stored token is compared, so the time taken doesn't say which one matched.
        let ok = csrf.is_some_and(|c| {
            s.csrf
                .iter()
                .fold(false, |hit, t| ct_eq(c.as_bytes(), t.as_bytes()) | hit)
        });
        if !ok {
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

    /// A launch token minted and not yet used is still valid (`DashOpen` then opens no second
    /// tab: fix round 2, F2).
    pub fn launch_pending(&mut self, now: Instant) -> bool {
        self.launch.retain(|_, exp| *exp > now);
        !self.launch.is_empty()
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

/// At most [`REFUSALS_PER_MINUTE`] refusal receipts per agent session per minute, and as many
/// for every caller outside an agent session together (security review S3: such callers are
/// keyed by PID, which a looping process changes at will).
#[derive(Debug, Default)]
pub struct Throttle {
    seen: HashMap<SessionId, (Instant, u32)>,
}

/// The key all non-agent refusals share; an agent session keeps its own.
pub fn family(s: &SessionId) -> SessionId {
    match &s.agent {
        ms_core::AgentKind::Other(_) => SessionId {
            agent: ms_core::AgentKind::Other("dashboard".into()),
            pid: 0,
            started_unix_ms: 0,
        },
        _ => s.clone(),
    }
}

impl Throttle {
    /// True when this refusal should get a receipt.
    pub fn allow(&mut self, s: &SessionId, now: Instant) -> bool {
        let s = &family(s);
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

/// The log-throttle key of a refusal: its [`family`] and reason, so a loop that changes PID with
/// every request (`while :; do curl …; done`) still shares one key (fix round 2, F1).
pub fn log_key(session: &SessionId, why: &str) -> String {
    let f = family(session);
    format!("{:?}/{}/{}:{why}", f.agent, f.pid, f.started_unix_ms)
}

/// Log lines for refusals: the first per key per minute, then one count of the rest when the
/// next minute's first arrives (review R3: msd's log is not rotated).
#[derive(Debug, Default)]
pub struct RateLog {
    seen: HashMap<String, (Instant, u64)>,
}

impl RateLog {
    /// `Some(suppressed since the last line)` when a line should be written now.
    pub fn allow(&mut self, key: &str, now: Instant) -> Option<u64> {
        if self.seen.len() >= THROTTLE_SESSIONS && !self.seen.contains_key(key) {
            self.seen
                .retain(|_, (t, _)| now.saturating_duration_since(*t) < Duration::from_secs(60));
            if self.seen.len() >= THROTTLE_SESSIONS {
                return None;
            }
        }
        match self.seen.get_mut(key) {
            Some((t, n)) if now.saturating_duration_since(*t) < Duration::from_secs(60) => {
                *n += 1;
                None
            }
            Some((t, n)) => {
                let quiet = *n;
                *t = now;
                *n = 0;
                Some(quiet)
            }
            None => {
                self.seen.insert(key.to_owned(), (now, 0));
                Some(0)
            }
        }
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
        let (c, x) = a.start_session(now, None).unwrap();
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

    // protects=review R1: a second sign-in from the same browser joins the session and adds a
    // CSRF token, so the first tab keeps working; an unknown cookie starts a new session;
    // fails_when=the first tab's token stops matching after one more sign-in, or a stale cookie
    // is joined; no_claim=-
    #[test]
    fn second_sign_in_joins_the_session() {
        let mut a = Auth::new(50);
        let now = Instant::now();
        let (c, x1) = a.start_session(now, None).unwrap();
        let (c2, x2) = a.start_session(now, Some(&c)).unwrap();
        assert_eq!(c, c2);
        assert_eq!(a.session_count(), 1);
        assert_eq!(a.check(Some(&c), Some(&x1), now), Access::Ok);
        assert_eq!(a.check(Some(&c), Some(&x2), now), Access::Ok);
        for _ in 0..CSRF_PER_SESSION {
            a.start_session(now, Some(&c)).unwrap();
        }
        assert_eq!(
            a.check(Some(&c), Some(&x1), now),
            Access::BadCsrf,
            "oldest dropped"
        );
        let (c3, _) = a.start_session(now, Some(&"f".repeat(64))).unwrap();
        assert_ne!(c3, c);
        assert_eq!(a.session_count(), 2);
    }

    // protects=review R3: one log line per key per minute, then the count of what was skipped;
    // fails_when=a looping caller writes a line per request; no_claim=-
    #[test]
    fn refusal_log_is_rate_limited() {
        let mut l = RateLog::default();
        let now = Instant::now();
        assert_eq!(l.allow("k", now), Some(0));
        assert!((0..50).all(|_| l.allow("k", now).is_none()));
        assert_eq!(l.allow("other", now), Some(0));
        assert_eq!(l.allow("k", now + Duration::from_secs(61)), Some(50));
    }

    // protects=fix round 2 F1: refusals from 100 different PIDs outside agent sessions share one
    // log key, so a curl loop writes one line a minute plus a count; agent sessions keep their own
    // key; fails_when=a new PID gets its own line; no_claim=-
    #[test]
    fn log_key_groups_non_agent_pids() {
        let mut l = RateLog::default();
        let now = Instant::now();
        let lines = (0..100u32)
            .filter(|i| {
                let s = SessionId {
                    agent: AgentKind::Other("dashboard".into()),
                    pid: 5000 + i,
                    started_unix_ms: u64::from(*i),
                };
                l.allow(&log_key(&s, "the Host header is not this dashboard"), now)
                    .is_some()
            })
            .count();
        assert_eq!(lines, 1);
        let any = SessionId {
            agent: AgentKind::Other("dashboard".into()),
            pid: 1,
            started_unix_ms: 1,
        };
        assert_eq!(
            l.allow(
                &log_key(&any, "the Host header is not this dashboard"),
                now + Duration::from_secs(61)
            ),
            Some(99)
        );
        let a = |pid| SessionId {
            agent: AgentKind::ClaudeCode,
            pid,
            started_unix_ms: 1,
        };
        assert_ne!(log_key(&a(1), "x"), log_key(&a(2), "x"));
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
        // Callers outside agent sessions share one budget whatever their PID (review S3).
        let n = (0..100u32)
            .filter(|i| {
                t.allow(
                    &SessionId {
                        agent: AgentKind::Other("dashboard".into()),
                        pid: 1000 + i,
                        started_unix_ms: 1,
                    },
                    now,
                )
            })
            .count();
        assert_eq!(n, REFUSALS_PER_MINUTE as usize);
    }
}
