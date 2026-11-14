//! `ms doctor --probe` support (L17): what msd saw for each probe nonce.
//!
//! Two things are recorded per nonce: the canary sighting (the proxy refused a CONNECT to
//! `<nonce>.doctor.morsec.invalid`, so the request really reached msd, from a known session) and
//! the probe's own report (sent over IPC from inside the agent's sandbox). Neither involves a key,
//! so nothing here is a receipt. The store is small and bounded; nonces are 32 lowercase hex
//! characters, so nothing an agent sends can grow it or put free text in it beyond the report's
//! capped detail.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ms_core::SessionId;
use ms_ipc::{ErrorCode, ProbeReport, ProbeSighting, ResponseBody};
use ms_proxy::{BlockEvent, EgressObserver, LogObserver};

/// Nonces remembered.
pub const MAX_PROBES: usize = 64;
/// Sessions remembered per nonce, for canaries and for reports.
pub const MAX_PER_NONCE: usize = 4;
/// An entry younger than this is never evicted to make room (security review S2): a full store
/// refuses new nonces instead, so flooding it can't wipe a report `ms doctor --live` is waiting
/// for. Longer than a live run (180 s per agent, two agents).
pub const MIN_AGE_TO_EVICT_MS: u64 = 10 * 60 * 1000;
/// The canary host suffix. `.invalid` never resolves (RFC 6761), so nothing leaves the machine.
pub const CANARY_SUFFIX: &str = ".doctor.morsec.invalid";

#[derive(Debug, Default, Clone)]
struct Entry {
    nonce: String,
    created_ms: u64,
    canaries: Vec<ProbeSighting>,
    reports: Vec<(ProbeReport, ProbeSighting)>,
    /// Any report said direct egress is open (security review S3: kept even when the report
    /// itself isn't).
    any_open: bool,
}

/// The probe store.
#[derive(Debug, Default)]
pub struct Probes {
    entries: Mutex<VecDeque<Entry>>,
}

/// True for exactly 32 lowercase hex characters.
pub fn valid_nonce(n: &str) -> bool {
    n.len() == 32
        && n.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The nonce in a canary host, if `host` is one.
pub fn canary_nonce(host: &str) -> Option<&str> {
    host.strip_suffix(CANARY_SUFFIX).filter(|n| valid_nonce(n))
}

/// Adds `item` unless this session already has one there (the first per session wins, so a
/// later "blocked" from the same session can't replace an "open") or the list is full.
fn add_once<T>(list: &mut Vec<T>, item: T, session: impl Fn(&T) -> &Option<SessionId>) -> bool {
    if list.len() >= MAX_PER_NONCE || list.iter().any(|x| session(x) == session(&item)) {
        return false;
    }
    list.push(item);
    true
}

impl Probes {
    /// Runs `f` on the entry for `nonce`, making one if there is room. `None`: the store is full
    /// of recent entries.
    fn with<R>(&self, nonce: &str, now_ms: u64, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = q.iter_mut().find(|e| e.nonce == nonce) {
            return Some(f(e));
        }
        if q.len() >= MAX_PROBES {
            let old = q
                .front()
                .is_some_and(|e| now_ms.saturating_sub(e.created_ms) >= MIN_AGE_TO_EVICT_MS);
            if !old {
                return None;
            }
            q.pop_front();
        }
        q.push_back(Entry {
            nonce: nonce.to_owned(),
            created_ms: now_ms,
            ..Entry::default()
        });
        q.back_mut().map(f)
    }

    /// The proxy refused a canary CONNECT.
    pub fn sighted(&self, nonce: &str, session: Option<SessionId>, now_ms: u64) {
        if !valid_nonce(nonce) {
            return;
        }
        let s = ProbeSighting {
            session,
            seen_unix_ms: now_ms,
        };
        let _ = self.with(nonce, now_ms, |e| {
            add_once(&mut e.canaries, s, |c| &c.session)
        });
    }

    /// Handles a `DoctorProbe` request from `session` (`None`: not an agent session).
    pub fn handle(
        &self,
        session: Option<SessionId>,
        nonce: Option<&str>,
        report: Option<ProbeReport>,
        now_ms: u64,
    ) -> ResponseBody {
        let Some(nonce) = nonce.filter(|n| valid_nonce(n)) else {
            return ResponseBody::error(
                ErrorCode::Invalid,
                "morsec: a doctor probe needs a nonce of 32 lowercase hex characters (ms doctor --live makes one)",
            );
        };
        match report {
            Some(r) => {
                if r.detail.chars().count() > ProbeReport::MAX_DETAIL {
                    return ResponseBody::error(
                        ErrorCode::Invalid,
                        "morsec: the probe report's detail is too long",
                    );
                }
                let open = r.direct_open;
                let item = (
                    r,
                    ProbeSighting {
                        session,
                        seen_unix_ms: now_ms,
                    },
                );
                match self.with(nonce, now_ms, |e| {
                    e.any_open |= open;
                    add_once(&mut e.reports, item, |(_, by)| &by.session)
                }) {
                    None => ResponseBody::error(
                        ErrorCode::Busy,
                        "morsec: too many doctor probes in flight; try again in a few minutes",
                    ),
                    Some(stored) => ResponseBody::Ok {
                        message: if stored {
                            "morsec: probe report recorded".into()
                        } else {
                            "morsec: a probe report from this session was already recorded; kept the first".into()
                        },
                    },
                }
            }
            None => {
                let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                let e = q
                    .iter()
                    .find(|e| e.nonce == nonce)
                    .cloned()
                    .unwrap_or_default();
                ResponseBody::Probe {
                    canaries: e.canaries,
                    reports: e.reports,
                    any_open: e.any_open,
                }
            }
        }
    }
}

/// The proxy's egress observer: logs every refusal (as before) and records canary sightings.
#[derive(Debug)]
pub struct CanaryObserver {
    /// Where sightings go.
    pub probes: Arc<Probes>,
}

impl EgressObserver for CanaryObserver {
    fn blocked(&self, event: &BlockEvent) {
        LogObserver.blocked(event);
        if let Some(n) = canary_nonce(&event.host) {
            self.probes
                .sighted(n, event.session.clone(), ms_session::peer::now_unix_ms());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::AgentKind;
    use ms_proxy::BlockKind;

    const N: &str = "0123456789abcdef0123456789abcdef";

    fn s(pid: u32) -> SessionId {
        SessionId {
            agent: AgentKind::ClaudeCode,
            pid,
            started_unix_ms: 7,
        }
    }

    fn report(open: bool) -> ProbeReport {
        ProbeReport {
            proxy_reached: true,
            direct_open: open,
            detail: String::new(),
        }
    }

    fn lookup(p: &Probes) -> (Vec<ProbeSighting>, Vec<(ProbeReport, ProbeSighting)>) {
        match p.handle(None, Some(N), None, 0) {
            ResponseBody::Probe {
                canaries, reports, ..
            } => (canaries, reports),
            other => panic!("{other:?}"),
        }
    }

    // protects=INJ-4 doctor evidence: only well-formed canary hosts are recorded, with the
    // session the proxy resolved; fails_when=a look-alike host (other suffix, upper case, wrong
    // length, extra label) is recorded; no_claim=the proxy's own refusal
    #[test]
    fn canary_hosts_only() {
        assert_eq!(canary_nonce(&format!("{N}.doctor.morsec.invalid")), Some(N));
        for h in [
            format!("{N}.doctor.morsec.invalid.evil.com"),
            format!("{}.doctor.morsec.invalid", N.to_uppercase()),
            format!("{}.doctor.morsec.invalid", &N[1..]),
            format!("x.{N}.doctor.morsec.invalid"),
            "doctor.morsec.invalid".into(),
        ] {
            assert_eq!(canary_nonce(&h), None, "{h}");
        }
        let p = Arc::new(Probes::default());
        let o = CanaryObserver { probes: p.clone() };
        o.blocked(&BlockEvent {
            session: Some(s(42)),
            host: format!("{N}.doctor.morsec.invalid"),
            port: 443,
            kind: BlockKind::NotAllowed,
        });
        let (c, r) = lookup(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].session, Some(s(42)));
        assert!(r.is_empty());
    }

    // protects=security review S1: another process can't crowd out the real agent's evidence by
    // getting in first: the first canary and report of each session are kept (a few sessions per
    // nonce), and within one session a later "blocked" can't replace an "open"; malformed nonces
    // and oversized details are refused; fails_when=a second session's evidence is dropped or a
    // session's first report is replaced; no_claim=which session doctor trusts (ms-cli judge)
    #[test]
    fn first_per_session_and_input_is_checked() {
        let p = Probes::default();
        assert!(matches!(
            p.handle(Some(s(1)), Some(N), Some(report(false)), 1),
            ResponseBody::Ok { .. }
        ));
        p.handle(Some(s(2)), Some(N), Some(report(true)), 2);
        p.handle(Some(s(2)), Some(N), Some(report(false)), 3);
        p.sighted(N, Some(s(1)), 4);
        p.sighted(N, Some(s(1)), 5);
        p.sighted(N, Some(s(2)), 6);
        let (c, r) = lookup(&p);
        assert_eq!(c.len(), 2);
        assert_eq!(r.len(), 2);
        assert!(
            r.iter()
                .any(|(rep, by)| by.session == Some(s(2)) && rep.direct_open)
        );
        for i in 3..10 {
            p.sighted(N, Some(s(i)), 7);
        }
        assert_eq!(lookup(&p).0.len(), MAX_PER_NONCE);
        // S3: once the report slots are full, or a session already reported "blocked", a later
        // "open" is still recorded as any_open.
        let m = "a".repeat(32);
        for i in 0..MAX_PER_NONCE as u32 {
            p.handle(Some(s(100 + i)), Some(&m), Some(report(false)), 8);
        }
        p.handle(Some(s(100)), Some(&m), Some(report(true)), 9);
        p.handle(Some(s(999)), Some(&m), Some(report(true)), 9);
        match p.handle(None, Some(&m), None, 10) {
            ResponseBody::Probe {
                reports, any_open, ..
            } => {
                assert_eq!(reports.len(), MAX_PER_NONCE);
                assert!(reports.iter().all(|(r, _)| !r.direct_open));
                assert!(any_open);
            }
            other => panic!("{other:?}"),
        }
        for bad in [None, Some("abc"), Some("0123456789ABCDEF0123456789ABCDEF")] {
            assert!(matches!(
                p.handle(None, bad, None, 0),
                ResponseBody::Error {
                    code: ErrorCode::Invalid,
                    ..
                }
            ));
        }
        let mut long = report(false);
        long.detail = "x".repeat(ProbeReport::MAX_DETAIL + 1);
        let other = "f".repeat(32);
        assert!(matches!(
            p.handle(None, Some(&other), Some(long), 0),
            ResponseBody::Error { .. }
        ));
    }

    // protects=security review S2: the store is bounded, and flooding it with fresh nonces can't
    // evict a recent entry (new nonces are refused instead); old entries are evicted;
    // fails_when=it grows past MAX_PROBES or a recent nonce's evidence is lost; no_claim=timing
    #[test]
    fn bounded_and_recent_entries_survive_a_flood() {
        let p = Probes::default();
        p.handle(Some(s(1)), Some(N), Some(report(true)), 1_000);
        for i in 1..(MAX_PROBES + 10) {
            p.sighted(&format!("{i:032x}"), None, 2_000);
        }
        assert_eq!(p.entries.lock().unwrap().len(), MAX_PROBES);
        assert_eq!(lookup(&p).1.len(), 1, "the real report was evicted");
        assert!(matches!(
            p.handle(None, Some(&"e".repeat(32)), Some(report(false)), 3_000),
            ResponseBody::Error {
                code: ErrorCode::Busy,
                ..
            }
        ));
        // Once old enough, entries make room again.
        let later = 1_000 + MIN_AGE_TO_EVICT_MS;
        assert!(matches!(
            p.handle(None, Some(&"e".repeat(32)), Some(report(false)), later),
            ResponseBody::Ok { .. }
        ));
        assert!(lookup(&p).1.is_empty());
    }
}
