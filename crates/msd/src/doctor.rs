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

/// Nonces remembered; the oldest is dropped first.
pub const MAX_PROBES: usize = 64;
/// The canary host suffix. `.invalid` never resolves (RFC 6761), so nothing leaves the machine.
pub const CANARY_SUFFIX: &str = ".doctor.morsec.invalid";

#[derive(Debug, Default, Clone)]
struct Entry {
    nonce: String,
    canary: Option<ProbeSighting>,
    report: Option<(ProbeReport, ProbeSighting)>,
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

impl Probes {
    fn with<R>(&self, nonce: &str, f: impl FnOnce(&mut Entry) -> R) -> R {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = q.iter_mut().find(|e| e.nonce == nonce) {
            return f(e);
        }
        if q.len() >= MAX_PROBES {
            q.pop_front();
        }
        q.push_back(Entry {
            nonce: nonce.to_owned(),
            ..Entry::default()
        });
        f(q.back_mut().expect("just pushed"))
    }

    /// The proxy refused a canary CONNECT. The first sighting is kept.
    pub fn sighted(&self, nonce: &str, session: Option<SessionId>, now_ms: u64) {
        if !valid_nonce(nonce) {
            return;
        }
        self.with(nonce, |e| {
            e.canary.get_or_insert(ProbeSighting {
                session,
                seen_unix_ms: now_ms,
            });
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
                // First report wins, so a later "blocked" can't overwrite an "open".
                let stored = self.with(nonce, |e| {
                    if e.report.is_some() {
                        return false;
                    }
                    e.report = Some((
                        r,
                        ProbeSighting {
                            session,
                            seen_unix_ms: now_ms,
                        },
                    ));
                    true
                });
                ResponseBody::Ok {
                    message: if stored {
                        "morsec: probe report recorded".into()
                    } else {
                        "morsec: a probe report for this nonce was already recorded; kept the first"
                            .into()
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
                    canary: e.canary,
                    report: e.report,
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

    fn s() -> SessionId {
        SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 42,
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
            session: Some(s()),
            host: format!("{N}.doctor.morsec.invalid"),
            port: 443,
            kind: BlockKind::NotAllowed,
        });
        match p.handle(None, Some(N), None, 0) {
            ResponseBody::Probe {
                canary: Some(c),
                report: None,
            } => assert_eq!(c.session, Some(s())),
            other => panic!("{other:?}"),
        }
    }

    // protects=a later "blocked" report can't overwrite an "open" one for the same nonce, and
    // malformed nonces and oversized details are refused; fails_when=the second report replaces
    // the first or a bad nonce is stored; no_claim=who may send a report (anyone; doctor weighs it)
    #[test]
    fn first_report_wins_and_input_is_checked() {
        let p = Probes::default();
        assert!(matches!(
            p.handle(Some(s()), Some(N), Some(report(true)), 1),
            ResponseBody::Ok { .. }
        ));
        p.handle(None, Some(N), Some(report(false)), 2);
        match p.handle(None, Some(N), None, 3) {
            ResponseBody::Probe {
                report: Some((r, by)),
                ..
            } => {
                assert!(r.direct_open);
                assert_eq!(by.session, Some(s()));
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

    // protects=the store is bounded: flooding it with nonces drops the oldest, never grows past
    // MAX_PROBES; fails_when=it grows without bound; no_claim=timing
    #[test]
    fn bounded() {
        let p = Probes::default();
        for i in 0..(MAX_PROBES + 10) {
            p.sighted(&format!("{i:032x}"), None, 0);
        }
        assert_eq!(p.entries.lock().unwrap().len(), MAX_PROBES);
        assert!(matches!(
            p.handle(None, Some(&format!("{:032x}", 0)), None, 0),
            ResponseBody::Probe { canary: None, .. }
        ));
    }
}
