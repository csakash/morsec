//! The human approver (SPEC D-1 … D-6): one pending request at a time, decided by a person
//! through `ms approve` and confirmed with Touch ID raised by msd itself.
//!
//! [`HumanApprover::ask`] (the frozen [`Approver`] trait) parks the request in the single slot and
//! waits. [`HumanApprover::decide`] is called for an `ApprovalDecide` from a caller msd has already
//! checked is outside every agent tree; on approve it runs the [`Authenticator`] (Touch ID) with a
//! reason built here from the real request, then issues a [`TokenIssuer`] token bound to it.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ms_core::ApprovalRequest;

use crate::auth::{AuthOutcome, Authenticator};
use crate::render;
use crate::token::{Binding, Scope, TokenError, TokenIssuer, random_bytes};
use crate::{ApprovalOutcome, ApprovalToken, Approver};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The request waiting for a person, as `ms approve` sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Random id; a decision must name it.
    pub id: String,
    /// What is being asked, exactly as the executor will carry it out.
    pub request: ApprovalRequest,
    /// When it was asked, Unix ms.
    pub requested_unix_ms: u64,
    /// When it times out, Unix ms.
    pub expires_unix_ms: u64,
}

/// Why a decision was not taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecideError {
    /// No pending request has this id (it was answered, timed out, or never existed).
    #[error("no approval request {0} is waiting (it was answered or timed out)")]
    NotPending(String),
    /// Someone is already deciding this request (a Touch ID sheet is up).
    #[error("this request is already being decided")]
    InProgress,
    /// Touch ID / password did not succeed; the request is denied.
    #[error("Touch ID did not confirm ({0}), so the request was denied")]
    AuthFailed(String),
    /// The request timed out while Touch ID was up; nothing was approved.
    #[error("the request timed out before Touch ID finished; nothing was approved")]
    Expired,
    /// `ms stop` (or another answer) ended the request while Touch ID was up.
    #[error("the request was ended (ms stop) while Touch ID was up; nothing was approved")]
    Ended,
    /// The token could not be made (no randomness).
    #[error("could not issue the approval: {0}")]
    Internal(String),
}

#[derive(Debug)]
struct Slot {
    pending: Pending,
    deciding: bool,
    answer: Option<ApprovalOutcome>,
}

#[derive(Debug, Default)]
struct State {
    slot: Option<Slot>,
    /// Session-scope grants: reused for the identical binding until they expire or `revoke_all`.
    grants: Vec<(Binding, ApprovalToken)>,
    /// Bumped by `revoke_all` (`ms stop`): a Touch ID that started before it approves nothing.
    epoch: u64,
}

/// The production approver.
pub struct HumanApprover {
    auth: Arc<dyn Authenticator>,
    tokens: TokenIssuer,
    state: Mutex<State>,
    changed: Condvar,
}

impl std::fmt::Debug for HumanApprover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HumanApprover").finish_non_exhaustive()
    }
}

impl HumanApprover {
    /// An approver confirming with `auth`, with a fresh random token key.
    pub fn new(auth: Arc<dyn Authenticator>) -> std::io::Result<Self> {
        Ok(Self::with_issuer(auth, TokenIssuer::random()?))
    }

    /// An approver with a given token issuer (tests).
    pub fn with_issuer(auth: Arc<dyn Authenticator>, tokens: TokenIssuer) -> Self {
        Self {
            auth,
            tokens,
            state: Mutex::default(),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The request waiting for a person, if any.
    pub fn pending(&self) -> Option<Pending> {
        self.lock().slot.as_ref().map(|s| s.pending.clone())
    }

    /// True while a request is waiting (a new one would be refused).
    pub fn busy(&self) -> bool {
        self.lock().slot.is_some()
    }

    /// A session grant that already covers `req`, without asking anyone.
    fn grant_for(&self, st: &mut State, b: &Binding, now: u64) -> Option<ApprovalToken> {
        st.grants
            .retain(|(gb, t)| self.tokens.check(t, gb, now).is_ok());
        st.grants
            .iter()
            .find(|(gb, _)| gb == b)
            .map(|(_, t)| t.clone())
    }

    /// A person's answer to pending request `id`. `approve` runs Touch ID (with a reason built
    /// from the real request) before anything is approved; a denial needs none.
    /// The caller must already have checked that the decision comes from outside every agent tree.
    pub fn decide(
        &self,
        id: &str,
        approve: bool,
        scope: Scope,
    ) -> Result<ApprovalOutcome, DecideError> {
        let (reason, deadline, epoch) = {
            let mut st = self.lock();
            let slot = match st.slot.as_mut() {
                Some(s) if s.pending.id == id && s.answer.is_none() => s,
                _ => return Err(DecideError::NotPending(render::inert(id))),
            };
            if slot.deciding {
                return Err(DecideError::InProgress);
            }
            if !approve {
                slot.answer = Some(ApprovalOutcome::Denied);
                self.changed.notify_all();
                return Ok(ApprovalOutcome::Denied);
            }
            let left = slot.pending.expires_unix_ms.saturating_sub(now_ms());
            if left == 0 {
                // Already past its deadline: don't raise a sheet at all.
                return Err(DecideError::Expired);
            }
            slot.deciding = true;
            let reason = render::touch_id_reason(&slot.pending.request, scope);
            (
                reason,
                Instant::now() + Duration::from_millis(left),
                st.epoch,
            )
        };
        // Outside the lock: the sheet can take a while, and `pending`/`busy` must stay answerable.
        let outcome = self.auth.authenticate(&reason, deadline);
        let mut st = self.lock();
        if st.epoch != epoch {
            return Err(DecideError::Ended);
        }
        let slot = match st.slot.as_mut() {
            Some(s) if s.pending.id == id => s,
            _ => return Err(DecideError::Expired),
        };
        // Answered meanwhile (ms stop denied it) or revoked since the sheet went up: the late
        // Touch ID approves nothing, and the earlier answer stands (review R1).
        if slot.answer.is_some() {
            return Err(DecideError::Ended);
        }
        let now = now_ms();
        if now >= slot.pending.expires_unix_ms || Instant::now() >= deadline {
            slot.answer = Some(ApprovalOutcome::TimedOut);
            self.changed.notify_all();
            return Err(DecideError::Expired);
        }
        match outcome {
            AuthOutcome::Approved => {
                let b = Binding::of(&slot.pending.request);
                match self.tokens.issue(&b, scope, now) {
                    Ok(t) => {
                        slot.answer = Some(ApprovalOutcome::Approved(t.clone()));
                        self.changed.notify_all();
                        Ok(ApprovalOutcome::Approved(t))
                    }
                    Err(e) => {
                        slot.answer = Some(ApprovalOutcome::Denied);
                        self.changed.notify_all();
                        Err(DecideError::Internal(e.to_string()))
                    }
                }
            }
            AuthOutcome::TimedOut => {
                slot.answer = Some(ApprovalOutcome::TimedOut);
                self.changed.notify_all();
                Err(DecideError::Expired)
            }
            AuthOutcome::Denied(why) | AuthOutcome::Unavailable(why) => {
                slot.answer = Some(ApprovalOutcome::Denied);
                self.changed.notify_all();
                Err(DecideError::AuthFailed(why))
            }
        }
    }

    /// The executor's check right before it acts (SPEC D-6): `t` must be for exactly `b`.
    /// Uses up a once token.
    pub fn verify(&self, t: &ApprovalToken, b: &Binding) -> Result<Scope, TokenError> {
        self.tokens.verify(t, b, now_ms())
    }

    /// `ms stop`: drop every session grant and invalidate every token issued so far. A request
    /// waiting for a person is denied.
    pub fn revoke_all(&self) -> std::io::Result<()> {
        let mut st = self.lock();
        st.epoch = st.epoch.wrapping_add(1);
        st.grants.clear();
        if let Some(s) = st.slot.as_mut()
            && s.answer.is_none()
        {
            s.answer = Some(ApprovalOutcome::Denied);
        }
        self.changed.notify_all();
        self.tokens.revoke_all()
    }
}

impl Approver for HumanApprover {
    fn ask(&self, req: &ApprovalRequest, timeout: Duration) -> ApprovalOutcome {
        let now = now_ms();
        let b = Binding::of(req);
        let mut st = self.lock();
        if let Some(t) = self.grant_for(&mut st, &b, now) {
            return ApprovalOutcome::Approved(t);
        }
        if st.slot.is_some() {
            tracing::warn!(key = %req.key, "approval refused: another approval is waiting");
            return ApprovalOutcome::Denied;
        }
        let id = match random_bytes::<16>() {
            Ok(r) => format!("apr-{}", hex::encode(r)),
            Err(e) => {
                tracing::error!(error = %e, "no randomness for an approval id");
                return ApprovalOutcome::Denied;
            }
        };
        let deadline = Instant::now() + timeout;
        st.slot = Some(Slot {
            pending: Pending {
                id: id.clone(),
                request: req.clone(),
                requested_unix_ms: now,
                expires_unix_ms: now
                    .saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            },
            deciding: false,
            answer: None,
        });
        tracing::info!(key = %req.key, id = %id, "approval waiting: run ms approve");
        let answer = loop {
            if let Some(a) = st.slot.as_ref().and_then(|s| s.answer.clone()) {
                break a;
            }
            let now = Instant::now();
            if now >= deadline {
                break ApprovalOutcome::TimedOut;
            }
            st = self
                .changed
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        };
        st.slot = None;
        self.changed.notify_all();
        if let ApprovalOutcome::Approved(t) = &answer
            && Scope::of_id(&t.id) == Some(Scope::Session)
        {
            st.grants.push((b, t.clone()));
        }
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::fake::FakeAuthenticator;
    use ms_core::{AgentKind, KeyName, SessionId, Tier};
    use std::path::PathBuf;

    fn req(arg: &str) -> ApprovalRequest {
        ApprovalRequest {
            session: SessionId {
                agent: AgentKind::ClaudeCode,
                pid: 7,
                started_unix_ms: 9,
            },
            key: KeyName::new("pg/production").unwrap(),
            tier: Tier::Production,
            argv_display: vec!["psql".into(), "-c".into(), arg.into()],
            argv_hash: {
                let mut h = [0u8; 32];
                for (i, b) in arg.bytes().enumerate() {
                    h[i % 32] ^= b;
                }
                h
            },
            cwd: PathBuf::from("/repo"),
            effect: None,
        }
    }

    fn approver(auth: FakeAuthenticator) -> (Arc<HumanApprover>, Arc<FakeAuthenticator>) {
        let auth = Arc::new(auth);
        (
            Arc::new(HumanApprover::with_issuer(
                auth.clone(),
                TokenIssuer::with_key([1; 32]),
            )),
            auth,
        )
    }

    /// Runs `ask` on a thread and waits until it is pending.
    fn ask_bg(
        a: &Arc<HumanApprover>,
        r: ApprovalRequest,
        timeout: Duration,
    ) -> (std::thread::JoinHandle<ApprovalOutcome>, Pending) {
        let a2 = a.clone();
        let h = std::thread::spawn(move || a2.ask(&r, timeout));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(p) = a.pending() {
                return (h, p);
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // protects=AUTH-3 end to end in the approver: a person approves with Touch ID, the token is
    // bound to the exact request, and the executor's verify refuses it after one argument
    // changes; the Touch ID reason is msd's text for the real request; fails_when=a changed
    // request verifies, or Touch ID is skipped; no_claim=the real LAContext sheet (PROOF manual)
    #[test]
    fn approve_then_one_argument_changes() {
        let (a, auth) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("select 1"), Duration::from_secs(10));
        assert_eq!(p.request, req("select 1"));
        let out = a.decide(&p.id, true, Scope::Once).unwrap();
        let ApprovalOutcome::Approved(t) = h.join().unwrap() else {
            panic!("not approved")
        };
        assert_eq!(out, ApprovalOutcome::Approved(t.clone()));
        let reasons = auth.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains(r#""select 1""#), "{}", reasons[0]);
        assert!(reasons[0].contains(&render::fingerprint(&req("select 1"))));
        // One argument changed between approval and execution: refused.
        assert_eq!(
            a.verify(&t, &Binding::of(&req("select 2"))),
            Err(TokenError::Mismatch)
        );
        assert_eq!(
            a.verify(&t, &Binding::of(&req("select 1"))),
            Ok(Scope::Once)
        );
        assert_eq!(
            a.verify(&t, &Binding::of(&req("select 1"))),
            Err(TokenError::Used)
        );
        assert!(!a.busy());
    }

    // protects=a timeout rejects: nobody decides → TimedOut, the slot is freed, and a decision
    // arriving after the timeout approves nothing; fails_when=a late decision yields a token or
    // the slot stays taken; no_claim=wall-clock accuracy
    #[test]
    fn timeout_is_rejected() {
        let (a, auth) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("x"), Duration::from_millis(150));
        assert_eq!(h.join().unwrap(), ApprovalOutcome::TimedOut);
        assert!(!a.busy());
        assert!(matches!(
            a.decide(&p.id, true, Scope::Once),
            Err(DecideError::NotPending(_))
        ));
        assert!(auth.reasons().is_empty(), "no Touch ID after a timeout");
    }

    // protects=Touch ID that finishes after the deadline approves nothing, and the waiting ask
    // returns TimedOut; fails_when=a late Touch ID issues a token; no_claim=LAContext invalidation
    #[test]
    fn touch_id_finishing_late_approves_nothing() {
        let (a, _) = approver(FakeAuthenticator::approve().after(Duration::from_millis(400)));
        let (h, p) = ask_bg(&a, req("x"), Duration::from_millis(200));
        let d = a.decide(&p.id, true, Scope::Once);
        assert!(matches!(d, Err(DecideError::Expired)), "{d:?}");
        assert_eq!(h.join().unwrap(), ApprovalOutcome::TimedOut);
    }

    // protects=a failed or cancelled Touch ID denies the request (no retry on the same id), and
    // deny needs no Touch ID; fails_when=the request stays approvable after a failed Touch ID;
    // no_claim=lockout behaviour of the real sheet
    #[test]
    fn failed_touch_id_denies_and_deny_needs_none() {
        let (a, _) = approver(FakeAuthenticator::deny("cancelled"));
        let (h, p) = ask_bg(&a, req("x"), Duration::from_secs(10));
        assert!(matches!(
            a.decide(&p.id, true, Scope::Once),
            Err(DecideError::AuthFailed(_))
        ));
        assert_eq!(h.join().unwrap(), ApprovalOutcome::Denied);
        assert!(a.decide(&p.id, true, Scope::Once).is_err());

        let (a, auth) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("x"), Duration::from_secs(10));
        assert_eq!(
            a.decide(&p.id, false, Scope::Once),
            Ok(ApprovalOutcome::Denied)
        );
        assert_eq!(h.join().unwrap(), ApprovalOutcome::Denied);
        assert!(auth.reasons().is_empty());
    }

    // protects=one prompt at a time: while one request waits, another is refused at once (not
    // queued), and a decision must name the pending id; fails_when=a second request is parked
    // or a wrong id decides; no_claim=fairness between agents
    #[test]
    fn one_prompt_at_a_time() {
        let (a, _) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("first"), Duration::from_secs(10));
        let started = Instant::now();
        assert_eq!(
            a.ask(&req("second"), Duration::from_secs(10)),
            ApprovalOutcome::Denied
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(a.pending().unwrap().id, p.id);
        assert!(matches!(
            a.decide("apr-0000", true, Scope::Once),
            Err(DecideError::NotPending(_))
        ));
        a.decide(&p.id, false, Scope::Once).unwrap();
        assert_eq!(h.join().unwrap(), ApprovalOutcome::Denied);
    }

    // protects=session scope: an approval "for this session" covers only the identical request
    // in the same session, without asking again; a different argument or session asks again;
    // revoke_all (ms stop) ends it; fails_when=a grant covers anything else or survives revoke;
    // no_claim=session end detection (grants also end at 8h and msd exit)
    #[test]
    fn session_scope_covers_only_the_same_request() {
        let (a, auth) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("same"), Duration::from_secs(10));
        a.decide(&p.id, true, Scope::Session).unwrap();
        let ApprovalOutcome::Approved(t) = h.join().unwrap() else {
            panic!()
        };
        // Same request: no prompt, same grant, reusable.
        assert_eq!(
            a.ask(&req("same"), Duration::from_millis(50)),
            ApprovalOutcome::Approved(t.clone())
        );
        assert_eq!(a.verify(&t, &Binding::of(&req("same"))), Ok(Scope::Session));
        assert_eq!(a.verify(&t, &Binding::of(&req("same"))), Ok(Scope::Session));
        assert_eq!(auth.reasons().len(), 1);
        // Different argument: asks (and times out here).
        assert_eq!(
            a.ask(&req("other"), Duration::from_millis(50)),
            ApprovalOutcome::TimedOut
        );
        let mut other_session = req("same");
        other_session.session.pid = 8;
        assert_eq!(
            a.ask(&other_session, Duration::from_millis(50)),
            ApprovalOutcome::TimedOut
        );
        a.revoke_all().unwrap();
        assert!(a.verify(&t, &Binding::of(&req("same"))).is_err());
        assert_eq!(
            a.ask(&req("same"), Duration::from_millis(50)),
            ApprovalOutcome::TimedOut
        );
    }

    // protects=review R1: ms stop while Touch ID is up wins: the waiting request is denied, the
    // late Touch ID approves nothing and leaves no session grant; fails_when=a token or grant is
    // issued after revoke_all; no_claim=-
    #[test]
    fn stop_during_touch_id_approves_nothing() {
        let (a, _) = approver(FakeAuthenticator::approve().after(Duration::from_millis(300)));
        let (h, p) = ask_bg(&a, req("x"), Duration::from_secs(10));
        let a2 = a.clone();
        let id = p.id.clone();
        let decider = std::thread::spawn(move || a2.decide(&id, true, Scope::Session));
        std::thread::sleep(Duration::from_millis(100));
        a.revoke_all().unwrap();
        assert_eq!(decider.join().unwrap(), Err(DecideError::Ended));
        assert_eq!(h.join().unwrap(), ApprovalOutcome::Denied);
        assert_eq!(
            a.ask(&req("x"), Duration::from_millis(50)),
            ApprovalOutcome::TimedOut,
            "no session grant survived"
        );
    }

    // protects=ms stop while a request waits denies it at once; fails_when=it stays approvable;
    // no_claim=-
    #[test]
    fn revoke_denies_the_waiting_request() {
        let (a, _) = approver(FakeAuthenticator::approve());
        let (h, p) = ask_bg(&a, req("x"), Duration::from_secs(10));
        a.revoke_all().unwrap();
        assert_eq!(h.join().unwrap(), ApprovalOutcome::Denied);
        assert!(a.decide(&p.id, true, Scope::Once).is_err());
    }
}
