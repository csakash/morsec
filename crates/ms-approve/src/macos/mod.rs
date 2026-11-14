//! Touch ID through LocalAuthentication, raised by msd itself (SPEC D-1, D-10).
//!
//! msd runs as a LaunchAgent in the user's GUI session, so `LAContext.evaluatePolicy` puts the
//! system sheet on screen with msd's own `localizedReason`. No other process can complete it on
//! msd's behalf: it needs the enrolled finger, or the login password typed into the system sheet.
//!
//! Biometrics first (`.deviceOwnerAuthenticationWithBiometrics`); when the person picks "Use
//! Password", or biometry is missing, not enrolled or locked out, the password policy
//! (`.deviceOwnerAuthentication`). At the deadline the context is invalidated, which takes the
//! sheet down; a late reply is ignored.

use std::sync::mpsc;
use std::time::Instant;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};

use crate::auth::{AuthOutcome, Authenticator};

/// The real authenticator.
#[derive(Debug, Default, Clone, Copy)]
pub struct TouchId;

enum Eval {
    Ok,
    Err(isize),
    Timeout,
}

fn evaluate(policy: LAPolicy, reason: &str, deadline: Instant) -> Eval {
    let (tx, rx) = mpsc::sync_channel::<Option<isize>>(1);
    // SAFETY: `+[LAContext new]` has no preconditions and returns an owned, retained object.
    #[allow(unsafe_code)]
    let ctx = unsafe { LAContext::new() };
    let reason = NSString::from_str(reason);
    let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        let code = if ok.as_bool() {
            None
        } else if err.is_null() {
            Some(LAError::AuthenticationFailed.0)
        } else {
            // SAFETY: LocalAuthentication passes a valid NSError (or nil, handled above) that
            // lives for the duration of the reply.
            #[allow(unsafe_code)]
            let code = unsafe { (*err).code() };
            Some(code)
        };
        // A second reply (or one after we stopped waiting) has nowhere to go; that is fine.
        let _ = tx.try_send(code);
    });
    // SAFETY: `ctx`, `reason` and `reply` are valid, retained objects; the framework copies the
    // block and calls it once, on its own queue. `policy` is one of the two documented values.
    #[allow(unsafe_code)]
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &reply)
    };
    let wait = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(wait) {
        Ok(None) => Eval::Ok,
        Ok(Some(code)) => Eval::Err(code),
        Err(_) => {
            // SAFETY: `invalidate` may be called at any time on a live context; it cancels the
            // pending evaluation (its reply then reports AppCancel, which nobody reads).
            #[allow(unsafe_code)]
            unsafe {
                ctx.invalidate()
            };
            Eval::Timeout
        }
    }
}

fn describe(code: isize) -> String {
    let what = match LAError(code) {
        LAError::AuthenticationFailed => "authentication failed",
        LAError::UserCancel => "cancelled",
        LAError::SystemCancel => "cancelled by the system",
        LAError::AppCancel => "cancelled by morsec",
        LAError::UserFallback => "password not chosen",
        LAError::BiometryNotAvailable => "biometry not available",
        LAError::BiometryNotEnrolled => "no finger enrolled",
        LAError::BiometryLockout => "Touch ID locked out",
        LAError::PasscodeNotSet => "no login password set",
        LAError::NotInteractive => "no GUI session to show the sheet in",
        _ => "refused",
    };
    format!("{what} (LAError {code})")
}

impl Authenticator for TouchId {
    fn authenticate(&self, reason: &str, deadline: Instant) -> AuthOutcome {
        match evaluate(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            reason,
            deadline,
        ) {
            Eval::Ok => AuthOutcome::Approved,
            Eval::Timeout => AuthOutcome::TimedOut,
            Eval::Err(code)
                if [
                    LAError::UserFallback,
                    LAError::BiometryNotAvailable,
                    LAError::BiometryNotEnrolled,
                    LAError::BiometryLockout,
                ]
                .contains(&LAError(code)) =>
            {
                match evaluate(LAPolicy::DeviceOwnerAuthentication, reason, deadline) {
                    Eval::Ok => AuthOutcome::Approved,
                    Eval::Timeout => AuthOutcome::TimedOut,
                    Eval::Err(code) if LAError(code) == LAError::NotInteractive => {
                        AuthOutcome::Unavailable(describe(code))
                    }
                    Eval::Err(code) => AuthOutcome::Denied(describe(code)),
                }
            }
            Eval::Err(code) if LAError(code) == LAError::NotInteractive => {
                AuthOutcome::Unavailable(describe(code))
            }
            Eval::Err(code) => AuthOutcome::Denied(describe(code)),
        }
    }
}
