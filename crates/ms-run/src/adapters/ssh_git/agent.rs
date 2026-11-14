//! The SSH agent protocol, restricted to pinned destinations (SPEC D4).
//!
//! One [`AgentConn`] per agent connection. It serves only:
//!
//! - `REQUEST_IDENTITIES`: the one key, read from the vault for the answer.
//! - the `session-bind@openssh.com` extension (OpenSSH 8.9+): the server's host key, the SSH
//!   session id and the host's signature over it. The host key must be pinned in the key's rule,
//!   the signature must verify, and the connection must not be a forwarded one. One bind per
//!   connection; anything else poisons the connection.
//! - `SIGN_REQUEST`: only on a bound connection, only for a `publickey` user-auth request for
//!   that session id and this key (and, host-bound, that host key). The key is read from the
//!   vault for the signature and dropped right after. Every sign request is recorded through
//!   [`Audit`] before anything is signed; if recording fails, nothing is signed.
//!
//! Everything else (adding or removing keys, locking, other extensions) answers failure.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ms_core::KeyName;
use ms_vault::{Vault, VaultExt};

use super::key::{self, ED25519_NAME, PrivateKey};
use super::wire::{Reader, put_string, put_u32};
use super::{Action, Audit, AuditEvent, HostPin};

pub(crate) const FAILURE: u8 = 5;
pub(crate) const SUCCESS: u8 = 6;
pub(crate) const REQUEST_IDENTITIES: u8 = 11;
pub(crate) const IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SIGN_REQUEST: u8 = 13;
pub(crate) const SIGN_RESPONSE: u8 = 14;
pub(crate) const EXTENSION: u8 = 27;
const USERAUTH_REQUEST: u8 = 50;
pub(crate) const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
const HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
/// Most sign requests answered in one run.
pub const MAX_SIGNS: usize = 16;
/// Longest SSH session id accepted (SHA-512 output is 64 bytes).
const MAX_SESSION_ID: usize = 64;

/// What every connection of one run's agent shares.
pub(crate) struct AgentCtx {
    pub(crate) key: KeyName,
    pub(crate) pins: Vec<HostPin>,
    pub(crate) vault: Arc<dyn Vault>,
    pub(crate) audit: Arc<dyn Audit>,
    pub(crate) signs: AtomicUsize,
}

impl std::fmt::Debug for AgentCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCtx")
            .field("key", &self.key)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bind {
    None,
    Bound { pin: usize, session_id: Vec<u8> },
    Refused(&'static str),
}

/// One agent connection's state.
#[derive(Debug)]
pub(crate) struct AgentConn {
    bind: Bind,
}

fn failure() -> Vec<u8> {
    vec![FAILURE]
}

impl AgentConn {
    pub(crate) fn new() -> Self {
        Self { bind: Bind::None }
    }

    /// Answers one message (type byte and body); returns the reply's type byte and body.
    pub(crate) fn handle(&mut self, ctx: &AgentCtx, msg: &[u8]) -> Vec<u8> {
        let Some((&kind, body)) = msg.split_first() else {
            return failure();
        };
        match kind {
            REQUEST_IDENTITIES => identities(ctx),
            EXTENSION => self.extension(ctx, body),
            SIGN_REQUEST => self.sign(ctx, body),
            _ => failure(),
        }
    }

    fn extension(&mut self, ctx: &AgentCtx, body: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(body);
        if r.string() != Some(SESSION_BIND) {
            return failure();
        }
        if self.bind != Bind::None {
            self.bind = Bind::Refused("the connection was bound twice");
            return failure();
        }
        match check_bind(ctx, &mut r) {
            Ok(b) => {
                self.bind = b;
                vec![SUCCESS]
            }
            Err(why) => {
                self.bind = Bind::Refused(why);
                failure()
            }
        }
    }

    fn sign(&mut self, ctx: &AgentCtx, body: &[u8]) -> Vec<u8> {
        let n = ctx.signs.fetch_add(1, Ordering::SeqCst) + 1;
        if n > MAX_SIGNS + 1 {
            // The limit was recorded once (below); later requests are refused unrecorded so a
            // looping client can't flood the receipts.
            return failure();
        }
        let host = match &self.bind {
            Bind::Bound { pin, .. } => ctx.pins[*pin].host_field(),
            _ => "an unbound connection".to_owned(),
        };
        let refuse = |why: &str| {
            let event = AuditEvent {
                key: ctx.key.clone(),
                action: Action::Sign { host: host.clone() },
                refused: Some(why.to_owned()),
            };
            if let Err(e) = ctx.audit.record(&event) {
                tracing::error!(error = %e, "could not record a refused SSH signature");
            }
            failure()
        };
        if n > MAX_SIGNS {
            return refuse("more than 16 signatures in one run");
        }
        if ctx.audit.stopped() {
            return refuse("morsec is stopped (ms stop) or this agent session was stopped");
        }
        let (pin, session_id) = match &self.bind {
            Bind::Bound { pin, session_id } => (*pin, session_id.clone()),
            Bind::None => {
                return refuse(
                    "the client did not bind the connection to a host (session-bind@openssh.com, OpenSSH 8.9 or later)",
                );
            }
            Bind::Refused(why) => return refuse(why),
        };
        let mut r = Reader::new(body);
        let (Some(blob), Some(data), Some(_flags)) = (r.string(), r.string(), r.u32()) else {
            return refuse("a malformed sign request");
        };
        if !r.is_empty() {
            return refuse("a malformed sign request");
        }
        let loaded = ctx.vault.read_with(&ctx.key, PrivateKey::from_openssh);
        let k = match loaded {
            Ok(Ok(k)) => k,
            Ok(Err(why)) => return refuse(why),
            Err(e) => {
                tracing::error!(error = %e, "could not read the SSH key");
                return refuse("the key could not be read from the vault");
            }
        };
        if blob != k.public_blob() {
            return refuse("the sign request names another key");
        }
        if let Err(why) = check_userauth(data, &session_id, &k.public_blob(), &ctx.pins[pin]) {
            return refuse(why);
        }
        let event = AuditEvent {
            key: ctx.key.clone(),
            action: Action::Sign { host },
            refused: None,
        };
        if let Err(e) = ctx.audit.record(&event) {
            tracing::error!(error = %e, "could not record an SSH signature, so it was refused");
            return failure();
        }
        // The key is dropped here, before the reply goes out.
        let sig = { k }.sign(data);
        let mut out = vec![SIGN_RESPONSE];
        put_string(&mut out, &sig);
        out
    }
}

fn identities(ctx: &AgentCtx) -> Vec<u8> {
    let public = ctx.vault.read_with(&ctx.key, |v| {
        PrivateKey::from_openssh(v).map(|k| k.public())
    });
    let mut out = vec![IDENTITIES_ANSWER];
    match public {
        Ok(Ok(p)) => {
            put_u32(&mut out, 1);
            put_string(&mut out, &key::public_blob(&p));
            put_string(&mut out, format!("morsec:{}", ctx.key).as_bytes());
        }
        _ => put_u32(&mut out, 0),
    }
    out
}

fn check_bind(ctx: &AgentCtx, r: &mut Reader<'_>) -> Result<Bind, &'static str> {
    const MALFORMED: &str = "a malformed session-bind";
    let host_blob = r.string().ok_or(MALFORMED)?;
    let session_id = r.string().ok_or(MALFORMED)?;
    let sig = r.string().ok_or(MALFORMED)?;
    let forwarding = r.bool().ok_or(MALFORMED)?;
    if !r.is_empty() || session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return Err(MALFORMED);
    }
    if forwarding {
        return Err(
            "the connection was forwarded to another host (ssh -A), which morsec never signs for",
        );
    }
    let host_key = key::public_from_blob(host_blob)
        .ok_or("the host's key is not an ssh-ed25519 key pinned in the key's rule")?;
    let pin = ctx.pins.iter().position(|p| p.key == host_key).ok_or(
        "the host's key is not pinned in the key's rule (ms rules <key> --add-ssh-host-key)",
    )?;
    if !key::verify(&host_key, session_id, sig) {
        return Err("the host's session-bind signature does not verify");
    }
    Ok(Bind::Bound {
        pin,
        session_id: session_id.to_vec(),
    })
}

/// `data` must be an SSH `publickey` user-auth request (RFC 4252 §7, or OpenSSH's host-bound
/// form) for `session_id`, signed with `our_blob`, and, host-bound, for `pin`'s host key.
fn check_userauth(
    data: &[u8],
    session_id: &[u8],
    our_blob: &[u8],
    pin: &HostPin,
) -> Result<(), &'static str> {
    const NOT_AUTH: &str = "the data to sign is not an SSH login for the bound host";
    let mut r = Reader::new(data);
    if r.string() != Some(session_id) {
        return Err("the data to sign belongs to another SSH session than the bound one");
    }
    if r.u8() != Some(USERAUTH_REQUEST) {
        return Err(NOT_AUTH);
    }
    let _user = r.string().ok_or(NOT_AUTH)?;
    if r.string() != Some(&b"ssh-connection"[..]) {
        return Err(NOT_AUTH);
    }
    let method = r.string().ok_or(NOT_AUTH)?;
    let hostbound = match method {
        b"publickey" => false,
        HOSTBOUND => true,
        _ => return Err(NOT_AUTH),
    };
    if r.bool() != Some(true) || r.string() != Some(ED25519_NAME) || r.string() != Some(our_blob) {
        return Err(NOT_AUTH);
    }
    if hostbound && r.string() != Some(&key::public_blob(&pin.key)[..]) {
        return Err(NOT_AUTH);
    }
    if !r.is_empty() {
        return Err(NOT_AUTH);
    }
    Ok(())
}

/// Test helpers that build what an OpenSSH client sends.
#[cfg(test)]
pub(crate) mod client {
    use super::*;

    pub(crate) fn bind(host_seed: &[u8; 32], session_id: &[u8], forwarding: bool) -> Vec<u8> {
        let host = key::testkey::public_of(host_seed);
        let mut m = vec![EXTENSION];
        put_string(&mut m, SESSION_BIND);
        put_string(&mut m, &key::public_blob(&host));
        put_string(&mut m, session_id);
        put_string(&mut m, &key::testkey::sign_with(host_seed, session_id));
        m.push(u8::from(forwarding));
        m
    }

    pub(crate) fn userauth(
        session_id: &[u8],
        user_blob: &[u8],
        host: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut d = Vec::new();
        put_string(&mut d, session_id);
        d.push(USERAUTH_REQUEST);
        put_string(&mut d, b"git");
        put_string(&mut d, b"ssh-connection");
        put_string(
            &mut d,
            if host.is_some() {
                HOSTBOUND
            } else {
                b"publickey"
            },
        );
        d.push(1);
        put_string(&mut d, ED25519_NAME);
        put_string(&mut d, user_blob);
        if let Some(h) = host {
            put_string(&mut d, &key::public_blob(h));
        }
        d
    }

    pub(crate) fn sign(user_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![SIGN_REQUEST];
        put_string(&mut m, user_blob);
        put_string(&mut m, data);
        put_u32(&mut m, 0);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::client::*;
    use super::*;
    use crate::adapters::ssh_git::tests_support::{FakeAudit, vault_with};

    const USER: [u8; 32] = [1; 32];
    const HOST: [u8; 32] = [2; 32];
    const OTHER_HOST: [u8; 32] = [3; 32];
    const SID: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn ctx() -> (AgentCtx, Arc<FakeAudit>) {
        let audit = Arc::new(FakeAudit::default());
        let (vault, key) = vault_with(&key::testkey::openssh(&USER));
        (
            AgentCtx {
                key,
                pins: vec![HostPin {
                    host: "127.0.0.1".into(),
                    port: 4422,
                    key: key::testkey::public_of(&HOST),
                }],
                vault,
                audit: audit.clone(),
                signs: AtomicUsize::new(0),
            },
            audit,
        )
    }

    fn user_blob() -> Vec<u8> {
        key::public_blob(&key::testkey::public_of(&USER))
    }

    fn signs_ok(conn: &mut AgentConn, c: &AgentCtx, data: &[u8]) -> bool {
        let r = conn.handle(c, &sign(&user_blob(), data));
        if r[0] != SIGN_RESPONSE {
            assert_eq!(r, [FAILURE]);
            return false;
        }
        let mut rd = Reader::new(&r[1..]);
        let sig = rd.string().unwrap();
        assert!(key::verify(&key::testkey::public_of(&USER), data, sig));
        true
    }

    // protects=SPEC D4 / Verify 1: a sign request is answered only on a connection bound to a
    // pinned host key, for a login to that session with this key; an unpinned host, a missing
    // bind, a forwarded bind, a bad bind signature, a second bind, another session id, another
    // key, a non-login payload and a stopped morsec are each refused, and every request is
    // recorded (refusals with the reason); fails_when=any of those gets a signature, or a request
    // goes unrecorded; no_claim=a real ssh client (tests/ssh_git.rs)
    #[test]
    fn signs_only_for_pinned_bound_logins() {
        let (c, audit) = ctx();

        // Identities: the public key only.
        let mut conn = AgentConn::new();
        let ids = conn.handle(&c, &[REQUEST_IDENTITIES]);
        assert_eq!(ids[0], IDENTITIES_ANSWER);
        let mut rd = Reader::new(&ids[1..]);
        assert_eq!(rd.u32(), Some(1));
        assert_eq!(rd.string(), Some(&user_blob()[..]));

        // No bind: refused.
        let data = userauth(SID, &user_blob(), None);
        assert!(!signs_ok(&mut conn, &c, &data));

        // Bound to the pinned host: plain and host-bound logins are signed.
        let mut conn = AgentConn::new();
        assert_eq!(conn.handle(&c, &bind(&HOST, SID, false)), [SUCCESS]);
        assert!(signs_ok(&mut conn, &c, &data));
        let hb = userauth(SID, &user_blob(), Some(&key::testkey::public_of(&HOST)));
        assert!(signs_ok(&mut conn, &c, &hb));
        // Host-bound for another host key, another session, another key, junk: refused.
        let wrong_host = userauth(
            SID,
            &user_blob(),
            Some(&key::testkey::public_of(&OTHER_HOST)),
        );
        assert!(!signs_ok(&mut conn, &c, &wrong_host));
        assert!(!signs_ok(
            &mut conn,
            &c,
            &userauth(b"another-session", &user_blob(), None)
        ));
        let other_user = key::public_blob(&key::testkey::public_of(&[9; 32]));
        assert_eq!(
            conn.handle(&c, &sign(&other_user, &userauth(SID, &other_user, None))),
            [FAILURE]
        );
        assert!(!signs_ok(&mut conn, &c, b"just some bytes to sign"));
        let mut trailing = data.clone();
        trailing.push(0);
        assert!(!signs_ok(&mut conn, &c, &trailing));
        // A second bind poisons the connection.
        assert_eq!(conn.handle(&c, &bind(&HOST, SID, false)), [FAILURE]);
        assert!(!signs_ok(&mut conn, &c, &data));

        // Unpinned host, forwarded, bad signature: refused, and the connection stays refused.
        for m in [bind(&OTHER_HOST, SID, false), bind(&HOST, SID, true), {
            let mut m = bind(&HOST, SID, false);
            let n = m.len();
            m[n - 2] ^= 1;
            m
        }] {
            let mut conn = AgentConn::new();
            assert_eq!(conn.handle(&c, &m), [FAILURE]);
            assert!(!signs_ok(&mut conn, &c, &data));
        }

        // Stopped: refused even when bound.
        let mut conn = AgentConn::new();
        assert_eq!(conn.handle(&c, &bind(&HOST, SID, false)), [SUCCESS]);
        audit.stop();
        assert!(!signs_ok(&mut conn, &c, &data));

        let events = audit.events();
        let allowed = events.iter().filter(|e| e.refused.is_none()).count();
        assert_eq!(allowed, 2, "{events:?}");
        assert_eq!(events.len(), 13, "{events:?}");
        assert!(events.iter().any(|e| {
            e.refused
                .as_deref()
                .is_some_and(|r| r.contains("not pinned"))
        }));
        assert!(events.iter().any(|e| {
            e.refused
                .as_deref()
                .is_some_and(|r| r.contains("forwarded"))
        }));
    }

    // protects=SPEC D8: a signature whose receipt can't be written is refused; other messages
    // (add identity, remove all, lock, other extensions) fail; the sign count is capped and the
    // cap itself is recorded once; fails_when=a signature leaves without a receipt or the agent
    // accepts keys; no_claim=-
    #[test]
    fn receipts_first_and_bounded() {
        let (c, audit) = ctx();
        let data = userauth(SID, &user_blob(), None);
        let mut conn = AgentConn::new();
        assert_eq!(conn.handle(&c, &bind(&HOST, SID, false)), [SUCCESS]);
        audit.fail_writes();
        assert!(!signs_ok(&mut conn, &c, &data));
        audit.allow_writes();
        for kind in [17u8, 19, 22, 25, 0, 255] {
            assert_eq!(conn.handle(&c, &[kind]), [FAILURE]);
        }
        let mut other_ext = vec![EXTENSION];
        put_string(&mut other_ext, b"query");
        assert_eq!(conn.handle(&c, &other_ext), [FAILURE]);
        assert_eq!(conn.handle(&c, &[]), [FAILURE]);
        let mut ok = 0;
        for _ in 0..40 {
            if signs_ok(&mut conn, &c, &data) {
                ok += 1;
            }
        }
        assert_eq!(ok, MAX_SIGNS - 1);
        // 15 signatures, then one receipt for the limit; later requests go unrecorded.
        let events = audit.events();
        assert_eq!(events.len(), MAX_SIGNS, "{events:?}");
        assert!(
            events
                .last()
                .unwrap()
                .refused
                .as_deref()
                .unwrap()
                .contains("more than")
        );
    }
}
