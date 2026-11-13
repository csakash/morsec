//! What the proxy needs from the rest of `msd`. L07 plugs in the real ones (L01 vault, L02
//! receipts, L03 policy, L06 sessions, L11 approvals); tests use the fakes from each crate.

use std::net::SocketAddr;
use std::sync::Arc;

use ms_approve::Approver;
use ms_core::{Decision, Request, SessionId};
use ms_receipts::ReceiptSink;
use ms_vault::Vault;

use crate::ca::Ca;
use crate::ssrf::{Resolve, SystemResolver};

/// Policy as the proxy sees it. L07 implements it with `ms_rules::decide` over the live rules.
pub trait Policy: Send + Sync + std::fmt::Debug {
    /// Decides one swap.
    fn decide(&self, session: &SessionId, request: &Request) -> Decision;
    /// Version of the rules in force, recorded in receipts.
    fn version(&self) -> u64;
}

/// Maps an agent connection to its session. L06 does this by loopback source port → PID, with
/// the per-connector proxy username as a cross-check. `None` refuses the connection.
pub trait SessionResolver: Send + Sync + std::fmt::Debug {
    /// The session behind `peer`, if known.
    fn resolve(&self, peer: SocketAddr, proxy_user: Option<&str>) -> Option<SessionId>;
}

/// Why a connection or request was refused without a key in sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockKind {
    /// Not bound and not on the allowlist.
    NotAllowed,
    /// The SSRF guard refused every address.
    NonPublicAddress,
    /// No session for the peer.
    NoSession,
    /// The request was malformed or broke a proxy rule (e.g. SNI mismatch).
    Protocol,
}

/// A refusal that has no key, so it can't be a receipt. Never holds a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEvent {
    /// Who, when known.
    pub session: Option<SessionId>,
    /// Destination host as the agent named it (escaped, truncated).
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Why.
    pub kind: BlockKind,
}

/// Where key-less refusals go. L07 records them; the default logs them.
pub trait EgressObserver: Send + Sync + std::fmt::Debug {
    /// A refusal happened.
    fn blocked(&self, event: &BlockEvent);
}

/// Logs refusals with `tracing` at `warn`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogObserver;

impl EgressObserver for LogObserver {
    fn blocked(&self, e: &BlockEvent) {
        tracing::warn!(host = %e.host, port = e.port, kind = ?e.kind, "morsec proxy refused a destination");
    }
}

/// Everything injected into the proxy.
#[derive(Clone)]
pub struct Deps {
    /// Where values live.
    pub vault: Arc<dyn Vault>,
    /// Decides each swap.
    pub policy: Arc<dyn Policy>,
    /// Where receipts go. A swap whose receipt can't be written is not sent.
    pub receipts: Arc<dyn ReceiptSink>,
    /// Asks a person for production keys. `None` refuses anything that needs approval.
    pub approver: Option<Arc<dyn Approver>>,
    /// Who is calling.
    pub sessions: Arc<dyn SessionResolver>,
    /// Key-less refusals.
    pub egress: Arc<dyn EgressObserver>,
    /// DNS.
    pub resolver: Arc<dyn Resolve>,
    /// The morsec CA.
    pub ca: Arc<Ca>,
}

impl std::fmt::Debug for Deps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deps")
            .field("policy", &self.policy)
            .field("approver", &self.approver.is_some())
            .field("ca", &self.ca)
            .finish_non_exhaustive()
    }
}

impl Deps {
    /// Deps with the system resolver and the logging observer.
    pub fn new(
        vault: Arc<dyn Vault>,
        policy: Arc<dyn Policy>,
        receipts: Arc<dyn ReceiptSink>,
        sessions: Arc<dyn SessionResolver>,
        ca: Arc<Ca>,
    ) -> Self {
        Self {
            vault,
            policy,
            receipts,
            approver: None,
            sessions,
            egress: Arc::new(LogObserver),
            resolver: Arc::new(SystemResolver),
            ca,
        }
    }
}
