//! Unix-socket peers: kernel peer PID → [`Caller`], and a [`PeerCheck`] for the daemon.

use ms_core::Result;
use ms_ipc::{PeerCheck, PeerInfo};

use crate::error::SessionError;
use crate::table::{OsProcessTable, ProcessTable};
use crate::walk::{Caller, Resolver};

/// Resolves a Unix-socket peer. The PID comes from the kernel (`LOCAL_PEERPID` /
/// `SO_PEERCRED`), never from the client. The PID is refused as reused if the process now has
/// a different uid from the one the kernel reported, or started after `accepted_unix_ms` (when
/// the daemon accepted the connection).
///
/// Residual risk: a same-uid process that reuses the PID *before* the connection was accepted
/// passes both checks. Closing that needs the audit token's PID version (macOS) or a pidfd
/// (Linux), which ms-ipc does not expose in IPC v1.
pub fn resolve_peer<T: ProcessTable>(
    resolver: &Resolver<T>,
    peer: &PeerInfo,
    accepted_unix_ms: u64,
) -> std::result::Result<Caller, SessionError> {
    let pid = peer
        .pid
        .and_then(|p| u32::try_from(p).ok())
        .filter(|&p| p > 0)
        .ok_or(SessionError::NoPeerPid)?;
    let info = resolver.info(pid)?;
    if info.uid != peer.uid || info.started_unix_ms > accepted_unix_ms {
        return Err(SessionError::PidChanged { pid });
    }
    resolver.resolve_from(info)
}

/// Accepts a peer only if it runs as the daemon's user and its session can be identified.
/// A drop-in replacement for [`ms_ipc::SameUid`].
#[derive(Debug, Clone)]
pub struct SessionPeerCheck<T = OsProcessTable> {
    uid: u32,
    resolver: Resolver<T>,
}

impl SessionPeerCheck<OsProcessTable> {
    /// A check for the daemon running as `uid`, over the live process table.
    pub fn new(uid: u32) -> Self {
        Self::with_table(uid, OsProcessTable)
    }
}

impl<T: ProcessTable> SessionPeerCheck<T> {
    /// A check over a given process table (tests).
    pub fn with_table(uid: u32, table: T) -> Self {
        Self {
            uid,
            resolver: Resolver::new(table),
        }
    }

    /// The caller behind `peer`, for a connection accepted at `accepted_unix_ms`. Handlers
    /// should record the accept time and pass it here.
    pub fn caller(
        &self,
        peer: &PeerInfo,
        accepted_unix_ms: u64,
    ) -> std::result::Result<Caller, SessionError> {
        if peer.uid != self.uid {
            return Err(SessionError::WrongUser { uid: peer.uid });
        }
        resolve_peer(&self.resolver, peer, accepted_unix_ms)
    }
}

impl<T: ProcessTable + 'static> PeerCheck for SessionPeerCheck<T> {
    fn check(&self, peer: &PeerInfo) -> Result<()> {
        // `check` runs right after accept, so now is the accept time.
        self.caller(peer, now_unix_ms())
            .map(|_| ())
            .map_err(Into::into)
    }
}

/// Wall-clock now, Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::fake::FakeTable;

    fn peer(uid: u32, pid: Option<i32>) -> PeerInfo {
        PeerInfo { uid, gid: 20, pid }
    }

    impl SessionPeerCheck<FakeTable> {
        fn caller2(&self, p: &PeerInfo) -> std::result::Result<Caller, SessionError> {
            self.caller(p, 1_000)
        }
    }

    fn check() -> SessionPeerCheck<FakeTable> {
        let t = FakeTable::with(&[
            (1, 0, 1, "launchd"),
            (10, 1, 5, "claude"),
            (11, 10, 6, "ms"),
        ]);
        SessionPeerCheck::with_table(501, t)
    }

    // protects=AUTH-1 peer check; fails_when=a wrong uid, missing pid, dead pid or reused pid
    // is accepted; no_claim=live kernel peer credentials (ms-ipc tests those)
    #[test]
    fn peer_check_cases() {
        let c = check();
        assert!(c.check(&peer(501, Some(11))).is_ok());
        assert_eq!(
            c.caller2(&peer(501, Some(11)))
                .unwrap()
                .session()
                .unwrap()
                .pid,
            10
        );
        assert!(matches!(
            c.caller2(&peer(502, Some(11))),
            Err(SessionError::WrongUser { uid: 502 })
        ));
        assert!(matches!(
            c.caller2(&peer(501, None)),
            Err(SessionError::NoPeerPid)
        ));
        assert!(matches!(
            c.caller2(&peer(501, Some(-1))),
            Err(SessionError::NoPeerPid)
        ));
        assert!(matches!(
            c.caller2(&peer(501, Some(999))),
            Err(SessionError::Unreadable { pid: 999, .. })
        ));
        let e = c.check(&peer(501, Some(999))).unwrap_err();
        assert!(matches!(e, ms_core::Error::PeerRejected(_)));
    }

    // protects=uid re-check catches PID reuse by another user; fails_when=a reused pid owned by
    // a different uid is resolved; no_claim=same-uid reuse (start time handles that downstream)
    // protects=same-uid PID reuse after accept; fails_when=a process that started after the
    // connection was accepted is resolved as the peer; no_claim=reuse before accept
    #[test]
    fn started_after_accept_is_refused() {
        let c = check(); // pid 11 started at 6
        assert!(c.caller(&peer(501, Some(11)), 6).is_ok());
        assert!(c.caller(&peer(501, Some(11)), 7).is_ok());
        assert!(matches!(
            c.caller(&peer(501, Some(11)), 5),
            Err(SessionError::PidChanged { pid: 11 })
        ));
    }

    #[test]
    fn uid_changed_since_connect_is_refused() {
        let c = check();
        c.resolver
            .table()
            .0
            .lock()
            .unwrap()
            .get_mut(&11)
            .unwrap()
            .uid = 0;
        assert!(matches!(
            c.caller2(&peer(501, Some(11))),
            Err(SessionError::PidChanged { pid: 11 })
        ));
    }
}
