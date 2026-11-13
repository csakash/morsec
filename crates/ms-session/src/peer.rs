//! Unix-socket peers: kernel peer PID → [`Caller`], and a [`PeerCheck`] for the daemon.

use ms_core::Result;
use ms_ipc::{PeerCheck, PeerInfo};

use crate::error::SessionError;
use crate::table::{OsProcessTable, ProcessTable};
use crate::walk::{Caller, Resolver};

/// Resolves a Unix-socket peer. The PID comes from the kernel (`LOCAL_PEERPID` /
/// `SO_PEERCRED`), never from the client. The process's current uid must still be the uid the
/// kernel reported at connect, otherwise the PID was reused and the peer is refused.
pub fn resolve_peer<T: ProcessTable>(
    resolver: &Resolver<T>,
    peer: &PeerInfo,
) -> std::result::Result<Caller, SessionError> {
    let pid = peer
        .pid
        .and_then(|p| u32::try_from(p).ok())
        .filter(|&p| p > 0)
        .ok_or(SessionError::NoPeerPid)?;
    let info = resolver.info(pid)?;
    if info.uid != peer.uid {
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

    /// The caller behind `peer`, after the same checks as [`PeerCheck::check`].
    pub fn caller(&self, peer: &PeerInfo) -> std::result::Result<Caller, SessionError> {
        if peer.uid != self.uid {
            return Err(SessionError::WrongUser { uid: peer.uid });
        }
        resolve_peer(&self.resolver, peer)
    }
}

impl<T: ProcessTable + 'static> PeerCheck for SessionPeerCheck<T> {
    fn check(&self, peer: &PeerInfo) -> Result<()> {
        self.caller(peer).map(|_| ()).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::fake::FakeTable;

    fn peer(uid: u32, pid: Option<i32>) -> PeerInfo {
        PeerInfo { uid, gid: 20, pid }
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
            c.caller(&peer(501, Some(11)))
                .unwrap()
                .session()
                .unwrap()
                .pid,
            10
        );
        assert!(matches!(
            c.caller(&peer(502, Some(11))),
            Err(SessionError::WrongUser { uid: 502 })
        ));
        assert!(matches!(
            c.caller(&peer(501, None)),
            Err(SessionError::NoPeerPid)
        ));
        assert!(matches!(
            c.caller(&peer(501, Some(-1))),
            Err(SessionError::NoPeerPid)
        ));
        assert!(matches!(
            c.caller(&peer(501, Some(999))),
            Err(SessionError::Unreadable { pid: 999, .. })
        ));
        let e = c.check(&peer(501, Some(999))).unwrap_err();
        assert!(matches!(e, ms_core::Error::PeerRejected(_)));
    }

    // protects=uid re-check catches PID reuse by another user; fails_when=a reused pid owned by
    // a different uid is resolved; no_claim=same-uid reuse (start time handles that downstream)
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
            c.caller(&peer(501, Some(11))),
            Err(SessionError::PidChanged { pid: 11 })
        ));
    }
}
