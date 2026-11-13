//! Loopback TCP source port → owning process → [`Caller`], for proxy clients.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::SessionError;
use crate::table::{ProcessTable, SocketTable};
use crate::walk::{Caller, Resolver};

/// How long a `(source port, proxy port) → PID` answer is kept. Every use re-checks it.
pub const CACHE_TTL: Duration = Duration::from_secs(30);
/// Recent owners probed before a full scan.
pub const RECENT_OWNERS: usize = 32;
/// Most cache entries kept.
const MAX_CACHE: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    pid: u32,
    started_unix_ms: u64,
    at: Instant,
}

#[derive(Debug, Default)]
struct State {
    cache: HashMap<(u16, u16), Entry>,
    recent: VecDeque<u32>,
}

/// Finds which process is on the client end of a proxy connection and resolves its session.
///
/// Lookup order: the cached owner for this port pair, then recently seen owners (agents open
/// many connections), then a scan of every process. Any candidate must be shown, live, to hold
/// a socket with `local = loopback:src_port` and `remote = loopback:proxy_port`, and still have
/// the start time it had when cached, so a stale cache entry or a reused PID can't answer.
/// The daemon's own accepted socket has those ports the other way round, so it never matches.
///
/// A socket held by processes in different sessions is refused when the full scan sees it.
/// The cached and recent-owner paths return the first verified holder: a socket only reaches a
/// second process by inheritance (same session) or by the holder passing it on, so this can't
/// pull another session's identity onto a connection without that session's cooperation.
#[derive(Debug)]
pub struct PortResolver<S, T> {
    sockets: S,
    resolver: Resolver<T>,
    state: Mutex<State>,
}

impl<S: SocketTable, T: ProcessTable> PortResolver<S, T> {
    /// A resolver over the given socket and process tables.
    pub fn new(sockets: S, table: T) -> Self {
        Self {
            sockets,
            resolver: Resolver::new(table),
            state: Mutex::new(State::default()),
        }
    }

    /// The process-tree resolver used after the owner is found.
    pub fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock leaves only cache data behind; every entry is
        // re-verified before use, so recovering it is safe.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn verified(
        &self,
        pid: u32,
        started: Option<u64>,
        src: u16,
        proxy: u16,
    ) -> Option<(Caller, u64)> {
        if !matches!(self.sockets.holds(pid, src, proxy), Ok(true)) {
            return None;
        }
        let info = self.resolver.info(pid).ok()?;
        if started.is_some_and(|s| s != info.started_unix_ms) {
            return None;
        }
        // Re-check after reading the process, so the socket and the start time both belong to
        // the same incarnation of `pid`.
        if !matches!(self.sockets.holds(pid, src, proxy), Ok(true)) {
            return None;
        }
        let started = info.started_unix_ms;
        Some((self.resolver.resolve_from(info).ok()?, started))
    }

    fn remember(&self, src: u16, proxy: u16, pid: u32, started: u64) {
        let mut st = self.lock();
        let now = Instant::now();
        if st.cache.len() >= MAX_CACHE {
            st.cache.retain(|_, e| now.duration_since(e.at) < CACHE_TTL);
            if st.cache.len() >= MAX_CACHE {
                st.cache.clear();
            }
        }
        st.cache.insert(
            (src, proxy),
            Entry {
                pid,
                started_unix_ms: started,
                at: now,
            },
        );
        st.recent.retain(|&p| p != pid);
        st.recent.push_front(pid);
        st.recent.truncate(RECENT_OWNERS);
    }

    /// The caller on the client end of the loopback connection `src_port → proxy_port`.
    pub fn resolve(&self, src_port: u16, proxy_port: u16) -> Result<Caller, SessionError> {
        let (cached, recent) = {
            let st = self.lock();
            let cached = st
                .cache
                .get(&(src_port, proxy_port))
                .filter(|e| e.at.elapsed() < CACHE_TTL)
                .copied();
            (cached, st.recent.clone())
        };
        if let Some(e) = cached
            && let Some((c, _)) =
                self.verified(e.pid, Some(e.started_unix_ms), src_port, proxy_port)
        {
            return Ok(c);
        }
        for pid in recent {
            if let Some((c, started)) = self.verified(pid, None, src_port, proxy_port) {
                self.remember(src_port, proxy_port, pid, started);
                return Ok(c);
            }
        }
        let owners = self
            .sockets
            .owners(src_port, proxy_port)
            .map_err(SessionError::SocketTable)?;
        let mut found: Option<(u32, u64, Caller)> = None;
        for pid in owners {
            let Some((c, started)) = self.verified(pid, None, src_port, proxy_port) else {
                continue;
            };
            match &found {
                None => found = Some((pid, started, c)),
                Some((_, _, prev)) if *prev == c => {}
                Some(_) => return Err(SessionError::AmbiguousOwner { port: src_port }),
            }
        }
        let (pid, started, caller) = found.ok_or(SessionError::NoSocketOwner { port: src_port })?;
        self.remember(src_port, proxy_port, pid, started);
        Ok(caller)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ms_core::{AgentKind, SessionId};

    use super::*;
    use crate::walk::fake::FakeTable;

    /// Socket owners keyed by (src, proxy).
    #[derive(Debug, Default)]
    struct FakeSockets {
        owners: Mutex<HashMap<(u16, u16), Vec<u32>>>,
        scans: AtomicUsize,
    }

    impl FakeSockets {
        fn set(&self, src: u16, proxy: u16, pids: &[u32]) {
            self.owners
                .lock()
                .unwrap()
                .insert((src, proxy), pids.to_vec());
        }
    }

    impl SocketTable for &FakeSockets {
        fn owners(&self, l: u16, r: u16) -> io::Result<Vec<u32>> {
            self.scans.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .owners
                .lock()
                .unwrap()
                .get(&(l, r))
                .cloned()
                .unwrap_or_default())
        }
        fn holds(&self, pid: u32, l: u16, r: u16) -> io::Result<bool> {
            Ok(self
                .owners
                .lock()
                .unwrap()
                .get(&(l, r))
                .is_some_and(|v| v.contains(&pid)))
        }
    }

    fn table() -> FakeTable {
        FakeTable::with(&[
            (1, 0, 10, "launchd"),
            (100, 1, 100, "claude"),
            (101, 100, 110, "curl"),
            (200, 1, 200, "codex"),
            (201, 200, 210, "python3"),
        ])
    }

    fn claude() -> Caller {
        Caller::Agent(SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 100,
            started_unix_ms: 100,
        })
    }

    // protects=AUTH-1 for proxy clients; fails_when=a connection is attributed to the wrong
    // process or session; no_claim=live socket tables (tests/port.rs)
    #[test]
    fn resolves_owner_and_caches_by_recent_owner() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101]);
        let r = PortResolver::new(&s, table());
        assert_eq!(r.resolve(50000, 4600).unwrap(), claude());
        assert_eq!(s.scans.load(Ordering::SeqCst), 1);
        // Same port again: served from cache, verified, no scan.
        assert_eq!(r.resolve(50000, 4600).unwrap(), claude());
        // New port, same process: found via recent owners, no scan.
        s.set(50001, 4600, &[101]);
        assert_eq!(r.resolve(50001, 4600).unwrap(), claude());
        assert_eq!(s.scans.load(Ordering::SeqCst), 1);
    }

    // protects=no stale cache answers; fails_when=a closed connection's port, reused by another
    // session, still resolves to the old owner; no_claim=TTL tuning
    #[test]
    fn port_reused_by_another_process_is_rechecked() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101]);
        let r = PortResolver::new(&s, table());
        assert_eq!(r.resolve(50000, 4600).unwrap(), claude());
        s.set(50000, 4600, &[201]);
        let c = r.resolve(50000, 4600).unwrap();
        assert_eq!(c.session().unwrap().agent, AgentKind::Codex);
        s.set(50000, 4600, &[]);
        assert!(matches!(
            r.resolve(50000, 4600),
            Err(SessionError::NoSocketOwner { port: 50000 })
        ));
    }

    // protects=PID reuse on the cached path; fails_when=a cached pid that now belongs to a new
    // process is accepted without re-resolving; no_claim=sub-millisecond reuse
    #[test]
    fn cached_pid_with_new_start_time_is_not_trusted() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101]);
        let t = table();
        let r = PortResolver::new(&s, t);
        assert_eq!(r.resolve(50000, 4600).unwrap(), claude());
        // 101 exits; the pid is reused by a detached process that now holds the port.
        r.resolver().table().put(101, 1, 9999, "sh");
        let c = r.resolve(50000, 4600).unwrap();
        assert_eq!(
            c,
            Caller::Unattributed {
                pid: 101,
                started_unix_ms: 9999
            }
        );
    }

    // protects=fail closed on shared sockets; fails_when=one socket held by two sessions
    // resolves to either; no_claim=fd passing detection beyond ownership
    #[test]
    fn socket_shared_across_sessions_is_ambiguous() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101, 201]);
        let r = PortResolver::new(&s, table());
        assert!(matches!(
            r.resolve(50000, 4600),
            Err(SessionError::AmbiguousOwner { port: 50000 })
        ));
        // Shared within one session (fork) is fine.
        s.set(50002, 4600, &[100, 101]);
        assert_eq!(r.resolve(50002, 4600).unwrap(), claude());
    }
}
