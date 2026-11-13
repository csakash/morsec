//! Loopback TCP connection → owning process → [`Caller`], for proxy clients.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::SessionError;
use crate::table::{ProcessTable, SocketTable, canonical};
use crate::walk::{Caller, Resolver};

/// How long a `(client address, proxy address) → PID` answer is kept. Every use re-checks it.
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
    cache: HashMap<(SocketAddr, SocketAddr), Entry>,
    recent: VecDeque<u32>,
}

/// Finds which process is on the client end of a proxy connection and resolves its session.
///
/// The connection is named by its full address pair, as `accept()` reports it: the client's
/// address (`peer_addr`) and the proxy's own address (`local_addr`). Matching only ports would
/// let a process that binds the same source port on another loopback address (any of 127/8 on
/// Linux, or `::1`) borrow a live connection's identity.
///
/// Lookup order: the cached owner for this address pair, then recently seen owners (agents
/// open many connections), then a scan of every process. Any candidate must be shown, live, to
/// hold a socket with exactly `local = client` and `remote = proxy`, and still have the start
/// time it had when cached, so a stale cache entry or a reused PID can't answer. The daemon's
/// own process is never an owner (its accepted socket is the same pair the other way round,
/// and a crafted `client == proxy` pair must not resolve to the daemon's own ancestry).
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
    own_pid: u32,
}

impl<S: SocketTable, T: ProcessTable> PortResolver<S, T> {
    /// A resolver over the given socket and process tables.
    pub fn new(sockets: S, table: T) -> Self {
        Self {
            sockets,
            resolver: Resolver::new(table),
            state: Mutex::new(State::default()),
            own_pid: std::process::id(),
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
        client: SocketAddr,
        proxy: SocketAddr,
    ) -> Option<(Caller, u64)> {
        if pid == self.own_pid {
            return None;
        }
        if !matches!(self.sockets.holds(pid, client, proxy), Ok(true)) {
            return None;
        }
        let info = self.resolver.info(pid).ok()?;
        if started.is_some_and(|s| s != info.started_unix_ms) {
            return None;
        }
        // Re-check after reading the process, so the socket and the start time both belong to
        // the same incarnation of `pid`.
        if !matches!(self.sockets.holds(pid, client, proxy), Ok(true)) {
            return None;
        }
        let started = info.started_unix_ms;
        Some((self.resolver.resolve_from(info).ok()?, started))
    }

    fn remember(&self, key: (SocketAddr, SocketAddr), pid: u32, started: u64) {
        let mut st = self.lock();
        let now = Instant::now();
        if st.cache.len() >= MAX_CACHE {
            st.cache.retain(|_, e| now.duration_since(e.at) < CACHE_TTL);
            if st.cache.len() >= MAX_CACHE {
                st.cache.clear();
            }
        }
        st.cache.insert(
            key,
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

    /// The caller on the client end of the loopback connection `client → proxy`, where
    /// `client` is the accepted stream's `peer_addr()` and `proxy` its `local_addr()`.
    pub fn resolve(&self, client: SocketAddr, proxy: SocketAddr) -> Result<Caller, SessionError> {
        let (client, proxy) = (canonical(client), canonical(proxy));
        let port = client.port();
        if !client.ip().is_loopback() || !proxy.ip().is_loopback() {
            return Err(SessionError::NoSocketOwner { port });
        }
        let key = (client, proxy);
        let (cached, recent) = {
            let st = self.lock();
            let cached = st
                .cache
                .get(&key)
                .filter(|e| e.at.elapsed() < CACHE_TTL)
                .copied();
            (cached, st.recent.clone())
        };
        if let Some(e) = cached
            && let Some((c, _)) = self.verified(e.pid, Some(e.started_unix_ms), client, proxy)
        {
            return Ok(c);
        }
        for pid in recent {
            if let Some((c, started)) = self.verified(pid, None, client, proxy) {
                self.remember(key, pid, started);
                return Ok(c);
            }
        }
        let owners = self
            .sockets
            .owners(client, proxy)
            .map_err(SessionError::SocketTable)?;
        let mut found: Option<(u32, u64, Caller)> = None;
        for pid in owners {
            let Some((c, started)) = self.verified(pid, None, client, proxy) else {
                continue;
            };
            match &found {
                None => found = Some((pid, started, c)),
                Some((_, _, prev)) if *prev == c => {}
                Some(_) => return Err(SessionError::AmbiguousOwner { port }),
            }
        }
        let (pid, started, caller) = found.ok_or(SessionError::NoSocketOwner { port })?;
        self.remember(key, pid, started);
        Ok(caller)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ms_core::{AgentKind, SessionId};

    use super::*;
    use crate::walk::fake::FakeTable;

    /// Socket owners keyed by (client, proxy).
    #[derive(Debug, Default)]
    struct FakeSockets {
        owners: Mutex<HashMap<(SocketAddr, SocketAddr), Vec<u32>>>,
        scans: AtomicUsize,
    }

    const PROXY: &str = "127.0.0.1:4600";

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Client `127.0.0.1:<port>` to the proxy.
    fn c(port: u16) -> SocketAddr {
        SocketAddr::new([127, 0, 0, 1].into(), port)
    }

    impl FakeSockets {
        fn set_at(&self, client: SocketAddr, pids: &[u32]) {
            self.owners
                .lock()
                .unwrap()
                .insert((client, a(PROXY)), pids.to_vec());
        }
        fn set(&self, src: u16, _proxy: u16, pids: &[u32]) {
            self.set_at(c(src), pids);
        }
    }

    impl SocketTable for &FakeSockets {
        fn owners(&self, l: SocketAddr, r: SocketAddr) -> io::Result<Vec<u32>> {
            self.scans.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .owners
                .lock()
                .unwrap()
                .get(&(l, r))
                .cloned()
                .unwrap_or_default())
        }
        fn holds(&self, pid: u32, l: SocketAddr, r: SocketAddr) -> io::Result<bool> {
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
    // process or session; no_claim=live socket tables (tests/live.rs)
    #[test]
    fn resolves_owner_and_caches_by_recent_owner() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101]);
        let r = PortResolver::new(&s, table());
        assert_eq!(r.resolve(c(50000), a(PROXY)).unwrap(), claude());
        assert_eq!(s.scans.load(Ordering::SeqCst), 1);
        // Same port again: served from cache, verified, no scan.
        assert_eq!(r.resolve(c(50000), a(PROXY)).unwrap(), claude());
        // New port, same process: found via recent owners, no scan.
        s.set(50001, 4600, &[101]);
        assert_eq!(r.resolve(c(50001), a(PROXY)).unwrap(), claude());
        assert_eq!(s.scans.load(Ordering::SeqCst), 1);
    }

    // protects=no stale cache answers; fails_when=a closed connection's port, reused by another
    // session, still resolves to the old owner; no_claim=TTL tuning
    #[test]
    fn port_reused_by_another_process_is_rechecked() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101]);
        let r = PortResolver::new(&s, table());
        assert_eq!(r.resolve(c(50000), a(PROXY)).unwrap(), claude());
        s.set(50000, 4600, &[201]);
        let got = r.resolve(c(50000), a(PROXY)).unwrap();
        assert_eq!(got.session().unwrap().agent, AgentKind::Codex);
        s.set(50000, 4600, &[]);
        assert!(matches!(
            r.resolve(c(50000), a(PROXY)),
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
        assert_eq!(r.resolve(c(50000), a(PROXY)).unwrap(), claude());
        // 101 exits; the pid is reused by a detached process that now holds the port.
        r.resolver().table().put(101, 1, 9999, "sh");
        let got = r.resolve(c(50000), a(PROXY)).unwrap();
        assert_eq!(
            got,
            Caller::Unattributed {
                pid: 101,
                started_unix_ms: 9999
            }
        );
        // Only a rejected cache entry is replaced: had the cached path accepted the stale
        // entry, it would still carry the old start time.
        let st = r.lock();
        assert_eq!(st.cache[&(c(50000), a(PROXY))].started_unix_ms, 9999);
    }

    // protects=full address pair, not just ports; fails_when=a process holding the same source
    // port on another loopback address borrows a live connection's session via the cache or
    // the recent-owner path; no_claim=kernel 4-tuple uniqueness
    #[test]
    fn same_port_on_another_loopback_address_is_a_different_connection() {
        let s = FakeSockets::default();
        s.set_at(a("127.0.0.1:50000"), &[101]); // claude's real connection
        let r = PortResolver::new(&s, table());
        assert_eq!(r.resolve(a("127.0.0.1:50000"), a(PROXY)).unwrap(), claude());
        // codex's process binds 127.0.0.2:50000 and connects; 101 is cached and recent.
        s.set_at(a("127.0.0.2:50000"), &[201]);
        let got = r.resolve(a("127.0.0.2:50000"), a(PROXY)).unwrap();
        assert_eq!(got.session().unwrap().agent, AgentKind::Codex);
        // Same over ::1 and IPv4-mapped forms.
        s.set_at(a("[::1]:50000"), &[201]);
        let got = r.resolve(a("[::1]:50000"), a(PROXY)).unwrap();
        assert_eq!(got.session().unwrap().agent, AgentKind::Codex);
        assert_eq!(
            r.resolve(a("[::ffff:127.0.0.1]:50000"), a(PROXY)).unwrap(),
            claude()
        );
        // Non-loopback addresses never resolve.
        assert!(r.resolve(a("10.0.0.1:50000"), a(PROXY)).is_err());
    }

    // protects=the daemon never resolves to itself; fails_when=a crafted pair whose only holder
    // is the daemon's own process resolves to the daemon's ancestry; no_claim=other self pids
    #[test]
    fn own_process_is_never_an_owner() {
        let s = FakeSockets::default();
        let me = std::process::id();
        let t = table();
        t.put(me, 100, 150, "msd");
        s.set_at(a("127.0.0.1:4600"), &[me]);
        let r = PortResolver::new(&s, t);
        assert!(matches!(
            r.resolve(a("127.0.0.1:4600"), a(PROXY)),
            Err(SessionError::NoSocketOwner { .. })
        ));
    }

    // protects=fail closed on shared sockets; fails_when=one socket held by two sessions
    // resolves to either; no_claim=fd passing detection beyond ownership
    #[test]
    fn socket_shared_across_sessions_is_ambiguous() {
        let s = FakeSockets::default();
        s.set(50000, 4600, &[101, 201]);
        let r = PortResolver::new(&s, table());
        assert!(matches!(
            r.resolve(c(50000), a(PROXY)),
            Err(SessionError::AmbiguousOwner { port: 50000 })
        ));
        // Shared within one session (fork) is fine.
        s.set(50002, 4600, &[100, 101]);
        assert_eq!(r.resolve(c(50002), a(PROXY)).unwrap(), claude());
    }
}
