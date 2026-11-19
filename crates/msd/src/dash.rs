//! msd's dashboard (L32 dash-core, design §6.1 and §6.2.1): the listener lives in `ms-dash`;
//! this module gives it msd's data and the per-connection process check.
//!
//! The check maps the connection's address pair to the process holding the client end, as the
//! swap proxy does (`ms_session::PortResolver`), and walks up its process tree. An agent session,
//! another uid, or an owner that can't be identified gets the connection closed before a byte is
//! read, and a `blocked` receipt (charged to the agent session when there is one, so it counts
//! towards that session's LOG-2 alert).

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};

use ms_core::{AgentKind, SessionId};
use ms_dash::{Dash, DashConfig, Refusal};
use ms_session::{Caller, OsProcessTable, PortResolver, ProcessTable, SocketTable};

use crate::daemon::{Daemon, DashSource};

/// Most process-table scans for dashboard connections at once.
const MAX_SCANS: usize = 4;

/// The process check for dashboard connections.
pub struct ConnCheck<S, T> {
    ports: PortResolver<S, T>,
    uid: u32,
    scans: (Mutex<usize>, Condvar),
}

impl<S, T> std::fmt::Debug for ConnCheck<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnCheck").field("uid", &self.uid).finish()
    }
}

fn dashboard_session(pid: u32, started_unix_ms: u64) -> SessionId {
    SessionId {
        agent: AgentKind::Other("dashboard".into()),
        pid,
        started_unix_ms,
    }
}

impl<S: SocketTable, T: ProcessTable> ConnCheck<S, T> {
    /// A check for msd running as `uid`.
    pub fn new(sockets: S, table: T, uid: u32) -> Self {
        Self {
            ports: PortResolver::new(sockets, table),
            uid,
            scans: (Mutex::new(0), Condvar::new()),
        }
    }

    /// `Ok(who)` for a process of this user outside every agent session; `Err` otherwise.
    pub fn check(&self, peer: SocketAddr, local: SocketAddr) -> Result<SessionId, Refusal> {
        let caller = {
            let (m, cv) = &self.scans;
            let mut n = m.lock().unwrap_or_else(|e| e.into_inner());
            while *n >= MAX_SCANS {
                n = cv.wait(n).unwrap_or_else(|e| e.into_inner());
            }
            *n += 1;
            drop(n);
            let r = self.ports.resolve(peer, local);
            *m.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
            cv.notify_one();
            r
        };
        match caller {
            Ok(Caller::Agent(session)) => Err(Refusal {
                session,
                why: "a connection from an agent session".into(),
            }),
            Ok(Caller::Unattributed {
                pid,
                started_unix_ms,
            }) => match self.ports.resolver().info(pid) {
                Ok(info) if info.uid == self.uid && info.started_unix_ms == started_unix_ms => {
                    Ok(dashboard_session(pid, started_unix_ms))
                }
                Ok(info) if info.uid != self.uid => Err(Refusal {
                    session: dashboard_session(pid, started_unix_ms),
                    why: format!("a connection from another user (uid {})", info.uid),
                }),
                _ => Err(Refusal {
                    session: dashboard_session(pid, started_unix_ms),
                    why: "the connecting process changed while it was checked".into(),
                }),
            },
            Err(e) => Err(Refusal {
                session: dashboard_session(0, 0),
                why: format!("the connecting process can't be identified ({e})"),
            }),
        }
    }
}

/// Builds the dashboard for `d` (not listening until the first `DashOpen`) and installs it.
pub fn install(d: &Arc<Daemon>, cfg: DashConfig, uid: u32) {
    let check = Arc::new(ConnCheck::new(OsProcessTable, OsProcessTable, uid));
    install_with(d, cfg, Arc::new(move |p, l| check.check(p, l)));
}

/// [`install`] with another connection check (tests).
pub fn install_with(d: &Arc<Daemon>, cfg: DashConfig, check: crate::daemon::ConnChecker) {
    let source = DashSource::new(d, check);
    d.set_dash(Dash::new(
        cfg,
        Arc::new(source),
        tokio::runtime::Handle::current(),
    ));
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;

    use ms_session::ProcInfo;

    use super::*;

    /// Sockets: every pair is held by `owner` (if set). Processes: a fixed table.
    struct Fake {
        owner: Option<u32>,
        procs: HashMap<u32, ProcInfo>,
    }

    impl SocketTable for &Fake {
        fn owners(&self, _l: SocketAddr, _r: SocketAddr) -> io::Result<Vec<u32>> {
            Ok(self.owner.into_iter().collect())
        }
        fn holds(&self, pid: u32, _l: SocketAddr, _r: SocketAddr) -> io::Result<bool> {
            Ok(self.owner == Some(pid))
        }
    }

    impl ProcessTable for &Fake {
        fn info(&self, pid: u32) -> io::Result<ProcInfo> {
            self.procs
                .get(&pid)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn p(pid: u32, ppid: u32, uid: u32, name: &str) -> (u32, ProcInfo) {
        (
            pid,
            ProcInfo {
                pid,
                ppid,
                uid,
                started_unix_ms: 100 + u64::from(pid),
                name: name.into(),
            },
        )
    }

    fn fake(owner: Option<u32>) -> Fake {
        Fake {
            owner,
            procs: [
                p(1, 0, 0, "launchd"),
                p(10, 1, 501, "claude"),
                p(11, 10, 501, "zsh"),
                p(12, 11, 501, "curl"),
                p(20, 1, 501, "Google Chrome"),
                p(21, 20, 501, "Google Chrome Helper"),
                p(30, 1, 502, "Safari"),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    // protects=design §6.2.1 and §8 (agent curls the dashboard): a connection whose owner is in an
    // agent's process tree, belongs to another user, or can't be found is refused, the agent's
    // refusal charged to its own session; the user's browser passes; fails_when=curl under claude,
    // another uid's process or an unowned socket gets Ok, or the browser is refused;
    // no_claim=the live OS tables (ms-cli dashboard.rs drives a real fake agent)
    #[test]
    fn conn_check_refuses_agent_other_uid_and_unknown() {
        let check = |owner| {
            let f = fake(owner);
            ConnCheck::new(&f, &f, 501).check(addr(50000), addr(7311))
        };
        let e = check(Some(12)).unwrap_err();
        assert_eq!(e.session.agent, AgentKind::ClaudeCode);
        assert_eq!(e.session.pid, 10, "charged to the agent session's root");
        assert!(e.why.contains("agent"), "{}", e.why);
        let e = check(Some(30)).unwrap_err();
        assert!(e.why.contains("another user"), "{}", e.why);
        let e = check(None).unwrap_err();
        assert!(e.why.contains("can't be identified"), "{}", e.why);
        let ok = check(Some(21)).unwrap();
        assert_eq!(ok.pid, 21);
        assert_eq!(ok.agent, AgentKind::Other("dashboard".into()));
    }
}
