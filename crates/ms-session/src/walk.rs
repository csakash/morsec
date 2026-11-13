//! Process-tree walk from a caller's PID to its agent session.

use ms_core::{AgentKind, SessionId};

use crate::error::SessionError;
use crate::table::{ProcInfo, ProcessTable};

/// Most parent links followed before giving up (fail closed).
pub const MAX_DEPTH: usize = 64;

/// Who is calling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Caller {
    /// A process inside an agent session.
    Agent(SessionId),
    /// A process with no agent ancestor: a person running `ms` in a plain terminal, or a process
    /// that detached from its agent (double fork, `nohup`, launchd).
    ///
    /// **This is not proof of a person.** A same-user process can always detach from its agent
    /// and land here, so an unattributed caller must never get more rights than an agent
    /// session. Anything sensitive still needs an approval.
    Unattributed {
        /// The calling process.
        pid: u32,
        /// Its start time, Unix milliseconds.
        started_unix_ms: u64,
    },
}

impl Caller {
    /// The agent session, if there is one.
    pub fn session(&self) -> Option<&SessionId> {
        match self {
            Caller::Agent(s) => Some(s),
            Caller::Unattributed { .. } => None,
        }
    }
}

/// The agent a process is, by its short name (`p_comm` / `comm`). Exact and case-sensitive.
///
/// Desktop and IDE hosts (Claude Desktop's `Claude`, VS Code's `Code`, `Cursor`, Electron
/// helpers) are deliberately not agents: Claude Desktop runs one `claude` process per session
/// under its `Claude` app, so treating the app as the root would merge every session into one.
pub fn agent_kind(name: &str) -> Option<AgentKind> {
    match name {
        "claude" => Some(AgentKind::ClaudeCode),
        "codex" => Some(AgentKind::Codex),
        "cursor-agent" => Some(AgentKind::Cursor),
        "gemini" => Some(AgentKind::GeminiCli),
        _ => None,
    }
}

/// Maps a PID to its [`Caller`] using a [`ProcessTable`].
#[derive(Debug, Clone, Default)]
pub struct Resolver<T> {
    table: T,
}

impl<T: ProcessTable> Resolver<T> {
    /// A resolver over `table`.
    pub fn new(table: T) -> Self {
        Self { table }
    }

    /// The underlying table.
    pub fn table(&self) -> &T {
        &self.table
    }

    /// Reads `pid`, failing closed.
    pub fn info(&self, pid: u32) -> Result<ProcInfo, SessionError> {
        self.table
            .info(pid)
            .map_err(|source| SessionError::Unreadable { pid, source })
    }

    /// Walks from `pid` up the parent links and returns the session of the **outermost** agent
    /// process on the chain, or [`Caller::Unattributed`] if there is none.
    ///
    /// Outermost, not nearest: a process inside a Claude Code session that calls itself `codex`
    /// (or `claude`) must not start a fresh session or change agent kind; its authority comes
    /// from the real agent above it.
    ///
    /// A parent that exists but can't be read is an error (fail closed); one that no longer
    /// exists ends the chain.
    ///
    /// Each step requires `parent.started <= child.started`. A parent that started later is a
    /// reused PID (the real parent exited), so the chain is broken there and the walk stops.
    pub fn resolve(&self, pid: u32) -> Result<Caller, SessionError> {
        let leaf = self.info(pid)?;
        self.resolve_from(leaf)
    }

    /// Like [`Resolver::resolve`], starting from an already-read process.
    pub fn resolve_from(&self, leaf: ProcInfo) -> Result<Caller, SessionError> {
        let mut chain = vec![leaf];
        loop {
            if chain.len() > MAX_DEPTH {
                return Err(SessionError::TooDeep {
                    pid: chain[0].pid,
                    max: MAX_DEPTH,
                });
            }
            let cur = chain.last().expect("chain starts non-empty");
            // PID 1 (launchd / init) and kernel processes end the chain.
            if cur.pid <= 1 || cur.ppid == 0 || cur.ppid == cur.pid {
                break;
            }
            // A parent that no longer exists (exited mid-walk; the child is being reparented)
            // ends the chain, like a detach. A parent that exists but can't be read fails
            // closed: an agent above it could be hidden, which would break the outermost rule.
            let parent = match self.table.info(cur.ppid) {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(source) => {
                    return Err(SessionError::Unreadable {
                        pid: cur.ppid,
                        source,
                    });
                }
            };
            if parent.pid != cur.ppid || parent.started_unix_ms > cur.started_unix_ms {
                break;
            }
            chain.push(parent);
        }
        let mut root: Option<(AgentKind, &ProcInfo)> = None;
        for p in &chain {
            if let Some(kind) = agent_kind(&p.name) {
                root = Some((kind, p));
            }
        }
        let leaf = &chain[0];
        Ok(match root {
            Some((agent, p)) => Caller::Agent(SessionId {
                agent,
                pid: p.pid,
                started_unix_ms: p.started_unix_ms,
            }),
            None => Caller::Unattributed {
                pid: leaf.pid,
                started_unix_ms: leaf.started_unix_ms,
            },
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;

    use super::*;

    /// An in-memory process table. PIDs in `denied` exist but can't be read.
    #[derive(Debug, Default)]
    pub struct FakeTable(pub Mutex<HashMap<u32, ProcInfo>>, pub Mutex<Vec<u32>>);

    impl FakeTable {
        pub fn with(procs: &[(u32, u32, u64, &str)]) -> Self {
            let t = FakeTable::default();
            for &(pid, ppid, started, name) in procs {
                t.put(pid, ppid, started, name);
            }
            t
        }

        pub fn put(&self, pid: u32, ppid: u32, started: u64, name: &str) {
            self.0.lock().unwrap().insert(
                pid,
                ProcInfo {
                    pid,
                    ppid,
                    uid: 501,
                    started_unix_ms: started,
                    name: name.into(),
                },
            );
        }
    }

    impl ProcessTable for FakeTable {
        fn info(&self, pid: u32) -> io::Result<ProcInfo> {
            if self.1.lock().unwrap().contains(&pid) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            self.0
                .lock()
                .unwrap()
                .get(&pid)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeTable;
    use super::*;

    fn session(agent: AgentKind, pid: u32, started: u64) -> Caller {
        Caller::Agent(SessionId {
            agent,
            pid,
            started_unix_ms: started,
        })
    }

    /// Claude Desktop's real chain on macOS: zsh -> claude -> disclaimer -> Claude -> launchd.
    fn desktop() -> FakeTable {
        FakeTable::with(&[
            (1, 0, 10, "launchd"),
            (85147, 1, 100, "Claude"),
            (464, 85147, 200, "disclaimer"),
            (466, 464, 210, "claude"),
            (5971, 466, 300, "zsh"),
            (6000, 5971, 400, "ms"),
        ])
    }

    // protects=AUTH-1 session = agent root, not the caller; fails_when=the leaf or the desktop
    // host is taken as the session; no_claim=live process reads (tests/live.rs)
    #[test]
    fn desktop_chain_resolves_to_the_claude_process() {
        let r = Resolver::new(desktop());
        assert_eq!(
            r.resolve(6000).unwrap(),
            session(AgentKind::ClaudeCode, 466, 210)
        );
        // The agent process itself is its own session.
        assert_eq!(
            r.resolve(466).unwrap(),
            session(AgentKind::ClaudeCode, 466, 210)
        );
    }

    // protects=desktop host never merges sessions; fails_when=two claude children of one
    // Claude app resolve to the same session; no_claim=IDE hosts beyond name matching
    #[test]
    fn two_desktop_sessions_stay_apart() {
        let t = desktop();
        t.put(470, 85147, 220, "claude");
        t.put(7000, 470, 500, "bash");
        let r = Resolver::new(t);
        let a = r.resolve(6000).unwrap();
        let b = r.resolve(7000).unwrap();
        assert_ne!(a, b);
        assert_eq!(b, session(AgentKind::ClaudeCode, 470, 220));
    }

    // protects=outermost-agent rule; fails_when=a process inside a Claude session named codex
    // or claude gets its own session or agent kind; no_claim=legit nested agents get separate
    // sessions (they don't, by design)
    #[test]
    fn impostor_inside_a_session_resolves_to_the_outer_agent() {
        let t = desktop();
        t.put(8000, 5971, 500, "codex");
        t.put(8001, 8000, 501, "claude");
        t.put(8002, 8001, 502, "node");
        let r = Resolver::new(t);
        assert_eq!(
            r.resolve(8002).unwrap(),
            session(AgentKind::ClaudeCode, 466, 210)
        );
    }

    // protects=PID reuse is a new session; fails_when=same pid with a new start time yields
    // the old SessionId; no_claim=the kernel's start-time precision
    #[test]
    fn reused_pid_is_a_new_session() {
        let t = FakeTable::with(&[(1, 0, 10, "launchd"), (500, 1, 1000, "codex")]);
        let r = Resolver::new(t);
        let first = r.resolve(500).unwrap();
        r.table().put(500, 1, 9000, "codex");
        let second = r.resolve(500).unwrap();
        assert_ne!(first, second);
        assert_eq!(second, session(AgentKind::Codex, 500, 9000));
    }

    // protects=walk stops at a reused parent PID; fails_when=an orphan whose old parent PID now
    // belongs to a later-started agent is attributed to it; no_claim=reparenting to launchd
    #[test]
    fn parent_started_after_child_breaks_the_chain() {
        // 900's parent 466 exited; 466 was reused by a *later* claude.
        let t = FakeTable::with(&[
            (1, 0, 10, "launchd"),
            (466, 1, 5000, "claude"),
            (900, 466, 300, "python3"),
        ]);
        let r = Resolver::new(t);
        assert_eq!(
            r.resolve(900).unwrap(),
            Caller::Unattributed {
                pid: 900,
                started_unix_ms: 300
            }
        );
    }

    // protects=fail closed on a hidden ancestor; fails_when=an unreadable middle process lets an
    // inner impostor agent become the session; no_claim=which errno the OS gives
    #[test]
    fn unreadable_parent_fails_closed_but_gone_parent_ends_chain() {
        let t = desktop();
        t.put(8000, 5971, 500, "codex");
        t.put(8001, 8000, 501, "node");
        t.1.lock().unwrap().push(5971); // zsh unreadable
        let r = Resolver::new(t);
        assert!(matches!(
            r.resolve(8001),
            Err(SessionError::Unreadable { pid: 5971, .. })
        ));
        // Gone (not unreadable): the chain ends at codex, like a detach.
        r.table().1.lock().unwrap().clear();
        r.table().0.lock().unwrap().remove(&5971);
        assert_eq!(
            r.resolve(8001).unwrap(),
            session(AgentKind::Codex, 8000, 500)
        );
    }

    // protects=fail closed; fails_when=an unreadable caller gets an identity; no_claim=error text
    #[test]
    fn unreadable_caller_is_an_error() {
        let r = Resolver::new(FakeTable::default());
        assert!(matches!(
            r.resolve(42),
            Err(SessionError::Unreadable { pid: 42, .. })
        ));
    }

    // protects=terminal use without an agent; fails_when=a plain shell gets an agent session;
    // no_claim=that unattributed means human
    #[test]
    fn plain_terminal_is_unattributed() {
        let t = FakeTable::with(&[
            (1, 0, 10, "launchd"),
            (50, 1, 20, "Terminal"),
            (60, 50, 30, "zsh"),
            (70, 60, 40, "ms"),
        ]);
        let r = Resolver::new(t);
        assert_eq!(
            r.resolve(70).unwrap(),
            Caller::Unattributed {
                pid: 70,
                started_unix_ms: 40
            }
        );
    }

    // protects=bounded walk; fails_when=a cycle or very deep chain hangs or succeeds;
    // no_claim=real kernels produce cycles
    #[test]
    fn deep_chains_fail_closed() {
        let t = FakeTable::default();
        let n = u32::try_from(MAX_DEPTH).unwrap() + 10;
        for pid in 2..=n {
            t.put(pid, pid + 1, 100, "sh");
        }
        t.put(n + 1, 2, 100, "sh"); // cycle back
        let r = Resolver::new(t);
        assert!(matches!(r.resolve(2), Err(SessionError::TooDeep { .. })));
    }

    // protects=exact name matching; fails_when=host apps or lookalikes classify as agents;
    // no_claim=renamed binaries are caught (they are not; see SPEC residual risks)
    #[test]
    fn classification_is_exact() {
        assert_eq!(agent_kind("claude"), Some(AgentKind::ClaudeCode));
        assert_eq!(agent_kind("codex"), Some(AgentKind::Codex));
        assert_eq!(agent_kind("cursor-agent"), Some(AgentKind::Cursor));
        assert_eq!(agent_kind("gemini"), Some(AgentKind::GeminiCli));
        for host in [
            "Claude",
            "Code",
            "Cursor",
            "Electron",
            "claude-helper",
            "node",
            "",
        ] {
            assert_eq!(agent_kind(host), None, "{host}");
        }
    }
}
