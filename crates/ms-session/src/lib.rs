//! Session identity: which agent session a caller belongs to.
//!
//! The daemon never takes a session from the client. It derives it from the kernel:
//!
//! - **Unix-socket clients** (`ms`, the shim, `ms mcp`): the peer PID from the kernel
//!   ([`resolve_peer`], [`SessionPeerCheck`]).
//! - **Proxy clients** over loopback TCP: the source port mapped to the owning process
//!   ([`PortResolver`]), with the per-connector proxy username as a cross-check
//!   ([`cross_check`]).
//!
//! Either way, the process tree is walked up to the outermost agent process, and the session is
//! `{agent, pid, start time}` ([`ms_core::SessionId`]), so a reused PID is a new session.
//!
//! Identity here is attribution among same-user processes, not authentication against a
//! hostile one: a process can always detach from its agent ([`Caller::Unattributed`]) or exec
//! a binary named like an agent outside any session. Rights for sensitive actions must still
//! come from approvals (AUTH-3), and an unattributed caller never gets more than an agent.
//! A never-seen session gets no standing grants: a fresh `SessionId` must not be a way to
//! escape a revoked or capped one.
//!
//! [`PortResolver::resolve`] may scan every process (a few ms); call it off the async runtime.

pub mod error;
pub mod kinfo;
pub mod peer;
pub mod port;
pub mod procfs;
pub mod proxy;
pub mod sockparse;
mod sys;
pub mod table;
pub mod walk;

pub use error::SessionError;
pub use peer::{SessionPeerCheck, resolve_peer};
pub use port::PortResolver;
pub use proxy::{
    DEV_PROXY_USER_PREFIX, agent_for_proxy_user, cross_check, is_dev_proxy_user, proxy_user_for,
};
pub use table::{OsProcessTable, ProcInfo, ProcessTable, SocketTable, exe_path, is_sandboxed};
pub use walk::{Caller, MAX_DEPTH, Resolver, agent_install_path, agent_kind};
