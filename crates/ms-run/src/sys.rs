//! The one place `ms-run` needs `unsafe`: starting a run's child in a session of its own.
//!
//! Security review S1 (L16): with only a process group of its own, a run's child stayed in
//! msd's session, so a process left behind by another run could `setpgid` into the group and
//! pass the per-run SSH agent's peer check. `setsid` in the child gives it a new session (and a
//! new process group with the same id, so the group kill still works); `setpgid` across
//! sessions fails with EPERM.
#![allow(unsafe_code)]

/// Makes `cmd`'s child call `setsid()` before exec: its own session and process group, both with
/// id = its PID.
pub(crate) fn new_session(cmd: &mut tokio::process::Command) {
    // SAFETY: the closure runs in the child between fork and exec, where only
    // async-signal-safe work is allowed. It makes one `setsid` call through rustix (a raw system
    // call on Linux, libc's `setsid` on macOS; async-signal-safe under POSIX either way; no
    // allocation, no locks) and builds an `io::Error` from an errno, which allocates
    // nothing either.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid()
                .map(drop)
                .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
        });
    }
}
