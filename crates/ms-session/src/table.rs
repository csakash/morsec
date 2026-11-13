//! Reading the OS process and socket tables.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

/// What session identity needs to know about one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id (0 for the root of the tree).
    pub ppid: u32,
    /// Effective uid.
    pub uid: u32,
    /// Start time, Unix milliseconds. With `pid`, this tells a reused PID apart.
    pub started_unix_ms: u64,
    /// Short process name (`p_comm` on macOS, `comm` on Linux), as set at exec.
    pub name: String,
}

/// A source of process information. [`OsProcessTable`] reads the live system; tests use fakes.
pub trait ProcessTable: Send + Sync {
    /// Information about `pid`. [`io::ErrorKind::NotFound`] means no such process; any other
    /// error means it exists but could not be read.
    fn info(&self, pid: u32) -> io::Result<ProcInfo>;
}

/// A source of TCP socket ownership. [`OsProcessTable`] reads the live system.
pub trait SocketTable: Send + Sync {
    /// PIDs of processes holding a TCP socket whose local end is exactly `local` and whose
    /// remote end is exactly `remote` (both loopback; IPv4-mapped addresses compare as IPv4).
    fn owners(&self, local: SocketAddr, remote: SocketAddr) -> io::Result<Vec<u32>>;

    /// Whether `pid` holds such a socket. Used to re-check a cached answer cheaply.
    fn holds(&self, pid: u32, local: SocketAddr, remote: SocketAddr) -> io::Result<bool>;
}

/// The live process and socket tables of this machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsProcessTable;

/// `addr` with an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) turned into IPv4.
pub(crate) fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The full address pair must match, not just the ports: on Linux any 127/8 address is
/// bindable, so another process can hold the same source port on `127.0.0.2`.
pub(crate) fn matches(
    ends: &crate::sockparse::TcpEnds,
    local: SocketAddr,
    remote: SocketAddr,
) -> bool {
    let (l, r) = (canonical(ends.local), canonical(ends.remote));
    l == canonical(local) && r == canonical(remote) && l.ip().is_loopback() && r.ip().is_loopback()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::sys::macos;

    fn proc_info(pid: u32) -> io::Result<ProcInfo> {
        let raw = macos::kinfo_proc(pid)?;
        let k = crate::kinfo::parse(&raw)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad kinfo_proc"))?;
        if k.pid != pid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kinfo_proc pid mismatch",
            ));
        }
        Ok(ProcInfo {
            pid,
            ppid: k.ppid,
            uid: k.uid,
            started_unix_ms: k.started_unix_ms,
            name: k.comm,
        })
    }

    fn pid_holds(pid: u32, local: SocketAddr, remote: SocketAddr) -> io::Result<bool> {
        let fds = macos::list_fds(pid)?;
        let socket_type = u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap_or(u32::MAX);
        for (fd, kind) in fds {
            if kind != socket_type {
                continue;
            }
            // A descriptor closed between the two calls is simply skipped.
            let Ok(raw) = macos::socket_info(pid, fd) else {
                continue;
            };
            if let Some(ends) = crate::sockparse::parse_darwin_socket_fdinfo(&raw)
                && matches(&ends, local, remote)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    impl ProcessTable for OsProcessTable {
        fn info(&self, pid: u32) -> io::Result<ProcInfo> {
            proc_info(pid)
        }
    }

    impl SocketTable for OsProcessTable {
        fn owners(&self, local: SocketAddr, remote: SocketAddr) -> io::Result<Vec<u32>> {
            let mut out = Vec::new();
            for pid in macos::list_all_pids()? {
                // Other users' processes refuse PROC_PIDLISTFDS; they can't be our clients.
                if let Ok(true) = pid_holds(pid, local, remote) {
                    out.push(pid);
                }
            }
            Ok(out)
        }

        fn holds(&self, pid: u32, local: SocketAddr, remote: SocketAddr) -> io::Result<bool> {
            pid_holds(pid, local, remote)
        }
    }

    /// Executable path of `pid`, for diagnostics.
    pub(crate) fn exe_path(pid: u32) -> io::Result<PathBuf> {
        macos::pid_path(pid)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::procfs;
    use crate::sockparse::parse_proc_net_tcp_row;
    use std::fs;

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
    }

    /// Boot time, read once: the kernel recomputes `btime` from the wall clock on every read,
    /// so it can move after a clock change, which would change every session's start time.
    fn boot_time() -> io::Result<u64> {
        static BTIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        if let Some(b) = BTIME.get() {
            return Ok(*b);
        }
        let b = procfs::parse_btime(&fs::read_to_string("/proc/stat")?)
            .ok_or_else(|| invalid("no btime in /proc/stat"))?;
        Ok(*BTIME.get_or_init(|| b))
    }

    fn proc_info(pid: u32) -> io::Result<ProcInfo> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let stat = procfs::parse_stat(&stat).ok_or_else(|| invalid("bad /proc/<pid>/stat"))?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let uid =
            procfs::parse_status_euid(&status).ok_or_else(|| invalid("bad /proc/<pid>/status"))?;
        let btime = boot_time()?;
        let hz = rustix::param::clock_ticks_per_second();
        let started = procfs::start_unix_ms(btime, stat.start_ticks, hz)
            .ok_or_else(|| invalid("bad start time"))?;
        Ok(ProcInfo {
            pid,
            ppid: stat.ppid,
            uid,
            started_unix_ms: started,
            name: stat.comm,
        })
    }

    fn inodes(local: SocketAddr, remote: SocketAddr) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            for row in text.lines().skip(1).filter_map(parse_proc_net_tcp_row) {
                if matches(&row.ends, local, remote) && row.inode != 0 {
                    out.push(row.inode);
                }
            }
        }
        Ok(out)
    }

    fn pid_has_inode(pid: u32, wanted: &[u64]) -> bool {
        let Ok(dir) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            return false;
        };
        dir.flatten().any(|e| {
            fs::read_link(e.path())
                .ok()
                .and_then(|t| procfs::socket_inode(&t.to_string_lossy()))
                .is_some_and(|i| wanted.contains(&i))
        })
    }

    impl ProcessTable for OsProcessTable {
        fn info(&self, pid: u32) -> io::Result<ProcInfo> {
            proc_info(pid)
        }
    }

    impl SocketTable for OsProcessTable {
        fn owners(&self, local: SocketAddr, remote: SocketAddr) -> io::Result<Vec<u32>> {
            let wanted = inodes(local, remote)?;
            if wanted.is_empty() {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            for e in fs::read_dir("/proc")?.flatten() {
                if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())
                    && pid_has_inode(pid, &wanted)
                {
                    out.push(pid);
                }
            }
            Ok(out)
        }

        fn holds(&self, pid: u32, local: SocketAddr, remote: SocketAddr) -> io::Result<bool> {
            let wanted = inodes(local, remote)?;
            Ok(!wanted.is_empty() && pid_has_inode(pid, &wanted))
        }
    }

    /// Executable path of `pid`, for diagnostics.
    pub(crate) fn exe_path(pid: u32) -> io::Result<PathBuf> {
        fs::read_link(format!("/proc/{pid}/exe"))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "session identity supports macOS and Linux only",
        )
    }

    impl ProcessTable for OsProcessTable {
        fn info(&self, _pid: u32) -> io::Result<ProcInfo> {
            Err(unsupported())
        }
    }

    impl SocketTable for OsProcessTable {
        fn owners(&self, _l: SocketAddr, _r: SocketAddr) -> io::Result<Vec<u32>> {
            Err(unsupported())
        }
        fn holds(&self, _p: u32, _l: SocketAddr, _r: SocketAddr) -> io::Result<bool> {
            Err(unsupported())
        }
    }

    pub(crate) fn exe_path(_pid: u32) -> io::Result<PathBuf> {
        Err(unsupported())
    }
}

/// Executable path of `pid`, when readable. For diagnostics and `ms status`; identity never
/// depends on it.
pub fn exe_path(pid: u32) -> io::Result<PathBuf> {
    imp::exe_path(pid)
}
