//! Reading the OS process and socket tables.

use std::io;
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
    /// Information about `pid`. An error means the process is gone or unreadable.
    fn info(&self, pid: u32) -> io::Result<ProcInfo>;
}

/// A source of TCP socket ownership. [`OsProcessTable`] reads the live system.
pub trait SocketTable: Send + Sync {
    /// PIDs of processes holding a TCP socket whose local end is a loopback address on
    /// `local_port` and whose remote end is on `remote_port`.
    fn owners(&self, local_port: u16, remote_port: u16) -> io::Result<Vec<u32>>;

    /// Whether `pid` holds such a socket. Used to re-check a cached answer cheaply.
    fn holds(&self, pid: u32, local_port: u16, remote_port: u16) -> io::Result<bool>;
}

/// The live process and socket tables of this machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsProcessTable;

pub(crate) fn matches(ends: &crate::sockparse::TcpEnds, local_port: u16, remote_port: u16) -> bool {
    ends.local.port() == local_port
        && ends.remote.port() == remote_port
        // `to_canonical` so an IPv4-mapped `::ffff:127.0.0.1` on a dual-stack socket counts.
        && ends.local.ip().to_canonical().is_loopback()
        && ends.remote.ip().to_canonical().is_loopback()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::sys::macos;

    fn proc_info(pid: u32) -> io::Result<ProcInfo> {
        let b = macos::bsd_info(pid)?;
        let ms = b
            .start_sec
            .checked_mul(1000)
            .and_then(|s| s.checked_add(b.start_usec / 1000))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "start time overflow"))?;
        Ok(ProcInfo {
            pid,
            ppid: b.ppid,
            uid: b.uid,
            started_unix_ms: ms,
            name: b.comm,
        })
    }

    fn pid_holds(pid: u32, local_port: u16, remote_port: u16) -> io::Result<bool> {
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
                && matches(&ends, local_port, remote_port)
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
        fn owners(&self, local_port: u16, remote_port: u16) -> io::Result<Vec<u32>> {
            let mut out = Vec::new();
            for pid in macos::list_all_pids()? {
                // Other users' processes refuse PROC_PIDLISTFDS; they can't be our clients.
                if let Ok(true) = pid_holds(pid, local_port, remote_port) {
                    out.push(pid);
                }
            }
            Ok(out)
        }

        fn holds(&self, pid: u32, local_port: u16, remote_port: u16) -> io::Result<bool> {
            pid_holds(pid, local_port, remote_port)
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

    fn proc_info(pid: u32) -> io::Result<ProcInfo> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let stat = procfs::parse_stat(&stat).ok_or_else(|| invalid("bad /proc/<pid>/stat"))?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let uid =
            procfs::parse_status_euid(&status).ok_or_else(|| invalid("bad /proc/<pid>/status"))?;
        let btime = procfs::parse_btime(&fs::read_to_string("/proc/stat")?)
            .ok_or_else(|| invalid("no btime in /proc/stat"))?;
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

    fn inodes(local_port: u16, remote_port: u16) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            for row in text.lines().skip(1).filter_map(parse_proc_net_tcp_row) {
                if matches(&row.ends, local_port, remote_port) && row.inode != 0 {
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
        fn owners(&self, local_port: u16, remote_port: u16) -> io::Result<Vec<u32>> {
            let wanted = inodes(local_port, remote_port)?;
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

        fn holds(&self, pid: u32, local_port: u16, remote_port: u16) -> io::Result<bool> {
            let wanted = inodes(local_port, remote_port)?;
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
        fn owners(&self, _l: u16, _r: u16) -> io::Result<Vec<u32>> {
            Err(unsupported())
        }
        fn holds(&self, _p: u32, _l: u16, _r: u16) -> io::Result<bool> {
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
