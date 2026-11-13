//! The only `unsafe` in this crate: four libproc calls on macOS.
//!
//! Each function passes an owned, correctly sized buffer to the kernel and returns owned Rust
//! values. Nothing here keeps a pointer past the call, and nothing parses kernel structs whose
//! layout `libc` does not define: the socket record comes back as plain bytes and is parsed in
//! safe code (`crate::sockparse`), at offsets that a test checks against a real socket.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;

/// Size of `struct socket_fdinfo` (`PROC_PIDFDSOCKETINFO_SIZE` in `<sys/proc_info.h>`).
pub(crate) const SOCKET_FDINFO_SIZE: usize = 792;
/// `PROC_PIDFDSOCKETINFO` flavor for `proc_pidfdinfo`. Not exported by `libc`.
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
/// Largest PID list accepted. macOS's `kern.maxproc` is far below this.
const MAX_PIDS: usize = 1 << 20;
/// Most file descriptors listed per process.
const MAX_FDS: usize = 1 << 20;

/// The fields of `proc_bsdinfo` that session identity needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BsdInfo {
    pub ppid: u32,
    pub uid: u32,
    pub start_sec: u64,
    pub start_usec: u64,
    pub comm: String,
}

fn pid_arg(pid: u32) -> io::Result<libc::c_int> {
    libc::c_int::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn len_arg(len: usize) -> io::Result<libc::c_int> {
    libc::c_int::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)`.
pub(crate) fn bsd_info(pid: u32) -> io::Result<BsdInfo> {
    let cpid = pid_arg(pid)?;
    let size = len_arg(size_of::<libc::proc_bsdinfo>())?;
    // SAFETY: `proc_bsdinfo` is a plain C struct of integers and byte arrays, so the all-zero
    // bit pattern is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a live, writable `proc_bsdinfo` and `size` is exactly its size, so the
    // kernel writes at most `size` bytes into memory we own. No pointer outlives the call.
    let n = unsafe {
        libc::proc_pidinfo(
            cpid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast::<c_void>(),
            size,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    if n != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short proc_bsdinfo",
        ));
    }
    let comm: Vec<u8> = info
        .pbi_comm
        .iter()
        .map(|&c| c.to_ne_bytes()[0])
        .take_while(|&b| b != 0)
        .collect();
    Ok(BsdInfo {
        ppid: info.pbi_ppid,
        uid: info.pbi_uid,
        start_sec: info.pbi_start_tvsec,
        start_usec: info.pbi_start_tvusec,
        comm: String::from_utf8_lossy(&comm).into_owned(),
    })
}

/// `proc_pidpath`: the executable path, when readable.
pub(crate) fn pid_path(pid: u32) -> io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let cpid = pid_arg(pid)?;
    let cap = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).unwrap_or(4096);
    let mut buf = vec![0u8; cap];
    let cap_u32 = u32::try_from(cap).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `buf` is an owned, writable allocation of `cap` bytes and `cap` is passed as its
    // size, so the kernel cannot write past it.
    let n = unsafe { libc::proc_pidpath(cpid, buf.as_mut_ptr().cast::<c_void>(), cap_u32) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let n = usize::try_from(n).unwrap_or(0).min(cap);
    buf.truncate(n);
    Ok(std::ffi::OsString::from_vec(buf).into())
}

/// `proc_listallpids`: every PID on the system.
pub(crate) fn list_all_pids() -> io::Result<Vec<u32>> {
    // SAFETY: a null buffer of size 0 asks only for the count; the kernel writes nothing.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    // Headroom for processes started between the two calls.
    let cap = usize::try_from(count)
        .unwrap_or(0)
        .saturating_add(256)
        .min(MAX_PIDS);
    let mut buf: Vec<libc::c_int> = vec![0; cap];
    let bytes = len_arg(cap * size_of::<libc::c_int>())?;
    // SAFETY: `buf` owns `cap` initialised `c_int`s and `bytes` is exactly their total size.
    let n = unsafe { libc::proc_listallpids(buf.as_mut_ptr().cast::<c_void>(), bytes) };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let n = usize::try_from(n).unwrap_or(0).min(cap);
    Ok(buf[..n]
        .iter()
        .filter_map(|&p| u32::try_from(p).ok())
        .filter(|&p| p > 0)
        .collect())
}

/// `proc_pidinfo(PROC_PIDLISTFDS)`: `(fd, fd type)` for every open descriptor of `pid`.
pub(crate) fn list_fds(pid: u32) -> io::Result<Vec<(i32, u32)>> {
    let cpid = pid_arg(pid)?;
    let rec = size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer of size 0 asks only for the size needed; the kernel writes nothing.
    let need =
        unsafe { libc::proc_pidinfo(cpid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(io::Error::last_os_error());
    }
    // Headroom for descriptors opened between the two calls.
    let cap = (usize::try_from(need).unwrap_or(0) / rec)
        .saturating_add(32)
        .min(MAX_FDS);
    let mut buf: Vec<libc::proc_fdinfo> = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        cap
    ];
    let bytes = len_arg(cap * rec)?;
    // SAFETY: `buf` owns `cap` initialised `proc_fdinfo`s and `bytes` is exactly their size.
    let n = unsafe {
        libc::proc_pidinfo(
            cpid,
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast::<c_void>(),
            bytes,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    let count = (usize::try_from(n).unwrap_or(0) / rec).min(cap);
    Ok(buf[..count]
        .iter()
        .map(|f| (f.proc_fd, f.proc_fdtype))
        .collect())
}

/// `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`: the raw `socket_fdinfo` record for `fd` in `pid`.
pub(crate) fn socket_info(pid: u32, fd: i32) -> io::Result<Vec<u8>> {
    let cpid = pid_arg(pid)?;
    let mut buf = vec![0u8; SOCKET_FDINFO_SIZE];
    let size = len_arg(SOCKET_FDINFO_SIZE)?;
    // SAFETY: `buf` is an owned, writable allocation of `SOCKET_FDINFO_SIZE` bytes, the size
    // passed, so the kernel cannot write past it. Byte buffers have no alignment requirement
    // for `copyout`.
    let n = unsafe {
        libc::proc_pidfdinfo(
            cpid,
            fd,
            PROC_PIDFDSOCKETINFO,
            buf.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    if n != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short socket_fdinfo",
        ));
    }
    Ok(buf)
}
