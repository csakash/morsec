//! The only `unsafe` in this crate: `sysctl(KERN_PROC_PID)`, four libproc calls and
//! `sandbox_check` on macOS.
//!
//! Each function passes an owned, correctly sized buffer to the kernel and returns owned Rust
//! values. Nothing here keeps a pointer past the call, and nothing parses kernel structs whose
//! layout `libc` does not define: `kinfo_proc` and `socket_fdinfo` come back as plain bytes and
//! are parsed in safe code (`crate::kinfo`, `crate::sockparse`) at offsets checked by unit tests
//! against `clang` `offsetof` values and by `tests/live.rs` against real processes and sockets.
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

fn pid_arg(pid: u32) -> io::Result<libc::c_int> {
    libc::c_int::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn len_arg(len: usize) -> io::Result<libc::c_int> {
    libc::c_int::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)`: the raw `struct kinfo_proc`, parsed in
/// `crate::kinfo`. Unlike `proc_pidinfo`, this works for every process (including root-owned
/// ones such as `login` and `launchd`), which is what `ps` uses. A PID with no process gives
/// `NotFound`.
pub(crate) fn kinfo_proc(pid: u32) -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid_arg(pid)?,
    ];
    let mut buf = vec![0u8; crate::kinfo::SIZE];
    let mut len: libc::size_t = buf.len();
    // SAFETY: `mib` is a live array of 4 ints and 4 is passed as its length. `buf` is an owned,
    // writable allocation of `len` bytes and `len` points at that size; the kernel writes at
    // most `len` bytes and stores the written length back in `len`. No new value is set
    // (`newp` null, `newlen` 0). No pointer outlives the call.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast::<c_void>(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if len == 0 {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    if len != crate::kinfo::SIZE {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short kinfo_proc",
        ));
    }
    Ok(buf)
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

// `sandbox_check` from libsystem_sandbox (part of libSystem, linked by default). Declared by
// hand: `libc` doesn't export it. It is variadic in the header; the call below passes no
// variadic arguments, which is valid with `SANDBOX_FILTER_NONE`.
unsafe extern "C" {
    fn sandbox_check(
        pid: libc::pid_t,
        operation: *const libc::c_char,
        filter: libc::c_int,
        ...
    ) -> libc::c_int;
}

/// `sandbox_check(pid, NULL, SANDBOX_FILTER_NONE)`: whether `pid` runs inside an App Sandbox or
/// Seatbelt profile (`sandbox-exec`, an agent's command sandbox). An error (no such process)
/// comes back as `Err`.
pub(crate) fn is_sandboxed(pid: u32) -> io::Result<bool> {
    let cpid = pid_arg(pid)?;
    // SAFETY: `operation` is null and the filter type is SANDBOX_FILTER_NONE (0), for which the
    // function reads no further arguments; nothing is written through any pointer.
    let r = unsafe { sandbox_check(cpid, std::ptr::null(), 0) };
    match r {
        0 => Ok(false),
        r if r > 0 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}
