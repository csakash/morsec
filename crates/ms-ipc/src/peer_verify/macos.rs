//! The only `unsafe` in ms-ipc: reading the peer's audit token from a connected Unix socket
//! (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`), listing a process's descriptors and reading a
//! socket record (`proc_pidinfo` / `proc_pidfdinfo`), and reading this process's own Team ID
//! (`SecCodeCopySigningInformation`, which security-framework does not wrap). Socket records are
//! parsed in safe code (`parse_unix_record`).
//!
//! Why the signature alone is not enough: `LOCAL_PEERTOKEN` describes whatever image runs *now*
//! at the PID that last touched the listening socket. A process can listen, fork a child that
//! keeps the listener, and exec the genuine msd: the token then says "msd" while the child
//! accepts and reads. So the check also requires that the verified process itself holds the
//! server end of *this* connection, that nobody else holds a reference to it (not shared, not in
//! flight over `SCM_RIGHTS`, not inherited by a child) and that it is close-on-exec, and then it
//! looks the token up again so the image can't have changed while it looked.
#![allow(unsafe_code)]

use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::SecStaticCodeRef;

/// `sizeof(audit_token_t)`: eight 32-bit words.
const AUDIT_TOKEN_LEN: usize = 32;
/// `kSecCSSigningInformation` (CSCommon.h): include certificate-derived fields such as the team.
const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
}

/// The audit token of the process that listens on the other end of `fd`.
fn peer_audit_token(fd: BorrowedFd<'_>) -> Result<[u8; AUDIT_TOKEN_LEN], String> {
    let mut token = [0u8; AUDIT_TOKEN_LEN];
    let mut len = libc::socklen_t::try_from(AUDIT_TOKEN_LEN).map_err(|e| e.to_string())?;
    // SAFETY: `fd` is a live descriptor borrowed for this call; `token` is a writable buffer of
    // `len` bytes and `len` is a valid in/out length. The kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "can't read the peer's audit token: {}",
            std::io::Error::last_os_error()
        ));
    }
    if usize::try_from(len).ok() != Some(AUDIT_TOKEN_LEN) {
        return Err(format!("the kernel returned a {len}-byte audit token"));
    }
    Ok(token)
}

/// How long to wait for msd to accept the connection before giving up.
const ACCEPT_WAIT: Duration = Duration::from_secs(2);
/// `PROC_PIDFDSOCKETINFO` (`<sys/proc_info.h>`).
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
/// `PROX_FDTYPE_SOCKET`.
const PROX_FDTYPE_SOCKET: u32 = 2;
/// Most descriptors read from one process. msd caps its connections far below this; past it the
/// check fails closed (a false "did not accept", never a pass) (review S2).
const MAX_FDS: usize = 16_384;

/// Offsets into `struct socket_fdinfo` (LP64 macOS), from `clang` `offsetof` (the same layout
/// ms-session's `sockparse::darwin` uses) and checked against live sockets by
/// `unix_records_identify_the_accepted_end`.
mod rec {
    /// `sizeof(struct socket_fdinfo)`.
    pub const SIZE: usize = 792;
    /// `pfi.fi_status` (u32: `PROC_FP_*`).
    pub const FI_STATUS: usize = 4;
    /// `psi.soi_so` (u64: the kernel socket, address-permuted).
    pub const SOI_SO: usize = 160;
    /// `psi.soi_kind` (i32).
    pub const SOI_KIND: usize = 256;
    /// `psi.soi_proto.pri_un.unsi_conn_so` (u64: the connected peer socket).
    pub const UNSI_CONN_SO: usize = 264;
    /// `SOCKINFO_UN`.
    pub const SOCKINFO_UN: i32 = 3;
    /// `PROC_FP_SHARED`: the open file has more than one reference.
    pub const FP_SHARED: u32 = 1;
    /// `PROC_FP_CLEXEC`: close-on-exec.
    pub const FP_CLEXEC: u32 = 2;
}

/// The fields of a Unix-domain `socket_fdinfo` record this check needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnixRecord {
    /// `PROC_FP_*` flags of the descriptor.
    pub status: u32,
    /// This socket.
    pub so: u64,
    /// The socket it is connected to (0 when none).
    pub conn_so: u64,
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Parses a `socket_fdinfo` record. `None` for anything that is not a Unix-domain socket or is
/// malformed.
pub(super) fn parse_unix_record(b: &[u8]) -> Option<UnixRecord> {
    if b.len() != rec::SIZE {
        return None;
    }
    let kind = i32::from_ne_bytes(b.get(rec::SOI_KIND..rec::SOI_KIND + 4)?.try_into().ok()?);
    if kind != rec::SOCKINFO_UN {
        return None;
    }
    Some(UnixRecord {
        status: read_u32(b, rec::FI_STATUS)?,
        so: read_u64(b, rec::SOI_SO)?,
        conn_so: read_u64(b, rec::UNSI_CONN_SO)?,
    })
}

/// What one descriptor in the peer says about our connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ownership {
    /// Some other socket.
    NotOurs,
    /// The server end of our connection, held by this process alone and close-on-exec.
    Sole,
    /// The server end, but not (yet) safe. msd passes through both states briefly on its own:
    /// right after `accept` (close-on-exec is set by a second call) and while a child it forks
    /// has not exec'd yet (shared). The attacks leave them permanent (a holder never drops its
    /// copy on its own, and an inherited descriptor never becomes close-on-exec), so these are
    /// waited out until the deadline rather than refused at once (review R6).
    NotYet(&'static str),
}

/// The decision on one candidate descriptor in the peer.
pub(super) fn owns_server_end(r: &UnixRecord, server_so: u64) -> Ownership {
    if server_so == 0 || r.so != server_so {
        Ownership::NotOurs
    } else if r.status & rec::FP_SHARED != 0 {
        Ownership::NotYet("another process also holds this connection")
    } else if r.status & rec::FP_CLEXEC == 0 {
        Ownership::NotYet("msd's end of this connection is not close-on-exec")
    } else {
        Ownership::Sole
    }
}

/// msd closed the connection before the check finished, typically because the calling process
/// already holds msd's per-process connection limit (review R7). Nothing was sent.
const CLOSED_EARLY: &str = "msd closed the connection before it could be verified (msd refused it, or this process holds too many connections to msd)";

fn pid_arg(pid: u32) -> Result<libc::c_int, String> {
    libc::c_int::try_from(pid)
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| format!("bad peer pid {pid}"))
}

/// `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` for `fd` in `pid`, parsed.
fn unix_record(pid: libc::c_int, fd: libc::c_int) -> Option<UnixRecord> {
    let mut buf = vec![0u8; rec::SIZE];
    let size = libc::c_int::try_from(rec::SIZE).ok()?;
    // SAFETY: `buf` is an owned, writable allocation of exactly `size` bytes, so the kernel
    // can't write past it; byte buffers need no alignment for copyout.
    let n = unsafe {
        libc::proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf.as_mut_ptr().cast(), size)
    };
    if n != size {
        return None;
    }
    parse_unix_record(&buf)
}

/// Every socket descriptor of `pid`.
fn socket_fds(pid: libc::c_int) -> Result<Vec<libc::c_int>, String> {
    let rec_size = std::mem::size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer of size 0 asks only for the size needed; the kernel writes nothing.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(format!(
            "can't list msd's descriptors: {}",
            std::io::Error::last_os_error()
        ));
    }
    let cap = (usize::try_from(need).unwrap_or(0) / rec_size)
        .saturating_add(32)
        .min(MAX_FDS);
    let mut buf = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        cap
    ];
    let bytes = libc::c_int::try_from(cap * rec_size).map_err(|e| e.to_string())?;
    // SAFETY: `buf` owns `cap` initialised `proc_fdinfo`s and `bytes` is exactly their size.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            bytes,
        )
    };
    if n <= 0 {
        return Err(format!(
            "can't list msd's descriptors: {}",
            std::io::Error::last_os_error()
        ));
    }
    let count = (usize::try_from(n).unwrap_or(0) / rec_size).min(cap);
    Ok(buf[..count]
        .iter()
        .filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET)
        .map(|f| f.proc_fd)
        .collect())
}

/// Waits (up to [`ACCEPT_WAIT`]) until `pid` holds the server end of our connection (`own_fd`
/// in this process) alone and close-on-exec.
fn wait_for_sole_owner(pid: libc::c_int, own_fd: libc::c_int) -> Result<(), String> {
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    let deadline = Instant::now() + ACCEPT_WAIT;
    let mut last = None;
    loop {
        let ours = unix_record(me, own_fd)
            .ok_or_else(|| "can't read this connection's socket record".to_owned())?;
        if ours.conn_so == 0 {
            return Err(CLOSED_EARLY.into());
        }
        for fd in socket_fds(pid)? {
            match unix_record(pid, fd).map(|r| owns_server_end(&r, ours.conn_so)) {
                Some(Ownership::Sole) => return Ok(()),
                Some(Ownership::NotYet(why)) => last = Some(why),
                Some(Ownership::NotOurs) | None => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(match last {
                Some(why) => format!("{why} (still so after {}s)", ACCEPT_WAIT.as_secs()),
                None => format!(
                    "the verified process (pid {pid}) did not accept this connection; another process holds the socket"
                ),
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Looks the audit token up and checks it against `requirement`.
fn check_token(token: &[u8; AUDIT_TOKEN_LEN], requirement: &SecRequirement) -> Result<(), String> {
    let data = CFData::from_buffer(token);
    let mut attrs = GuestAttributes::new();
    // The dictionary retains `data`, and `data` outlives the lookup anyway.
    attrs.set_audit_token(data.as_concrete_TypeRef());
    // Host `None`: the kernel is asked. A token whose PID version no longer matches (the process
    // exited or exec'd since the token was read) is an error here, never another process.
    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
        .map_err(|e| format!("the peer's code can't be identified: {e}"))?;
    code.check_validity(Flags::NONE, requirement)
        .map_err(|e| e.to_string())
}

/// Checks that the server end of `fd` is held by one process alone, whose code satisfies
/// `requirement`, and that its image did not change while this looked.
pub(super) fn verify_peer(fd: BorrowedFd<'_>, requirement: &str) -> Result<(), String> {
    let requirement: SecRequirement = requirement
        .parse()
        .map_err(|e| format!("bad code requirement: {e}"))?;
    let token = peer_audit_token(fd)?;
    check_token(&token, &requirement)?;
    // audit_token_t val[5] is the PID.
    let pid = u32::from_ne_bytes([token[20], token[21], token[22], token[23]]);
    let pid = pid_arg(pid)?;
    wait_for_sole_owner(pid, fd.as_raw_fd())?;
    // Same token again: if the process exec'd (or exited) since the first lookup, its PID
    // version changed and this fails.
    check_token(&token, &requirement)
}

/// This process's Team ID: `Ok(None)` for unsigned, ad-hoc and linker-signed code.
pub(super) fn own_team_id() -> Result<Option<String>, String> {
    let me = SecCode::for_self(Flags::NONE).map_err(|e| e.to_string())?;
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `me` is a valid SecCodeRef for the call (Apple documents that a SecCodeRef may be
    // passed where a SecStaticCodeRef is expected); `info` is a valid out-pointer.
    let status = unsafe {
        SecCodeCopySigningInformation(
            me.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return Err(format!(
            "SecCodeCopySigningInformation failed (OSStatus {status})"
        ));
    }
    // SAFETY: `info` is a non-null CFDictionary returned under the create rule; wrapping it hands
    // that single reference to `dict`, which releases it on drop.
    let dict: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    // SAFETY: an immutable CFStringRef constant exported by Security.framework (linked above),
    // wrapped with the get rule, so no ownership is taken.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
    match dict.find(&key) {
        None => Ok(None),
        Some(v) => v
            .downcast::<CFString>()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| "the Team ID in this program's signature is not a string".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=a cargo-built (ad-hoc / linker-signed) binary reports no Team ID, so dev builds
    // take the refuse-or-opt-out path; fails_when=reading the own signature errors or invents a
    // team; no_claim=a Developer ID-signed binary (needs the release identity)
    #[test]
    fn test_binary_has_no_team() {
        assert_eq!(own_team_id(), Ok(None));
    }

    fn record(status: u32, so: u64, conn_so: u64, kind: i32) -> Vec<u8> {
        let mut b = vec![0u8; rec::SIZE];
        b[rec::FI_STATUS..rec::FI_STATUS + 4].copy_from_slice(&status.to_ne_bytes());
        b[rec::SOI_SO..rec::SOI_SO + 8].copy_from_slice(&so.to_ne_bytes());
        b[rec::SOI_KIND..rec::SOI_KIND + 4].copy_from_slice(&kind.to_ne_bytes());
        b[rec::UNSI_CONN_SO..rec::UNSI_CONN_SO + 8].copy_from_slice(&conn_so.to_ne_bytes());
        b
    }

    // protects=T-03 sole-owner rule: msd's end of the connection must be this socket, held by
    // msd alone (not dup'd, forked or in flight) and close-on-exec; fails_when=a shared or
    // inheritable server end passes, or a non-Unix / short record parses; no_claim=live kernel
    // values (unix_records_identify_the_accepted_end)
    #[test]
    fn sole_owner_decision_table() {
        let ok = parse_unix_record(&record(rec::FP_CLEXEC, 7, 9, rec::SOCKINFO_UN)).unwrap();
        assert_eq!(owns_server_end(&ok, 7), Ownership::Sole);
        assert_eq!(owns_server_end(&ok, 8), Ownership::NotOurs);
        assert_eq!(owns_server_end(&ok, 0), Ownership::NotOurs);
        let shared = UnixRecord {
            status: rec::FP_CLEXEC | rec::FP_SHARED,
            ..ok
        };
        assert!(
            matches!(owns_server_end(&shared, 7), Ownership::NotYet(w) if w.contains("another process"))
        );
        let inheritable = UnixRecord { status: 0, ..ok };
        assert!(
            matches!(owns_server_end(&inheritable, 7), Ownership::NotYet(w) if w.contains("close-on-exec"))
        );
        assert_eq!(parse_unix_record(&record(rec::FP_CLEXEC, 7, 9, 2)), None);
        assert_eq!(
            parse_unix_record(&record(rec::FP_CLEXEC, 7, 9, rec::SOCKINFO_UN)[..100]),
            None
        );
    }

    // protects=the record offsets match the running kernel: our end's conn_so is the accepted
    // socket's so, a fresh accepted socket is close-on-exec and unshared, and a dup marks it
    // shared; fails_when=an offset or flag is wrong (every verification would refuse, or a shared
    // socket would pass); no_claim=another process's descriptors (tests/peer_verify.rs in msd)
    #[test]
    fn unix_records_identify_the_accepted_end() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::Builder::new()
            .prefix("mspvr")
            .tempdir_in("/tmp")
            .unwrap();
        let path = dir.path().join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let ours = unix_record(me, client.as_raw_fd()).unwrap();
        let theirs = unix_record(me, accepted.as_raw_fd()).unwrap();
        assert_eq!(ours.conn_so, theirs.so);
        assert_eq!(owns_server_end(&theirs, ours.conn_so), Ownership::Sole);
        let dup = accepted.try_clone().unwrap();
        let shared = unix_record(me, accepted.as_raw_fd()).unwrap();
        assert!(matches!(
            owns_server_end(&shared, ours.conn_so),
            Ownership::NotYet(_)
        ));
        drop(dup);
        assert!(socket_fds(me).unwrap().contains(&accepted.as_raw_fd()));
    }

    fn pair(
        dir: &std::path::Path,
    ) -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        let path = dir.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        (client, listener.accept().unwrap().0)
    }

    // protects=review R6: msd's own brief states (shared while a forked child hasn't exec'd,
    // not close-on-exec right after accept) are waited out, not refused; fails_when=the real msd
    // is refused while it forks or accepts; no_claim=msd's actual fork timing (the attack tests
    // show the permanent states still fail)
    #[test]
    fn transient_states_are_waited_out() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::Builder::new()
            .prefix("mspvt")
            .tempdir_in("/tmp")
            .unwrap();
        let (client, accepted) = pair(dir.path());
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let dup = accepted.try_clone().unwrap();
        let fd = accepted.as_raw_fd();
        // SAFETY: `fd` is open (owned by `accepted`); F_SETFD only changes its descriptor flags.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(dup);
            std::thread::sleep(Duration::from_millis(300));
            // SAFETY: as above; `accepted` outlives this thread (joined below).
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        });
        let started = Instant::now();
        assert_eq!(wait_for_sole_owner(me, client.as_raw_fd()), Ok(()));
        assert!(started.elapsed() >= Duration::from_millis(500));
        t.join().unwrap();
    }

    // protects=review R7: a connection msd closes before the check finishes gets its own error,
    // not an impostor alarm; fails_when=it waits out the deadline and blames another process;
    // no_claim=msd's per-peer limit itself (ipc.rs per_peer_cap)
    #[test]
    fn closed_connection_is_reported_as_closed() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::Builder::new()
            .prefix("mspvc")
            .tempdir_in("/tmp")
            .unwrap();
        let (client, accepted) = pair(dir.path());
        drop(accepted);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let started = Instant::now();
        assert_eq!(
            wait_for_sole_owner(me, client.as_raw_fd()),
            Err(CLOSED_EARLY.into())
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    // protects=the Developer ID requirement for msd is valid requirement language;
    // fails_when=SecRequirementCreateWithString rejects it (every release client would refuse);
    // no_claim=that a real release msd satisfies it (manual check in PROOF.md)
    #[test]
    fn requirement_compiles() {
        let r = super::super::developer_id_requirement(super::super::MSD_IDENTIFIER, "ABCDE12345")
            .unwrap();
        assert!(r.parse::<SecRequirement>().is_ok(), "{r}");
    }
}
