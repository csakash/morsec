//! Safe parser for macOS `struct kinfo_proc` bytes from `sysctl(KERN_PROC_PID)`.
//!
//! Offsets are LP64 macOS (arm64 and x86_64), from `clang` `offsetof` on `<sys/sysctl.h>`
//! (recorded in `docs/evidence/session-identity.md`), and checked against live processes by
//! `tests/live.rs` (`reads_this_process`, `reads_root_owned_processes`).

/// `sizeof(struct kinfo_proc)`.
pub const SIZE: usize = 648;
/// `kp_proc.p_starttime.tv_sec` (i64); `tv_usec` (i32) follows at +8.
const START_SEC: usize = 0;
const START_USEC: usize = 8;
/// `kp_proc.p_pid` (i32).
const PID: usize = 40;
/// `kp_proc.p_comm` (char[17], NUL-terminated).
const COMM: usize = 243;
const COMM_LEN: usize = 17;
/// `kp_eproc.e_ucred.cr_uid` (effective uid, u32).
const UID: usize = 420;
/// `kp_eproc.e_ppid` (i32).
const PPID: usize = 560;

/// The fields of `kinfo_proc` that session identity needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kinfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id.
    pub ppid: u32,
    /// Effective uid.
    pub uid: u32,
    /// Start time, Unix milliseconds.
    pub started_unix_ms: u64,
    /// `p_comm`.
    pub comm: String,
}

fn bytes<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Parses a `kinfo_proc` record. `None` if it is the wrong size or holds impossible values.
pub fn parse(b: &[u8]) -> Option<Kinfo> {
    if b.len() != SIZE {
        return None;
    }
    let sec = u64::try_from(i64::from_ne_bytes(bytes(b, START_SEC)?)).ok()?;
    let usec = u64::try_from(i32::from_ne_bytes(bytes(b, START_USEC)?)).ok()?;
    if usec >= 1_000_000 {
        return None;
    }
    let pid = u32::try_from(i32::from_ne_bytes(bytes(b, PID)?)).ok()?;
    let ppid = u32::try_from(i32::from_ne_bytes(bytes(b, PPID)?)).ok()?;
    let uid = u32::from_ne_bytes(bytes(b, UID)?);
    let comm: Vec<u8> = b
        .get(COMM..COMM + COMM_LEN)?
        .iter()
        .copied()
        .take_while(|&c| c != 0)
        .collect();
    Some(Kinfo {
        pid,
        ppid,
        uid,
        started_unix_ms: sec.checked_mul(1000)?.checked_add(usec / 1000)?,
        comm: String::from_utf8_lossy(&comm).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: i32, ppid: i32, uid: u32, sec: i64, usec: i32, comm: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; SIZE];
        b[START_SEC..START_SEC + 8].copy_from_slice(&sec.to_ne_bytes());
        b[START_USEC..START_USEC + 4].copy_from_slice(&usec.to_ne_bytes());
        b[PID..PID + 4].copy_from_slice(&pid.to_ne_bytes());
        b[PPID..PPID + 4].copy_from_slice(&ppid.to_ne_bytes());
        b[UID..UID + 4].copy_from_slice(&uid.to_ne_bytes());
        b[COMM..COMM + comm.len()].copy_from_slice(comm);
        b
    }

    // protects=macOS process reads (start time, ppid, uid, name); fails_when=an offset or unit
    // is wrong; no_claim=that offsets match the running kernel (tests/live.rs checks that)
    #[test]
    fn parses_fields() {
        let k = parse(&record(466, 464, 501, 1_794_578_065, 658_123, b"claude")).unwrap();
        assert_eq!(
            k,
            Kinfo {
                pid: 466,
                ppid: 464,
                uid: 501,
                started_unix_ms: 1_794_578_065_658,
                comm: "claude".into()
            }
        );
        // A full 17-byte name without a NUL stops at the field end.
        let k = parse(&record(1, 0, 0, 1, 0, &[b'a'; 17])).unwrap();
        assert_eq!(k.comm.len(), 17);
    }

    // protects=fail closed on bad records; fails_when=a short buffer, negative pid or bogus
    // usec parses; no_claim=every corrupt field
    #[test]
    fn rejects_bad_records() {
        assert!(parse(&[0u8; 10]).is_none());
        assert!(parse(&record(-1, 0, 0, 1, 0, b"x")).is_none());
        assert!(parse(&record(1, 0, 0, -5, 0, b"x")).is_none());
        assert!(parse(&record(1, 0, 0, 1, 2_000_000, b"x")).is_none());
    }
}
