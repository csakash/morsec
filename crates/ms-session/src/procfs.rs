//! Safe parsers for Linux `/proc` text files. Compiled everywhere so the tests run on macOS too.

/// Fields of `/proc/<pid>/stat` that session identity needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// `comm`, without the parentheses.
    pub comm: String,
    /// Parent PID.
    pub ppid: u32,
    /// Start time in clock ticks since boot.
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. `comm` may contain spaces and `)`, so the fields after it are
/// found from the *last* `)`.
pub fn parse_stat(s: &str) -> Option<Stat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = s.get(open + 1..close)?.to_owned();
    let rest: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    // rest[0] = state (field 3), rest[1] = ppid (field 4), rest[19] = starttime (field 22).
    let ppid = rest.get(1)?.parse().ok()?;
    let start_ticks = rest.get(19)?.parse().ok()?;
    Some(Stat {
        comm,
        ppid,
        start_ticks,
    })
}

/// Effective uid from `/proc/<pid>/status` (`Uid:` real, effective, saved, fs).
pub fn parse_status_euid(s: &str) -> Option<u32> {
    let line = s.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Boot time (Unix seconds) from `/proc/stat`.
pub fn parse_btime(s: &str) -> Option<u64> {
    let line = s.lines().find(|l| l.starts_with("btime "))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Start time in Unix milliseconds from boot time and start ticks.
pub fn start_unix_ms(btime_s: u64, start_ticks: u64, ticks_per_s: u64) -> Option<u64> {
    if ticks_per_s == 0 {
        return None;
    }
    let since_boot_ms = start_ticks.checked_mul(1000)? / ticks_per_s;
    btime_s.checked_mul(1000)?.checked_add(since_boot_ms)
}

/// The inode from a `/proc/<pid>/fd/<n>` link target such as `socket:[12345]`.
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=Linux parent/start-time reads; fails_when=a comm with spaces or ')' shifts the
    // fields; no_claim=live /proc behaviour (not exercised on macOS)
    #[test]
    fn stat_with_hostile_comm() {
        let s = "4242 (evil) 1 2 ) S 77 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        let st = parse_stat(s).expect("parses");
        assert_eq!(st.comm, "evil) 1 2 ");
        assert_eq!(st.ppid, 77);
        assert_eq!(st.start_ticks, 987654);
        assert!(parse_stat("1 (x S 1").is_none());
        assert!(parse_stat("").is_none());
    }

    // protects=uid and boot time reads; fails_when=real uid is taken instead of effective;
    // no_claim=other status fields
    #[test]
    fn status_and_btime() {
        let st = "Name:\tclaude\nUid:\t1000\t1001\t1000\t1000\nGid:\t1\t1\t1\t1\n";
        assert_eq!(parse_status_euid(st), Some(1001));
        assert_eq!(
            parse_btime("cpu 1 2\nbtime 1700000000\n"),
            Some(1_700_000_000)
        );
        assert_eq!(
            start_unix_ms(1_700_000_000, 250, 100),
            Some(1_700_000_002_500)
        );
        assert_eq!(start_unix_ms(1, 1, 0), None);
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("pipe:[1]"), None);
    }
}
