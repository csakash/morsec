//! Safe parsers for kernel socket tables.
//!
//! - macOS: the `struct socket_fdinfo` bytes from `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`.
//! - Linux: rows of `/proc/net/tcp` and `/proc/net/tcp6`.
//!
//! Both are compiled on every platform so their unit tests run everywhere.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A TCP socket's two ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpEnds {
    /// This socket's own address.
    pub local: SocketAddr,
    /// The other end.
    pub remote: SocketAddr,
}

/// Offsets into `struct socket_fdinfo` (`<sys/proc_info.h>`, LP64 macOS). Checked against a
/// real socket by `tests/port.rs` and against `clang` `offsetof` output recorded in
/// `docs/evidence/session-identity.md`.
pub(crate) mod darwin {
    /// `sizeof(struct socket_fdinfo)`.
    pub const SIZE: usize = 792;
    /// `psi.soi_kind`.
    pub const SOI_KIND: usize = 256;
    /// `psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport` (int, port in network order).
    pub const FPORT: usize = 264;
    /// `…insi_lport`.
    pub const LPORT: usize = 268;
    /// `…insi_vflag` (u_char).
    pub const VFLAG: usize = 288;
    /// `…insi_faddr` (16-byte union).
    pub const FADDR: usize = 296;
    /// `…insi_laddr`.
    pub const LADDR: usize = 312;
    /// `SOCKINFO_TCP`.
    pub const SOCKINFO_TCP: i32 = 2;
    /// `INI_IPV4`.
    pub const INI_IPV4: u8 = 0x1;
    /// `INI_IPV6`.
    pub const INI_IPV6: u8 = 0x2;
}

fn read_i32_ne(b: &[u8], at: usize) -> Option<i32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(i32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_port(b: &[u8], at: usize) -> Option<u16> {
    // The kernel stores the in_pcb's u_short port (network byte order) in an int field. In
    // memory the u_short sits in the int's low-order bytes, which on little-endian are the first
    // two. Both supported macOS targets (arm64, x86_64) are little-endian.
    let v = u32::try_from(read_i32_ne(b, at)?).ok()?;
    let raw = u16::try_from(v).ok()?;
    Some(u16::from_be(raw))
}

fn read_addr(b: &[u8], at: usize, v6: bool) -> Option<IpAddr> {
    let s: [u8; 16] = b.get(at..at.checked_add(16)?)?.try_into().ok()?;
    if v6 {
        Some(IpAddr::V6(Ipv6Addr::from(s)))
    } else {
        // `struct in4in6_addr`: 12 bytes of padding, then the IPv4 address.
        Some(IpAddr::V4(Ipv4Addr::new(s[12], s[13], s[14], s[15])))
    }
}

/// Parses a macOS `socket_fdinfo` record. `None` for anything that is not a TCP/IP socket or
/// is malformed.
pub fn parse_darwin_socket_fdinfo(b: &[u8]) -> Option<TcpEnds> {
    use darwin::*;
    if b.len() != SIZE {
        return None;
    }
    if read_i32_ne(b, SOI_KIND)? != SOCKINFO_TCP {
        return None;
    }
    let vflag = *b.get(VFLAG)?;
    let v6 = if vflag & INI_IPV6 != 0 {
        true
    } else if vflag & INI_IPV4 != 0 {
        false
    } else {
        return None;
    };
    let local = SocketAddr::new(read_addr(b, LADDR, v6)?, read_port(b, LPORT)?);
    let remote = SocketAddr::new(read_addr(b, FADDR, v6)?, read_port(b, FPORT)?);
    Some(TcpEnds { local, remote })
}

/// One row of `/proc/net/tcp{,6}`: the socket's ends and its inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcNetTcpRow {
    /// Ends of the socket.
    pub ends: TcpEnds,
    /// Socket inode, matched against `/proc/<pid>/fd/*` links (`socket:[inode]`).
    pub inode: u64,
}

fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        // The kernel prints the in-memory u32 in host order; on little-endian hosts the bytes
        // come out reversed. `from_str_radix` + `to_ne_bytes` undoes exactly what it printed.
        8 => {
            let v = u32::from_str_radix(ip, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = ip.get(i * 8..i * 8 + 8)?;
                let v = u32::from_str_radix(word, 16).ok()?;
                chunk.copy_from_slice(&v.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses one data row of `/proc/net/tcp` or `/proc/net/tcp6`. The header row and malformed
/// rows give `None`.
pub fn parse_proc_net_tcp_row(line: &str) -> Option<ProcNetTcpRow> {
    let mut f = line.split_whitespace();
    let _sl = f.next()?.strip_suffix(':')?;
    let local = parse_hex_addr(f.next()?)?;
    let remote = parse_hex_addr(f.next()?)?;
    // st, tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode
    let inode = f.nth(6)?.parse().ok()?;
    Some(ProcNetTcpRow {
        ends: TcpEnds { local, remote },
        inode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn darwin_record(v6: bool, l: (IpAddr, u16), r: (IpAddr, u16)) -> Vec<u8> {
        use darwin::*;
        let mut b = vec![0u8; SIZE];
        b[SOI_KIND..SOI_KIND + 4].copy_from_slice(&SOCKINFO_TCP.to_ne_bytes());
        b[VFLAG] = if v6 { INI_IPV6 } else { INI_IPV4 };
        let port = |p: u16| i32::from(u16::from_ne_bytes(p.to_be_bytes())).to_ne_bytes();
        b[LPORT..LPORT + 4].copy_from_slice(&port(l.1));
        b[FPORT..FPORT + 4].copy_from_slice(&port(r.1));
        let put = |b: &mut Vec<u8>, at: usize, ip: IpAddr| match ip {
            IpAddr::V4(a) => b[at + 12..at + 16].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => b[at..at + 16].copy_from_slice(&a.octets()),
        };
        put(&mut b, LADDR, l.0);
        put(&mut b, FADDR, r.0);
        b
    }

    // protects=port->pid parsing of macOS socket records; fails_when=offsets or byte order are
    // wrong; no_claim=that the offsets match the running kernel (tests/port.rs checks that)
    #[test]
    fn darwin_v4_and_v6_round_trip() {
        let lo4: IpAddr = Ipv4Addr::LOCALHOST.into();
        let b = darwin_record(false, (lo4, 51234), (lo4, 4600));
        let e = parse_darwin_socket_fdinfo(&b).expect("tcp v4");
        assert_eq!(e.local, SocketAddr::new(lo4, 51234));
        assert_eq!(e.remote, SocketAddr::new(lo4, 4600));

        let lo6: IpAddr = Ipv6Addr::LOCALHOST.into();
        let b = darwin_record(true, (lo6, 1), (lo6, 65535));
        let e = parse_darwin_socket_fdinfo(&b).expect("tcp v6");
        assert_eq!(e.local, SocketAddr::new(lo6, 1));
        assert_eq!(e.remote, SocketAddr::new(lo6, 65535));
    }

    // protects=fail closed on non-TCP or truncated records; fails_when=a UDP/unix record or a
    // short buffer parses as TCP; no_claim=coverage of every socket kind
    #[test]
    fn darwin_rejects_non_tcp_and_bad_sizes() {
        let lo4: IpAddr = Ipv4Addr::LOCALHOST.into();
        let mut b = darwin_record(false, (lo4, 1), (lo4, 2));
        b[darwin::SOI_KIND] = 1; // SOCKINFO_IN (UDP)
        assert!(parse_darwin_socket_fdinfo(&b).is_none());
        let b = darwin_record(false, (lo4, 1), (lo4, 2));
        assert!(parse_darwin_socket_fdinfo(&b[..100]).is_none());
        let mut b = darwin_record(false, (lo4, 1), (lo4, 2));
        b[darwin::VFLAG] = 0;
        assert!(parse_darwin_socket_fdinfo(&b).is_none());
    }

    // protects=Linux /proc/net/tcp parsing; fails_when=address byte order, port or inode column
    // is misread; no_claim=big-endian hosts
    #[test]
    #[cfg(target_endian = "little")]
    fn proc_net_tcp_rows() {
        let v4 = "   3: 0100007F:C822 0100007F:11F8 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 4 30 10 -1";
        let r = parse_proc_net_tcp_row(v4).expect("v4 row");
        assert_eq!(r.ends.local, "127.0.0.1:51234".parse().unwrap());
        assert_eq!(r.ends.remote, "127.0.0.1:4600".parse().unwrap());
        assert_eq!(r.inode, 123456);

        let v6 = "   0: 00000000000000000000000001000000:C822 00000000000000000000000001000000:11F8 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 20 4 30 10 -1";
        let r = parse_proc_net_tcp_row(v6).expect("v6 row");
        assert_eq!(r.ends.local, "[::1]:51234".parse().unwrap());
        assert_eq!(r.inode, 777);

        assert!(parse_proc_net_tcp_row("  sl  local_address rem_address   st tx_queue").is_none());
        assert!(parse_proc_net_tcp_row("").is_none());
        assert!(parse_proc_net_tcp_row("   1: zz:1 0100007F:11F8 01").is_none());
    }
}
