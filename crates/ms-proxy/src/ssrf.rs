//! SSRF guard (ARI-42 INJ-4): resolve first, classify every address, connect only to one that
//! passed. The proxy never hands a host name to `connect`, so DNS rebinding between the check and
//! the connection can't move it.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

/// Why an address is not a public upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `127/8`, `::1`.
    Loopback,
    /// RFC 1918, `fc00::/7`.
    Private,
    /// `169.254/16` (includes cloud metadata `169.254.169.254`), `fe80::/10`.
    LinkLocal,
    /// `100.64/10`.
    SharedAddressSpace,
    /// `224/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`, `240/4`.
    Reserved,
    /// Documentation, benchmarking and IETF protocol-assignment ranges.
    SpecialPurpose,
}

/// Classifies `ip`. `None` means it may be used as an upstream.
pub fn classify(ip: IpAddr) -> Option<Blocked> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<Blocked> {
    let o = ip.octets();
    let b = match o {
        [0, ..] => Blocked::Unspecified,
        [127, ..] => Blocked::Loopback,
        [10, ..] | [192, 168, ..] => Blocked::Private,
        [172, x, ..] if (16..=31).contains(&x) => Blocked::Private,
        [169, 254, ..] => Blocked::LinkLocal,
        [100, x, ..] if (64..=127).contains(&x) => Blocked::SharedAddressSpace,
        [x, ..] if (224..=239).contains(&x) => Blocked::Multicast,
        [x, ..] if x >= 240 => Blocked::Reserved,
        [192, 0, 0, _] | [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => {
            Blocked::SpecialPurpose
        }
        [198, x, ..] if x == 18 || x == 19 => Blocked::SpecialPurpose,
        [192, 88, 99, _] => Blocked::SpecialPurpose,
        _ => return None,
    };
    Some(b)
}

fn classify_v6(ip: Ipv6Addr) -> Option<Blocked> {
    if ip.is_unspecified() {
        return Some(Blocked::Unspecified);
    }
    if ip.is_loopback() {
        return Some(Blocked::Loopback);
    }
    // Forms that carry an IPv4 address are judged by that address.
    if let Some(v4) = embedded_v4(ip) {
        // A mapped or translated public v4 address is still fine to use.
        return classify_v4(v4);
    }
    let s = ip.segments();
    let b = match s[0] {
        x if x & 0xfe00 == 0xfc00 => Blocked::Private,
        x if x & 0xffc0 == 0xfe80 => Blocked::LinkLocal,
        // Deprecated site-local fec0::/10.
        x if x & 0xffc0 == 0xfec0 => Blocked::Private,
        x if x & 0xff00 == 0xff00 => Blocked::Multicast,
        0x2001 if s[1] == 0x0db8 => Blocked::SpecialPurpose,
        // 2001::/23 IETF protocol assignments (Teredo 2001::/32 included).
        0x2001 if s[1] < 0x0200 => Blocked::SpecialPurpose,
        // 100::/64 discard-only.
        0x0100 if s[1] == 0 && s[2] == 0 && s[3] == 0 => Blocked::SpecialPurpose,
        _ => return None,
    };
    Some(b)
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`),
/// NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`) or 6to4 (`2002::/16`) address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if s[0..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
        return Some(tail);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && (s[2..6] == [0, 0, 0, 0] || s[2] == 1) {
        return Some(tail);
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// A boxed future, so [`Resolve`] stays object-safe without an extra crate.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// DNS resolution. The default uses the system resolver; tests inject a table.
pub trait Resolve: Send + Sync + std::fmt::Debug {
    /// Every address `host` resolves to, with `port` filled in.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>>;
}

/// The system resolver (`getaddrinfo` via tokio).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// Outcome of checking a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// Connect only to these, in order.
    Ok(Vec<SocketAddr>),
    /// Every address was refused; the first refusal is reported.
    Refused(IpAddr, Blocked),
    /// The name did not resolve.
    NoAddress,
}

/// Resolves `host` (a name or an IP literal) and keeps only addresses that pass [`classify`].
/// `allow_loopback` exists only for the in-crate tests, which run upstreams on 127.0.0.1.
pub(crate) async fn check(
    resolver: &dyn Resolve,
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> io::Result<Checked> {
    let addrs = match host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => resolver.resolve(host, port).await?,
    };
    if addrs.is_empty() {
        return Ok(Checked::NoAddress);
    }
    let mut ok = Vec::new();
    let mut first_refusal = None;
    for a in addrs {
        match classify(a.ip()) {
            None => ok.push(a),
            Some(Blocked::Loopback) if allow_loopback => ok.push(a),
            Some(b) => {
                first_refusal.get_or_insert((a.ip(), b));
            }
        }
    }
    Ok(match (ok.is_empty(), first_refusal) {
        (false, _) => Checked::Ok(ok),
        (true, Some((ip, b))) => Checked::Refused(ip, b),
        (true, None) => Checked::NoAddress,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Option<Blocked> {
        classify(s.parse().unwrap())
    }

    // protects=every listed non-public range is refused (INJ-4); fails_when=any of them is
    // classified as usable; no_claim=resolution and connect-to-checked-IP (see itests)
    #[test]
    fn blocked_ranges() {
        use Blocked::*;
        let table = [
            ("0.0.0.0", Unspecified),
            ("0.1.2.3", Unspecified),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("10.0.0.1", Private),
            ("172.16.0.1", Private),
            ("172.31.255.255", Private),
            ("192.168.1.1", Private),
            ("169.254.169.254", LinkLocal),
            ("169.254.0.1", LinkLocal),
            ("100.64.0.1", SharedAddressSpace),
            ("100.127.255.255", SharedAddressSpace),
            ("224.0.0.1", Multicast),
            ("239.255.255.250", Multicast),
            ("240.0.0.1", Reserved),
            ("255.255.255.255", Reserved),
            ("192.0.0.1", SpecialPurpose),
            ("192.0.2.1", SpecialPurpose),
            ("198.18.0.1", SpecialPurpose),
            ("198.19.255.1", SpecialPurpose),
            ("198.51.100.1", SpecialPurpose),
            ("203.0.113.1", SpecialPurpose),
            ("::", Unspecified),
            ("::1", Loopback),
            ("fc00::1", Private),
            ("fd00:ec2::254", Private),
            ("fec0::1", Private),
            ("fe80::1", LinkLocal),
            ("ff02::1", Multicast),
            ("2001:db8::1", SpecialPurpose),
            ("2001::1", SpecialPurpose),
            ("100::1", SpecialPurpose),
            ("::ffff:169.254.169.254", LinkLocal),
            ("::ffff:127.0.0.1", Loopback),
            ("::ffff:10.1.2.3", Private),
            ("::127.0.0.1", Loopback),
            ("64:ff9b::a9fe:a9fe", LinkLocal),
            ("64:ff9b:1::a00:1", Private),
            ("2002:a9fe:a9fe::1", LinkLocal),
            ("2002:7f00:1::", Loopback),
        ];
        for (ip, want) in table {
            assert_eq!(c(ip), Some(want), "{ip}");
        }
    }

    // protects=public addresses stay usable; fails_when=a public v4/v6 address (or a mapped
    // public one) is refused; no_claim=reachability
    #[test]
    fn public_ranges_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "52.84.1.1",
            "172.15.255.255",
            "172.32.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "169.253.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450::1",
            "::ffff:1.1.1.1",
            "64:ff9b::808:808",
            "2002:0808:0808::1",
        ] {
            assert_eq!(c(ip), None, "{ip}");
        }
    }

    #[derive(Debug)]
    struct Table(Vec<SocketAddr>);
    impl Resolve for Table {
        fn resolve<'a>(&'a self, _: &'a str, _: u16) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            let v = self.0.clone();
            Box::pin(async move { Ok(v) })
        }
    }

    // protects=a name resolving to a mix keeps only public addresses, a name resolving only to
    // private ones is refused, IP literals skip DNS but not the check; fails_when=a refused
    // address is returned for connecting; no_claim=the system resolver itself
    #[tokio::test]
    async fn check_filters() {
        let mixed = Table(vec![
            "10.0.0.1:443".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
        ]);
        assert_eq!(
            check(&mixed, "x.example", 443, false).await.unwrap(),
            Checked::Ok(vec!["1.1.1.1:443".parse().unwrap()])
        );
        let private = Table(vec!["169.254.169.254:80".parse().unwrap()]);
        assert!(matches!(
            check(&private, "metadata.example", 80, false)
                .await
                .unwrap(),
            Checked::Refused(_, Blocked::LinkLocal)
        ));
        let none = Table(vec![]);
        assert_eq!(
            check(&none, "nx.example", 80, false).await.unwrap(),
            Checked::NoAddress
        );
        assert!(matches!(
            check(&mixed, "[::1]", 443, false).await.unwrap(),
            Checked::Refused(_, Blocked::Loopback)
        ));
        assert!(matches!(
            check(&mixed, "127.0.0.1", 443, true).await.unwrap(),
            Checked::Ok(_)
        ));
        assert!(matches!(
            check(&mixed, "169.254.169.254", 80, true).await.unwrap(),
            Checked::Refused(_, Blocked::LinkLocal)
        ));
    }
}
