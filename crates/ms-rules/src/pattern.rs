//! Host and command patterns, with exact matching, intersection and containment.
//!
//! Both kinds are closed under intersection: `a.intersect(b)` matches exactly the inputs that
//! match both `a` and `b`. That is what makes the project merge provably tighten-only.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most hosts in one rule.
pub const MAX_HOSTS: usize = 256;
/// Most command patterns in one rule.
pub const MAX_COMMANDS: usize = 256;
/// Most tokens in one command pattern.
pub const MAX_TOKENS: usize = 64;
/// Longest single token, in bytes.
pub const MAX_TOKEN_LEN: usize = 4096;
/// Longest host name, in bytes.
pub const MAX_HOST_LEN: usize = 253;

/// A host a key may be sent to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostPattern {
    /// Exactly this host: a lowercase DNS name or a canonical IP literal.
    Exact(String),
    /// `*.<suffix>`: any DNS name with one or more labels before `suffix`; never `suffix` itself
    /// and never an IP literal.
    Suffix(String),
}

impl HostPattern {
    /// Parses `api.stripe.com`, `*.example.com`, `10.0.0.1` or `::1`.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(suffix) = s.strip_prefix("*.") {
            validate_dns_name(suffix)?;
            if suffix.split('.').next_back().is_some_and(all_digits) {
                return Err(format!(
                    "wildcard host \"*.{suffix}\" ends in a numeric label; wildcards are for DNS names only"
                ));
            }
            return Ok(HostPattern::Suffix(suffix.to_owned()));
        }
        if s.contains('*') {
            return Err(format!(
                "host \"{s}\": '*' is only allowed as the whole first label, as in *.example.com"
            ));
        }
        if let Some(ip) = parse_ip(s) {
            return Ok(HostPattern::Exact(ip.to_string()));
        }
        validate_dns_name(s)?;
        Ok(HostPattern::Exact(s.to_owned()))
    }

    /// True when the (already normalised) host matches.
    pub fn matches(&self, host: &NormalHost) -> bool {
        match (self, host) {
            (HostPattern::Exact(e), h) => e == h.as_str(),
            (HostPattern::Suffix(_), NormalHost::Ip(_)) => false,
            (HostPattern::Suffix(s), NormalHost::Dns(h)) => is_strict_subdomain(h, s),
        }
    }

    /// The pattern matching exactly the hosts both match, if any.
    pub fn intersect(&self, other: &HostPattern) -> Option<HostPattern> {
        use HostPattern::*;
        match (self, other) {
            (Exact(a), Exact(b)) => (a == b).then(|| self.clone()),
            (Exact(e), p @ Suffix(_)) | (p @ Suffix(_), Exact(e)) => {
                p.matches(&NormalHost::parse(e)?).then(|| Exact(e.clone()))
            }
            (Suffix(a), Suffix(b)) => {
                if a == b || is_strict_subdomain(a, b) {
                    Some(Suffix(a.clone()))
                } else if is_strict_subdomain(b, a) {
                    Some(Suffix(b.clone()))
                } else {
                    None
                }
            }
        }
    }

    /// True when every host `self` matches, `other` matches too.
    pub fn is_within(&self, other: &HostPattern) -> bool {
        self.intersect(other).as_ref() == Some(self)
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => f.write_str(h),
            HostPattern::Suffix(s) => write!(f, "*.{s}"),
        }
    }
}

/// A request's destination host after normalisation. Anything that is not a plain DNS name or IP
/// literal (ports, userinfo, paths, brackets, odd characters) fails to normalise and so matches
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalHost {
    /// Lowercase DNS name without a trailing dot.
    Dns(String),
    /// IP literal, canonical text form.
    Ip(String),
}

impl NormalHost {
    /// Lowercases and strips one trailing dot; `None` when the input is not a bare host.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.len() > MAX_HOST_LEN + 1 {
            return None;
        }
        let lower = raw.to_ascii_lowercase();
        if let Some(ip) = parse_ip(&lower) {
            return Some(NormalHost::Ip(ip.to_string()));
        }
        let name = lower.strip_suffix('.').unwrap_or(&lower);
        validate_dns_name(name).ok()?;
        Some(NormalHost::Dns(name.to_owned()))
    }

    /// The normalised text.
    pub fn as_str(&self) -> &str {
        match self {
            NormalHost::Dns(s) | NormalHost::Ip(s) => s,
        }
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    // Only plain dotted-quad v4 and bracket-free v6; std rejects octal and shortened v4 forms.
    s.parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .or_else(|_| s.parse::<Ipv6Addr>().map(IpAddr::V6))
        .ok()
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `host` is `<one or more labels>.<suffix>`.
fn is_strict_subdomain(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() + 1
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

fn validate_dns_name(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_HOST_LEN {
        return Err(format!(
            "host \"{s}\" must be 1 to {MAX_HOST_LEN} bytes long"
        ));
    }
    for label in s.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(format!(
                "host \"{s}\" is not a lowercase DNS name (labels of a-z, 0-9 and '-', 1 to 63 bytes, separated by '.'; no port, path or user)"
            ));
        }
    }
    Ok(())
}

/// One position in a command pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Token {
    /// Exactly this argument.
    Lit(String),
    /// Any one argument (`*`).
    One,
}

impl Token {
    fn matches(&self, arg: &str) -> bool {
        match self {
            Token::Lit(l) => l == arg,
            Token::One => true,
        }
    }

    fn intersect(&self, other: &Token) -> Option<Token> {
        match (self, other) {
            (Token::Lit(a), Token::Lit(b)) => (a == b).then(|| self.clone()),
            (Token::Lit(_), Token::One) => Some(self.clone()),
            (Token::One, t) => Some(t.clone()),
        }
    }
}

/// An argv pattern: tokens matched position by position, optionally followed by `**` (zero or
/// more further arguments).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommandPattern {
    tokens: Vec<Token>,
    rest: bool,
}

impl CommandPattern {
    /// Parses the array form used in TOML. `*` is one argument, a final `**` is the rest, and a
    /// leading `\` makes a token literal (`\*` is a literal `*`).
    pub fn parse(raw: &[String]) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("a command pattern must not be empty".into());
        }
        if raw.len() > MAX_TOKENS + 1 {
            return Err(format!(
                "a command pattern has more than {MAX_TOKENS} tokens"
            ));
        }
        let mut tokens = Vec::with_capacity(raw.len());
        let mut rest = false;
        for (i, t) in raw.iter().enumerate() {
            if t.len() > MAX_TOKEN_LEN {
                return Err(format!(
                    "a command token is longer than {MAX_TOKEN_LEN} bytes"
                ));
            }
            match t.as_str() {
                "**" if i + 1 == raw.len() && i > 0 => rest = true,
                "**" => {
                    return Err(
                        "\"**\" is only allowed as the last token, after the program name".into(),
                    );
                }
                "*" if i == 0 => {
                    return Err("the program name (first token) must be literal, not \"*\"".into());
                }
                "*" => tokens.push(Token::One),
                s => match s.strip_prefix('\\') {
                    Some(lit) => tokens.push(Token::Lit(lit.to_owned())),
                    None => tokens.push(Token::Lit(s.to_owned())),
                },
            }
        }
        if tokens.len() > MAX_TOKENS {
            return Err(format!(
                "a command pattern has more than {MAX_TOKENS} tokens"
            ));
        }
        if tokens[0] == Token::Lit(String::new()) {
            return Err("the program name must not be empty".into());
        }
        Ok(Self { tokens, rest })
    }

    /// The array form, inverse of [`CommandPattern::parse`].
    pub fn to_strings(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .tokens
            .iter()
            .map(|t| match t {
                Token::One => "*".to_owned(),
                Token::Lit(s) if s.starts_with('\\') || s == "*" || s == "**" => format!("\\{s}"),
                Token::Lit(s) => s.clone(),
            })
            .collect();
        if self.rest {
            out.push("**".into());
        }
        out
    }

    /// True when `argv` matches.
    pub fn matches(&self, argv: &[String]) -> bool {
        let n = self.tokens.len();
        let len_ok = if self.rest {
            argv.len() >= n
        } else {
            argv.len() == n
        };
        len_ok && self.tokens.iter().zip(argv).all(|(t, a)| t.matches(a))
    }

    /// The literal argv when the pattern has no wildcards; such a pattern matches exactly one argv.
    pub fn literal(&self) -> Option<Vec<String>> {
        if self.rest {
            return None;
        }
        self.tokens
            .iter()
            .map(|t| match t {
                Token::Lit(s) => Some(s.clone()),
                Token::One => None,
            })
            .collect()
    }

    /// The pattern matching exactly the argvs both match, if any.
    pub fn intersect(&self, other: &CommandPattern) -> Option<CommandPattern> {
        let (a, b) = (&self.tokens, &other.tokens);
        let (short, long, short_rest, long_rest) = if a.len() <= b.len() {
            (a, b, self.rest, other.rest)
        } else {
            (b, a, other.rest, self.rest)
        };
        // A fixed-length short side can only meet the long side at equal length; a short side with
        // `**` accepts every length the long side can have.
        if !short_rest && long.len() != short.len() {
            return None;
        }
        let mut tokens = Vec::with_capacity(long.len());
        for (i, lt) in long.iter().enumerate() {
            match short.get(i) {
                Some(st) => tokens.push(st.intersect(lt)?),
                // Only reached when the short side has `**`: it accepts whatever long has here.
                None => tokens.push(lt.clone()),
            }
        }
        Some(CommandPattern {
            tokens,
            rest: short_rest && long_rest,
        })
    }

    /// True when every argv `self` matches, `other` matches too.
    pub fn is_within(&self, other: &CommandPattern) -> bool {
        self.intersect(other).as_ref() == Some(self)
    }
}

impl fmt::Display for CommandPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.to_strings().iter().map(|s| format!("{s:?}")).collect();
        write!(f, "[{}]", parts.join(", "))
    }
}

/// Pairwise intersection of two pattern sets, deduplicated and sorted: matches exactly what some
/// pattern of `a` and some pattern of `b` both match.
pub(crate) fn intersect_sets<T: Ord + Clone>(
    a: &[T],
    b: &[T],
    f: impl Fn(&T, &T) -> Option<T>,
) -> Vec<T> {
    let mut out: Vec<T> = a
        .iter()
        .flat_map(|x| b.iter().filter_map(|y| f(x, y)).collect::<Vec<_>>())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
pub(crate) mod tests_support {
    use proptest::prelude::*;

    pub(crate) fn host_pattern_strings() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec!["a.com", "b.a.com", "c.b.a.com", "x.com", "10.0.0.1"])
                .prop_map(String::from),
            prop::sample::select(vec!["*.a.com", "*.b.a.com", "*.com", "*.x.com"])
                .prop_map(String::from),
        ]
    }
    pub(crate) fn probe_host() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "a.com",
            "b.a.com",
            "c.b.a.com",
            "d.c.b.a.com",
            "x.com",
            "y.x.com",
            "com",
            "10.0.0.1",
            "z.b.a.com",
        ])
        .prop_map(String::from)
    }
    pub(crate) fn token() -> impl Strategy<Value = String> {
        prop::sample::select(vec!["a", "b", "*"]).prop_map(String::from)
    }
    pub(crate) fn pattern_strings() -> impl Strategy<Value = Vec<String>> {
        (
            prop::sample::select(vec!["git", "psql"]),
            prop::collection::vec(token(), 0..4),
            any::<bool>(),
        )
            .prop_map(|(p, mut v, rest)| {
                v.insert(0, p.to_owned());
                if rest {
                    v.push("**".into());
                }
                v
            })
    }
    pub(crate) fn probe_argv() -> impl Strategy<Value = Vec<String>> {
        (
            prop::sample::select(vec!["git", "psql"]),
            prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 0..6),
        )
            .prop_map(|(p, v)| {
                let mut out = vec![p.to_owned()];
                out.extend(v.into_iter().map(String::from));
                out
            })
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use proptest::prelude::*;

    fn h(s: &str) -> HostPattern {
        HostPattern::parse(s).unwrap()
    }
    fn nh(s: &str) -> NormalHost {
        NormalHost::parse(s).unwrap()
    }
    fn c(parts: &[&str]) -> CommandPattern {
        CommandPattern::parse(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    // protects=host patterns match exactly the documented hosts; fails_when=a wildcard matches its
    // apex, a look-alike suffix, an IP, or a host with port/userinfo/path; no_claim=DNS resolution
    // (L05 checks the resolved address)
    #[test]
    fn host_matching() {
        let w = h("*.example.com");
        assert!(w.matches(&nh("a.example.com")));
        assert!(w.matches(&nh("a.b.example.com")));
        assert!(w.matches(&nh("A.Example.COM.")));
        assert!(!w.matches(&nh("example.com")));
        assert!(!w.matches(&nh("aexample.com")));
        assert!(!w.matches(&nh("example.com.evil.net")));
        let e = h("api.stripe.com");
        assert!(e.matches(&nh("API.stripe.com")));
        assert!(!e.matches(&nh("api.stripe.com.evil.net")));
        assert_eq!(h("10.0.0.1"), HostPattern::Exact("10.0.0.1".into()));
        assert!(h("::1").matches(&nh("0:0:0:0:0:0:0:1")));
        for bad in [
            "api.stripe.com:443",
            "user@api.stripe.com",
            "api.stripe.com/x",
            "[::1]",
            "a..b",
            "",
            "-a.com",
            "a b.com",
            "ăpi.com",
            "api.stripe.com..",
        ] {
            assert!(NormalHost::parse(bad).is_none(), "normalised {bad:?}");
        }
    }

    // protects=only well-formed host patterns are accepted; fails_when=a bare or embedded '*',
    // uppercase, port or numeric wildcard suffix is accepted; no_claim=IDN/punycode handling
    #[test]
    fn host_pattern_parse_rejects() {
        for bad in [
            "*",
            "*.",
            "a.*.com",
            "*a.com",
            "**.a.com",
            "API.com",
            "a.com:443",
            "*.0.1",
            "*.10.0.0.1",
            "a.com/",
            "",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    // protects=command patterns parse and match per the grammar; fails_when='*' matches zero or two
    // args, '**' appears mid-pattern, the program is a wildcard, or escapes are lost;
    // no_claim=PATH resolution of argv[0]
    #[test]
    fn command_matching() {
        let p = c(&["psql", "-c", "*"]);
        assert!(p.matches(&argv(&["psql", "-c", "select 1"])));
        assert!(!p.matches(&argv(&["psql", "-c"])));
        assert!(!p.matches(&argv(&["psql", "-c", "a", "b"])));
        assert!(!p.matches(&argv(&["/usr/bin/psql", "-c", "a"])));
        let r = c(&["git", "push", "**"]);
        assert!(r.matches(&argv(&["git", "push"])));
        assert!(r.matches(&argv(&["git", "push", "origin", "main"])));
        assert!(!r.matches(&argv(&["git", "pull"])));
        let lit = c(&["echo", "\\*", "\\**", "\\\\x"]);
        assert!(lit.matches(&argv(&["echo", "*", "**", "\\x"])));
        assert!(!lit.matches(&argv(&["echo", "a", "**", "\\x"])));
        assert_eq!(lit.to_strings(), ["echo", "\\*", "\\**", "\\\\x"]);
        assert_eq!(lit.literal().unwrap(), argv(&["echo", "*", "**", "\\x"]));
        assert!(p.literal().is_none() && r.literal().is_none());
        for bad in [
            vec![],
            vec!["*"],
            vec!["**"],
            vec!["git", "**", "x"],
            vec![""],
        ] {
            let v: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(CommandPattern::parse(&v).is_err(), "accepted {bad:?}");
        }
    }

    proptest! {
        // protects=host intersection is exact (matches iff both match) and is_within is sound;
        // fails_when=the intersection matches a host one side rejects, or misses one both accept;
        // no_claim=hosts outside the generator's small alphabet
        #[test]
        fn host_intersection_is_exact(a in host_pattern_strings(), b in host_pattern_strings(), x in probe_host()) {
            let (a, b, x) = (h(&a), h(&b), nh(&x));
            let both = a.matches(&x) && b.matches(&x);
            let i = a.intersect(&b);
            prop_assert_eq!(i.as_ref().is_some_and(|i| i.matches(&x)), both);
            if a.is_within(&b) {
                prop_assert!(!a.matches(&x) || b.matches(&x));
            }
        }

        // protects=command intersection is exact and is_within is sound; fails_when=the
        // intersection accepts an argv one side rejects or misses one both accept;
        // no_claim=argvs outside the generator's alphabet
        #[test]
        fn command_intersection_is_exact(a in pattern_strings(), b in pattern_strings(), x in probe_argv()) {
            let (a, b) = (CommandPattern::parse(&a).unwrap(), CommandPattern::parse(&b).unwrap());
            let both = a.matches(&x) && b.matches(&x);
            let i = a.intersect(&b);
            prop_assert_eq!(i.as_ref().is_some_and(|i| i.matches(&x)), both, "{:?}", i);
            if a.is_within(&b) {
                prop_assert!(!a.matches(&x) || b.matches(&x));
            }
        }

        // protects=to_strings is the inverse of parse; fails_when=a pattern changes meaning when
        // written back to a file; no_claim=TOML quoting (store tests cover the file)
        #[test]
        fn command_roundtrip(a in pattern_strings(), lit in "[\\\\*a]{1,3}") {
            let mut a = a;
            a.insert(1, format!("\\{lit}"));
            let p = CommandPattern::parse(&a).unwrap();
            prop_assert_eq!(CommandPattern::parse(&p.to_strings()).unwrap(), p);
        }
    }
}
