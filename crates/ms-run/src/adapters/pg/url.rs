//! Postgres connection URIs: split the password out, rewrite the rest (SPEC D2, D3).
//!
//! Only the URI form (`postgres://` / `postgresql://`) is accepted. It is split the way libpq
//! splits it (`conninfo_uri_parse_options`): the userinfo is everything before the first `@` that
//! comes before any `/` (a `?` doesn't stop that search); the user ends at the first `:`; the
//! host list then ends at the first `/` or `?`, and the database at the first `?`. So the host
//! and user morsec writes into the passfile, and the password it takes out, are libpq's.

use zeroize::Zeroizing;

/// Added to `options` for read-only rules.
pub const READ_ONLY_OPTION: &str = "-c default_transaction_read_only=on";
/// `connect_timeout` added when the URL has none, seconds. Below the passfile's lifetime.
pub const CONNECT_TIMEOUT_SECS: u32 = 10;

/// A parsed URI. `Debug` never shows the password.
pub struct PgUrl {
    scheme: &'static str,
    user_raw: Option<String>,
    user: Option<String>,
    password: Option<Zeroizing<Vec<u8>>>,
    hosts_raw: String,
    host_param: Option<String>,
    path_raw: String,
    params: Vec<(String, String)>,
}

impl std::fmt::Debug for PgUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUrl")
            .field("user", &self.user)
            .field("hosts", &self.hosts_raw)
            .field("password", &self.password.as_ref().map(|_| "[hidden]"))
            .finish_non_exhaustive()
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes `s` (libpq doesn't turn `+` into a space).
fn decode(s: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) else {
                return Err("the key's URL has a malformed %-escape".into());
            };
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn decode_text(s: &str) -> Result<String, String> {
    String::from_utf8(decode(s)?.to_vec())
        .map_err(|_| "the key's URL has a %-escape that isn't UTF-8".into())
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Every `host[:port]` / `[v6][:port]` in a host list has a numeric (or no) port.
fn ports_numeric(hosts: &str) -> bool {
    let digits = |p: &str| p.is_empty() || p.bytes().all(|b| b.is_ascii_digit());
    hosts.split(',').all(|h| {
        if let Some(r) = h.strip_prefix('[') {
            match r.split_once(']') {
                Some((_, rest)) => rest.is_empty() || rest.strip_prefix(':').is_some_and(digits),
                None => false,
            }
        } else {
            h.split_once(':').is_none_or(|(_, p)| digits(p))
        }
    })
}

impl PgUrl {
    /// Parses a key's value.
    pub fn parse(value: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(value)
            .map_err(|_| "the key's value is not text, so it isn't a postgres:// URL")?;
        let (scheme, rest) = if let Some(r) = text.strip_prefix("postgresql://") {
            ("postgresql", r)
        } else if let Some(r) = text.strip_prefix("postgres://") {
            ("postgres", r)
        } else {
            return Err("the key's value must be a postgres:// or postgresql:// URL (a keyword/value connection string isn't supported)".into());
        };
        if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(
                "the key's URL contains whitespace or a control character; %-encode it".into(),
            );
        }
        // libpq: scan for '@' stopping only at '/'.
        let (userinfo, after_user) = match rest.find(['@', '/']) {
            Some(i) if rest.as_bytes()[i] == b'@' => (Some(&rest[..i]), &rest[i + 1..]),
            _ => (None, rest),
        };
        let host_end = after_user.find(['/', '?']).unwrap_or(after_user.len());
        let hosts_raw = &after_user[..host_end];
        let after_host = &after_user[host_end..];
        let (path_raw, query) = match after_host.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (after_host, None),
        };
        // A password with an unencoded '/' or a second '@' leaves part of it in the host or
        // database, which would go into argv: refuse rather than follow libpq there.
        if hosts_raw.contains('@') || after_host.contains('@') || !ports_numeric(hosts_raw) {
            return Err("the key's URL has an unencoded '@', '/' or ':' in its user or password (or a port that isn't a number); %-encode them".into());
        }
        let mut user_raw = None;
        let mut user = None;
        let mut password = None;
        if let Some(ui) = userinfo {
            let (u, p) = match ui.split_once(':') {
                Some((u, p)) => (u, Some(p)),
                None => (ui, None),
            };
            if !u.is_empty() {
                user = Some(decode_text(u)?);
                user_raw = Some(u.to_owned());
            }
            if let Some(p) = p {
                password = Some(decode(p)?);
            }
        }
        let mut params = Vec::new();
        let mut host_param = None;
        for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode_text(k)?;
            match key.as_str() {
                "password" => {
                    if password.is_some() {
                        return Err("the key's URL has a password twice (in the user part and as password=)".into());
                    }
                    password = Some(decode(v)?);
                }
                "passfile" => {
                    return Err("the key's URL sets passfile=, which morsec sets itself; remove it from the stored URL".into());
                }
                "sslpassword" => {
                    return Err("the key's URL carries sslpassword=, a secret morsec would have to put in the command line; use an unencrypted client key file instead".into());
                }
                "user" => {
                    if user.is_some() {
                        return Err(
                            "the key's URL names the user twice (in the user part and as user=)"
                                .into(),
                        );
                    }
                    user = Some(decode_text(v)?);
                    params.push((key, v.to_owned()));
                }
                "options" => {
                    decode_text(v)?;
                    params.push((key, v.to_owned()));
                }
                "dbname" => {
                    return Err("the key's URL sets dbname=; put the database in the path (postgres://…/db) instead".into());
                }
                "host" => {
                    host_param = Some(decode_text(v)?);
                    params.push((key, v.to_owned()));
                }
                _ => params.push((key, v.to_owned())),
            }
        }
        if password.as_ref().is_some_and(|p| p.is_empty()) {
            password = None;
        }
        Ok(Self {
            scheme,
            user_raw,
            user,
            password,
            hosts_raw: hosts_raw.to_owned(),
            host_param,
            path_raw: path_raw.to_owned(),
            params,
        })
    }

    /// The password, when the URL has one.
    pub fn password(&self) -> Option<&[u8]> {
        self.password.as_deref().map(|v| v.as_slice())
    }

    /// The user libpq will log in as, when the URL names one.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The host for the passfile line: the single TCP host the URL names, else `*`.
    pub fn passfile_host(&self) -> String {
        let spec = match &self.host_param {
            Some(h) => h.clone(),
            None => match decode_text(&self.hosts_raw) {
                Ok(h) => h,
                Err(_) => return "*".into(),
            },
        };
        if spec.is_empty() || spec.contains(',') || spec.starts_with('/') {
            return "*".into();
        }
        if self.host_param.is_some() {
            return spec;
        }
        // `[v6]:port` or `name:port`.
        if let Some(r) = spec.strip_prefix('[') {
            return r.split_once(']').map_or("*".into(), |(h, _)| h.to_owned());
        }
        spec.split(':').next().unwrap_or("*").to_owned()
    }

    /// The URL without any password, with `connect_timeout` (when absent) and, for read-only
    /// rules, `default_transaction_read_only=on` in `options`.
    pub fn rewritten(&self, read_only: bool) -> String {
        self.rewritten_inner(read_only, None)
    }

    /// [`PgUrl::rewritten`] for another database on the same server (the read-only check
    /// covers every database the role can connect to, since psql can `\c` to them).
    pub fn rewritten_db(&self, read_only: bool, db: &str) -> String {
        self.rewritten_inner(read_only, Some(db))
    }

    fn rewritten_inner(&self, read_only: bool, db: Option<&str>) -> String {
        let mut out = format!("{}://", self.scheme);
        if let Some(u) = &self.user_raw {
            out.push_str(u);
            out.push('@');
        }
        out.push_str(&self.hosts_raw);
        match db {
            Some(d) => {
                out.push('/');
                out.push_str(&encode(d));
            }
            None => out.push_str(&self.path_raw),
        }
        let mut params: Vec<(String, String)> = Vec::new();
        let mut had_options = false;
        let mut had_timeout = false;
        for (k, v) in &self.params {
            match k.as_str() {
                "options" if read_only => {
                    had_options = true;
                    // Checked to decode when parsed.
                    let old = decode_text(v).unwrap_or_default();
                    let merged = if old.trim().is_empty() {
                        READ_ONLY_OPTION.to_owned()
                    } else {
                        format!("{old} {READ_ONLY_OPTION}")
                    };
                    params.push((k.clone(), encode(&merged)));
                }
                _ => {
                    had_timeout |= k == "connect_timeout";
                    params.push((encode(k), v.clone()));
                }
            }
        }
        if read_only && !had_options {
            params.push(("options".into(), encode(READ_ONLY_OPTION)));
        }
        if !had_timeout {
            params.push(("connect_timeout".into(), CONNECT_TIMEOUT_SECS.to_string()));
        }
        for (i, (k, v)) in params.iter().enumerate() {
            out.push(if i == 0 { '?' } else { '&' });
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=SPEC D2: the rewritten URL never carries the password in any form libpq reads
    // (userinfo, password=), and the host/user used for the passfile are libpq's; fails_when=a
    // password survives the rewrite or the split disagrees with libpq's; no_claim=libpq itself
    #[test]
    fn password_is_split_out() {
        let u = PgUrl::parse(b"postgres://app:s%40cr3t@db.example.com:5433/shop?sslmode=require")
            .unwrap();
        assert_eq!(u.password(), Some(&b"s@cr3t"[..]));
        assert_eq!(u.user(), Some("app"));
        assert_eq!(u.passfile_host(), "db.example.com");
        let r = u.rewritten(false);
        assert_eq!(
            r,
            "postgres://app@db.example.com:5433/shop?sslmode=require&connect_timeout=10"
        );
        assert!(!format!("{u:?}").contains("cr3t"));

        let u =
            PgUrl::parse(b"postgresql://h/db?user=ro&password=pw%3Ax&connect_timeout=3").unwrap();
        assert_eq!(u.password(), Some(&b"pw:x"[..]));
        assert_eq!(u.user(), Some("ro"));
        let r = u.rewritten(false);
        assert!(!r.contains("pw") && !r.contains("password"), "{r}");
        assert!(r.ends_with("?user=ro&connect_timeout=3"), "{r}");
        assert_eq!(
            u.rewritten_db(true, "other db"),
            "postgresql://h/other%20db?user=ro&connect_timeout=3&options=-c%20default_transaction_read_only%3Don"
        );

        let u = PgUrl::parse(b"postgres://u:p@[::1]:5432,other/db").unwrap();
        assert_eq!(u.passfile_host(), "*");
        let u = PgUrl::parse(b"postgres://u:p@[::1]:5432/db").unwrap();
        assert_eq!(u.passfile_host(), "::1");
        // libpq's split: a '?' in the userinfo is part of the password.
        let u = PgUrl::parse(b"postgres://app:pa?ss@db/shop").unwrap();
        assert_eq!(u.password(), Some(&b"pa?ss"[..]));
        assert_eq!(u.passfile_host(), "db");
        assert_eq!(
            u.rewritten(false),
            "postgres://app@db/shop?connect_timeout=10"
        );
        let u = PgUrl::parse(b"postgres://h?application_name=a@b").unwrap();
        assert_eq!(u.user(), Some("h?application_name=a"));
        assert_eq!(u.passfile_host(), "b");
        // An '@' after the first '/' must be %-encoded (review F3: a password with '/' would
        // otherwise spill into the query and argv).
        assert!(PgUrl::parse(b"postgres://h/db?application_name=a@b").is_err());
        let u = PgUrl::parse(b"postgres://h/db?application_name=a%40b").unwrap();
        assert_eq!(u.user(), None);
        assert_eq!(u.passfile_host(), "h");
        let u = PgUrl::parse(b"postgres://u@%2Ftmp%2Fsock/db").unwrap();
        assert_eq!(u.passfile_host(), "*");
        assert!(u.password().is_none());
    }

    // protects=SPEC D2: values morsec can't place safely are refused, never passed on; fails_when=
    // a passfile= override, an sslpassword, a duplicate password or a non-URI DSN is accepted;
    // no_claim=-
    #[test]
    fn unsafe_urls_are_refused() {
        for bad in [
            &b"host=db password=x"[..],
            b"postgres://u:p@h/db?password=q",
            b"postgres://u@h/db?passfile=/tmp/x",
            b"postgres://u@h/db?sslpassword=k",
            b"postgres://u@h/db?user=v",
            b"postgres://u:p%zz@h/db",
            b"postgres://u:p@h/d b",
            b"postgres://u:p@h/db?options=%ff",
            b"postgres://u:p@h/db?dbname=other",
            b"postgres://app:pa/ss@db/shop",
            b"postgres://app:p@ss@db/shop",
            b"postgres://h:5x/db",
            b"postgres://app:2024/secret?x@db/shop",
            b"\xff",
        ] {
            assert!(
                PgUrl::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    // protects=SPEC D3: a read-only rule adds default_transaction_read_only=on to options,
    // merged with options already there; fails_when=the option is missing or replaces the
    // user's; no_claim=that the GUC alone stops writes (the role check does)
    #[test]
    fn read_only_option() {
        let u = PgUrl::parse(b"postgres://u:p@h/db").unwrap();
        assert_eq!(
            u.rewritten(true),
            "postgres://u@h/db?options=-c%20default_transaction_read_only%3Don&connect_timeout=10"
        );
        let u = PgUrl::parse(b"postgres://u:p@h/db?options=-c%20search_path%3Dapp").unwrap();
        let r = u.rewritten(true);
        assert!(
            r.contains("options=-c%20search_path%3Dapp%20-c%20default_transaction_read_only%3Don"),
            "{r}"
        );
    }
}
