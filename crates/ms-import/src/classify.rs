//! Decides, per `.env` entry, whether it is a secret, which provider it belongs to and its tier.

use ms_core::{SecretRef, Tier};

use crate::catalog::{Catalog, Provider};
use crate::dotenv::Entry;

/// What the classifier found for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// Already an `ms://` reference.
    AlreadyRef,
    /// Uses `${…}`/`$NAME`; left untouched.
    Interpolated,
    /// Empty value.
    Empty,
    /// Public by design (publishable key or a browser-bundled variable).
    Public,
    /// Not a secret by any rule.
    NotSecret,
    /// A secret.
    Secret(Secret),
}

/// A secret and what is known about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Provider id, or `None` when unknown.
    pub provider: Option<String>,
    /// Tier, from the strongest hint, or `None` when nothing hints.
    pub tier_hint: Option<Tier>,
    /// What may be shown of the value: a public catalog prefix or URL scheme, else empty.
    pub shown_prefix: String,
}

/// Name tokens that mark a secret.
const SECRET_TOKENS: &[&str] = &[
    "KEY",
    "KEYS",
    "SECRET",
    "SECRETS",
    "TOKEN",
    "TOKENS",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "PASS",
    "CREDENTIAL",
    "CREDENTIALS",
    "CREDS",
    "AUTH",
    "PRIVATE",
    "DSN",
    "SALT",
    "COOKIE",
    "APIKEY",
    "SIGNATURE",
];
/// Substrings that mark a secret even inside a token (`APIKEY`, `CLIENTSECRET`).
const SECRET_SUBSTRINGS: &[&str] = &["SECRET", "TOKEN", "PASSWORD", "APIKEY", "PRIVATEKEY"];

const PROD_TOKENS: &[&str] = &["PROD", "PRODUCTION", "LIVE", "PRD"];
const TEST_TOKENS: &[&str] = &[
    "TEST",
    "TESTING",
    "DEV",
    "DEVELOPMENT",
    "STAGING",
    "STAGE",
    "SANDBOX",
    "LOCAL",
];

fn tokens(name: &str) -> impl Iterator<Item = String> + '_ {
    name.split(['_', '.', '-'])
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_uppercase())
}

fn name_tier(name: &str) -> Option<Tier> {
    let toks: Vec<String> = tokens(name).collect();
    if toks.iter().any(|t| PROD_TOKENS.contains(&t.as_str())) {
        Some(Tier::Production)
    } else if toks.iter().any(|t| TEST_TOKENS.contains(&t.as_str())) {
        Some(Tier::Test)
    } else {
        None
    }
}

fn name_says_secret(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    tokens(name).any(|t| SECRET_TOKENS.contains(&t.as_str()))
        || SECRET_SUBSTRINGS.iter().any(|s| up.contains(s))
}

/// The parts of a URL the classifier needs. Not a general URL parser.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UrlParts {
    pub scheme: String,
    pub host: String,
    pub has_password: bool,
}

pub(crate) fn url_parts(value: &[u8]) -> Option<UrlParts> {
    let s = std::str::from_utf8(value).ok()?;
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    let has_password = userinfo
        .and_then(|u| u.split_once(':'))
        .is_some_and(|(_, p)| !p.is_empty());
    // Query-string passwords (`?password=…`, `?sslpassword=…`) count too.
    let query_password = rest.split_once('?').is_some_and(|(_, q)| {
        q.split('&')
            .any(|kv| kv.to_ascii_lowercase().contains("password="))
    });
    Some(UrlParts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        has_password: has_password || query_password,
    })
}

fn host_tier(host: &str) -> Option<Tier> {
    if host.contains("prod") {
        return Some(Tier::Production);
    }
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host == "::1"
        || host == "0.0.0.0";
    if loopback
        || ["localhost", "dev", "staging", "test", "sandbox"]
            .iter()
            .any(|w| host.contains(w))
    {
        return Some(Tier::Test);
    }
    None
}

/// Shannon entropy in bits per byte.
fn entropy(v: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in v {
        counts[b as usize] += 1;
    }
    let n = v.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

fn looks_random(v: &[u8]) -> bool {
    v.len() >= 20
        && !v.iter().any(|b| b.is_ascii_whitespace())
        && url_parts(v).is_none()
        && !v.starts_with(b"/")
        && !v.starts_with(b"./")
        && entropy(v) >= 3.5
}

/// Classifies one entry.
pub fn classify(catalog: &Catalog, entry: &Entry) -> Class {
    let v = entry.value();
    if v.is_empty() {
        return Class::Empty;
    }
    if std::str::from_utf8(v).is_ok_and(|s| SecretRef::parse(s).is_ok()) {
        return Class::AlreadyRef;
    }
    if entry.interpolated {
        return Class::Interpolated;
    }
    let name = entry.name.as_str();
    let url = url_parts(v);
    let tier_from_name = name_tier(name);

    // 1. A provider prefix.
    if let Some((p, pre)) = catalog.match_prefix(v) {
        return secret(p, pre.tier.or(tier_from_name), pre.prefix.clone());
    }
    // 2. A provider URL.
    if let Some(u) = &url {
        let by_scheme = catalog
            .providers
            .iter()
            .find(|p| p.url_schemes.contains(&u.scheme));
        let by_host = (u.scheme == "https")
            .then(|| {
                catalog
                    .providers
                    .iter()
                    .find(|p| p.url_hosts.contains(&u.host))
            })
            .flatten();
        if let Some(p) = by_scheme.or(by_host) {
            let tier = host_tier(&u.host).or(tier_from_name);
            return secret(p, tier, format!("{}://", u.scheme));
        }
    }
    // 3. Public by design.
    if catalog
        .public_prefixes
        .iter()
        .any(|p| v.starts_with(p.as_bytes()))
    {
        return Class::Public;
    }
    let upper = name.to_ascii_uppercase();
    if catalog
        .public_name_prefixes
        .iter()
        .any(|p| upper.starts_with(p.as_str()))
    {
        return Class::Public;
    }
    // 4. A provider variable name.
    if let Some(p) = catalog.providers.iter().find(|p| p.matches_env_name(name)) {
        let tier = url
            .as_ref()
            .and_then(|u| host_tier(&u.host))
            .or(tier_from_name);
        return secret(p, tier, String::new());
    }
    // 5. Unknown secrets: by name, URL password or randomness.
    let url_secret = url.as_ref().is_some_and(|u| u.has_password);
    if name_says_secret(name) || url_secret || looks_random(v) {
        let tier = url
            .as_ref()
            .and_then(|u| host_tier(&u.host))
            .or(tier_from_name);
        let shown = url.map(|u| format!("{}://", u.scheme)).unwrap_or_default();
        return Class::Secret(Secret {
            provider: None,
            tier_hint: tier,
            shown_prefix: shown,
        });
    }
    Class::NotSecret
}

fn secret(p: &Provider, tier_hint: Option<Tier>, shown_prefix: String) -> Class {
    Class::Secret(Secret {
        provider: Some(p.id.clone()),
        tier_hint,
        shown_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotenv::parse;

    fn class_of(line: &str) -> Class {
        let e = parse(line).unwrap();
        classify(Catalog::builtin(), &e[0])
    }

    fn sec(provider: Option<&str>, tier: Option<Tier>) -> (Option<String>, Option<Tier>) {
        (provider.map(str::to_owned), tier)
    }

    fn got(line: &str) -> (Option<String>, Option<Tier>) {
        match class_of(line) {
            Class::Secret(s) => (s.provider, s.tier_hint),
            other => panic!("{line}: {other:?}"),
        }
    }

    // protects=every catalog provider and tier hint classifies as the card says;
    // fails_when=a provider, tier or the sk-ant-/sk- split is wrong; no_claim=values outside the
    // table
    #[test]
    fn provider_table() {
        let x40 = "x".repeat(40);
        let cases: Vec<(String, Option<&str>, Option<Tier>)> = vec![
            (
                format!("K=sk_live_{x40}"),
                Some("stripe"),
                Some(Tier::Production),
            ),
            (
                format!("K=rk_live_{x40}"),
                Some("stripe"),
                Some(Tier::Production),
            ),
            (format!("K=sk_test_{x40}"), Some("stripe"), Some(Tier::Test)),
            (format!("K=sk-proj-{x40}"), Some("openai"), None),
            (format!("K=sk-{x40}"), Some("openai"), None),
            (format!("K=sk-ant-api03-{x40}"), Some("anthropic"), None),
            (format!("K=ghp_{x40}"), Some("github"), None),
            (format!("K=github_pat_{x40}{x40}"), Some("github"), None),
            (format!("K=xoxb-{x40}"), Some("slack"), None),
            (
                "K=https://hooks.slack.com/services/T000/B000/XXXX".into(),
                Some("slack-webhook"),
                None,
            ),
            (format!("K=SG.{x40}{x40}"), Some("sendgrid"), None),
            (
                "TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef".into(),
                Some("twilio"),
                None,
            ),
            (
                "DATABASE_URL=postgres://app:pw@db.prod.internal:5432/app".into(),
                Some("pg"),
                Some(Tier::Production),
            ),
            (
                "DATABASE_URL=postgresql://app:pw@localhost/app".into(),
                Some("pg"),
                Some(Tier::Test),
            ),
            (
                "DB=mysql://u:p@staging-db.example.com/x".into(),
                Some("mysql"),
                Some(Tier::Test),
            ),
            ("PG=postgres://db.example.com/app".into(), Some("pg"), None),
            (
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".into(),
                Some("aws-access-key-id"),
                None,
            ),
            (
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                Some("aws-secret-access-key"),
                None,
            ),
            (
                "AWS_PROD_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                Some("aws-secret-access-key"),
                Some(Tier::Production),
            ),
            // Name hint applies when the prefix has none.
            (
                format!("OPENAI_KEY_PROD=sk-proj-{x40}"),
                Some("openai"),
                Some(Tier::Production),
            ),
            (
                format!("OPENAI_KEY_DEV=sk-proj-{x40}"),
                Some("openai"),
                Some(Tier::Test),
            ),
            // The prefix's hint beats the name.
            (
                format!("STRIPE_PROD=sk_test_{x40}"),
                Some("stripe"),
                Some(Tier::Test),
            ),
            // A secret in a browser-public variable is still a secret.
            (
                format!("NEXT_PUBLIC_STRIPE=sk_live_{x40}"),
                Some("stripe"),
                Some(Tier::Production),
            ),
            // Unknown secrets.
            ("MY_API_KEY=abc".into(), None, None),
            ("SESSION_SECRET=hunter2".into(), None, None),
            ("DB_PASSWORD_STAGING=hunter2".into(), None, Some(Tier::Test)),
            ("CLIENTSECRET=x".into(), None, None),
            ("URL=https://u:pw@internal.example.com/x".into(), None, None),
            ("BLOB=Zx81Lq0pW2nR7tY5uI3oP9aS4dF6gH1j".into(), None, None),
        ];
        for (line, p, t) in cases {
            assert_eq!(got(&line), sec(p, t), "{line}");
        }
    }

    // protects=non-secrets, public values, refs, interpolation and empty values are not
    // imported; fails_when=any is classed as a secret; no_claim=every config name in the wild
    #[test]
    fn not_imported() {
        let x40 = "x".repeat(40);
        for (line, want) in [
            ("PORT=3000", Class::NotSecret),
            ("NODE_ENV=development", Class::NotSecret),
            ("MONKEY=banana", Class::NotSecret),
            (
                "API_URL=https://api.example.com/v1/some/long/path",
                Class::NotSecret,
            ),
            (
                "LOG_DIR=/var/log/some/really/long/path/name",
                Class::NotSecret,
            ),
            (
                "GREETING=hello there my friend how are you",
                Class::NotSecret,
            ),
            ("STRIPE_KEY=ms://stripe/test", Class::AlreadyRef),
            ("A=${OTHER}", Class::Interpolated),
            ("SECRET=\"$OTHER\"", Class::Interpolated),
            ("SECRET=", Class::Empty),
            ("NEXT_PUBLIC_API_KEY=abc", Class::Public),
            ("VITE_TOKEN=abc", Class::Public),
        ] {
            assert_eq!(class_of(line), want, "{line}");
        }
        assert_eq!(
            class_of(&format!("STRIPE_PUBLISHABLE_KEY=pk_live_{x40}")),
            Class::Public
        );
    }

    // protects=the URL helper finds scheme, host and passwords; fails_when=a password in
    // userinfo or query is missed or a host is mis-read; no_claim=full RFC 3986 parsing
    #[test]
    fn urls() {
        let u = url_parts(b"postgres://u:p@[::1]:5432/db").unwrap();
        assert_eq!(
            (u.scheme.as_str(), u.host.as_str(), u.has_password),
            ("postgres", "::1", true)
        );
        let u = url_parts(b"postgres://u@h/db?sslmode=require&password=x").unwrap();
        assert!(u.has_password);
        let u = url_parts(b"https://user@Example.COM/a").unwrap();
        assert_eq!((u.host.as_str(), u.has_password), ("example.com", false));
        assert!(url_parts(b"not a url").is_none());
        assert!(url_parts(b"1http://x").is_none());
    }
}
