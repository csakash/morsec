//! Proxy configuration: which key goes to which host, where its placeholder sits, and what may
//! be tunnelled. L07 builds this from the L04 catalog and the L03 rules.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use ms_core::{KeyName, SecretRef};
use rustls_pki_types::CertificateDer;

use crate::error::ProxyError;

/// Where a provider expects its credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// A header whose value is `prefix` followed by the key, e.g. `Authorization: Bearer <key>`.
    Header {
        /// Header name, any case.
        name: String,
        /// Text before the key, e.g. `"Bearer "`. May be empty.
        prefix: String,
    },
    /// HTTP Basic auth (`Authorization: Basic base64(user:password)`).
    Basic {
        /// Which half holds the key.
        field: BasicField,
    },
    /// A query parameter, e.g. `?api_key=<key>`.
    Query {
        /// Parameter name, exact.
        param: String,
    },
}

/// Which half of Basic credentials holds the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicField {
    /// `key:` (Stripe's form).
    User,
    /// `user:key`.
    Password,
}

/// One key bound to one provider's hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The vault key.
    pub key: KeyName,
    /// Provider name for base-URL mode (`/p/<provider>/…`), `[a-z0-9-]+`.
    pub provider: String,
    /// Hosts the key may go to. Lowercase DNS names, no wildcards. The first is the base-URL
    /// mode upstream.
    pub hosts: Vec<String>,
    /// Upstream TLS port, normally 443.
    pub port: u16,
    /// Where the placeholder sits and the value goes.
    pub location: Location,
    /// A format-shaped placeholder (e.g. `sk_test_ms_…`) that also stands for this key, for SDKs
    /// that validate key format. `ms://<key>` always works too.
    pub shaped_placeholder: Option<String>,
}

impl Binding {
    /// The `ms://` placeholder for this key.
    pub fn reference(&self) -> String {
        SecretRef::new(self.key.clone()).to_string()
    }

    /// True when `s` is one of this key's placeholders.
    pub(crate) fn is_placeholder(&self, s: &str) -> bool {
        s == self.reference() || self.shaped_placeholder.as_deref() == Some(s)
    }

    pub(crate) fn serves(&self, host: &str, port: u16) -> bool {
        self.port == port && self.hosts.iter().any(|h| h == host)
    }
}

/// Resource limits. Defaults are deliberately modest; L07 may raise them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Most agent connections handled at once; more wait in the accept queue.
    pub max_connections: usize,
    /// Time allowed to send a request head.
    pub header_read_timeout: Duration,
    /// Largest request head, bytes.
    pub max_head_bytes: usize,
    /// Largest request body the proxy buffers for an inspected request; above it, `413`.
    pub max_body_bytes: usize,
    /// Time allowed to connect (TCP and TLS) to an upstream.
    pub upstream_connect_timeout: Duration,
    /// How long a person has to answer an approval.
    pub approval_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            header_read_timeout: Duration::from_secs(30),
            max_head_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            upstream_connect_timeout: Duration::from_secs(15),
            approval_timeout: Duration::from_secs(120),
        }
    }
}

/// Which roots verify upstream TLS.
#[derive(Debug, Clone, Default)]
pub enum UpstreamRoots {
    /// The operating system's trust store.
    #[default]
    System,
    /// Exactly these roots (tests, or an operator who pins).
    Only(Vec<CertificateDer<'static>>),
}

/// Everything the proxy needs to know besides its dependencies.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Listen address. Must be loopback.
    pub listen: SocketAddr,
    /// Keys and the hosts they go to.
    pub bindings: Vec<Binding>,
    /// Hosts tunnelled without inspection: `example.com` or `*.example.com` (subdomains only).
    pub allow: Vec<String>,
    /// Limits.
    pub limits: Limits,
    /// Upstream trust.
    pub upstream_roots: UpstreamRoots,
}

impl ProxyConfig {
    /// A config listening on `listen` with no bindings, nothing allowed and default limits.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            bindings: Vec::new(),
            allow: Vec::new(),
            limits: Limits::default(),
            upstream_roots: UpstreamRoots::default(),
        }
    }

    /// Checks the config. Every error names the problem and the fix.
    pub(crate) fn validate(&self, ca_hosts: &BTreeSet<String>) -> Result<(), ProxyError> {
        if !self.listen.ip().is_loopback() {
            return Err(ProxyError::Config(format!(
                "the proxy must listen on loopback, not {}. Use 127.0.0.1",
                self.listen.ip()
            )));
        }
        let mut providers = BTreeSet::new();
        let mut shaped = BTreeSet::new();
        for b in &self.bindings {
            if b.provider.is_empty()
                || !b
                    .provider
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            {
                return Err(ProxyError::Config(format!(
                    "provider name {:?} for {} must be [a-z0-9-]+",
                    b.provider, b.key
                )));
            }
            if !providers.insert(b.provider.clone()) {
                return Err(ProxyError::Config(format!(
                    "provider {} is bound twice; give each binding its own provider name",
                    b.provider
                )));
            }
            if b.hosts.is_empty() {
                return Err(ProxyError::Config(format!(
                    "{} is bound to no host; add one with: ms rules",
                    b.key
                )));
            }
            for h in &b.hosts {
                validate_host(h)?;
                if !ca_hosts.contains(h) {
                    return Err(ProxyError::Config(format!(
                        "{h} is bound to {} but the morsec CA does not cover it. Re-issue the CA with the new host list",
                        b.key
                    )));
                }
            }
            if b.port == 0 {
                return Err(ProxyError::Config(format!("{} has port 0", b.key)));
            }
            match &b.location {
                Location::Header { name, .. } => {
                    http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        ProxyError::Config(format!("{name:?} is not a valid header name"))
                    })?;
                }
                Location::Query { param } if param.is_empty() => {
                    return Err(ProxyError::Config(format!(
                        "{} has an empty query parameter name",
                        b.key
                    )));
                }
                _ => {}
            }
            if let Some(p) = &b.shaped_placeholder {
                if p.len() < 8 || !p.bytes().all(|c| c.is_ascii_graphic()) {
                    return Err(ProxyError::Config(format!(
                        "the shaped placeholder for {} must be at least 8 printable ASCII characters",
                        b.key
                    )));
                }
                if !shaped.insert(p.clone()) {
                    return Err(ProxyError::Config(format!(
                        "the shaped placeholder for {} is used by another key",
                        b.key
                    )));
                }
            }
        }
        for a in &self.allow {
            validate_host(a.strip_prefix("*.").unwrap_or(a))?;
        }
        if self.limits.max_connections == 0 || self.limits.max_body_bytes == 0 {
            return Err(ProxyError::Config("limits must be above zero".into()));
        }
        Ok(())
    }

    /// True when `host` matches the tunnel allowlist.
    pub(crate) fn allowed(&self, host: &str) -> bool {
        self.allow.iter().any(|a| match a.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
            None => a == host,
        })
    }
}

/// A lowercase DNS name: labels of `[a-z0-9-]`, not an IP literal, no wildcard.
pub(crate) fn validate_host(h: &str) -> Result<(), ProxyError> {
    let bad = |why: &str| {
        Err(ProxyError::Config(format!(
            "{:?} is not a host name morsec can bind ({why}). Use a lowercase DNS name such as api.stripe.com",
            h.chars().take(80).collect::<String>()
        )))
    };
    if h.is_empty() || h.len() > 253 {
        return bad("length");
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return bad("IP addresses can't be bound");
    }
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 {
            return bad("empty or long label");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return bad("only a-z, 0-9 and '-' in labels");
        }
    }
    if !h.contains('.') {
        return bad("needs a dot");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=allowlist wildcards match subdomains only and exact entries match exactly;
    // fails_when=*.x.com matches x.com or evilx.com, or exact matches a subdomain; no_claim=CONNECT
    #[test]
    fn allowlist_matching() {
        let mut c = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        c.allow = vec!["*.example.com".into(), "github.com".into()];
        assert!(c.allowed("api.example.com"));
        assert!(c.allowed("a.b.example.com"));
        assert!(!c.allowed("example.com"));
        assert!(!c.allowed("evilexample.com"));
        assert!(!c.allowed(".example.com"));
        assert!(c.allowed("github.com"));
        assert!(!c.allowed("api.github.com"));
        assert!(!c.allowed("github.com.evil.net"));
    }

    // protects=only loopback listen addresses and well-formed hosts are accepted; fails_when=a
    // public bind, an IP or uppercase binding, or an uncovered host is accepted; no_claim=runtime
    #[test]
    fn validation() {
        let ca: BTreeSet<String> = ["api.stripe.com".to_string()].into();
        let b = Binding {
            key: KeyName::new("stripe/test").unwrap(),
            provider: "stripe".into(),
            hosts: vec!["api.stripe.com".into()],
            port: 443,
            location: Location::Header {
                name: "authorization".into(),
                prefix: "Bearer ".into(),
            },
            shaped_placeholder: None,
        };
        let mut c = ProxyConfig::new("127.0.0.1:0".parse().unwrap());
        c.bindings = vec![b.clone()];
        c.validate(&ca).unwrap();

        let mut bad = c.clone();
        bad.listen = "0.0.0.0:0".parse().unwrap();
        assert!(bad.validate(&ca).is_err());
        for h in [
            "API.stripe.com",
            "1.2.3.4",
            "*.stripe.com",
            "stripe",
            "a..b",
        ] {
            let mut bad = c.clone();
            bad.bindings[0].hosts = vec![h.into()];
            assert!(bad.validate(&ca).is_err(), "{h}");
        }
        let mut bad = c.clone();
        bad.bindings[0].hosts = vec!["evil.example.com".into()];
        assert!(bad.validate(&ca).unwrap_err().to_string().contains("CA"));
        let mut bad = c.clone();
        bad.bindings.push(b);
        assert!(bad.validate(&ca).is_err(), "duplicate provider");
    }
}
