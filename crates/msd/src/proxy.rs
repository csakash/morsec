//! Runs the L05 swap proxy with the daemon's vault, rules, receipts, sessions and approvals.
//!
//! The proxy's config (bindings, CA) is fixed when it binds, so a supervisor rebuilds it whenever
//! the rules change. Stopping (`ms stop`) needs no rebuild to take effect: the session resolver
//! returns no session while stopped, so every new request is refused at once.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ms_core::{Decision, KeyMeta, KeyName, Mode, Request, SessionId, Tier};
use ms_proxy::{
    BasicField, Binding, Ca, Deps, Location, Policy, Proxy, ProxyConfig, SessionResolver,
};
use ms_rules::{HostPattern, Rules, is_reserved};
use ms_session::{OsProcessTable, PortResolver, cross_check};
use tokio::sync::watch;

use crate::backend::{CA_PEM_KEY, CaKeyWriter};
use crate::daemon::Daemon;
use crate::paths::atomic_write;

/// The host a CA is issued for when nothing is bound: a reserved TLD, never trusted or stored.
const PLACEHOLDER_HOST: &str = "morsec.invalid";
/// Most concurrent process-table scans for proxy connections (L06 must-do).
const MAX_SCANS: usize = 8;

/// Counting gate for blocking scans.
#[derive(Debug)]
struct Gate {
    n: Mutex<usize>,
    cv: Condvar,
}

struct GateGuard<'a>(&'a Gate);

impl Gate {
    fn new() -> Self {
        Self {
            n: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    fn enter(&self) -> GateGuard<'_> {
        let mut n = self.n.lock().unwrap_or_else(|e| e.into_inner());
        while *n >= MAX_SCANS {
            n = self.cv.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n += 1;
        GateGuard(self)
    }
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        let mut n = self.0.n.lock().unwrap_or_else(|e| e.into_inner());
        *n -= 1;
        self.0.cv.notify_one();
    }
}

/// `ms_rules::decide` over the live rules.
#[derive(Debug)]
struct LivePolicy(Arc<Daemon>);

impl Policy for LivePolicy {
    fn decide(&self, session: &SessionId, request: &Request) -> (Decision, u64) {
        self.0.decide(session, request)
    }
    fn version(&self) -> u64 {
        self.0.rules_version()
    }
}

/// L06 port → PID → session, cross-checked against the proxy username. No session while
/// stopped, or for a session a LOG-2 alert stopped.
struct Sessions {
    daemon: Arc<Daemon>,
    ports: PortResolver<OsProcessTable, OsProcessTable>,
    gate: Gate,
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sessions")
    }
}

impl SessionResolver for Sessions {
    fn resolve(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        proxy_user: Option<&str>,
    ) -> Option<SessionId> {
        if self.daemon.is_stopped() {
            return None;
        }
        let caller = {
            let _g = self.gate.enter();
            self.ports.resolve(peer, local).ok()?
        };
        let session = match proxy_user {
            Some(u) => cross_check(&caller, u).ok()?.clone(),
            // Without a username the process tree alone decides; an unattributed caller has no
            // session, so it is refused.
            None => caller.session()?.clone(),
        };
        if self.daemon.session_stopped(&session) {
            return None;
        }
        Some(session)
    }
}

/// Maps a catalog credential location to the proxy's. `None` for locations the proxy can't
/// swap (URL paths, DSNs, SigV4).
fn location(l: &ms_import::catalog::Location) -> Option<Location> {
    use ms_import::catalog::Location as C;
    match l {
        C::Header { name, prefix } => Some(Location::Header {
            name: name.clone(),
            prefix: prefix.clone(),
        }),
        C::BasicUser => Some(Location::Basic {
            field: BasicField::User,
        }),
        C::BasicPassword => Some(Location::Basic {
            field: BasicField::Password,
        }),
        C::UrlPath | C::Dsn | C::Sigv4 => None,
    }
}

/// The catalog provider for a key: one whose default key name is this key, else one whose id
/// is the key's first segment.
fn provider_for(key: &KeyName) -> Option<&'static ms_import::catalog::Provider> {
    let cat = ms_import::catalog::Catalog::builtin();
    cat.providers
        .iter()
        .find(|p| p.key_name(Tier::Test) == *key || p.key_name(Tier::Production) == *key)
        .or_else(|| {
            let first = key.as_str().split('/').next()?;
            cat.get(first)
        })
}

/// Swap bindings from the rules: swap keys with exact DNS hosts and a catalog location.
pub fn bindings(rules: &Rules) -> (Vec<Binding>, Vec<String>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    if rules.tampered {
        return (out, skipped);
    }
    for (key, rule) in &rules.keys {
        if rule.mode != Mode::Swap || rule.hosts.is_empty() || is_reserved(key) {
            continue;
        }
        let hosts: Vec<String> = rule
            .hosts
            .iter()
            .filter_map(|h| match h {
                HostPattern::Exact(s) if s.parse::<IpAddr>().is_err() => Some(s.clone()),
                _ => None,
            })
            .collect();
        if hosts.len() != rule.hosts.len() {
            skipped.push(format!(
                "{key}: wildcard and IP hosts can't be swapped (the CA only issues for exact names); bind exact hosts"
            ));
        }
        if hosts.is_empty() {
            continue;
        }
        let Some(loc) = provider_for(key).and_then(|p| location(&p.location)) else {
            skipped.push(format!(
                "{key}: no catalog entry says where its credential goes in a request, so it is not swapped"
            ));
            continue;
        };
        out.push(Binding {
            key: key.clone(),
            provider: key.as_str().replace('/', "-"),
            hosts,
            port: 443,
            location: loc,
            shaped_placeholder: None,
        });
    }
    (out, skipped)
}

/// The CA for `hosts`: the stored one when it covers them, else a new one (stored in the vault,
/// certificate written to the state directory). With no hosts, a throwaway CA for a reserved name.
fn ensure_ca(d: &Daemon, hosts: &BTreeSet<String>) -> Result<Ca, String> {
    if hosts.is_empty() {
        return Ca::generate([PLACEHOLDER_HOST]).map_err(|e| e.to_string());
    }
    let paths = d.paths();
    let name = KeyName::new(CA_PEM_KEY).map_err(|e| e.to_string())?;
    let stored: Option<(String, BTreeSet<String>)> = (|| {
        let pem = std::fs::read_to_string(&paths.ca_pem).ok()?;
        let list: Vec<String> =
            serde_json::from_slice(&std::fs::read(&paths.ca_hosts).ok()?).ok()?;
        Some((pem, list.into_iter().collect()))
    })();
    if let Some((pem, covered)) = stored
        && hosts.is_subset(&covered)
    {
        match Ca::load(&*d.vault(), &name, &pem, &covered) {
            Ok(ca) => return Ok(ca),
            Err(e) => tracing::warn!(error = %e, "stored CA unusable; issuing a new one"),
        }
    }
    let ca = Ca::generate(hosts).map_err(|e| e.to_string())?;
    let meta = KeyMeta {
        name: name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 0,
    };
    ca.store(&CaKeyWriter(d.backend()), &name, meta)
        .map_err(|e| e.to_string())?;
    let list: Vec<&String> = hosts.iter().collect();
    let json = serde_json::to_vec(&list).map_err(|e| e.to_string())?;
    atomic_write(&paths.ca_pem, ca.cert_pem().as_bytes(), 0o644).map_err(|e| e.to_string())?;
    atomic_write(&paths.ca_hosts, &json, 0o600).map_err(|e| e.to_string())?;
    d.alert(format!(
        "the morsec CA was issued for {} host(s); tools that use the system trust store need it trusted again: ms init --trust",
        hosts.len()
    ));
    Ok(ca)
}

/// Builds a proxy config and its dependencies from the daemon's current state.
pub fn build(d: &Arc<Daemon>, listen: SocketAddr) -> Result<(ProxyConfig, Deps), String> {
    let rules = d.rules();
    let (binds, skipped) = bindings(&rules);
    for s in skipped {
        tracing::warn!("{s}");
        d.alert(s);
    }
    let hosts: BTreeSet<String> = binds.iter().flat_map(|b| b.hosts.iter().cloned()).collect();
    let ca = Arc::new(ensure_ca(d, &hosts)?);
    d.set_ca((!hosts.is_empty()).then(|| {
        (
            ca.cert_pem().to_owned(),
            ca.hosts().iter().cloned().collect(),
        )
    }));
    let mut cfg = ProxyConfig::new(listen);
    cfg.bindings = binds;
    let mut deps = Deps::new(
        d.vault(),
        Arc::new(LivePolicy(d.clone())),
        d.receipts(),
        Arc::new(Sessions {
            daemon: d.clone(),
            ports: PortResolver::new(OsProcessTable, OsProcessTable),
            gate: Gate::new(),
        }),
        ca,
    );
    deps.approver = Some(d.approver());
    Ok((cfg, deps))
}

/// Runs the proxy on `127.0.0.1:<port>` until `shutdown` is set, rebuilding on every rules
/// change.
pub async fn supervise(d: Arc<Daemon>, mut shutdown: watch::Receiver<bool>) {
    let listen = SocketAddr::from(([127, 0, 0, 1], d.proxy_port()));
    let mut changes = d.proxy_changes();
    loop {
        if *shutdown.borrow() {
            return;
        }
        changes.borrow_and_update();
        let dd = d.clone();
        let built = tokio::task::spawn_blocking(move || build(&dd, listen))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        let bound = match built {
            Ok((cfg, deps)) => {
                let current = cfg.bindings.clone();
                Proxy::bind(cfg, deps)
                    .await
                    .map(|p| (p, current))
                    .map_err(|e| e.to_string())
            }
            Err(e) => Err(e),
        };
        match bound {
            Ok((proxy, current)) => {
                tracing::info!(addr = %listen, "swap proxy listening");
                d.clear_alert("the swap proxy is not running");
                let (mut c, mut s, dd) = (changes.clone(), shutdown.clone(), d.clone());
                // Rebinding briefly closes the port, so only rebuild when the bindings change;
                // policy and the stop flag are read live and need no rebuild.
                proxy
                    .serve(async move {
                        loop {
                            tokio::select! {
                                r = c.changed() => if r.is_err() { return },
                                _ = s.changed() => return,
                            }
                            if bindings(&dd.rules()).0 != current {
                                return;
                            }
                        }
                    })
                    .await;
            }
            Err(e) => {
                tracing::error!(error = %e, "swap proxy is not running");
                d.alert(format!("the swap proxy is not running: {e}"));
                // Retry on a change, on shutdown, or after a pause (port briefly in use).
                tokio::select! {
                    _ = changes.changed() => {},
                    _ = shutdown.changed() => {},
                    () = tokio::time::sleep(Duration::from_secs(5)) => {},
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Rules {
        Rules::from_toml(text, "test").unwrap()
    }

    // protects=only swap keys with exact DNS hosts and a catalog location become bindings;
    // wildcards, IPs, run keys, reserved keys and unknown providers are skipped (with a note), and
    // tampered rules bind nothing; fails_when=a key is bound to a host its rule doesn't name, or a
    // tampered file still binds; no_claim=the proxy's own validation (ms-proxy tests)
    #[test]
    fn bindings_from_rules() {
        let r = rules(
            r#"
version = 3
[keys."stripe/test"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com", "*.stripe.com"]
[keys."openai/production"]
mode = "swap"
tier = "production"
hosts = ["api.openai.com"]
[keys."zzz/unknown"]
mode = "swap"
tier = "test"
hosts = ["example.com"]
[keys."pg/staging"]
mode = "run"
tier = "test"
commands = [["psql", "**"]]
"#,
        );
        let (b, skipped) = bindings(&r);
        let keys: Vec<_> = b.iter().map(|b| b.key.as_str()).collect();
        assert_eq!(keys, ["openai/production", "stripe/test"]);
        let stripe = b.iter().find(|b| b.key.as_str() == "stripe/test").unwrap();
        assert_eq!(stripe.hosts, ["api.stripe.com"]);
        assert_eq!(stripe.provider, "stripe-test");
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        let mut t = r.clone();
        t.tampered = true;
        assert!(bindings(&t).0.is_empty());
    }
}
