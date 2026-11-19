//! Runs the L05 swap proxy with the daemon's vault, rules, receipts, sessions and approvals.
//!
//! The proxy's config (bindings, CA) is fixed when it binds, so a supervisor rebuilds it whenever
//! the rules change. Stopping (`ms stop`) needs no rebuild to take effect: the session resolver
//! returns no session while stopped, so every new request is refused at once.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ms_core::{Decision, KeyMeta, KeyName, Mode, Request, SessionId, Tier};
use ms_proxy::{
    BasicField, Binding, Ca, Deps, Location, Policy, Proxy, ProxyConfig, SessionResolver,
};
use ms_rules::{HostPattern, Rules, is_reserved};
use ms_session::{
    Caller, OsProcessTable, PortResolver, ProcessTable, Resolver, cross_check, is_dev_proxy_user,
};
use tokio::sync::watch;

use crate::backend::{CA_CERT_KEY, CA_PEM_KEY, CaKeyWriter};
use crate::daemon::Daemon;
use crate::paths::atomic_write;
use ms_vault::VaultExt;

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
        let _g = self.gate.enter();
        let caller = self.ports.resolve(peer, local).ok()?;
        let session = session_for(
            &caller,
            proxy_user,
            |c| self.daemon.dev_by_credential(c),
            self.ports.resolver(),
        )?;
        if self.daemon.session_stopped(&session) {
            return None;
        }
        Some(session)
    }

    fn open_egress(&self, session: &SessionId) -> bool {
        self.daemon.dev_session(session).is_some()
    }
}

/// The session a proxy connection is served as (L06, L34 SPEC D-1/D-2):
///
/// - an agent anywhere on the chain: that agent's session. Its username is cross-checked,
///   except that an `ms dev` credential is ignored (an agent inside a dev tree stays an agent);
/// - no agent, an `ms dev` credential that `dev` knows, and the dev session's `ms dev` process
///   (same start time) on the caller's parent chain: the dev session;
/// - anything else (no username, an unknown or copied credential, a process outside the tree):
///   none, so the connection is refused.
pub fn session_for<T: ProcessTable>(
    caller: &Caller,
    proxy_user: Option<&str>,
    dev: impl Fn(&str) -> Option<SessionId>,
    tree: &Resolver<T>,
) -> Option<SessionId> {
    match (caller, proxy_user) {
        (Caller::Agent(s), Some(u)) if is_dev_proxy_user(u) => Some(s.clone()),
        (_, Some(u)) if !is_dev_proxy_user(u) => cross_check(caller, u).ok().cloned(),
        (
            Caller::Unattributed {
                pid,
                started_unix_ms,
            },
            Some(u),
        ) => {
            let d = dev(u)?;
            tree.within(*pid, *started_unix_ms, d.pid, d.started_unix_ms)
                .ok()?
                .then_some(d)
        }
        // Without a username the process tree alone decides; an unattributed caller has no
        // session, so it is refused.
        (_, None) => caller.session().cloned(),
        (Caller::Agent(_), Some(_)) => None,
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

/// The catalog provider for a key: the one its project record names (L31 keys are
/// `<project>/<var>`, so only the MAC'd record knows their provider), else one whose default key
/// name is this key, else one whose id is the key's first segment.
///
/// A recorded provider counts only when every host of the key's rule is one of that provider's
/// catalog hosts (review N1): the record says where the credential goes in a request, never
/// where it may be sent, so a record can't make a hand-made key's hosts get another provider's
/// header.
fn provider_for(
    key: &KeyName,
    rule: &ms_rules::KeyRule,
    recorded: &BTreeMap<KeyName, Option<String>>,
) -> Option<&'static ms_import::catalog::Provider> {
    let cat = ms_import::catalog::Catalog::builtin();
    // Review round 2: a key a project record lists gets only the provider that record names
    // (when its hosts cover the rule), never the first-segment guess below: a project slug such
    // as `stripe` must not lend Stripe's location to the project's other keys.
    if let Some(named) = recorded.get(key) {
        return named.as_deref().and_then(|p| cat.get(p)).filter(|p| {
            rule.hosts.iter().all(|h| {
                let h = h.to_string();
                p.hosts.iter().any(|c| c.eq_ignore_ascii_case(&h))
            })
        });
    }
    cat.providers
        .iter()
        .find(|p| p.key_name(Tier::Test) == *key || p.key_name(Tier::Production) == *key)
        .or_else(|| {
            let first = key.as_str().split('/').next()?;
            cat.get(first)
        })
}

/// Swap bindings from the rules alone (no project records).
#[cfg(test)]
pub fn bindings(rules: &Rules) -> (Vec<Binding>, Vec<String>) {
    bindings_with(rules, &BTreeMap::new())
}

/// Swap bindings from the rules: swap keys with exact DNS hosts and a catalog location, the
/// provider of a project key coming from its project record (`recorded`).
pub fn bindings_with(
    rules: &Rules,
    recorded: &BTreeMap<KeyName, Option<String>>,
) -> (Vec<Binding>, Vec<String>) {
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
        // L30: git hosts get their own binding, with the key in the Basic-auth password (where
        // git sends a token); the rest keep the catalog location.
        let (git, hosts): (Vec<String>, Vec<String>) =
            hosts.into_iter().partition(|h| rule.git_hosts.contains(h));
        if !git.is_empty() {
            out.push(Binding {
                key: key.clone(),
                provider: format!("{}-git", key.as_str().replace('/', "-")),
                hosts: git,
                port: 443,
                location: Location::Basic {
                    field: BasicField::Password,
                },
                shaped_placeholder: None,
            });
        }
        if hosts.is_empty() {
            continue;
        }
        let Some(loc) = provider_for(key, rule, recorded).and_then(|p| location(&p.location))
        else {
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
    // Provider names come from key names (`/` → `-`, git bindings add `-git`), so two keys can
    // land on one name (`a/b` and `a-b`, or `x/y` with git hosts and `x/y/git`). The proxy refuses
    // a config with a duplicate, which would stop every swap; drop just the colliding bindings.
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    for b in &out {
        *count.entry(b.provider.clone()).or_default() += 1;
    }
    out.retain(|b| {
        let dup = count[&b.provider] > 1;
        if dup {
            skipped.push(format!(
                "{}: its proxy name {} is also another key's (key names that differ only in '/' and '-'), so neither is swapped; rename one",
                b.key, b.provider
            ));
        }
        !dup
    });
    (out, skipped)
}

/// The CA certificate and its hosts, as kept in the vault ([`CA_CERT_KEY`]).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CaRecord {
    cert_pem: String,
    hosts: Vec<String>,
}

/// The CA for `hosts`: the stored one when it covers them, else a new one. The private key, the
/// certificate and the host list all live in the vault (security review S1: a certificate read
/// from disk could be swapped for one that merely embeds our public key). `ca.pem` in the state
/// directory is only an export for connectors and is never read back. With no hosts, a throwaway
/// CA for a reserved name.
pub(crate) fn ensure_ca(d: &Daemon, hosts: &BTreeSet<String>) -> Result<Ca, String> {
    if hosts.is_empty() {
        return Ca::generate([PLACEHOLDER_HOST]).map_err(|e| e.to_string());
    }
    let key_name = KeyName::new(CA_PEM_KEY).map_err(|e| e.to_string())?;
    let cert_name = KeyName::new(CA_CERT_KEY).map_err(|e| e.to_string())?;
    let stored: Option<CaRecord> = d
        .vault()
        .read_with(&cert_name, |v| serde_json::from_slice::<CaRecord>(v).ok())
        .ok()
        .flatten();
    if let Some(rec) = stored {
        let covered: BTreeSet<String> = rec.hosts.into_iter().collect();
        if hosts.is_subset(&covered) {
            match Ca::load(&*d.vault(), &key_name, &rec.cert_pem, &covered) {
                Ok(ca) => {
                    export_pem(d, ca.cert_pem());
                    return Ok(ca);
                }
                Err(e) => tracing::warn!(error = %e, "stored CA unusable; issuing a new one"),
            }
        }
    }
    let ca = Ca::generate(hosts).map_err(|e| e.to_string())?;
    let meta = KeyMeta {
        name: key_name.clone(),
        mode: Mode::Swap,
        tier: Tier::Production,
        created_unix_ms: 0,
    };
    ca.store(&CaKeyWriter(d.backend()), &key_name, meta)
        .map_err(|e| e.to_string())?;
    let rec = CaRecord {
        cert_pem: ca.cert_pem().to_owned(),
        hosts: hosts.iter().cloned().collect(),
    };
    let json = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
    d.backend()
        .put_internal(&cert_name, ms_core::SecretBytes::new(json))
        .map_err(|e| e.to_string())?;
    export_pem(d, ca.cert_pem());
    d.alert(format!(
        "the morsec CA was issued for {} host(s); tools that use the system trust store need it trusted again: ms init --trust",
        hosts.len()
    ));
    Ok(ca)
}

/// Writes the CA certificate to `ca.pem` for connectors (public; never read back by msd). Always
/// a fresh atomic write: the rename replaces whatever is there, a symlink or FIFO included,
/// without following or opening it.
fn export_pem(d: &Daemon, pem: &str) {
    if let Err(e) = atomic_write(&d.paths().ca_pem, pem.as_bytes(), 0o644) {
        tracing::warn!(error = %e, "could not export ca.pem");
    }
}

/// The L30 QA hook (SPEC D5): test upstreams for a debug build with the memory vault. Empty
/// otherwise; a release build refuses the flags and has no hook to hold.
#[derive(Debug, Clone, Default)]
pub struct TestHook(#[cfg(debug_assertions)] Option<Arc<ms_proxy::test_upstreams::TestUpstreams>>);

impl TestHook {
    /// From `--test-upstream` and `--test-upstream-ca`. Refused outside a debug build or without
    /// the memory vault.
    pub fn new(
        specs: &[String],
        ca: Option<&std::path::Path>,
        memory_vault: bool,
    ) -> Result<Self, String> {
        if specs.is_empty() && ca.is_none() {
            return Ok(Self::default());
        }
        if !cfg!(debug_assertions) {
            return Err(
                "morsec: --test-upstream is for tests and works only in a debug build".into(),
            );
        }
        if !memory_vault {
            return Err(
                "morsec: --test-upstream only works with --vault memory (an ephemeral dev vault)"
                    .into(),
            );
        }
        let Some(ca) = ca else {
            return Err("morsec: --test-upstream needs --test-upstream-ca".into());
        };
        let pem = std::fs::read_to_string(ca)
            .map_err(|e| format!("morsec: can't read {}: {e}", ca.display()))?;
        #[cfg(debug_assertions)]
        {
            let t = ms_proxy::test_upstreams::TestUpstreams::new(specs, &pem)
                .map_err(|e| format!("morsec: {e}"))?;
            Ok(Self(Some(Arc::new(t))))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = pem;
            Err("morsec: --test-upstream works only in a debug build".into())
        }
    }

    fn configure(&self, _cfg: &mut ProxyConfig, _deps: &mut Deps) {
        #[cfg(debug_assertions)]
        if let Some(t) = &self.0 {
            t.configure(_cfg, _deps);
        }
    }

    fn allow(&self, _proxy: &mut Proxy) {
        #[cfg(debug_assertions)]
        if let Some(t) = &self.0 {
            t.allow(_proxy);
        }
    }
}

/// Builds a proxy config and its dependencies from the daemon's current state.
pub fn build(d: &Arc<Daemon>, listen: SocketAddr) -> Result<(ProxyConfig, Deps), String> {
    let rules = d.rules();
    let (binds, skipped) = bindings_with(&rules, &d.project_providers());
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
    deps.egress = Arc::new(crate::doctor::CanaryObserver { probes: d.probes() });
    Ok((cfg, deps))
}

/// Runs the proxy on `127.0.0.1:<port>` until `shutdown` is set, rebuilding on every rules
/// change.
pub async fn supervise(d: Arc<Daemon>, mut shutdown: watch::Receiver<bool>, test: TestHook) {
    let listen = SocketAddr::from(([127, 0, 0, 1], d.proxy_port()));
    let mut changes = d.proxy_changes();
    loop {
        if *shutdown.borrow() {
            return;
        }
        changes.borrow_and_update();
        let (dd, t) = (d.clone(), test.clone());
        let built = tokio::task::spawn_blocking(move || {
            build(&dd, listen).map(|(mut cfg, mut deps)| {
                t.configure(&mut cfg, &mut deps);
                (cfg, deps)
            })
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        let bound = match built {
            Ok((cfg, deps)) => {
                let current = cfg.bindings.clone();
                Proxy::bind(cfg, deps)
                    .await
                    .map(|mut p| {
                        test.allow(&mut p);
                        (p, current)
                    })
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
                            if bindings_with(&dd.rules(), &dd.project_providers()).0 != current {
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
    use ms_core::AgentKind;
    use ms_session::ProcInfo;
    use std::collections::HashMap;

    /// A fixed process table: pid → (ppid, start, name).
    struct Table(HashMap<u32, (u32, u64, &'static str)>);

    impl ProcessTable for Table {
        fn info(&self, pid: u32) -> std::io::Result<ProcInfo> {
            let (ppid, started, name) = *self
                .0
                .get(&pid)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            Ok(ProcInfo {
                pid,
                ppid,
                uid: 501,
                started_unix_ms: started,
                name: name.into(),
            })
        }
    }

    // protects=L34 SPEC D-1/D-2 (design §7.4): a proxy client under the ms dev process that
    // presents the session's credential is served as the dev session; the same credential from a
    // process outside the tree, from a tree whose ms dev restarted (new start time), an unknown
    // credential, and the tree without a credential are refused; an agent inside the tree stays
    // that agent's session whatever it presents, and agent usernames are still cross-checked;
    // fails_when=a copied credential works outside the tree, or a dev credential turns an agent
    // connection into a dev session; no_claim=the live port→PID lookup (ms-session live tests) and
    // the swap itself (e2e dev_swaps_for_the_users_own_command)
    #[test]
    fn dev_swaps_refs_for_child_tree() {
        let t = Resolver::new(Table(HashMap::from([
            (1, (0, 1, "launchd")),
            (60, (1, 10, "zsh")),
            (70, (60, 20, "ms")),
            (80, (70, 30, "node")),
            (90, (80, 40, "node")),
            (95, (90, 50, "claude")),
            (96, (95, 60, "curl")),
            (200, (60, 25, "python3")),
        ])));
        let cred = format!("ms-dev-{}", "ab".repeat(32));
        let dev = crate::daemon::dev::dev_session_id(70, 20);
        let known = |c: &str| (c == cred).then(|| dev.clone());
        let un = |pid, started_unix_ms| Caller::Unattributed {
            pid,
            started_unix_ms,
        };
        assert_eq!(
            session_for(&un(90, 40), Some(&cred), known, &t),
            Some(dev.clone())
        );
        assert_eq!(session_for(&un(200, 25), Some(&cred), known, &t), None);
        assert_eq!(session_for(&un(90, 40), None, known, &t), None);
        let other = format!("ms-dev-{}", "cd".repeat(32));
        assert_eq!(session_for(&un(90, 40), Some(&other), known, &t), None);
        let restarted = crate::daemon::dev::dev_session_id(70, 21);
        assert_eq!(
            session_for(&un(90, 40), Some(&cred), |_| Some(restarted.clone()), &t),
            None
        );
        let agent = SessionId {
            agent: AgentKind::ClaudeCode,
            pid: 95,
            started_unix_ms: 50,
        };
        let a = Caller::Agent(agent.clone());
        assert_eq!(session_for(&a, Some(&cred), known, &t), Some(agent.clone()));
        assert_eq!(
            session_for(&a, Some("claude-code"), known, &t),
            Some(agent.clone())
        );
        assert_eq!(session_for(&a, Some("codex"), known, &t), None);
        assert_eq!(session_for(&a, None, known, &t), Some(agent));
    }

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

    // protects=L34 (found building ms dev): a project key (`shop/stripe-secret-key`) is swapped
    // with the location of the provider its project record names; without a record it is skipped
    // with a note (fails closed); a recorded provider whose catalog hosts don't cover the rule's
    // hosts is not used (review N1), and a recorded key never falls back to the first-segment
    // guess (round 2);
    // fails_when=project keys are never bound, or bound with another provider's location;
    // no_claim=the records' MAC (ms-projects store tests)
    #[test]
    fn project_keys_bind_with_their_recorded_provider() {
        let r = rules(
            r#"
version = 3
[keys."shop/stripe-secret-key"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com"]
"#,
        );
        let key = KeyName::new("shop/stripe-secret-key").unwrap();
        let (none, skipped) = bindings(&r);
        assert!(none.is_empty() && skipped.len() == 1, "{skipped:?}");
        let recorded = BTreeMap::from([(key.clone(), Some("stripe".to_string()))]);
        let (b, skipped) = bindings_with(&r, &recorded);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].hosts, ["api.stripe.com"]);
        assert!(
            matches!(&b[0].location, Location::Header { name, .. } if name.eq_ignore_ascii_case("authorization"))
        );
        // A recorded provider whose catalog hosts don't cover the rule's hosts is ignored: the
        // key falls back to the old lookup, which finds nothing for `shop/…` (fails closed).
        let other = rules(
            r#"
version = 3
[keys."shop/stripe-secret-key"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com", "evil.example"]
"#,
        );
        let (b, skipped) = bindings_with(&other, &recorded);
        assert!(b.is_empty() && skipped.len() == 1, "{b:?} {skipped:?}");
        let openai = BTreeMap::from([(key.clone(), Some("openai".to_string()))]);
        let (b, _) = bindings_with(&r, &openai);
        assert!(b.is_empty(), "openai's header for a stripe host: {b:?}");
        // Review round 2: a project slugged like a provider (`stripe`) doesn't lend that
        // provider's location to a recorded key without one; unrecorded, the old lookup holds.
        let slugged = rules(
            r#"
version = 3
[keys."stripe/session-secret"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com"]
"#,
        );
        let k2 = KeyName::new("stripe/session-secret").unwrap();
        let (b, _) = bindings_with(&slugged, &BTreeMap::from([(k2.clone(), None)]));
        assert!(b.is_empty(), "{b:?}");
        let (b, _) = bindings_with(&slugged, &BTreeMap::new());
        assert_eq!(b.len(), 1);
    }

    // protects=L30 D2 a key's git hosts get their own Basic-password binding and its other hosts
    // keep the catalog location; a key with only git hosts needs no catalog entry;
    // fails_when=a git host keeps the Bearer location, or an API host gets the Basic one;
    // no_claim=the swap itself (ms-proxy git itest)
    #[test]
    fn git_hosts_bind_basic_password() {
        let r = rules(
            r#"
version = 1
[keys."github/test"]
mode = "swap"
tier = "test"
hosts = ["api.github.com", "github.com"]
git_hosts = ["github.com"]
[keys."zzz/git"]
mode = "swap"
tier = "test"
hosts = ["git.example.com"]
git_hosts = ["git.example.com"]
"#,
        );
        let (b, skipped) = bindings(&r);
        assert!(skipped.is_empty(), "{skipped:?}");
        let by = |p: &str| b.iter().find(|b| b.provider == p).unwrap();
        let api = by("github-test");
        assert_eq!(api.hosts, ["api.github.com"]);
        assert!(matches!(api.location, Location::Header { .. }));
        let basic = Location::Basic {
            field: BasicField::Password,
        };
        let git = by("github-test-git");
        assert_eq!(
            (git.hosts.as_slice(), &git.location, git.port),
            (&["github.com".to_string()][..], &basic, 443)
        );
        let other = by("zzz-git-git");
        assert_eq!(
            (other.key.as_str(), other.hosts.as_slice(), &other.location),
            ("zzz/git", &["git.example.com".to_string()][..], &basic)
        );
        assert_eq!(b.len(), 3);
    }

    // protects=L30 D5 the test-upstream hook needs the memory vault, a CA and loopback targets,
    // and nothing given means no hook; fails_when=it is accepted with the keychain vault or
    // without a CA; no_claim=the release-build refusal (cfg!(debug_assertions) is false only
    // there; checked by building release in the gate)
    #[test]
    fn test_upstreams_need_the_memory_vault() {
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join("ca.pem");
        std::fs::write(&ca, ms_proxy::Ca::generate(["x.test"]).unwrap().cert_pem()).unwrap();
        let spec = vec!["git.test=127.0.0.1:4471".to_string()];
        assert!(TestHook::new(&[], None, false).is_ok());
        assert!(TestHook::new(&spec, Some(&ca), false).is_err());
        assert!(TestHook::new(&spec, None, true).is_err());
        assert!(TestHook::new(&["git.test=10.1.1.1:443".into()], Some(&ca), true).is_err());
        assert!(TestHook::new(&spec, Some(&ca), true).is_ok());
    }

    // protects=review finding 2: two keys whose proxy names collide are both skipped with a note
    // instead of failing the whole proxy config; fails_when=a duplicate provider reaches the
    // config; no_claim=ProxyConfig::validate itself (ms-proxy)
    #[test]
    fn colliding_provider_names_are_skipped() {
        let r = rules(
            r#"
version = 1
[keys."stripe/x"]
mode = "swap"
tier = "test"
hosts = ["git.example.com"]
git_hosts = ["git.example.com"]
[keys."stripe/x/git"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com"]
[keys."stripe/test"]
mode = "swap"
tier = "test"
hosts = ["api.stripe.com"]
"#,
        );
        let (b, skipped) = bindings(&r);
        let names: Vec<_> = b.iter().map(|b| b.provider.as_str()).collect();
        assert_eq!(names, ["stripe-test"]);
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(skipped.iter().all(|s| s.contains("stripe-x-git")));
    }
}
