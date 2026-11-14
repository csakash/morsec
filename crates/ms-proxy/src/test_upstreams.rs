//! QA hook (L30 SPEC D5), compiled only in debug builds: lets a dev msd reach a local HTTPS
//! server under a chosen name. `HOST=127.0.0.1:PORT` maps one name to one loopback address, and
//! upstream TLS is verified against the given CA only. Every other name resolves as usual with
//! loopback answers dropped, so the SSRF guard still keeps them away from loopback. msd accepts
//! it only with the memory vault; release builds don't have this module at all.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::config::{ProxyConfig, UpstreamRoots};
use crate::deps::Deps;
use crate::server::Proxy;
use crate::ssrf::{BoxFuture, Resolve, SystemResolver};

/// Test upstreams: names mapped to loopback addresses, and the CA that verifies them.
#[derive(Debug, Clone)]
pub struct TestUpstreams {
    map: Arc<BTreeMap<String, SocketAddr>>,
    roots: Vec<CertificateDer<'static>>,
}

impl TestUpstreams {
    /// Parses `HOST=IP:PORT` specs (the IP must be loopback) and a PEM CA file's contents.
    pub fn new(specs: &[String], ca_pem: &str) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        for s in specs {
            let (host, addr) = s
                .split_once('=')
                .ok_or_else(|| format!("test upstream {s:?} must be HOST=127.0.0.1:PORT"))?;
            let addr: SocketAddr = addr
                .parse()
                .map_err(|_| format!("test upstream {s:?} must be HOST=127.0.0.1:PORT"))?;
            if !addr.ip().is_loopback() || host.is_empty() {
                return Err(format!(
                    "test upstream {s:?} must map a name to a loopback address"
                ));
            }
            map.insert(host.to_ascii_lowercase(), addr);
        }
        let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ca_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| format!("test upstream CA: {e}"))?;
        if map.is_empty() || roots.is_empty() {
            return Err("test upstreams need at least one HOST=ADDR and a CA certificate".into());
        }
        Ok(Self {
            map: Arc::new(map),
            roots,
        })
    }

    /// Points `cfg` and `deps` at the test upstreams.
    pub fn configure(&self, cfg: &mut ProxyConfig, deps: &mut Deps) {
        cfg.upstream_roots = UpstreamRoots::Only(self.roots.clone());
        deps.resolver = Arc::new(MapResolver(self.map.clone()));
    }

    /// Lets `proxy` connect to the mapped loopback addresses.
    pub fn allow(&self, proxy: &mut Proxy) {
        proxy.allow_loopback_upstreams_for_tests();
    }
}

#[derive(Debug)]
struct MapResolver(Arc<BTreeMap<String, SocketAddr>>);

impl Resolve for MapResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            if let Some(a) = self.0.get(&host.to_ascii_lowercase()) {
                return Ok(vec![*a]);
            }
            let all = SystemResolver.resolve(host, port).await?;
            Ok(all.into_iter().filter(|a| !a.ip().is_loopback()).collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=L30 D5 only loopback mappings are accepted, and an unmapped name never resolves
    // to loopback; fails_when=a non-loopback mapping parses, or localhost resolves to 127.0.0.1;
    // no_claim=msd's debug/memory-vault gate (msd tests)
    #[tokio::test]
    async fn maps_only_named_hosts_to_loopback() {
        let ca = crate::Ca::generate(["x.test"]).unwrap();
        let pem = ca.cert_pem();
        assert!(TestUpstreams::new(&["git.test=10.0.0.1:443".into()], pem).is_err());
        assert!(TestUpstreams::new(&["git.test".into()], pem).is_err());
        assert!(TestUpstreams::new(&["git.test=127.0.0.1:1".into()], "").is_err());
        let t = TestUpstreams::new(&["Git.Test=127.0.0.1:4471".into()], pem).unwrap();
        let r = MapResolver(t.map.clone());
        assert_eq!(
            r.resolve("git.test", 443).await.unwrap(),
            vec!["127.0.0.1:4471".parse().unwrap()]
        );
        assert!(r.resolve("localhost", 443).await.unwrap().is_empty());
    }
}
