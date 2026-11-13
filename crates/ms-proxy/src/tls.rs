//! rustls setup. The proxy always uses the `ring` provider explicitly, never a process default.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use crate::config::UpstreamRoots;
use crate::error::ProxyError;

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Client config for upstreams: verified against `roots`, ALPN h2 then http/1.1.
pub(crate) fn client_config(
    roots: &UpstreamRoots,
) -> Result<Arc<rustls::ClientConfig>, ProxyError> {
    let mut store = rustls::RootCertStore::empty();
    match roots {
        UpstreamRoots::System => {
            // rustls-native-certs replaces the OS store with these files when either is set.
            // Connectors set them for the agent, and the agent can write files they point at, so
            // the broker refuses to start with them rather than trust agent-controlled roots.
            for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
                if std::env::var_os(var).is_some() {
                    return Err(ProxyError::Tls(format!(
                        "{var} is set in the broker's environment, so upstream roots could come from a file the agent controls. Start msd without {var}"
                    )));
                }
            }
            let found = rustls_native_certs::load_native_certs();
            for c in found.certs {
                // A malformed system root is skipped, not fatal; it just can't verify anything.
                let _ = store.add(c);
            }
            if store.is_empty() {
                return Err(ProxyError::Tls(
                    "no system root certificates were found, so upstream TLS can't be verified"
                        .into(),
                ));
            }
        }
        UpstreamRoots::Only(certs) => {
            for c in certs {
                store
                    .add(c.clone())
                    .map_err(|e| ProxyError::Tls(format!("bad upstream root: {e}")))?;
            }
        }
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
