//! The morsec CA: name-constrained to the bound hosts, private key kept in the vault.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ms_core::{KeyMeta, KeyName, SecretBytes};
use ms_vault::{Vault, VaultExt};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::config::validate_host;
use crate::error::ProxyError;

const CA_CN: &str = "morsec local CA";
const CA_O: &str = "morsec";
const CA_LIFETIME: time::Duration = time::Duration::days(730);
const LEAF_LIFETIME: time::Duration = time::Duration::days(7);
/// Leaves are replaced well before they expire.
const LEAF_REUSE: Duration = Duration::from_secs(5 * 24 * 3600);

/// A leaf certificate chain and its key, ready for rustls.
pub(crate) struct Leaf {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Leaf([redacted key])")
    }
}

/// The local CA. Issues leaves only for the hosts in its name constraints.
pub struct Ca {
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    hosts: BTreeSet<String>,
    leaves: Mutex<HashMap<String, (Arc<rustls::ServerConfig>, Instant)>>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("hosts", &self.hosts)
            .field("key", &"[redacted]")
            .finish()
    }
}

fn ca_params(hosts: &BTreeSet<String>) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    dn.push(DnType::OrganizationName, CA_O);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts
            .iter()
            .map(|h| GeneralSubtree::DnsName(h.clone()))
            .collect(),
        // A DNS-only constraint leaves iPAddress SANs unconstrained (RFC 5280), so exclude all
        // of them: a leaked CA key still can't sign for an IP literal.
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                0,
            )),
            GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                std::net::Ipv6Addr::UNSPECIFIED.into(),
                0,
            )),
        ],
    });
    let now = OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + CA_LIFETIME;
    p
}

fn ca_err(e: impl std::fmt::Display) -> ProxyError {
    ProxyError::Ca(e.to_string())
}

fn host_set<I, S>(hosts: I) -> Result<BTreeSet<String>, ProxyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: BTreeSet<String> = hosts.into_iter().map(|h| h.as_ref().to_owned()).collect();
    if set.is_empty() {
        return Err(ProxyError::Ca(
            "the CA needs at least one host to cover; bind a key to a host first".into(),
        ));
    }
    for h in &set {
        validate_host(h)?;
    }
    Ok(set)
}

impl Ca {
    /// A new CA (ECDSA P-256) whose name constraints permit exactly `hosts` (and their
    /// subdomains, per RFC 5280). Adding a host means generating a new CA.
    pub fn generate<I, S>(hosts: I) -> Result<Self, ProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = host_set(hosts)?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(ca_err)?;
        let params = ca_params(&hosts);
        let cert = params.self_signed(&key).map_err(ca_err)?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
            hosts,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate, PEM. Public: connectors put it in the trust bundle.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate, DER.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Hosts the CA may issue for.
    pub fn hosts(&self) -> &BTreeSet<String> {
        &self.hosts
    }

    /// Stores the private key in `vault` under `name`. The key is never written anywhere else.
    pub fn store(
        &self,
        vault: &dyn Vault,
        name: &KeyName,
        meta: KeyMeta,
    ) -> Result<(), ProxyError> {
        let pem = Zeroizing::new(self.issuer.key().serialize_pem());
        vault.put(name, SecretBytes::new(pem.as_bytes().to_vec()), meta)?;
        Ok(())
    }

    /// Loads a CA whose key is in `vault` under `name` and whose certificate is `cert_pem`.
    /// `hosts` must be the list the CA was generated with; the certificate's public key must
    /// match the stored key.
    pub fn load<I, S>(
        vault: &dyn Vault,
        name: &KeyName,
        cert_pem: &str,
        hosts: I,
    ) -> Result<Self, ProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = host_set(hosts)?;
        let key = vault.read_with(name, |bytes| {
            let pem = std::str::from_utf8(bytes).map_err(|_| "the stored CA key is not PEM")?;
            KeyPair::from_pem(pem).map_err(|_| "the stored CA key does not parse")
        })?;
        let key = key.map_err(ca_err)?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|_| ProxyError::Ca("the CA certificate is not PEM".into()))?;
        let pk = key.public_key_raw();
        if !cert_der.windows(pk.len()).any(|w| w == pk) {
            return Err(ProxyError::Ca(
                "the CA certificate does not match the key in the vault. Re-create the CA".into(),
            ));
        }
        // Rebuilding the issuer from the same template gives the same subject and key id.
        let params = ca_params(&hosts);
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            cert_der,
            issuer: Issuer::new(params, key),
            hosts,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// Issues a short-lived leaf for `host`. Refuses any host outside the CA's list.
    pub(crate) fn issue_leaf(&self, host: &str) -> Result<Leaf, ProxyError> {
        if !self.hosts.contains(host) {
            return Err(ProxyError::Ca(format!(
                "refusing to issue a certificate for {host}: no key is bound to it"
            )));
        }
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(ca_err)?;
        let mut p = CertificateParams::new(vec![host.to_owned()]).map_err(ca_err)?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::hours(1);
        p.not_after = now + LEAF_LIFETIME;
        let cert = p.signed_by(&key, &self.issuer).map_err(ca_err)?;
        let der = Zeroizing::new(key.serialize_der());
        Ok(Leaf {
            chain: vec![cert.der().clone(), self.cert_der.clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())),
        })
    }

    /// A TLS server config for `host`, cached. ALPN offers h2 and http/1.1.
    pub(crate) fn server_config(
        &self,
        host: &str,
    ) -> Result<Arc<rustls::ServerConfig>, ProxyError> {
        let mut cache = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cfg, made)) = cache.get(host)
            && made.elapsed() < LEAF_REUSE
        {
            return Ok(cfg.clone());
        }
        let leaf = self.issue_leaf(host)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(leaf.chain, leaf.key)
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        // Bounded: only CA hosts ever get an entry.
        cache.insert(host.to_owned(), (cfg.clone(), Instant::now()));
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ms_core::{Mode, Tier};
    use ms_vault::memory::MemoryVault;

    // protects=leaves are issued only for CA hosts and chain to the CA; fails_when=a leaf is
    // issued for an unbound host; no_claim=client-side constraint enforcement (see Go test)
    #[test]
    fn leaves_only_for_bound_hosts() {
        let ca = Ca::generate(["api.stripe.com"]).unwrap();
        let leaf = ca.issue_leaf("api.stripe.com").unwrap();
        assert_eq!(leaf.chain.len(), 2);
        assert_eq!(&leaf.chain[1], ca.cert_der());
        assert!(ca.issue_leaf("evil.example.com").is_err());
        assert!(ca.issue_leaf("x.api.stripe.com").is_err());
        assert!(!format!("{leaf:?} {ca:?}").contains("PRIVATE"));
    }

    // protects=the CA certificate carries a name-constraints extension listing the hosts;
    // fails_when=the extension or a host is missing; no_claim=DER-level criticality
    #[test]
    fn has_name_constraints() {
        let ca = Ca::generate(["api.stripe.com", "api.openai.com"]).unwrap();
        let der = ca.cert_der().as_ref();
        // id-ce-nameConstraints 2.5.29.30
        assert!(der.windows(3).any(|w| w == [0x55, 0x1d, 0x1e]));
        for h in ["api.stripe.com", "api.openai.com"] {
            assert!(der.windows(h.len()).any(|w| w == h.as_bytes()), "{h}");
        }
        // Excluded iPAddress subtrees: [7] 0.0.0.0/0 and [7] ::/0 (address + mask, all zero).
        assert!(
            der.windows(10)
                .any(|w| w == [0x87, 8, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert!(
            der.windows(34)
                .any(|w| w[0] == 0x87 && w[1] == 32 && w[2..].iter().all(|b| *b == 0))
        );
    }

    // protects=the CA key round-trips only through the vault, and a mismatched cert is refused;
    // fails_when=load accepts another CA's cert or loses the key; no_claim=keychain storage (L01)
    #[test]
    fn store_and_load() {
        let v = MemoryVault::new();
        let name = KeyName::new("morsec/ca").unwrap();
        let meta = KeyMeta {
            name: name.clone(),
            mode: Mode::Swap,
            tier: Tier::Production,
            created_unix_ms: 0,
        };
        let ca = Ca::generate(["api.stripe.com"]).unwrap();
        ca.store(&v, &name, meta).unwrap();
        let loaded = Ca::load(&v, &name, ca.cert_pem(), ["api.stripe.com"]).unwrap();
        loaded.issue_leaf("api.stripe.com").unwrap();
        let other = Ca::generate(["api.stripe.com"]).unwrap();
        let err = Ca::load(&v, &name, other.cert_pem(), ["api.stripe.com"]).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
        assert!(Ca::generate(Vec::<String>::new()).is_err());
    }
}
