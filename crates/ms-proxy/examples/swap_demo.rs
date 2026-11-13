//! Demo/QA harness: runs the swap proxy on 127.0.0.1:<port> with an in-memory vault holding a
//! fake canary key, bound to httpbin.org (which echoes request headers). Not part of `msd`.
//!
//! cargo run -p ms-proxy --example swap_demo -- <port> <ca-pem-out>
//! curl -x http://127.0.0.1:<port> --cacert <ca-pem-out> https://httpbin.org/headers \
//!      -H 'Authorization: Bearer ms://demo/test'

use std::net::SocketAddr;
use std::sync::Arc;

use ms_core::{
    AgentKind, Decision, KeyMeta, KeyName, Mode, ReceiptEvent, Request, Result, SecretBytes,
    SessionId, Tier,
};
use ms_proxy::{Binding, Ca, Deps, Location, Policy, Proxy, ProxyConfig, SessionResolver};
use ms_receipts::{ReceiptId, ReceiptSink};
use ms_vault::Vault;
use ms_vault::memory::MemoryVault;

#[derive(Debug)]
struct AllowAll;
impl Policy for AllowAll {
    fn decide(&self, _: &SessionId, _: &Request) -> Decision {
        Decision::Allow
    }
    fn version(&self) -> u64 {
        1
    }
}

#[derive(Debug)]
struct OneSession;
impl SessionResolver for OneSession {
    fn resolve(&self, _: SocketAddr, _: Option<&str>) -> Option<SessionId> {
        Some(SessionId {
            agent: AgentKind::Other("demo".into()),
            pid: std::process::id(),
            started_unix_ms: 0,
        })
    }
}

#[derive(Debug, Default)]
struct LogSink(std::sync::atomic::AtomicU64);
impl ReceiptSink for LogSink {
    fn append(&self, e: ReceiptEvent) -> Result<ReceiptId> {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        tracing::info!(receipt = n, key = %e.key, target = %e.target, result = ?e.result, "receipt");
        Ok(ReceiptId(n))
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .init();
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().unwrap_or_else(|| "4500".into()).parse()?;
    let ca_out = args.next().ok_or("usage: swap_demo <port> <ca-pem-out>")?;

    let vault = Arc::new(MemoryVault::new());
    let key = KeyName::new("demo/test")?;
    vault.put(
        &key,
        SecretBytes::from("demo-CANARY-value-123".to_owned()),
        KeyMeta {
            name: key.clone(),
            mode: Mode::Swap,
            tier: Tier::Test,
            created_unix_ms: 0,
        },
    )?;
    let ca = Arc::new(Ca::generate(["httpbin.org"])?);
    std::fs::write(&ca_out, ca.cert_pem())?;

    let mut cfg = ProxyConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
    cfg.bindings = vec![Binding {
        key,
        provider: "httpbin".into(),
        hosts: vec!["httpbin.org".into()],
        port: 443,
        location: Location::Header {
            name: "authorization".into(),
            prefix: "Bearer ".into(),
        },
        shaped_placeholder: None,
    }];
    cfg.allow = vec!["github.com".into(), "*.github.com".into()];
    let deps = Deps::new(
        vault,
        Arc::new(AllowAll),
        Arc::new(LogSink::default()),
        Arc::new(OneSession),
        ca,
    );
    let proxy = Proxy::bind(cfg, deps).await?;
    tracing::info!(addr = %proxy.local_addr()?, ca = %ca_out, "swap proxy listening");
    proxy
        .serve(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    Ok(())
}
