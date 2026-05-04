use rankigi_proxy::{config::Config, proxy::ProxyServer, queue, signing::PassportSigner, tls};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cfg = Arc::new(Config::from_env()?);
    info!(
        port = cfg.proxy_port,
        ingest = %cfg.ingest_url,
        agent = %cfg.agent_id,
        signing = cfg.signing_enabled(),
        seal_eval = cfg.seal_eval_enabled,
        "rankigi-proxy starting"
    );

    let signer = if cfg.signing_enabled() {
        match PassportSigner::from_b64_pkcs8(
            cfg.passport_key.as_ref().unwrap(),
            cfg.passport_id.as_ref().unwrap().clone(),
        ) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                error!(err = %e, "passport signing key invalid — submitting unsigned");
                None
            }
        }
    } else {
        None
    };

    let ca = tls::RootCa::load_or_generate(&cfg.ca_cert_path, &cfg.ca_key_path)?;
    info!(
        cert = ?cfg.ca_cert_path,
        key = ?cfg.ca_key_path,
        "ca ready (agent must trust this cert)"
    );
    let leaf_cache = Arc::new(tls::LeafCache::new(Arc::new(ca)));

    let (queue, drainer) = queue::spawn(cfg.clone(), signer);
    let server = Arc::new(ProxyServer::new(cfg.clone(), queue, leaf_cache));

    // Graceful shutdown on SIGINT / SIGTERM.
    let serve_fut = server.serve();
    tokio::select! {
        res = serve_fut => {
            if let Err(e) = res {
                error!(err = %e, "proxy listener exited");
            }
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received, draining ingest queue (max 5s)");
        }
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drainer).await;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
