use rankigi_proxy::{config::Config, proxy::ProxyServer, queue, signing::PassportSigner, tls};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--generate-ca-only") {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        return generate_ca_only();
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("rankigi-proxy {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

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

/// `--generate-ca-only`: load or generate the local root CA and exit.
/// Used by install.sh so the CA can be created and trusted before the
/// proxy is run with full RANKIGI credentials.
fn generate_ca_only() -> anyhow::Result<()> {
    let cert_path = PathBuf::from(
        env::var("CA_CERT_PATH").unwrap_or_else(|_| "rankigi-ca.crt".to_string()),
    );
    let key_path = PathBuf::from(
        env::var("CA_KEY_PATH").unwrap_or_else(|_| "rankigi-ca.key".to_string()),
    );
    let _ca = tls::RootCa::load_or_generate(&cert_path, &key_path)?;
    println!("CA cert written to: {}", cert_path.display());
    println!("CA key  written to: {}", key_path.display());
    Ok(())
}

fn print_help() {
    println!(
        "rankigi-proxy {}\n\
        \n\
        USAGE:\n    \
        rankigi-proxy [FLAGS]\n\
        \n\
        FLAGS:\n    \
        --generate-ca-only    Generate the local root CA at CA_CERT_PATH /\n                          \
        CA_KEY_PATH and exit. Defaults: ./rankigi-ca.crt\n                          \
        and ./rankigi-ca.key.\n    \
        --help, -h            Print this message.\n    \
        --version, -V         Print the version.\n\
        \n\
        Without flags the proxy reads its full configuration from the\n\
        environment (RANKIGI_INGEST_URL, RANKIGI_API_KEY, RANKIGI_AGENT_ID,\n\
        RANKIGI_ORG_ID) and starts the listener on RANKIGI_PROXY_PORT (8080).",
        env!("CARGO_PKG_VERSION")
    );
}
