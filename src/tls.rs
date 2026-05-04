//! Local root CA management plus dynamic leaf certificate generation for
//! TLS interception.
//!
//! On first startup the proxy generates a root CA and persists `cert.pem` +
//! `key.pem` to disk. Subsequent runs load only the keypair and re-derive
//! the in-memory issuer certificate using the same fixed Distinguished Name.
//! Because the keypair is preserved, leaf certificates signed by the
//! in-memory issuer chain back to the persisted CA cert in the agent's
//! trust store. Leaf certs are generated on demand per target hostname and
//! cached for the process lifetime.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("invalid CA on disk: {0}")]
    InvalidCa(String),
    #[error("invalid hostname")]
    InvalidHostname,
}

const CA_COMMON_NAME: &str = "RANKIGI Local Proxy CA";
const CA_ORG_NAME: &str = "RANKIGI";

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, CA_ORG_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = SystemTime::now();
    params.not_before = now.into();
    let ten_years = std::time::Duration::from_secs(60 * 60 * 24 * 365 * 10);
    params.not_after = (now + ten_years).into();
    params
}

/// Loaded root CA used to sign dynamic leaf certs.
pub struct RootCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub key_pair: KeyPair,
}

impl RootCa {
    /// Generate a new self-signed root CA suitable for signing leaf certs.
    pub fn generate() -> Result<Self, TlsError> {
        let key_pair = KeyPair::generate()?;
        let cert = ca_params().self_signed(&key_pair)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            key_pair,
        })
    }

    /// Load an existing CA from PEM files. Both files must already exist.
    /// Only the keypair is used at runtime; the persisted cert PEM is what
    /// the agent's trust store pins.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let key_pair =
            KeyPair::from_pem(&key_pem).map_err(|e| TlsError::InvalidCa(format!("key: {}", e)))?;
        Ok(Self {
            cert_pem,
            key_pem,
            key_pair,
        })
    }

    /// Load the CA at the given paths or generate-and-persist a new one.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        if cert_path.exists() && key_path.exists() {
            Self::load(cert_path, key_path)
        } else {
            let ca = Self::generate()?;
            if let Some(parent) = cert_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(cert_path, ca.cert_pem.as_bytes())?;
            std::fs::write(key_path, ca.key_pem.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(ca)
        }
    }

    /// Build an in-memory issuer certificate for signing leaf certs. Cheap
    /// to call repeatedly; we do not cache it because rcgen's
    /// `Certificate` is not `Sync`.
    fn issuer_certificate(&self) -> Result<rcgen::Certificate, TlsError> {
        Ok(ca_params().self_signed(&self.key_pair)?)
    }
}

/// Issue a leaf certificate for a hostname signed by the given root CA.
pub fn issue_leaf(
    ca: &RootCa,
    hostname: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    if hostname.is_empty() {
        return Err(TlsError::InvalidHostname);
    }
    let mut params = CertificateParams::new(vec![hostname.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    let san = if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        SanType::IpAddress(ip)
    } else {
        SanType::DnsName(
            hostname
                .to_string()
                .try_into()
                .map_err(|_| TlsError::InvalidHostname)?,
        )
    };
    params.subject_alt_names = vec![san];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = SystemTime::now();
    params.not_before = now.into();
    let one_year = std::time::Duration::from_secs(60 * 60 * 24 * 365);
    params.not_after = (now + one_year).into();

    let leaf_key = KeyPair::generate()?;
    let issuer = ca.issuer_certificate()?;
    let leaf_cert = params.signed_by(&leaf_key, &issuer, &ca.key_pair)?;

    let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    Ok((vec![leaf_der], PrivateKeyDer::Pkcs8(key_der)))
}

/// Cache of `rustls::ServerConfig` per hostname.
pub struct LeafCache {
    ca: Arc<RootCa>,
    cache: RwLock<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl LeafCache {
    pub fn new(ca: Arc<RootCa>) -> Self {
        Self {
            ca,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn server_config_for(
        &self,
        hostname: &str,
    ) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        {
            let read = self.cache.read().await;
            if let Some(cfg) = read.get(hostname) {
                return Ok(cfg.clone());
            }
        }
        let (chain, key) = issue_leaf(&self.ca, hostname)?;
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        let cfg = Arc::new(cfg);
        let mut write = self.cache.write().await;
        write.insert(hostname.to_string(), cfg.clone());
        Ok(cfg)
    }
}
