//! Proxy configuration loaded from environment variables.

use std::env;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_port: u16,
    pub ingest_url: String,
    pub api_key: String,
    pub agent_id: String,
    pub org_id: String,
    pub buffer_size: usize,
    pub ingest_timeout_ms: u64,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    /// Optional: base64 PKCS8 Ed25519 private key for passport signing. If
    /// both this and `passport_id` are present the proxy signs every event.
    /// Otherwise events are submitted ungoverned and the server marks them
    /// `data_quality_flag="unverified"`.
    pub passport_key: Option<String>,
    pub passport_id: Option<String>,
    /// Off by default — server endpoint does not exist yet.
    pub seal_eval_enabled: bool,
    pub seal_eval_timeout_ms: u64,
    /// Hosts that the proxy must NOT MITM, capture, or record. Always
    /// includes the host parsed from `ingest_url` so that the proxy never
    /// records its own ingest submissions (which would create a capture →
    /// ingest → capture loop). Users can extend this list via
    /// `RANKIGI_BYPASS_HOSTS` (comma-separated).
    pub bypass_hosts: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let proxy_port = parse_env_or("RANKIGI_PROXY_PORT", 8080u16)?;
        let ingest_url = require("RANKIGI_INGEST_URL")?;
        let api_key = require("RANKIGI_API_KEY")?;
        let agent_id = require("RANKIGI_AGENT_ID")?;
        let org_id = require("RANKIGI_ORG_ID")?;
        let buffer_size = parse_env_or("RANKIGI_BUFFER_SIZE", 1000usize)?;
        let ingest_timeout_ms = parse_env_or("RANKIGI_INGEST_TIMEOUT_MS", 5000u64)?;
        let ca_cert_path = PathBuf::from(
            env::var("CA_CERT_PATH").unwrap_or_else(|_| "rankigi-ca.crt".to_string()),
        );
        let ca_key_path =
            PathBuf::from(env::var("CA_KEY_PATH").unwrap_or_else(|_| "rankigi-ca.key".to_string()));
        let passport_key = env::var("RANKIGI_PASSPORT_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let passport_id = env::var("RANKIGI_PASSPORT_ID")
            .ok()
            .filter(|s| !s.is_empty());
        let seal_eval_enabled = parse_env_or("RANKIGI_SEAL_EVAL_ENABLED", false)?;
        let seal_eval_timeout_ms = parse_env_or("RANKIGI_SEAL_EVAL_TIMEOUT_MS", 20u64)?;

        // Bypass list: always includes the ingest URL host so the proxy
        // never re-captures its own outbound submissions. Users may add
        // additional hosts via RANKIGI_BYPASS_HOSTS (comma-separated).
        let mut bypass_hosts: Vec<String> = Vec::new();
        if let Some(host) = url::Url::parse(&ingest_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_ascii_lowercase()))
        {
            bypass_hosts.push(host);
        }
        if let Ok(extra) = env::var("RANKIGI_BYPASS_HOSTS") {
            for h in extra.split(',') {
                let trimmed = h.trim().trim_start_matches('.').to_ascii_lowercase();
                if !trimmed.is_empty() && !bypass_hosts.contains(&trimmed) {
                    bypass_hosts.push(trimmed);
                }
            }
        }

        Ok(Self {
            proxy_port,
            ingest_url,
            api_key,
            agent_id,
            org_id,
            buffer_size,
            ingest_timeout_ms,
            ca_cert_path,
            ca_key_path,
            passport_key,
            passport_id,
            seal_eval_enabled,
            seal_eval_timeout_ms,
            bypass_hosts,
        })
    }

    pub fn signing_enabled(&self) -> bool {
        self.passport_key.is_some() && self.passport_id.is_some()
    }

    /// Case-insensitive exact match against the bypass list.
    pub fn is_bypassed(&self, host: &str) -> bool {
        let h = host.trim_start_matches('.').to_ascii_lowercase();
        self.bypass_hosts.iter().any(|b| *b == h)
    }
}

fn require(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_env_or<T: std::str::FromStr>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(v) if !v.is_empty() => v
            .parse::<T>()
            .map_err(|e| ConfigError::Invalid(name, e.to_string())),
        _ => Ok(default),
    }
}
