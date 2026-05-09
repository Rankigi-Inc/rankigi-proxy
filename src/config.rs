//! Proxy configuration loaded from environment variables.

use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use thiserror::Error;

/// How the stamp footer is woven into the request body for a given pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StampBodyType {
    /// Inject into a JSON field path (e.g. "raw" for Gmail's base64 MIME).
    JsonField(String),
    /// Insert before the closing `</body>` tag of an HTML document.
    HtmlBody,
    /// Append to the end of a plain-text body.
    PlainText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampPattern {
    pub host: String,
    pub path_prefix: String,
    pub body_type: StampBodyType,
}

#[derive(Debug, Clone)]
pub struct StampConfig {
    pub enabled: bool,
    pub patterns: Vec<StampPattern>,
    /// Public base URL for receipt resolution (no trailing slash).
    pub verify_base_url: String,
    /// If true, the proxy waits for the stamp event to land before forwarding
    /// the modified request. Adds latency. V1: not implemented; reserved.
    pub sync_anchor: bool,
}

impl Default for StampConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            patterns: Vec::new(),
            verify_base_url: "https://rankigi.com/v".to_string(),
            sync_anchor: false,
        }
    }
}

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
    /// When true, the proxy expects iptables-redirected raw TLS connections
    /// on its listen port. The original destination is recovered via
    /// `SO_ORIGINAL_DST` (Linux only) and the hostname via reverse DNS.
    /// Agents do NOT need `HTTPS_PROXY` set in this mode.
    pub transparent_mode: bool,
    /// Stamp mode: when a request matches a pattern the proxy injects a
    /// verifiable receipt footer into the request body and submits a
    /// `stamp.issued` chain event. Disabled by default.
    pub stamp: StampConfig,
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
        let transparent_mode = parse_env_or("RANKIGI_TRANSPARENT_MODE", false)?;
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

        let stamp = load_stamp_config()?;

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
            transparent_mode,
            stamp,
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

fn load_stamp_config() -> Result<StampConfig, ConfigError> {
    let enabled = parse_env_or("RANKIGI_STAMP_ENABLED", false)?;
    let verify_base_url = env::var("RANKIGI_STAMP_VERIFY_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://rankigi.com/v".to_string());
    let verify_base_url = verify_base_url.trim_end_matches('/').to_string();
    let sync_anchor = parse_env_or("RANKIGI_STAMP_SYNC_ANCHOR", false)?;
    let patterns = match env::var("RANKIGI_STAMP_PATTERNS") {
        Ok(raw) if !raw.trim().is_empty() => serde_json::from_str::<Vec<StampPattern>>(&raw)
            .map_err(|e| ConfigError::Invalid("RANKIGI_STAMP_PATTERNS", e.to_string()))?,
        _ => Vec::new(),
    };
    Ok(StampConfig {
        enabled,
        patterns,
        verify_base_url,
        sync_anchor,
    })
}
