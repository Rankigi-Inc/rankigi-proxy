//! Map captured HTTP request/response pairs to the RANKIGI ingest wire schema.
//!
//! The wire schema matches `src/app/api/ingest/route.ts`:
//!   { agent_id, action, tool?, severity?, payload, passport_id?, signature?,
//!     occurred_at? }
//!
//! Everything proxy-specific (method, URL, hashes, latency, capture_source,
//! execution result, data quality) nests inside `payload`. The server
//! canonicalizes `payload`, hashes it into the chain, and stamps
//! `server_received_at` itself.

use crate::canonical_json::canonical_json_or_raw;
use crate::config::Config;
use crate::hash::sha256_hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const PROXY_VERSION: &str = "rankigi-proxy/0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPair {
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub request_body: Vec<u8>,
    pub response_status: Option<u16>,
    pub response_body: Vec<u8>,
    pub proxy_received_at: DateTime<Utc>,
    pub proxy_response_at: Option<DateTime<Utc>>,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestBody {
    pub agent_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub severity: String,
    pub occurred_at: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SealVerdictTag {
    Admissible,
    Denied,
    Timeout,
    Unavailable,
    Disabled,
}

impl SealVerdictTag {
    fn as_str(&self) -> &'static str {
        match self {
            SealVerdictTag::Admissible => "admissible",
            SealVerdictTag::Denied => "denied",
            SealVerdictTag::Timeout => "timeout",
            SealVerdictTag::Unavailable => "unavailable",
            SealVerdictTag::Disabled => "disabled",
        }
    }
}

/// Derive an action_type slug from method + host + path. Matches the mapping
/// the build spec calls out: known LLM endpoints get a stable namespaced slug,
/// everything else falls back to `tool.http.<method>`.
pub fn derive_action_type(method: &str, host: &str, path: &str) -> String {
    let m = method.to_ascii_uppercase();
    let h = host.to_ascii_lowercase();
    if m == "POST" {
        if h == "api.openai.com" && path.starts_with("/v1/chat/completions") {
            return "llm.openai.chat".to_string();
        }
        if h == "api.openai.com" && path.starts_with("/v1/completions") {
            return "llm.openai.completions".to_string();
        }
        if h == "api.openai.com" && path.starts_with("/v1/embeddings") {
            return "llm.openai.embeddings".to_string();
        }
        if h == "api.anthropic.com" && path.starts_with("/v1/messages") {
            return "llm.anthropic.messages".to_string();
        }
        if (h == "localhost"
            || h.starts_with("localhost:")
            || h == "127.0.0.1"
            || h.starts_with("127.0.0.1:"))
            && path.starts_with("/api/generate")
        {
            return "llm.ollama.generate".to_string();
        }
        if (h == "localhost"
            || h.starts_with("localhost:")
            || h == "127.0.0.1"
            || h.starts_with("127.0.0.1:"))
            && path.starts_with("/api/chat")
        {
            return "llm.ollama.chat".to_string();
        }
    }
    match m.as_str() {
        "GET" => "tool.http.get".to_string(),
        "POST" => "tool.http.post".to_string(),
        "PUT" => "tool.http.put".to_string(),
        "DELETE" => "tool.http.delete".to_string(),
        "PATCH" => "tool.http.patch".to_string(),
        "HEAD" => "tool.http.head".to_string(),
        "OPTIONS" => "tool.http.options".to_string(),
        other => format!("tool.http.{}", other.to_ascii_lowercase()),
    }
}

fn execution_result_for(status: Option<u16>) -> &'static str {
    match status {
        Some(s) if s < 400 => "success",
        Some(_) => "error",
        None => "unknown",
    }
}

fn severity_for(status: Option<u16>) -> &'static str {
    match status {
        Some(s) if s >= 500 => "critical",
        Some(s) if s >= 400 => "warn",
        _ => "info",
    }
}

/// Build the ingest body (without signature). Caller signs separately if
/// configured.
pub fn build_ingest_body(
    cfg: &Config,
    pair: &CapturedPair,
    seal_verdict: SealVerdictTag,
) -> IngestBody {
    let action = derive_action_type(&pair.method, &pair.host, &pair.path);
    let tool = format!("{}{}", pair.host, pair.path);

    let request_canon = canonical_json_or_raw(&pair.request_body);
    let response_canon = canonical_json_or_raw(&pair.response_body);
    let input_hash = sha256_hex(&request_canon);
    let output_hash = sha256_hex(&response_canon);

    let latency_ms = pair
        .proxy_response_at
        .map(|end| (end - pair.proxy_received_at).num_milliseconds().max(0))
        .unwrap_or(0);

    let mut decision_metadata = serde_json::Map::new();
    decision_metadata.insert("method".into(), Value::String(pair.method.clone()));
    decision_metadata.insert("url".into(), Value::String(pair.url.clone()));
    if let Some(s) = pair.response_status {
        decision_metadata.insert("status_code".into(), Value::Number(s.into()));
    } else {
        decision_metadata.insert("status_code".into(), Value::Null);
    }
    decision_metadata.insert(
        "request_size_bytes".into(),
        Value::Number(pair.request_body.len().into()),
    );
    decision_metadata.insert(
        "response_size_bytes".into(),
        Value::Number(pair.response_body.len().into()),
    );
    decision_metadata.insert("proxy_latency_ms".into(), Value::Number(latency_ms.into()));
    decision_metadata.insert("capture_source".into(), Value::String("proxy".into()));
    decision_metadata.insert(
        "seal_verdict".into(),
        Value::String(seal_verdict.as_str().into()),
    );

    // PII / secrets detection. Fail-open: timeout or error => null.
    let detection_value =
        match crate::detect::detect_pair(&pair.request_body, &pair.response_body) {
            Some(d) => d.to_json(),
            None => Value::Null,
        };
    decision_metadata.insert("detection".into(), detection_value);

    let payload = json!({
        "input_hash": input_hash,
        "output_hash": output_hash,
        "decision_metadata": Value::Object(decision_metadata),
        "proxy_execution_result": execution_result_for(pair.response_status),
        "proxy_data_quality_flag": if pair.body_truncated { "incomplete" } else { "ok" },
        "_proxy": PROXY_VERSION,
        "_ts": pair.proxy_received_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "_proof_provider": "rankigi.com",
    });

    IngestBody {
        agent_id: cfg.agent_id.clone(),
        action,
        tool: Some(tool),
        severity: severity_for(pair.response_status).to_string(),
        occurred_at: pair
            .proxy_received_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        payload,
        passport_id: None,
        signature: None,
    }
}
