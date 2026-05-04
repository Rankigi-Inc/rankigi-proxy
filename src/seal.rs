//! Optional seal evaluation. Off by default — the server endpoint
//! (`/api/seal/evaluate`) does not exist yet. When enabled the proxy POSTs a
//! request hash + action type to the seal endpoint, awaits a verdict (max 20
//! ms by default), and tags the resulting chain entry with the verdict.
//!
//! Fail-open: any error, timeout, or non-200 response yields a `Timeout` /
//! `Unavailable` tag and the proxy proceeds.

use crate::config::Config;
use crate::event::SealVerdictTag;
use serde::Serialize;
use std::time::Duration;
use tracing::warn;

#[derive(Serialize)]
struct SealRequest<'a> {
    agent_id: &'a str,
    request_hash: &'a str,
    action_type: &'a str,
}

pub async fn evaluate_seal(
    client: &reqwest::Client,
    cfg: &Config,
    request_hash: &str,
    action_type: &str,
) -> SealVerdictTag {
    if !cfg.seal_eval_enabled {
        return SealVerdictTag::Disabled;
    }
    let url = format!("{}/api/seal/evaluate", cfg.ingest_url.trim_end_matches('/'));
    let body = SealRequest {
        agent_id: &cfg.agent_id,
        request_hash,
        action_type,
    };

    let request = client
        .post(&url)
        .bearer_auth(&cfg.api_key)
        .json(&body)
        .timeout(Duration::from_millis(cfg.seal_eval_timeout_ms))
        .send();

    match tokio::time::timeout(Duration::from_millis(cfg.seal_eval_timeout_ms), request).await {
        Ok(Ok(resp)) => {
            if !resp.status().is_success() {
                warn!(status = %resp.status(), "seal eval non-success");
                return SealVerdictTag::Unavailable;
            }
            let json: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(err = %e, "seal eval json parse failed");
                    return SealVerdictTag::Unavailable;
                }
            };
            match json.get("verdict").and_then(|v| v.as_str()) {
                Some("admissible") => SealVerdictTag::Admissible,
                Some("denied") => SealVerdictTag::Denied,
                _ => SealVerdictTag::Unavailable,
            }
        }
        Ok(Err(e)) => {
            warn!(err = %e, "seal eval request failed");
            SealVerdictTag::Unavailable
        }
        Err(_) => SealVerdictTag::Timeout,
    }
}
