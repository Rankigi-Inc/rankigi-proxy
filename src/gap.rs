//! Gap event constructor. When events are dropped (queue full) or fail to
//! ingest after retries we emit a synthetic chain entry tagged
//! `proxy.gap` so the chain explicitly records the missing slot.

use crate::config::Config;
use crate::event::{IngestBody, PROXY_VERSION};
use crate::queue::GapReason;
use chrono::Utc;
use serde_json::json;

pub fn build_gap_body(cfg: &Config, reason: GapReason) -> IngestBody {
    let now = Utc::now();
    let reason_str = match reason {
        GapReason::QueueFull => "queue_full",
        GapReason::IngestFailure => "ingest_failure",
    };
    let payload = json!({
        "decision_metadata": {
            "reason": reason_str,
            "dropped_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "capture_source": "proxy",
        },
        "proxy_execution_result": "unknown",
        "proxy_data_quality_flag": "incomplete",
        "_proxy": PROXY_VERSION,
        "_ts": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "_proof_provider": "rankigi.com",
    });
    IngestBody {
        agent_id: cfg.agent_id.clone(),
        action: "proxy.gap".to_string(),
        tool: None,
        severity: "warn".to_string(),
        occurred_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        payload,
        passport_id: None,
        signature: None,
    }
}
