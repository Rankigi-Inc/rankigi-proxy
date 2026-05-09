//! Stamp engine. Injects a verifiable receipt footer into a matched request
//! body before the body is forwarded upstream. The agent never sees the
//! receipt or the modified body. The receipt is published to the chain via
//! a `stamp.issued` event submitted through the existing ingest queue.
//!
//! Failure mode: every public function is total. If the body cannot be
//! parsed, decoded, or the marker cannot be found, the original body is
//! returned unchanged and an error is logged. The proxy hot path NEVER
//! panics on stamp logic; an unstampable body is forwarded as-is.

use crate::config::{Config, StampBodyType, StampConfig, StampPattern};
use crate::event::IngestBody;
use crate::hash::sha256_bytes_hex;
use base64::{engine::general_purpose::URL_SAFE as B64_URL, Engine};
use serde::Serialize;
use serde_json::json;
use tracing::warn;

#[derive(Debug, Clone, Serialize)]
pub struct StampReceipt {
    pub receipt_id: String,
    pub agent_id: String,
    /// RFC3339 millisecond timestamp.
    pub timestamp: String,
    /// SHA-256 hex of the modified body (after footer injection).
    pub body_hash: String,
    pub body_truncated: bool,
    /// SHA-256 hex of the recipient identifier (URL or To header).
    pub recipient_hash: String,
    /// `{verify_base_url}/{receipt_id}`.
    pub verify_url: String,
}

/// Find the first pattern whose host and path-prefix match. Host match is
/// case-insensitive exact; path match is byte-prefix.
pub fn should_stamp<'a>(
    cfg: &'a StampConfig,
    host: &str,
    path: &str,
) -> Option<&'a StampPattern> {
    if !cfg.enabled {
        return None;
    }
    let host_lc = host.to_ascii_lowercase();
    cfg.patterns.iter().find(|p| {
        p.host.to_ascii_lowercase() == host_lc && path.starts_with(&p.path_prefix)
    })
}

/// Build the ingest body for a `stamp.issued` chain event. The matched host
/// is recorded as `tool` so dashboards can group stamps by recipient surface.
pub fn build_stamp_body(cfg: &Config, host: &str, receipt: &StampReceipt) -> IngestBody {
    IngestBody {
        agent_id: cfg.agent_id.clone(),
        action: "stamp.issued".to_string(),
        tool: Some(host.to_string()),
        severity: "info".to_string(),
        occurred_at: receipt.timestamp.clone(),
        payload: json!({
            "receipt_id": receipt.receipt_id,
            "body_hash": receipt.body_hash,
            "body_truncated": receipt.body_truncated,
            "recipient_hash": receipt.recipient_hash,
            "verify_url": receipt.verify_url,
        }),
        passport_id: None,
        signature: None,
    }
}

pub fn build_footer_text(receipt: &StampReceipt) -> String {
    format!(
        "\n\n---\nVerifiable receipt: {}\nAgent: {} | Time: {}\n",
        receipt.verify_url, receipt.agent_id, receipt.timestamp
    )
}

pub fn compute_body_hash(body: &[u8]) -> String {
    sha256_bytes_hex(body)
}

pub fn compute_recipient_hash(url: &str) -> String {
    sha256_bytes_hex(url.as_bytes())
}

/// Returns a new body with the footer woven in, or the original body bytes
/// if injection is not possible. Never panics.
pub fn inject_footer(body: &[u8], body_type: &StampBodyType, receipt: &StampReceipt) -> Vec<u8> {
    let footer = build_footer_text(receipt);
    match body_type {
        StampBodyType::PlainText => inject_plain_text(body, &footer),
        StampBodyType::HtmlBody => inject_html(body, &footer),
        StampBodyType::JsonField(field) => inject_json_field(body, field, &footer),
    }
}

fn inject_plain_text(body: &[u8], footer: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + footer.len());
    out.extend_from_slice(body);
    out.extend_from_slice(footer.as_bytes());
    out
}

/// Insert the footer as a hidden marker comment immediately before the
/// closing `</body>`. Case-insensitive search. Falls back to appending if
/// no closing tag is found.
fn inject_html(body: &[u8], footer: &str) -> Vec<u8> {
    let needle = b"</body>";
    let pos = find_subslice_ignore_case(body, needle);
    let footer_html = format!(
        "<div data-rankigi-stamp=\"true\" style=\"display:none\">{}</div>",
        html_escape(footer)
    );
    match pos {
        Some(idx) => {
            let mut out = Vec::with_capacity(body.len() + footer_html.len());
            out.extend_from_slice(&body[..idx]);
            out.extend_from_slice(footer_html.as_bytes());
            out.extend_from_slice(&body[idx..]);
            out
        }
        None => {
            warn!("stamp: html body has no </body> tag, appending footer");
            inject_plain_text(body, &footer_html)
        }
    }
}

/// Inject into a JSON string field. If the field value parses as URL-safe
/// base64 it is decoded, the footer text is appended, and the result is
/// re-encoded (this handles Gmail's `raw` field). Otherwise the footer is
/// appended directly to the string. Returns the original body on any error.
fn inject_json_field(body: &[u8], field: &str, footer: &str) -> Vec<u8> {
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, field = %field, "stamp: body is not valid JSON, skipping injection");
            return body.to_vec();
        }
    };

    let target = match value.pointer_mut(&json_pointer_for(field)) {
        Some(t) => t,
        None => {
            warn!(field = %field, "stamp: JSON field not found, skipping injection");
            return body.to_vec();
        }
    };

    let s = match target.as_str() {
        Some(s) => s.to_string(),
        None => {
            warn!(field = %field, "stamp: JSON field is not a string, skipping injection");
            return body.to_vec();
        }
    };

    let new_value = match B64_URL.decode(s.trim_end_matches('=')) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(text) => {
                let appended = format!("{}{}", text, footer);
                B64_URL.encode(appended.as_bytes())
            }
            Err(_) => format!("{}{}", s, footer),
        },
        Err(_) => format!("{}{}", s, footer),
    };

    *target = serde_json::Value::String(new_value);

    match serde_json::to_vec(&value) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "stamp: re-serialize failed, returning original body");
            body.to_vec()
        }
    }
}

/// Convert a dotted field path to a JSON Pointer (`a.b` -> `/a/b`). A bare
/// field with no dots becomes `/field`.
fn json_pointer_for(field: &str) -> String {
    let mut s = String::with_capacity(field.len() + 1);
    for segment in field.split('.') {
        s.push('/');
        for ch in segment.chars() {
            match ch {
                '~' => s.push_str("~0"),
                '/' => s.push_str("~1"),
                c => s.push(c),
            }
        }
    }
    s
}

fn find_subslice_ignore_case(haystack: &[u8], needle_lower: &[u8]) -> Option<usize> {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return None;
    }
    haystack
        .windows(needle_lower.len())
        .position(|w| w.iter().zip(needle_lower).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> StampReceipt {
        StampReceipt {
            receipt_id: "rid".into(),
            agent_id: "aid".into(),
            timestamp: "2026-05-09T00:00:00.000Z".into(),
            body_hash: String::new(),
            body_truncated: false,
            recipient_hash: "rh".into(),
            verify_url: "https://rankigi.com/v/rid".into(),
        }
    }

    #[test]
    fn plain_text_appends() {
        let r = receipt();
        let out = inject_footer(b"hello", &StampBodyType::PlainText, &r);
        assert!(out.starts_with(b"hello"));
        assert!(std::str::from_utf8(&out).unwrap().contains("Verifiable receipt"));
    }

    #[test]
    fn html_inserts_before_close() {
        let r = receipt();
        let out = inject_footer(
            b"<html><body>hi</body></html>",
            &StampBodyType::HtmlBody,
            &r,
        );
        let s = std::str::from_utf8(&out).unwrap();
        let footer_pos = s.find("data-rankigi-stamp").unwrap();
        let close_pos = s.find("</body>").unwrap();
        assert!(footer_pos < close_pos);
    }

    #[test]
    fn json_field_base64_round_trip() {
        let r = receipt();
        let payload = format!(
            "{{\"raw\":\"{}\"}}",
            B64_URL.encode("From: a@b\n\nbody".as_bytes())
        );
        let out = inject_footer(payload.as_bytes(), &StampBodyType::JsonField("raw".into()), &r);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let raw = v["raw"].as_str().unwrap();
        let decoded = String::from_utf8(B64_URL.decode(raw).unwrap()).unwrap();
        assert!(decoded.contains("Verifiable receipt"));
    }

    #[test]
    fn invalid_json_returns_original() {
        let r = receipt();
        let original = b"not json";
        let out = inject_footer(original, &StampBodyType::JsonField("x".into()), &r);
        assert_eq!(out, original);
    }

    #[test]
    fn should_stamp_matches_host_and_prefix() {
        let cfg = StampConfig {
            enabled: true,
            patterns: vec![StampPattern {
                host: "gmail.googleapis.com".into(),
                path_prefix: "/upload/".into(),
                body_type: StampBodyType::JsonField("raw".into()),
            }],
            verify_base_url: "https://rankigi.com/v".into(),
            sync_anchor: false,
        };
        assert!(should_stamp(&cfg, "gmail.googleapis.com", "/upload/x").is_some());
        assert!(should_stamp(&cfg, "GMAIL.googleapis.com", "/upload/x").is_some());
        assert!(should_stamp(&cfg, "gmail.googleapis.com", "/other").is_none());
    }

    #[test]
    fn should_stamp_disabled_returns_none() {
        let cfg = StampConfig::default();
        assert!(should_stamp(&cfg, "gmail.googleapis.com", "/upload/x").is_none());
    }
}
