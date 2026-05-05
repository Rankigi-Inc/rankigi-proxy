//! Seal evaluation timeout behavior. The seal endpoint is feature-flagged
//! off by default. When enabled, the proxy must time out within the
//! configured budget regardless of how slow the endpoint is.

use rankigi_proxy::config::Config;
use rankigi_proxy::event::SealVerdictTag;
use rankigi_proxy::seal::evaluate_seal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(ingest_url: &str, enabled: bool, timeout_ms: u64) -> Arc<Config> {
    Arc::new(Config {
        proxy_port: 0,
        ingest_url: ingest_url.to_string(),
        api_key: "test-key".into(),
        agent_id: "00000000-0000-0000-0000-000000000001".into(),
        org_id: "00000000-0000-0000-0000-0000000000aa".into(),
        buffer_size: 16,
        ingest_timeout_ms: 1000,
        ca_cert_path: PathBuf::from("/tmp/rkg-seal-test.crt"),
        ca_key_path: PathBuf::from("/tmp/rkg-seal-test.key"),
        passport_key: None,
        passport_id: None,
        seal_eval_enabled: enabled,
        seal_eval_timeout_ms: timeout_ms,
        bypass_hosts: Vec::new(),
        transparent_mode: false,
    })
}

#[tokio::test]
async fn seal_disabled_returns_disabled() {
    let c = cfg("http://127.0.0.1:1", false, 20);
    let client = reqwest::Client::new();
    let v = evaluate_seal(&client, &c, "abcdef", "tool.http.post").await;
    assert!(matches!(v, SealVerdictTag::Disabled));
}

#[tokio::test]
async fn seal_evaluation_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/seal/evaluate"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;

    let c = cfg(&server.uri(), true, 20);
    let client = reqwest::Client::new();
    let start = Instant::now();
    let v = evaluate_seal(&client, &c, "abcdef", "tool.http.post").await;
    let elapsed = start.elapsed();
    // Timeout must trip within ~3x the configured budget.
    assert!(
        elapsed < Duration::from_millis(200),
        "seal eval took {:?}, expected to timeout near 20ms",
        elapsed
    );
    assert!(
        matches!(v, SealVerdictTag::Timeout | SealVerdictTag::Unavailable),
        "expected Timeout/Unavailable on slow endpoint, got {:?}",
        std::mem::discriminant(&v)
    );
}

#[tokio::test]
async fn seal_admissible_passthrough() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/seal/evaluate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "verdict": "admissible",
            "seal_id": "seal-1",
            "policy_rule": "default-allow",
            "signed_at": "2026-05-04T12:00:00Z",
            "signature": "ABCD",
        })))
        .mount(&server)
        .await;
    let c = cfg(&server.uri(), true, 1000);
    let client = reqwest::Client::new();
    let v = evaluate_seal(&client, &c, "abc", "tool.http.post").await;
    assert!(matches!(v, SealVerdictTag::Admissible));
}
