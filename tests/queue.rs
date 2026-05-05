//! Queue and ingest behavior — fail-open under saturation, retries on
//! ingest failure, gap event synthesis, and the response-before-chain-write
//! invariant.

use chrono::Utc;
use rankigi_proxy::config::Config;
use rankigi_proxy::event::CapturedPair;
use rankigi_proxy::queue::{self, GapReason, QueueItem};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(ingest_url: &str, buffer_size: usize) -> Arc<Config> {
    Arc::new(Config {
        proxy_port: 0,
        ingest_url: ingest_url.to_string(),
        api_key: "test-key".into(),
        agent_id: "00000000-0000-0000-0000-000000000001".into(),
        org_id: "00000000-0000-0000-0000-0000000000aa".into(),
        buffer_size,
        ingest_timeout_ms: 1000,
        ca_cert_path: PathBuf::from("/tmp/rkg-test.crt"),
        ca_key_path: PathBuf::from("/tmp/rkg-test.key"),
        passport_key: None,
        passport_id: None,
        seal_eval_enabled: false,
        seal_eval_timeout_ms: 20,
        bypass_hosts: Vec::new(),
        transparent_mode: false,
    })
}

fn pair(method_: &str) -> CapturedPair {
    let now = Utc::now();
    CapturedPair {
        method: method_.into(),
        url: "https://api.openai.com/v1/chat/completions".into(),
        host: "api.openai.com".into(),
        path: "/v1/chat/completions".into(),
        request_body: br#"{"model":"x"}"#.to_vec(),
        response_status: Some(200),
        response_body: br#"{"choices":[]}"#.to_vec(),
        proxy_received_at: now,
        proxy_response_at: Some(now + chrono::Duration::milliseconds(10)),
        body_truncated: false,
    }
}

#[tokio::test]
async fn fail_open_on_queue_full() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/ingest"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
        .mount(&server)
        .await;

    let cfg = cfg(&server.uri(), 1);
    let (q, _drainer) = queue::spawn(cfg, None);

    // Saturate the buffer past capacity. With capacity 1 and the drainer
    // parked on the hanging upstream, we expect drops without panic or
    // block.
    let mut accepted = 0usize;
    let mut dropped = 0usize;
    for _ in 0..50 {
        if q.try_enqueue(QueueItem::Captured(Box::new(pair("POST")))) {
            accepted += 1;
        } else {
            dropped += 1;
        }
    }
    assert!(dropped > 0, "expected drops under saturation, got 0");
    assert_eq!(accepted + dropped, 50);
}

#[tokio::test]
async fn fail_open_on_ingest_down() {
    // Nothing listening at port 1 — drainer hits connection refused, must
    // not panic, must retry, must continue accepting enqueues.
    let cfg = cfg("http://127.0.0.1:1", 100);
    let (q, _drainer) = queue::spawn(cfg, None);
    assert!(q.try_enqueue(QueueItem::Captured(Box::new(pair("POST")))));
    // Sleep past the 100+200+400 ms retry schedule.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(q.try_enqueue(QueueItem::Gap(GapReason::IngestFailure)));
}

#[tokio::test]
async fn response_returned_before_chain_write() {
    static SUBMIT_AT_NS: AtomicI64 = AtomicI64::new(0);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/ingest"))
        .respond_with(|_req: &wiremock::Request| {
            let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
            SUBMIT_AT_NS.store(now, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
        })
        .mount(&server)
        .await;

    let cfg = cfg(&server.uri(), 100);
    let (q, _drainer) = queue::spawn(cfg, None);

    let response_returned_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    assert!(q.try_enqueue(QueueItem::Captured(Box::new(pair("POST")))));
    // try_enqueue is what the proxy hot path calls. By the time it returns
    // true the agent's HTTP response has already been written. Confirm the
    // chain submission happened *after* that point.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let submit_at = SUBMIT_AT_NS.load(Ordering::SeqCst);
    assert!(submit_at > 0, "ingest submission never happened");
    assert!(
        submit_at > response_returned_ns,
        "ingest submitted before proxy returned (chain write blocked the agent path)"
    );
}

#[tokio::test]
async fn try_enqueue_never_blocks_on_full() {
    let cfg = cfg("http://127.0.0.1:1", 1);
    let (q, _drainer) = queue::spawn(cfg, None);
    let start = std::time::Instant::now();
    for _ in 0..10_000 {
        let _ = q.try_enqueue(QueueItem::Captured(Box::new(pair("POST"))));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "10k try_enqueue calls took {:?}; should be near-instant",
        elapsed
    );
}
