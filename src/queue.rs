//! Bounded async ingest queue with retry. Owns submission to the RANKIGI
//! ingest endpoint. The proxy hot path enqueues a captured pair; this module
//! drains the queue, builds the ingest body, signs if configured, retries on
//! transient failure, and synthesizes a gap event when retries exhaust.
//!
//! Fail-open guarantees:
//!   - Enqueue never blocks: if the buffer is full the event is dropped, a
//!     warning is logged, and a gap event is emitted.
//!   - Submission failures never propagate to the proxy hot path. The proxy
//!     has already returned the response to the agent before the drainer ever
//!     sees the captured pair.

use crate::config::Config;
use crate::event::{build_ingest_body, CapturedPair, IngestBody};
use crate::gap::build_gap_body;
use crate::seal::evaluate_seal;
use crate::signing::PassportSigner;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug)]
pub enum QueueItem {
    Captured(Box<CapturedPair>),
    Gap(GapReason),
}

#[derive(Debug, Clone, Copy)]
pub enum GapReason {
    QueueFull,
    IngestFailure,
}

#[derive(Clone)]
pub struct IngestQueue {
    tx: mpsc::Sender<QueueItem>,
    capacity: usize,
}

impl IngestQueue {
    /// Try to enqueue an item. Returns `true` if accepted, `false` if the
    /// buffer was full (or the channel is closed). Never blocks. The proxy
    /// hot path treats `false` as a dropped event — fail open.
    pub fn try_enqueue(&self, item: QueueItem) -> bool {
        match self.tx.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    capacity = self.capacity,
                    "ingest queue full — dropping event"
                );
                let _ = self.tx.try_send(QueueItem::Gap(GapReason::QueueFull));
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("ingest queue closed");
                false
            }
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

pub struct Drainer {
    rx: mpsc::Receiver<QueueItem>,
    cfg: Arc<Config>,
    signer: Option<Arc<PassportSigner>>,
    client: reqwest::Client,
}

pub fn spawn(
    cfg: Arc<Config>,
    signer: Option<Arc<PassportSigner>>,
) -> (IngestQueue, tokio::task::JoinHandle<()>) {
    let capacity = cfg.buffer_size;
    let (tx, rx) = mpsc::channel(capacity);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.ingest_timeout_ms))
        .build()
        .expect("reqwest client build");
    let drainer = Drainer {
        rx,
        cfg,
        signer,
        client,
    };
    let handle = tokio::spawn(drainer.run());
    (IngestQueue { tx, capacity }, handle)
}

impl Drainer {
    async fn run(mut self) {
        info!(buffer_size = self.cfg.buffer_size, "ingest drainer started");
        while let Some(item) = self.rx.recv().await {
            match item {
                QueueItem::Captured(pair) => {
                    self.handle_captured(*pair).await;
                }
                QueueItem::Gap(reason) => {
                    self.handle_gap(reason).await;
                }
            }
        }
        info!("ingest drainer shutting down");
    }

    async fn handle_captured(&self, pair: CapturedPair) {
        let request_canon = crate::canonical_json::canonical_json_or_raw(&pair.request_body);
        let request_hash = crate::hash::sha256_hex(&request_canon);
        let action_preview = crate::event::derive_action_type(&pair.method, &pair.host, &pair.path);

        let verdict = evaluate_seal(&self.client, &self.cfg, &request_hash, &action_preview).await;

        let mut body = build_ingest_body(&self.cfg, &pair, verdict);
        self.attach_signature(&mut body);

        if !self.submit_with_retry(&body).await {
            // Retries exhausted — emit a gap event so the chain shows the
            // missing slot when connectivity is restored.
            self.handle_gap(GapReason::IngestFailure).await;
        }
    }

    async fn handle_gap(&self, reason: GapReason) {
        let mut body = build_gap_body(&self.cfg, reason);
        self.attach_signature(&mut body);
        // Best-effort: a single submission attempt. Don't recurse on gap-of-gap.
        if let Err(e) = self.submit_once(&body).await {
            warn!(err = %e, "gap event submission failed");
        }
    }

    fn attach_signature(&self, body: &mut IngestBody) {
        if let Some(signer) = &self.signer {
            match signer.sign_body(body) {
                Ok(sig) => {
                    body.passport_id = Some(signer.passport_id.clone());
                    body.signature = Some(sig);
                }
                Err(e) => {
                    warn!(err = %e, "signing failed — submitting unsigned");
                }
            }
        }
    }

    async fn submit_with_retry(&self, body: &IngestBody) -> bool {
        let backoffs = [100u64, 200, 400];
        let mut attempt = 0usize;
        loop {
            match self.submit_once(body).await {
                Ok(()) => return true,
                Err(e) => {
                    if attempt >= backoffs.len() {
                        error!(err = %e, "ingest submission failed after retries");
                        return false;
                    }
                    let delay = backoffs[attempt];
                    warn!(err = %e, attempt = attempt + 1, delay_ms = delay, "retrying ingest");
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn submit_once(&self, body: &IngestBody) -> Result<(), String> {
        let url = format!("{}/api/ingest", self.cfg.ingest_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.cfg.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "ingest {}: {}",
                status,
                &text[..text.len().min(200)]
            ));
        }
        Ok(())
    }
}
