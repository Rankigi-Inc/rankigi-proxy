//! PII and secrets detection for proxy-captured request/response bodies.
//!
//! Fail-open: detection runs against a best-effort UTF-8 view of the body and
//! is bounded by a wall-clock deadline (default 50ms). On timeout or any
//! internal error the caller receives `None` and the event is submitted
//! without detection metadata. No raw matched content is ever returned —
//! only counts, type tags, and aggregate stats.

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

const DEFAULT_DEADLINE_MS: u64 = 50;
const ENTROPY_THRESHOLD: f64 = 4.5;

#[derive(Debug, Clone, Serialize)]
pub struct DetectionResult {
    pub secrets_detected: bool,
    pub secrets_count: u32,
    pub secrets_types: Vec<String>,
    pub pii_detected: bool,
    pub pii_count: u32,
    pub pii_types: Vec<String>,
    pub entropy_max: f64,
    pub scanned_bytes: usize,
}

impl DetectionResult {
    pub fn empty() -> Self {
        Self {
            secrets_detected: false,
            secrets_count: 0,
            secrets_types: Vec::new(),
            pii_detected: false,
            pii_count: 0,
            pii_types: Vec::new(),
            entropy_max: 0.0,
            scanned_bytes: 0,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "secrets_detected": self.secrets_detected,
            "secrets_count": self.secrets_count,
            "secrets_types": self.secrets_types,
            "pii_detected": self.pii_detected,
            "pii_count": self.pii_count,
            "pii_types": self.pii_types,
            "entropy_max": self.entropy_max,
            "scanned_bytes": self.scanned_bytes,
        })
    }
}

struct Patterns {
    // Order matters: more specific patterns (anthropic, stripe variants) come
    // before the generic OpenAI sk- prefix so a richer label wins. Each
    // detector still runs independently for counting.
    secrets: Vec<(&'static str, Regex)>,
    pii: Vec<(&'static str, Regex)>,
    entropy_token: Regex,
}

static PATTERNS: OnceLock<Patterns> = OnceLock::new();

fn patterns() -> &'static Patterns {
    PATTERNS.get_or_init(|| Patterns {
        secrets: vec![
            (
                "anthropic_key",
                Regex::new(r"sk-ant-[a-zA-Z0-9\-_]{95}").unwrap(),
            ),
            ("openai_key", Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap()),
            (
                "bearer_token",
                Regex::new(r"[Bb]earer\s+[a-zA-Z0-9\-_\.]{20,}").unwrap(),
            ),
            (
                "stripe_live",
                Regex::new(r"sk_live_[a-zA-Z0-9]{24}").unwrap(),
            ),
            (
                "stripe_test",
                Regex::new(r"sk_test_[a-zA-Z0-9]{24}").unwrap(),
            ),
            ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            (
                "github_token",
                Regex::new(r"gh[pousr]_[a-zA-Z0-9]{36}").unwrap(),
            ),
            (
                "private_key",
                Regex::new(r"-----BEGIN.*PRIVATE KEY-----").unwrap(),
            ),
        ],
        pii: vec![
            (
                "email",
                Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            ),
            ("ssn", Regex::new(r"\d{3}-\d{2}-\d{4}").unwrap()),
            (
                "credit_card",
                Regex::new(r"\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}").unwrap(),
            ),
            (
                "phone_us",
                Regex::new(r"(\+1)?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}").unwrap(),
            ),
            (
                "ip_address",
                Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
            ),
        ],
        entropy_token: Regex::new(r"[a-zA-Z0-9]{20,}").unwrap(),
    })
}

/// Shannon entropy in bits per character. Returns 0.0 for empty input.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut total: u32 = 0;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    let n = total as f64;
    let mut h = 0.0_f64;
    for &c in counts.values() {
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn push_unique(types: &mut Vec<String>, name: &str) {
    if !types.iter().any(|t| t == name) {
        types.push(name.to_string());
    }
}

fn elapsed_exceeded(start: Instant, deadline_ms: u64) -> bool {
    start.elapsed().as_millis() as u64 > deadline_ms
}

/// Run all detectors against `data`. Returns `None` if the deadline is
/// exceeded or input cannot be processed. Never panics.
pub fn detect_with_deadline(data: &[u8], deadline_ms: u64) -> Option<DetectionResult> {
    let start = Instant::now();
    let p = patterns();

    // Best-effort UTF-8 view. All target patterns are ASCII so lossy
    // conversion does not change matching semantics.
    let s: std::borrow::Cow<'_, str> = String::from_utf8_lossy(data);

    let mut result = DetectionResult::empty();
    result.scanned_bytes = data.len();

    for (name, re) in &p.secrets {
        if elapsed_exceeded(start, deadline_ms) {
            return None;
        }
        let n = re.find_iter(&s).count() as u32;
        if n > 0 {
            result.secrets_count = result.secrets_count.saturating_add(n);
            push_unique(&mut result.secrets_types, name);
        }
    }

    for (name, re) in &p.pii {
        if elapsed_exceeded(start, deadline_ms) {
            return None;
        }
        let n = re.find_iter(&s).count() as u32;
        if n > 0 {
            result.pii_count = result.pii_count.saturating_add(n);
            push_unique(&mut result.pii_types, name);
        }
    }

    for m in p.entropy_token.find_iter(&s) {
        if elapsed_exceeded(start, deadline_ms) {
            return None;
        }
        let h = shannon_entropy(m.as_str());
        if h > result.entropy_max {
            result.entropy_max = h;
        }
        if h > ENTROPY_THRESHOLD {
            result.secrets_count = result.secrets_count.saturating_add(1);
            push_unique(&mut result.secrets_types, "high_entropy");
        }
    }

    result.secrets_detected = result.secrets_count > 0;
    result.pii_detected = result.pii_count > 0;

    Some(result)
}

/// Default 50ms deadline.
pub fn detect(data: &[u8]) -> Option<DetectionResult> {
    detect_with_deadline(data, DEFAULT_DEADLINE_MS)
}

/// Run detection across both request and response bodies under a shared
/// 50ms wall-clock budget. Returns `None` if the combined scan exceeds
/// the budget.
pub fn detect_pair(req: &[u8], resp: &[u8]) -> Option<DetectionResult> {
    let start = Instant::now();
    let budget = DEFAULT_DEADLINE_MS;

    let r1 = detect_with_deadline(req, budget)?;
    let elapsed = start.elapsed().as_millis() as u64;
    if elapsed > budget {
        return None;
    }
    let remaining = budget - elapsed;
    if remaining == 0 {
        return None;
    }
    let r2 = detect_with_deadline(resp, remaining)?;

    let mut secrets_types = r1.secrets_types;
    for t in r2.secrets_types {
        if !secrets_types.contains(&t) {
            secrets_types.push(t);
        }
    }
    let mut pii_types = r1.pii_types;
    for t in r2.pii_types {
        if !pii_types.contains(&t) {
            pii_types.push(t);
        }
    }

    let secrets_count = r1.secrets_count.saturating_add(r2.secrets_count);
    let pii_count = r1.pii_count.saturating_add(r2.pii_count);

    Some(DetectionResult {
        secrets_detected: secrets_count > 0,
        secrets_count,
        secrets_types,
        pii_detected: pii_count > 0,
        pii_count,
        pii_types,
        entropy_max: r1.entropy_max.max(r2.entropy_max),
        scanned_bytes: r1.scanned_bytes.saturating_add(r2.scanned_bytes),
    })
}
