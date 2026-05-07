use rankigi_proxy::detect::{detect, detect_with_deadline, shannon_entropy};
use std::time::Instant;

#[test]
fn detects_anthropic_key() {
    let key: String = std::iter::repeat('a').take(95).collect();
    let s = format!("authorization: sk-ant-{}", key);
    let r = detect_with_deadline(s.as_bytes(), 50).expect("scan completed");
    assert!(r.secrets_detected);
    assert!(r.secrets_types.contains(&"anthropic_key".to_string()));
    assert!(r.secrets_count >= 1);
}

#[test]
fn detects_email() {
    let r = detect(b"please contact user.name+test@example.com for details").expect("ok");
    assert!(r.pii_detected);
    assert!(r.pii_types.contains(&"email".to_string()));
}

#[test]
fn detects_ssn() {
    let r = detect(b"SSN on file: 123-45-6789, please verify").expect("ok");
    assert!(r.pii_detected);
    assert!(r.pii_types.contains(&"ssn".to_string()));
}

#[test]
fn clean_string_no_detections() {
    let r = detect(b"Hello world. This is fine.").expect("ok");
    assert!(!r.secrets_detected);
    assert!(!r.pii_detected);
    assert_eq!(r.secrets_count, 0);
    assert_eq!(r.pii_count, 0);
    assert!(r.secrets_types.is_empty());
    assert!(r.pii_types.is_empty());
}

#[test]
fn detects_high_entropy_string() {
    // 32 mixed alphanumeric characters chosen for high variety.
    let s = "Xq8mN2vK7pL3wR9fJ4sH1tY6bG5dC0aZ";
    let r = detect(s.as_bytes()).expect("ok");
    assert!(r.entropy_max > 4.5, "entropy_max = {}", r.entropy_max);
    assert!(r.secrets_types.contains(&"high_entropy".to_string()));
}

#[test]
fn low_entropy_english_not_flagged() {
    let r = detect(b"the quick brown fox jumps over the lazy dog").expect("ok");
    assert!(!r.secrets_detected, "got types: {:?}", r.secrets_types);
}

#[test]
fn empty_string_no_panic() {
    let r = detect(b"").expect("ok");
    assert!(!r.secrets_detected);
    assert!(!r.pii_detected);
    assert_eq!(r.scanned_bytes, 0);
    assert_eq!(r.entropy_max, 0.0);
}

#[test]
fn large_input_completes_under_50ms() {
    // ~1MB of benign content.
    let chunk = "hello world this is fine ";
    let mut s = String::with_capacity(1_100_000);
    while s.len() < 1_048_576 {
        s.push_str(chunk);
    }
    let bytes = s.as_bytes();
    let start = Instant::now();
    let _ = detect_with_deadline(bytes, 50);
    let elapsed = start.elapsed();
    // Detection either completes or times out — either way the call must
    // return promptly and not exceed the deadline by a meaningful margin.
    assert!(
        elapsed.as_millis() <= 75,
        "detection ran {}ms on 1MB input",
        elapsed.as_millis()
    );
}

#[test]
fn shannon_entropy_basic() {
    assert_eq!(shannon_entropy(""), 0.0);
    // All-same characters: zero entropy.
    assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    // Two equally frequent chars: 1 bit/char.
    let h = shannon_entropy("abababab");
    assert!((h - 1.0).abs() < 1e-9, "h = {}", h);
}
