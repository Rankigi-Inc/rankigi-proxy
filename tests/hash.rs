use rankigi_proxy::canonical_json::canonical_json_or_raw;
use rankigi_proxy::hash::{sha256_bytes_hex, sha256_hex};
use serde_json::json;

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase()))
}

#[test]
fn hash_construction_shape() {
    let body = json!({"prompt": "hello", "model": "gpt-4"}).to_string();
    let canon = canonical_json_or_raw(body.as_bytes());
    let h = sha256_hex(&canon);
    assert!(is_lower_hex_64(&h), "expected lowercase 64-hex, got {h}");
}

#[test]
fn hash_is_deterministic_across_key_order() {
    let a = json!({"prompt": "hello", "model": "gpt-4"}).to_string();
    let b = json!({"model": "gpt-4", "prompt": "hello"}).to_string();
    let ha = sha256_hex(&canonical_json_or_raw(a.as_bytes()));
    let hb = sha256_hex(&canonical_json_or_raw(b.as_bytes()));
    assert_eq!(ha, hb, "key order must not affect hash");
}

#[test]
fn hash_differs_on_content() {
    let a = sha256_hex(&canonical_json_or_raw(br#"{"x":1}"#));
    let b = sha256_hex(&canonical_json_or_raw(br#"{"x":2}"#));
    assert_ne!(a, b);
}

#[test]
fn raw_bytes_hash_stable() {
    let bytes = b"not-json-content";
    let a = sha256_bytes_hex(bytes);
    let b = sha256_bytes_hex(bytes);
    assert_eq!(a, b);
    assert!(is_lower_hex_64(&a));
}

#[test]
fn empty_body_hashable() {
    let canon = canonical_json_or_raw(b"");
    let h = sha256_hex(&canon);
    assert!(is_lower_hex_64(&h));
}
