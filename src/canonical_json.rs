//! Canonical JSON for chain hashing.
//!
//! Byte-for-byte port of `src/lib/crypto/canonical-json.ts`. Two semantically
//! identical payloads MUST produce identical output, across language ports of
//! the verifier. Any deviation here breaks chain hash compatibility with the
//! Node SDK and the server-side verifier.
//!
//! Hard rules (matching the KYA standard, mirrored from the TS source):
//!   1. Object keys sorted lexicographically by UTF-16 code units.
//!   2. Whole-valued numbers serialize as integers. `1.0` → `"1"`, `-0.0` → `"0"`.
//!   3. Other finite numbers serialize using shortest decimal that round-trips.
//!      Scientific notation is not allowed; values that would otherwise format
//!      that way are converted to fixed notation.
//!   4. Non-finite numbers (NaN, ±∞) are rejected.
//!   5. Strings escape only `"`, `\`, the C0 control block (`\b\f\n\r\t` and
//!      `\uXXXX` for the rest), DEL is left as-is. Forward slash is NOT
//!      escaped.
//!   6. `null` serializes as the literal `"null"`.
//!   7. No whitespace. Compact separators only.
//!   8. Maximum nesting depth 10.

use serde_json::{Number, Value};
use thiserror::Error;

const MAX_DEPTH: usize = 10;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("payload exceeds maximum nesting depth of {0}")]
    DepthExceeded(usize),
    #[error("non-finite number cannot be canonicalized")]
    NonFinite,
    #[error("number is not representable")]
    InvalidNumber,
}

/// Compare two strings by their UTF-16 code units. This matches JavaScript's
/// default `Array.sort()` ordering, which is what the TS reference relies on.
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

fn escape_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Lower-case hex, four digits, matches TS toString(16).padStart(4,"0").
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn format_number(n: &Number, out: &mut String) -> Result<(), CanonicalError> {
    // Integers (signed and unsigned) take the fast path. serde_json keeps
    // these distinct from floats when the original JSON did not contain a
    // decimal point.
    if let Some(i) = n.as_i64() {
        use std::fmt::Write;
        let _ = write!(out, "{}", i);
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        use std::fmt::Write;
        let _ = write!(out, "{}", u);
        return Ok(());
    }
    let f = n.as_f64().ok_or(CanonicalError::InvalidNumber)?;
    if !f.is_finite() {
        return Err(CanonicalError::NonFinite);
    }
    // -0 collapses to 0, matching TS, Python, and Go conventions.
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    if f.fract() == 0.0 {
        // Whole-valued float. Render without a decimal point. For values
        // beyond i64 range we fall back to the fixed-zero-precision form
        // which never produces scientific notation.
        if f.abs() < 9_007_199_254_740_992.0 {
            // Inside Number.MAX_SAFE_INTEGER — exact i64 conversion is safe.
            use std::fmt::Write;
            let _ = write!(out, "{}", f as i64);
        } else {
            let s = format!("{:.0}", f);
            out.push_str(&s);
        }
        return Ok(());
    }
    // Non-integer finite float. Try the default formatter; if it picks
    // scientific notation, fall back to fixed-precision-then-trim. This
    // mirrors `n.toString(10)` followed by the `n.toFixed(20)` fallback in
    // the TS source.
    let s = format!("{}", f);
    if !s.contains('e') && !s.contains('E') {
        out.push_str(&s);
        return Ok(());
    }
    let fixed = format!("{:.20}", f);
    let trimmed = fixed.trim_end_matches('0').trim_end_matches('.');
    out.push_str(trimmed);
    Ok(())
}

fn serialize(value: &Value, depth: usize, out: &mut String) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::DepthExceeded(MAX_DEPTH));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => format_number(n, out)?,
        Value::String(s) => escape_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string(k, out);
                out.push(':');
                serialize(&map[*k], depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonicalize a `serde_json::Value` to its KYA-canonical UTF-8 byte form.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    serialize(value, 0, &mut out)?;
    Ok(out)
}

/// Convenience: canonicalize raw bytes that are expected to be JSON. If the
/// bytes do not parse as JSON, returns the bytes interpreted as a JSON string
/// (so callers can still hash the wire content stably).
pub fn canonical_json_or_raw(bytes: &[u8]) -> String {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => match canonical_json(&v) {
            Ok(s) => s,
            Err(_) => raw_string_fallback(bytes),
        },
        Err(_) => raw_string_fallback(bytes),
    }
}

fn raw_string_fallback(bytes: &[u8]) -> String {
    // Non-JSON bodies hash as a JSON string of the lossy UTF-8 view. This
    // keeps input_hash / output_hash deterministic for binary and text/plain
    // payloads alike. The escape ensures the string is itself a valid JSON
    // value, so canonical-JSON consumers can interoperate.
    let mut out = String::new();
    let s = String::from_utf8_lossy(bytes);
    escape_string(&s, &mut out);
    out
}
