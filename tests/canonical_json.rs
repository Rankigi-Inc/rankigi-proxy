//! Cross-implementation canonical JSON test. Expected values are produced
//! by running `src/lib/crypto/canonical-json.ts` directly (see
//! `proxy/tests/fixtures/README.md`). If this test fails the Rust proxy and
//! the TS SDK no longer agree on the chain hash and the verifier will
//! reject proxy-captured events.

use rankigi_proxy::canonical_json::canonical_json;
use rankigi_proxy::hash::sha256_hex;
use serde_json::json;

struct Case {
    name: &'static str,
    value: serde_json::Value,
    canon: &'static str,
    hash: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "sort_keys",
            value: json!({ "b": 1, "a": 2 }),
            canon: r#"{"a":2,"b":1}"#,
            hash: "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        },
        Case {
            name: "unicode_and_null",
            value: json!({ "unicode": "café", "empty": null }),
            canon: r#"{"empty":null,"unicode":"café"}"#,
            hash: "e7af859d62e268fded5840e1c15e6e4b02184cd9cddcb45b09d329c14bb2ee32",
        },
        Case {
            // 1.0 collapses to "1", -0.0 collapses to "0".
            name: "numbers",
            value: json!({ "nums": [1, 1.5, 1.0, -0.0, 1000000, 0.1] }),
            canon: r#"{"nums":[1,1.5,1,0,1000000,0.1]}"#,
            hash: "ae5f5d76767905c543c282a31aee85797f3ded21911827e75ea637e89f31c056",
        },
        Case {
            name: "escapes",
            value: json!({ "s": "a\"b\\c\nd\te" }),
            canon: r#"{"s":"a\"b\\c\nd\te"}"#,
            hash: "3fe8db26dc2df0fc1e6cea51d173b76578b486002a00307b508f9fa116c30a36",
        },
        Case {
            name: "nested",
            value: json!({ "x": { "b": 1, "a": 2 }, "y": [{ "z": 1 }] }),
            canon: r#"{"x":{"a":2,"b":1},"y":[{"z":1}]}"#,
            hash: "a72c93f796b0299449b562a5dc9db4ed8e17a9edcf0d494810143fec1938c525",
        },
        Case {
            name: "control_chars",
            value: json!({ "c": "x\u{0001}y\u{001f}z" }),
            canon: r#"{"c":"x\u0001y\u001fz"}"#,
            hash: "b3e725342d59ec913d30fb39c955f2345cf5ef9b2bf8159e213402c13c3dfb3b",
        },
        Case {
            name: "bool_array_null",
            value: json!({ "a": [true, false, null], "b": null }),
            canon: r#"{"a":[true,false,null],"b":null}"#,
            hash: "6e76b727325f6b26ab25d6b38530607d7096e13ccfe84474852f60421afd2742",
        },
        Case {
            name: "empty_obj_arr",
            value: json!({ "o": {}, "a": [] }),
            canon: r#"{"a":[],"o":{}}"#,
            hash: "9bee7ebfc94b459dacb8cbc72cb2900e61f0aa42189df18329f84f92568f4f89",
        },
    ]
}

#[test]
fn canonical_json_matches_typescript() {
    for c in cases() {
        let got = canonical_json(&c.value).expect("canonicalize");
        assert_eq!(
            got, c.canon,
            "case {} canonical mismatch: rust={:?} ts={:?}",
            c.name, got, c.canon
        );
        let got_hash = sha256_hex(&got);
        assert_eq!(
            got_hash, c.hash,
            "case {} hash mismatch: rust={} ts={}",
            c.name, got_hash, c.hash
        );
    }
}

#[test]
fn deterministic() {
    let v = json!({ "z": 1, "a": [3, 1, 2], "m": { "y": "x", "x": "y" } });
    let a = canonical_json(&v).unwrap();
    let b = canonical_json(&v).unwrap();
    assert_eq!(a, b);
}

#[test]
fn depth_limit_rejected() {
    let mut v = json!(1);
    for _ in 0..12 {
        v = json!([v]);
    }
    assert!(canonical_json(&v).is_err());
}

#[test]
fn nan_rejected() {
    // serde_json does not parse NaN by default, so build the Number manually.
    let n = serde_json::Number::from_f64(f64::NAN);
    assert!(n.is_none(), "serde_json refuses NaN at construction time");
}
