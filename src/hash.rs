//! SHA-256 helpers. Mirrors `src/lib/crypto/hash.ts`.

use sha2::{Digest, Sha256};

/// SHA-256 hex digest of a UTF-8 string. Matches `sha256Hex` in the TS source.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// SHA-256 hex digest of arbitrary bytes.
pub fn sha256_bytes_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
