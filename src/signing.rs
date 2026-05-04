//! Optional Ed25519 passport signing. Mirrors the SDK's signing flow in
//! `packages/sdk-node/src/index.ts`: canonicalize a fixed-shape signing
//! payload, sign with PKCS8 Ed25519 private key, attach base64 signature.
//!
//! The SDK signing input is:
//!   canonical_json({ agent_id, action, tool, payload, occurred_at })
//!
//! This matches the SDK exactly so that proxy-submitted events validate the
//! same way SDK-submitted ones do (until the server adds proxy-passport
//! support, this lets a proxy stand in for the SDK transparently).

use crate::canonical_json::{canonical_json, CanonicalError};
use crate::event::IngestBody;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid base64 in passport key")]
    Base64,
    #[error("invalid PKCS8 Ed25519 key: {0}")]
    Pkcs8(String),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),
}

pub struct PassportSigner {
    key: SigningKey,
    pub passport_id: String,
}

impl PassportSigner {
    pub fn from_b64_pkcs8(b64: &str, passport_id: String) -> Result<Self, SigningError> {
        let der = B64.decode(b64.trim()).map_err(|_| SigningError::Base64)?;
        let key =
            SigningKey::from_pkcs8_der(&der).map_err(|e| SigningError::Pkcs8(e.to_string()))?;
        Ok(Self { key, passport_id })
    }

    pub fn sign_body(&self, body: &IngestBody) -> Result<String, SigningError> {
        let signing_input: Value = json!({
            "agent_id": body.agent_id,
            "action": body.action,
            "tool": body.tool.clone().unwrap_or_default(),
            "payload": body.payload,
            "occurred_at": body.occurred_at,
        });
        // Note: SDK passes `tool: tool ?? null` but then canonicalJson stringifies
        // null as "null" and the missing-tool case stays consistent. Replicate
        // that here by promoting None to JSON null.
        let signing_input = if body.tool.is_none() {
            let mut m = signing_input.as_object().unwrap().clone();
            m.insert("tool".into(), Value::Null);
            Value::Object(m)
        } else {
            signing_input
        };
        let canonical = canonical_json(&signing_input)?;
        let sig = self.key.sign(canonical.as_bytes());
        Ok(B64.encode(sig.to_bytes()))
    }
}
