use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD as B64; use base64::Engine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub key_id: String,
    pub digest: String, // Base64 32B
    pub signature: String,
    pub context_binding: String,
}

impl VerifyRequest {
    pub fn from_bytes(key_id: impl Into<String>, digest32: [u8;32], signature: Vec<u8>, context32: [u8;32]) -> Self {
        Self { key_id: key_id.into(), digest: B64.encode(digest32), signature: B64.encode(signature), context_binding: B64.encode(context32) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse { pub valid: bool, pub alg: String }
