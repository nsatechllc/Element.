use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD as B64; use base64::Engine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignDigestRequest {
    pub key_id: String,
    pub digest: String,          // Base64 32B
    #[serde(skip_serializing_if = "Option::is_none")] pub context_binding: Option<String>, // Base64 32B
    pub nonce: u64,
}

impl SignDigestRequest {
    pub fn from_bytes(key_id: impl Into<String>, digest32: [u8;32], context: Option<[u8;32]>, nonce: u64) -> Self {
        Self { key_id: key_id.into(), digest: B64.encode(digest32), context_binding: context.map(|c| B64.encode(c)), nonce }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignDigestResponse {
    pub signature: String,
    pub alg: String,
    pub counter: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignRequest { pub items: Vec<SignItemRequest> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignItemRequest { pub key_id: String, pub digest: String, pub context_binding: String, pub nonce: u64 }

impl SignItemRequest {
    pub fn from_bytes(key_id: impl Into<String>, digest32: [u8;32], context32: [u8;32], nonce: u64) -> Self {
        Self { key_id: key_id.into(), digest: B64.encode(digest32), context_binding: B64.encode(context32), nonce }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignResponse { pub results: Vec<BatchSignItemResult> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignItemResult {
    pub key_id: String,
    pub signature: Option<String>,
    pub alg: Option<String>,
    pub counter: Option<u64>,
    pub nonce: u64,
    pub status: String,
}
