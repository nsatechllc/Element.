use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKeyPairRequest { #[serde(skip_serializing_if = "Option::is_none")] pub strength: Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKeyPairResponse { pub pubkey: String, pub secret_key: String, pub strength: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberEncapsulateRequest { #[serde(skip_serializing_if = "Option::is_none")] pub strength: Option<String>, pub peer_pubkey: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberEncapsulateResponse { pub ciphertext: String, pub shared_secret: String, pub strength: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberDecapsulateRequest { #[serde(skip_serializing_if = "Option::is_none")] pub strength: Option<String>, pub secret_key: String, pub ciphertext: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberDecapsulateResponse { pub shared_secret: String, pub strength: String }
