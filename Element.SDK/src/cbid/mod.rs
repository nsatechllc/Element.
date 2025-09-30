use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbidDeriveRequest {
    #[serde(skip_serializing_if = "Option::is_none")] pub kem_strength: Option<String>,
    pub peer_pubkey: String,
    pub tag: String, // Base64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbidDeriveResponse { pub cbid: String, pub ciphertext: String }

pub fn local_cbid(shared_secret: &[u8], tag: &[u8]) -> [u8;32] {
    let mut h = Sha3_256::new();
    h.update(shared_secret);
    h.update(tag);
    let out = h.finalize();
    let mut arr = [0u8;32];
    arr.copy_from_slice(&out);
    arr
}
