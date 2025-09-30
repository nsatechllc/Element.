use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbidDeriveRequest {
    #[serde(skip_serializing_if = "Option::is_none")] pub kem_strength: Option<String>,
    pub peer_pubkey: String,
    pub tag: Option<String>, // Base64 tag (service presently requires non-empty)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbidDeriveResponse {
    pub cbid: String,        // hex64
    pub ciphertext: String,  // Base64
}

impl CbidDeriveResponse {
    pub fn cbid_bytes(&self) -> Result<[u8;32], String> {
        if self.cbid.len() != 64 { return Err("cbid hex length != 64".into()); }
        let mut out = [0u8;32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&self.cbid[i*2..i*2+2], 16).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}