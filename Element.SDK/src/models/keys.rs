use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm { Dilithium5, Dilithium3 }

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self { Algorithm::Dilithium5 => "dilithium5", Algorithm::Dilithium3 => "dilithium3" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenRequest { pub alg: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_id: String,
    pub pubkey: String,
    pub alg: String,
    pub created_at: u64,
}
