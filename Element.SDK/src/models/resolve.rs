use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRequest { pub pubkey: String, pub alg: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResponse { pub address: String, pub alg: String }
