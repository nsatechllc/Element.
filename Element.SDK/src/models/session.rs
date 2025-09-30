use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIssueRequest { pub cbid: String, #[serde(skip_serializing_if = "Option::is_none")] pub ttl_secs: Option<u64> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIssueResponse { pub token: String, pub expires_at: u64 }
