use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyStatus {
    #[serde(default)] pub allowed_algs: Vec<String>,
    #[serde(default)] pub build: Option<BuildInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub git_sha: Option<String>,
    pub ts: Option<String>,
}
