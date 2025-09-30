use std::time::Duration;

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub user_agent: String,
    pub max_retries: u8,
    #[cfg(feature = "hybrid-pq")] pub hybrid_pq_required: bool,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.nsatech.io".to_string(),
            timeout: Duration::from_secs(10),
            user_agent: format!("element-sdk/{}", env!("CARGO_PKG_VERSION")),
            max_retries: 2,
            #[cfg(feature = "hybrid-pq")] hybrid_pq_required: false,
        }
    }
}
