use crate::config::EndpointConfig;
use crate::errors::Error;
use crate::nonce::NonceTracker;
use crate::models::*;
use crate::cbid::{CbidDeriveRequest, CbidDeriveResponse};
use crate::retry::backoff_retry;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct ElementClient {
    cfg: EndpointConfig,
    #[cfg(feature = "http")]
    http: request::Client,
    session_token: Arc<parking_lot::RwLock<Option<String>>>,
    nonce_tracker: NonceTracker,
    #[cfg(feature = "hybrid-pq")]
    negotiated_groups: Arc<parking_lot::RwLock<Vec<String>>>,
}

pub struct ElementClientBuilder {
    cfg: EndpointConfig,
}

impl ElementClientBuilder {
    pub fn new(base_url: impl Into<String>) -> Self { let mut cfg = EndpointConfig::default(); cfg.base_url = base_url.into(); Self { cfg } }
    pub fn timeout(mut self, dur: Duration) -> Self { self.cfg.timeout = dur; self }
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self { self.cfg.user_agent = ua.into(); self }
    pub fn max_retries(mut self, mr: u8) -> Self { self.cfg.max_retries = mr; self }
    #[cfg(feature = "hybrid-pq")]
    pub fn require_pq(mut self, required: bool) -> Self { self.cfg.hybrid_pq_required = required; self }
    pub fn build(self) -> Result<ElementClient, Error> {
    #[cfg(feature = "http")]
    let http = request::Client::builder()
            .user_agent(&self.cfg.user_agent)
            .timeout(self.cfg.timeout)
            .build()?;
        Ok(ElementClient { cfg: self.cfg, #[cfg(feature = "http")] http, session_token: Arc::new(parking_lot::RwLock::new(None)), nonce_tracker: NonceTracker::default(), #[cfg(feature = "hybrid-pq")] negotiated_groups: Arc::new(parking_lot::RwLock::new(Vec::new())) })
    }
}

impl ElementClient {
    pub fn builder(base_url: impl Into<String>) -> ElementClientBuilder { ElementClientBuilder::new(base_url) }

    pub fn set_session_token(&self, token: impl Into<String>) { *self.session_token.write() = Some(token.into()); }
    pub fn session_token(&self) -> Option<String> { self.session_token.read().clone() }
    pub fn nonce_tracker(&self) -> &NonceTracker { &self.nonce_tracker }
    #[cfg(feature = "hybrid-pq")]
    pub fn negotiated_groups(&self) -> Vec<String> { self.negotiated_groups.read().clone() }
    #[cfg(feature = "hybrid-pq")]
    pub fn record_negotiated_group(&self, g: impl Into<String>) { self.negotiated_groups.write().push(g.into()); }
    #[cfg(feature = "hybrid-pq")]
    pub fn assert_pq(&self) -> Result<(), Error> {
        if self.cfg.hybrid_pq_required {
            let groups = self.negotiated_groups();
            let ok = groups.iter().any(|g| g.contains("Kyber") || g.contains("Hybrid") || g.contains("MLKEM"));
            if !ok { return Err(Error::Config("PQ/hybrid group not negotiated".into())); }
        }
        Ok(())
    }

    #[cfg(feature = "http")]
    fn auth_header(&self, rb: request::RequestBuilder) -> request::RequestBuilder {
        if let Some(tok) = self.session_token() { rb.header("Authorization", format!("Bearer {}", tok)) } else { rb }
    }

    #[cfg(feature = "http")]
    async fn post_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(&self, path: &str, body: &B) -> Result<T, Error> {
        let url = format!("{}/{}", self.cfg.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        let req = self.http.post(url).json(body);
        let req = self.auth_header(req);
        let execute = |_attempt| async {
            let resp = req.try_clone().ok_or_else(|| Error::Config("non-clonable request".into()))?.send().await?;
            classify(resp).await
        };
        backoff_retry(execute, self.cfg.max_retries).await
    }

    #[cfg(feature = "http")]
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}/{}", self.cfg.base_url.trim_end_matches('/'), path.trim_start_matches('/'));
        let req = self.http.get(url);
        let req = self.auth_header(req);
        let execute = |_attempt| async {
            let resp = req.try_clone().ok_or_else(|| Error::Config("non-clonable request".into()))?.send().await?;
            classify(resp).await
        };
        backoff_retry(execute, self.cfg.max_retries).await
    }

    // ---- Public API ----
    #[cfg(feature = "http")]
    pub async fn generate_key(&self, alg: Algorithm) -> Result<KeyRecord, Error> {
        let body = serde_json::json!({"alg": alg.as_str()});
        self.post_json("keys", &body).await
    }

    #[cfg(feature = "http")]
    pub async fn sign_digest(&self, req: SignDigestRequest) -> Result<SignDigestResponse, Error> {
        let resp: SignDigestResponse = self.post_json("sign", &req).await?;
        self.nonce_tracker.record_success(&req.key_id, req.nonce);
        Ok(resp)
    }

    #[cfg(feature = "http")]
    pub async fn batch_sign(&self, items: Vec<SignItemRequest>) -> Result<BatchSignResponse, Error> {
        let body = BatchSignRequest { items };
        self.post_json("sign/batch", &body).await
    }

    #[cfg(feature = "http")]
    pub async fn verify(&self, req: VerifyRequest) -> Result<VerifyResponse, Error> {
        self.post_json("verify", &req).await
    }

    #[cfg(feature = "http")]
    pub async fn resolve(&self, req: ResolveRequest) -> Result<ResolveResponse, Error> {
        self.post_json("resolve", &req).await
    }

    #[cfg(feature = "http")]
    pub async fn kyber_keypair(&self, strength: Option<&str>) -> Result<KyberKeyPairResponse, Error> {
        let body = serde_json::json!({"strength": strength});
        self.post_json("kem/kyber/keypair", &body).await
    }

    #[cfg(feature = "http")]
    pub async fn kyber_encapsulate(&self, req: KyberEncapsulateRequest) -> Result<KyberEncapsulateResponse, Error> {
        self.post_json("kem/kyber/encapsulate", &req).await
    }

    #[cfg(feature = "http")]
    pub async fn kyber_decapsulate(&self, req: KyberDecapsulateRequest) -> Result<KyberDecapsulateResponse, Error> {
        self.post_json("kem/kyber/decapsulate", &req).await
    }

    #[cfg(feature = "http")]
    pub async fn derive_cbid(&self, req: CbidDeriveRequest) -> Result<CbidDeriveResponse, Error> {
        self.post_json("cbid/derive", &req).await
    }

    #[cfg(feature = "http")]
    pub async fn issue_session(&self, req: SessionIssueRequest) -> Result<SessionIssueResponse, Error> {
        let r: SessionIssueResponse = self.post_json("session/issue", &req).await?;
        Ok(r)
    }

    #[cfg(feature = "http")]
    pub async fn health(&self) -> Result<HealthStatus, Error> { self.get_json("health").await }
    #[cfg(feature = "http")]
    pub async fn ready(&self) -> Result<ReadyStatus, Error> { self.get_json("ready").await }
}

#[cfg(feature = "http")]
async fn classify<T: serde::de::DeserializeOwned>(resp: request::Response) -> Result<T, Error> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if status.is_success() {
        let v: T = serde_json::from_slice(&bytes).map_err(|e| Error::Decode(e.to_string()))?;
        return Ok(v);
    }
    // Try parse error_code
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if let Some(code) = val.get("error_code").and_then(|c| c.as_str()) {
            return Err(match code {
                "NONCE_OUT_OF_ORDER" => Error::NonceOutOfOrder,
                "KEY_NOT_FOUND" => Error::KeyNotFound,
                "ALG_NOT_ALLOWED" => Error::AlgNotAllowed,
                "SESSION_INVALID" => Error::SessionInvalid,
                c if c.starts_with("INVALID_BASE64") => Error::InvalidBase64("field"),
                c if c == "TAG_TOO_LONG" => Error::TagTooLong,
                other => Error::Server(other.to_string()),
            });
        }
    }
    Err(Error::Server(format!("status {} body {}", status, String::from_utf8_lossy(&bytes))))
}
