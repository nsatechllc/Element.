/*
 Automated · Intelligent · Natural
  - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
use axum::{routing::{get, post}, Router, Json, extract::State, http::StatusCode, response::{IntoResponse, Response}};
use serde::{Serialize, Deserialize};
use std::{sync::Arc, time::Instant};
use base64::{engine::general_purpose, Engine};
use std::sync::atomic::{AtomicU64, Ordering};
use crate::{metrics::Metrics, store::{KeyStore, next_nonce_strict}, signer::{ActiveSigner, SignerBackend}, types::Alg, address::derive_address};

#[derive(Clone)]
pub struct AppState { pub metrics: Arc<Metrics>, pub store: Arc<KeyStore>, pub allowed_algs: Arc<Vec<String>>, rate: Arc<RateLimiter> }
impl AppState { pub fn new() -> Self { let allowed_algs = std::env::var("SE_ALLOWED_ALGS").ok().map(|s| s.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect()).unwrap_or_else(|| vec!["dilithium5".into(), "dilithium3".into()]); let cap = std::env::var("SE_RATE_CAPACITY").ok().and_then(|v| v.parse().ok()).unwrap_or(500); let fill = std::env::var("SE_RATE_FILL_PER_SEC").ok().and_then(|v| v.parse().ok()).unwrap_or(500); Self { metrics: Arc::new(Metrics::new()), store: Arc::new(KeyStore::new()), allowed_algs: Arc::new(allowed_algs), rate: Arc::new(RateLimiter::new(cap, fill)) } } pub fn is_allowed(&self, alg: &str) -> bool { self.allowed_algs.iter().any(|a| a == alg) } }

fn now_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }
struct RateLimiter { capacity: u64, replenish_per_sec: u64, last_refill: AtomicU64, tokens: AtomicU64 }
impl RateLimiter { fn new(capacity: u64, per_sec: u64) -> Self { let now = now_secs(); Self { capacity, replenish_per_sec: per_sec, last_refill: AtomicU64::new(now), tokens: AtomicU64::new(capacity) } } fn take(&self, n: u64) -> bool { self.refill(); loop { let cur = self.tokens.load(Ordering::Relaxed); if cur < n { return false; } if self.tokens.compare_exchange(cur, cur - n, Ordering::SeqCst, Ordering::SeqCst).is_ok() { return true; } } } fn refill(&self) { let now = now_secs(); let last = self.last_refill.load(Ordering::Relaxed); if now > last { if self.last_refill.compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst).is_ok() { let add = self.replenish_per_sec.min(self.capacity - self.tokens.load(Ordering::Relaxed)); if add > 0 { self.tokens.fetch_add(add, Ordering::SeqCst); } } } } }

fn parse_alg(s: &str) -> Result<Alg, &'static str> { match s { "dilithium5" => Ok(Alg::Dilithium5), "dilithium3" => Ok(Alg::Dilithium3), _ => Err("UNSUPPORTED_ALG") } }

#[allow(dead_code)]
#[derive(Deserialize)] struct KeyGenReq { alg: String, include_pubkey: Option<bool> }
#[derive(Serialize)] struct KeyGenResp { key_id: String, address: String, pubkey: Option<String>, alg: String, created_at: u64 }
#[derive(Deserialize)] struct SignReq { key_id: String, digest: String, context_binding: String, nonce: u64 }
#[derive(Serialize)] struct SignResp { signature: String, alg: String, counter: u64, nonce: u64 }
#[derive(Deserialize)] struct VerifyReq { key_id: String, digest: String, signature: String, context_binding: Option<String> }
#[derive(Serialize)] struct VerifyResp { valid: bool, alg: String }
#[derive(Deserialize)] struct ResolveReq { pubkey: String, alg: String }
#[derive(Serialize)] struct ResolveResp { address: String, alg: String }
#[allow(dead_code)]
#[derive(Deserialize)] struct CbidReq { kem_strength: Option<String>, peer_pubkey: String, tag: String }
#[derive(Serialize)] struct CbidResp { cbid: String, ciphertext: String }
#[allow(dead_code)]
#[derive(Deserialize)] struct KyberKeyGenReq { strength: Option<String> }
#[derive(Serialize)] struct KyberKeyGenResp { pubkey: String, secret_key: String, strength: String }
#[allow(dead_code)]
#[derive(Deserialize)] struct KyberEncapReq { strength: Option<String>, peer_pubkey: String }
#[derive(Serialize)] struct KyberEncapResp { ciphertext: String, shared_secret: String, strength: String }
#[allow(dead_code)]
#[derive(Deserialize)] struct KyberDecapReq { strength: Option<String>, secret_key: String, ciphertext: String }
#[derive(Serialize)] struct KyberDecapResp { shared_secret: String, strength: String }
#[derive(Deserialize)] struct BatchSignItem { key_id: String, digest: String, context_binding: String, nonce: u64 }
#[derive(Deserialize)] struct BatchSignReq { items: Vec<BatchSignItem> }
#[derive(Serialize)] struct BatchSignRespItem { key_id: String, signature: String, alg: String, counter: u64, nonce: u64, status: String }
#[derive(Serialize)] struct BatchSignResp { results: Vec<BatchSignRespItem> }

#[derive(Serialize)] struct ErrorBody { error_code: String, message: String }
enum ApiErrorKind { BadRequest, NotFound, Conflict, Internal, TooMany }
struct ApiError { kind: ApiErrorKind, code: String }
impl ApiError { fn bad_request<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::BadRequest, code: code.into() } } fn not_found<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::NotFound, code: code.into() } } fn conflict<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::Conflict, code: code.into() } } fn internal<E: std::fmt::Debug>(e: E) -> Self { tracing::error!(?e, "internal error"); Self { kind: ApiErrorKind::Internal, code: "INTERNAL".into() } } fn too_many<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::TooMany, code: code.into() } } }
impl IntoResponse for ApiError { fn into_response(self) -> Response { let status = match self.kind { ApiErrorKind::BadRequest => StatusCode::BAD_REQUEST, ApiErrorKind::NotFound => StatusCode::NOT_FOUND, ApiErrorKind::Conflict => StatusCode::CONFLICT, ApiErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR, ApiErrorKind::TooMany => StatusCode::TOO_MANY_REQUESTS }; let body = Json(ErrorBody { error_code: self.code.clone(), message: self.code }); (status, body).into_response() } }

pub fn build_router() -> Router<AppState> { Router::new()
    .route("/health", get(|| async { "ok" }))
    .route("/version", get(version))
    .route("/ready", get(ready))
    .route("/session/issue", post(issue_session))
    .route("/keys", post(gen_key))
    .route("/sign", post(sign))
    .route("/sign/batch", post(sign_batch))
    .route("/verify", post(verify))
    .route("/resolve", post(resolve))
    .route("/metrics", get(metrics_endpoint))
    .route("/metrics/text", get(metrics_text))
    .route("/cbid/derive", post(cbid_derive))
    .route("/kem/kyber/keypair", post(kyber_keypair))
    .route("/kem/kyber/encapsulate", post(kyber_encapsulate))
    .route("/kem/kyber/decapsulate", post(kyber_decapsulate)) }

// Session issue endpoint (same semantics as main binary)
#[derive(Deserialize)] struct IssueSessionReq { cbid: String, ttl_secs: Option<u64> }
#[derive(Serialize)] struct IssueSessionResp { token: String, expires_at: u64 }
async fn issue_session(State(st): State<AppState>, Json(req): Json<IssueSessionReq>) -> Result<Json<IssueSessionResp>, ApiError> {
    let ttl = req.ttl_secs.unwrap_or(600).min(3600);
    // Ensure global store exists for tests
    if crate::session::global_token_store().is_none() {
        let _ = crate::session::init_global_token_store();
    }
    let store = crate::session::global_token_store().ok_or_else(|| ApiError::internal("TOKEN_STORE_UNINIT"))?;
    let (token, exp) = store.issue(&req.cbid, ttl);
    st.metrics.session_tokens.set(store.count() as i64);
    Ok(Json(IssueSessionResp { token, expires_at: exp }))
}

// Handlers
async fn gen_key(State(st): State<AppState>, Json(req): Json<KeyGenReq>) -> Result<Json<KeyGenResp>, ApiError> {
    let alg = parse_alg(&req.alg).map_err(ApiError::bad_request)?;
    if !st.is_allowed(alg.as_str()) { return Err(ApiError::bad_request("ALG_NOT_ALLOWED")); }
    let (pk, sk) = ActiveSigner::keypair(alg).map_err(ApiError::internal)?;
    let address = derive_address(&pk);
    let rec = st.store.generate(alg, pk.clone(), sk, address.clone());
    let include = req.include_pubkey.unwrap_or(false);
    Ok(Json(KeyGenResp { key_id: rec.key_id.clone(), address, pubkey: if include { Some(general_purpose::STANDARD.encode(&pk)) } else { None }, alg: alg.as_str().to_string(), created_at: rec.created_at }))
}
async fn sign(State(st): State<AppState>, Json(req): Json<SignReq>) -> Result<Json<SignResp>, ApiError> { if !st.rate.take(1) { st.metrics.rate_limited.inc(); return Err(ApiError::too_many("RATE_LIMIT")); } let start = Instant::now(); let digest = general_purpose::STANDARD.decode(&req.digest).map_err(|_| ApiError::bad_request("INVALID_BASE64_DIGEST"))?; let ctx = general_purpose::STANDARD.decode(&req.context_binding).map_err(|_| ApiError::bad_request("INVALID_BASE64_CONTEXT"))?; if digest.len()!=32 || ctx.len()!=32 { return Err(ApiError::bad_request("INVALID_LENGTH")); } let rec = st.store.get(&req.key_id).ok_or_else(|| ApiError::not_found("KEY_NOT_FOUND"))?; if !st.is_allowed(rec.alg.as_str()) { return Err(ApiError::bad_request("ALG_NOT_ALLOWED")); } next_nonce_strict(&rec, req.nonce).map_err(|_| ApiError::conflict("NONCE_OUT_OF_ORDER"))?; let sig = ActiveSigner::sign(rec.alg, rec.secret_key.bytes(), &digest, &ctx).map_err(|e| ApiError::bad_request(e.to_string()))?; st.metrics.sign_by_alg.with_label_values(&[rec.alg.as_str()]).inc(); let ctr = rec.usage_count.fetch_add(1, Ordering::SeqCst)+1; st.metrics.sign_total.inc(); st.metrics.sign_latency.observe(start.elapsed().as_secs_f64()*1000.0); Ok(Json(SignResp { signature: general_purpose::STANDARD.encode(sig), alg: rec.alg.as_str().into(), counter: ctr, nonce: req.nonce })) }
async fn sign_batch(State(st): State<AppState>, Json(req): Json<BatchSignReq>) -> Result<Json<BatchSignResp>, ApiError> { let mut results = Vec::with_capacity(req.items.len()); for item in req.items.into_iter() { if !st.rate.take(1) { st.metrics.rate_limited.inc(); results.push(BatchSignRespItem { key_id: item.key_id, signature: String::new(), alg: String::new(), counter: 0, nonce: item.nonce, status: "RATE_LIMIT".into() }); continue; } let r = (|| -> Result<BatchSignRespItem, ApiError> { let digest = general_purpose::STANDARD.decode(&item.digest).map_err(|_| ApiError::bad_request("INVALID_BASE64_DIGEST"))?; let ctx = general_purpose::STANDARD.decode(&item.context_binding).map_err(|_| ApiError::bad_request("INVALID_BASE64_CONTEXT"))?; if digest.len()!=32 || ctx.len()!=32 { return Err(ApiError::bad_request("INVALID_LENGTH")); } let rec = st.store.get(&item.key_id).ok_or_else(|| ApiError::not_found("KEY_NOT_FOUND"))?; if !st.is_allowed(rec.alg.as_str()) { return Err(ApiError::bad_request("ALG_NOT_ALLOWED")); } next_nonce_strict(&rec, item.nonce).map_err(|_| ApiError::conflict("NONCE_OUT_OF_ORDER"))?; let sig = ActiveSigner::sign(rec.alg, rec.secret_key.bytes(), &digest, &ctx).map_err(|e| ApiError::bad_request(e.to_string()))?; st.metrics.sign_by_alg.with_label_values(&[rec.alg.as_str()]).inc(); st.metrics.sign_total.inc(); let ctr = rec.usage_count.fetch_add(1, Ordering::SeqCst)+1; Ok(BatchSignRespItem { key_id: rec.key_id.clone(), signature: general_purpose::STANDARD.encode(sig), alg: rec.alg.as_str().into(), counter: ctr, nonce: item.nonce, status: "OK".into() }) })(); match r { Ok(ok) => results.push(ok), Err(e) => results.push(BatchSignRespItem { key_id: item.key_id, signature: String::new(), alg: String::new(), counter: 0, nonce: item.nonce, status: e.code }) } } Ok(Json(BatchSignResp { results })) }
async fn verify(State(st): State<AppState>, Json(req): Json<VerifyReq>) -> Result<Json<VerifyResp>, ApiError> {
    if !st.rate.take(1) { st.metrics.rate_limited.inc(); return Err(ApiError::too_many("RATE_LIMIT")); }
    let raw_digest = general_purpose::STANDARD.decode(&req.digest).map_err(|_| ApiError::bad_request("INVALID_BASE64_DIGEST"))?;
    let sig = general_purpose::STANDARD.decode(&req.signature).map_err(|_| ApiError::bad_request("INVALID_BASE64_SIGNATURE"))?;
    let rec = st.store.get(&req.key_id).ok_or_else(|| ApiError::not_found("KEY_NOT_FOUND"))?;
    let message = {
        let cb64 = req.context_binding.as_ref().ok_or_else(|| ApiError::bad_request("CONTEXT_REQUIRED"))?;
        let ctx = general_purpose::STANDARD.decode(cb64).map_err(|_| ApiError::bad_request("INVALID_BASE64_CONTEXT"))?;
        if raw_digest.len() != 32 || ctx.len() != 32 { return Err(ApiError::bad_request("INVALID_LENGTH")); }
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&raw_digest);
        combined.extend_from_slice(&ctx);
        combined
    };
    if !st.is_allowed(rec.alg.as_str()) { return Err(ApiError::bad_request("ALG_NOT_ALLOWED")); }
    let valid = ActiveSigner::verify(rec.alg, rec.public_key.as_ref(), &message, &sig).map_err(ApiError::internal)?;
    if !valid { st.metrics.verify_fail.with_label_values(&[rec.alg.as_str()]).inc(); }
    Ok(Json(VerifyResp { valid, alg: rec.alg.as_str().into() }))
}
async fn resolve(Json(req): Json<ResolveReq>) -> Result<Json<ResolveResp>, ApiError> { let _alg = parse_alg(&req.alg).map_err(ApiError::bad_request)?; let pk = general_purpose::STANDARD.decode(req.pubkey).map_err(|_| ApiError::bad_request("INVALID_BASE64_PUBKEY"))?; let address = derive_address(&pk); Ok(Json(ResolveResp { address, alg: req.alg })) }
async fn metrics_endpoint(State(st): State<AppState>) -> Json<serde_json::Value> { Json(st.metrics.registry_gather()) }
async fn metrics_text(State(st): State<AppState>) -> String { st.metrics.prometheus_text() }

// Simple version & build metadata endpoint for operational introspection.
async fn version() -> Response {
    let body = serde_json::json!({
    "service": "Element.",
        "pkg_version": env!("CARGO_PKG_VERSION"),
        "git_sha": std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".into()),
        "build_ts": std::env::var("BUILD_TS").unwrap_or_else(|_| "unknown".into()),
        "features": {
            "pqc": cfg!(feature = "pqc"),
            "grpc": cfg!(feature = "grpc"),
            "quic_overlay": cfg!(feature = "quic-overlay")
        }
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn ready(State(st): State<AppState>) -> Response {
    let allowed: Vec<String> = st.allowed_algs.iter().cloned().collect();
    let up = serde_json::json!({
        "status": "ready",
        "allowed_algs": allowed,
        "pqc": cfg!(feature = "pqc"),
        "address_hash": "sha256",
        "persistent_keystore": false,
        "git_sha": std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".into()),
        "build_ts": std::env::var("BUILD_TS").unwrap_or_else(|_| "unknown".into())
    });
    (StatusCode::OK, Json(up)).into_response()
}

#[cfg(feature = "pqc")]
async fn cbid_derive(Json(req): Json<CbidReq>) -> Result<Json<CbidResp>, ApiError> { use crate::kem::kyber::{KyberKEM, KyberStrength, derive_cbid}; let strength = match req.kem_strength.as_deref() { Some("kyber1024") => KyberStrength::Kyber1024, Some("kyber768") | None => KyberStrength::Kyber768, _ => return Err(ApiError::bad_request("UNSUPPORTED_KEM")) }; let kem = KyberKEM::new(strength).map_err(ApiError::internal)?; let peer_pk = general_purpose::STANDARD.decode(&req.peer_pubkey).map_err(|_| ApiError::bad_request("INVALID_BASE64_PUBKEY"))?; let (ct, ss) = kem.encapsulate(&peer_pk).map_err(ApiError::internal)?; let tag = general_purpose::STANDARD.decode(&req.tag).map_err(|_| ApiError::bad_request("INVALID_BASE64_TAG"))?; if tag.len() > 64 { return Err(ApiError::bad_request("TAG_TOO_LONG")); } let cbid = derive_cbid(&ss, &tag); Ok(Json(CbidResp { cbid, ciphertext: general_purpose::STANDARD.encode(ct) })) }
#[cfg(not(feature = "pqc"))]
async fn cbid_derive() -> Result<Json<CbidResp>, ApiError> { Err(ApiError::bad_request("PQC_DISABLED")) }

#[cfg(feature = "pqc")]
async fn kyber_keypair(Json(req): Json<KyberKeyGenReq>) -> Result<Json<KyberKeyGenResp>, ApiError> { use crate::kem::kyber::KyberKEM; let strength = match req.strength.as_deref() { Some("kyber1024") => crate::kem::kyber::KyberStrength::Kyber1024, Some("kyber768") | None => crate::kem::kyber::KyberStrength::Kyber768, _ => return Err(ApiError::bad_request("UNSUPPORTED_KEM")) }; let kem = KyberKEM::new(strength).map_err(ApiError::internal)?; let (pk, sk) = kem.keypair().map_err(ApiError::internal)?; Ok(Json(KyberKeyGenResp { pubkey: general_purpose::STANDARD.encode(pk), secret_key: general_purpose::STANDARD.encode(sk), strength: req.strength.unwrap_or_else(|| "kyber768".into()) })) }
#[cfg(not(feature = "pqc"))]
async fn kyber_keypair() -> Result<Json<KyberKeyGenResp>, ApiError> { Err(ApiError::bad_request("PQC_DISABLED")) }
#[cfg(feature = "pqc")]
async fn kyber_encapsulate(Json(req): Json<KyberEncapReq>) -> Result<Json<KyberEncapResp>, ApiError> { use crate::kem::kyber::KyberKEM; let strength = match req.strength.as_deref() { Some("kyber1024") => crate::kem::kyber::KyberStrength::Kyber1024, Some("kyber768") | None => crate::kem::kyber::KyberStrength::Kyber768, _ => return Err(ApiError::bad_request("UNSUPPORTED_KEM")) }; let kem = KyberKEM::new(strength).map_err(ApiError::internal)?; let peer_pk = general_purpose::STANDARD.decode(&req.peer_pubkey).map_err(|_| ApiError::bad_request("INVALID_BASE64_PUBKEY"))?; let (ct, ss) = kem.encapsulate(&peer_pk).map_err(ApiError::internal)?; Ok(Json(KyberEncapResp { ciphertext: general_purpose::STANDARD.encode(ct), shared_secret: general_purpose::STANDARD.encode(ss), strength: req.strength.unwrap_or_else(|| "kyber768".into()) })) }
#[cfg(not(feature = "pqc"))]
async fn kyber_encapsulate() -> Result<Json<KyberEncapResp>, ApiError> { Err(ApiError::bad_request("PQC_DISABLED")) }
#[cfg(feature = "pqc")]
async fn kyber_decapsulate(Json(req): Json<KyberDecapReq>) -> Result<Json<KyberDecapResp>, ApiError> { use crate::kem::kyber::KyberKEM; let strength = match req.strength.as_deref() { Some("kyber1024") => crate::kem::kyber::KyberStrength::Kyber1024, Some("kyber768") | None => crate::kem::kyber::KyberStrength::Kyber768, _ => return Err(ApiError::bad_request("UNSUPPORTED_KEM")) }; let kem = KyberKEM::new(strength).map_err(ApiError::internal)?; let sk = general_purpose::STANDARD.decode(&req.secret_key).map_err(|_| ApiError::bad_request("INVALID_BASE64_SECKEY"))?; let ct = general_purpose::STANDARD.decode(&req.ciphertext).map_err(|_| ApiError::bad_request("INVALID_BASE64_CT"))?; let ss = kem.decapsulate(&sk, &ct).map_err(ApiError::internal)?; Ok(Json(KyberDecapResp { shared_secret: general_purpose::STANDARD.encode(ss), strength: req.strength.unwrap_or_else(|| "kyber768".into()) })) }

// Convenience runner for tests (HTTP only)
pub async fn run_http_listener(listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let state = AppState::new();
    let app = build_router().with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}
#[cfg(not(feature = "pqc"))]
async fn kyber_decapsulate() -> Result<Json<KyberDecapResp>, ApiError> { Err(ApiError::bad_request("PQC_DISABLED")) }
