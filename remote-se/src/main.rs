mod config; mod errors; mod types; mod store; mod signer; mod address; mod metrics;
use crate::{config::Config, metrics::Metrics, types::Alg, store::{KeyStore, next_nonce_strict}, signer::SoftwareSigner, address::derive_address};
use axum::{routing::{get, post}, Router, Json, extract::State, http::StatusCode, response::{IntoResponse, Response}};
use serde::{Serialize, Deserialize};
use std::{sync::Arc, net::SocketAddr, time::Instant};
use tracing_subscriber::{EnvFilter, fmt};
use base64::{engine::general_purpose, Engine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	init_tracing();
	let config = Config::from_env()?;
	let state = AppState::new();
	let addr: SocketAddr = config.listen_addr.parse()?;
	tracing::info!(%addr, "remote-se starting (HTTP baseline, option1)");
	let app = build_router().with_state(state);
	let listener = tokio::net::TcpListener::bind(addr).await?;
	axum::serve(listener, app).await?;
	Ok(())
}

#[derive(Clone)]
struct AppState { metrics: Arc<Metrics>, store: Arc<KeyStore> }

impl AppState {
	fn new() -> Self { Self { metrics: Arc::new(Metrics::new()), store: Arc::new(KeyStore::new()) } }
}

#[derive(Deserialize)]
struct KeyGenReq { alg: String }
#[derive(Serialize)]
struct KeyGenResp { key_id: String, address: String, pubkey: String, alg: String, created_at: u64 }

#[derive(Deserialize)]
struct SignReq { key_id: String, digest: String, context_binding: String, nonce: u64 }
#[derive(Serialize)]
struct SignResp { signature: String, alg: String, counter: u64, nonce: u64 }

#[derive(Deserialize)]
struct VerifyReq { key_id: String, digest: String, signature: String }
#[derive(Serialize)]
struct VerifyResp { valid: bool, alg: String }

#[derive(Deserialize)]
struct ResolveReq { pubkey: String, alg: String }
#[derive(Serialize)]
struct ResolveResp { address: String, alg: String }

fn build_router() -> Router<AppState> {
	Router::new()
		.route("/health", get(|| async { "ok" }))
		.route("/keys", post(gen_key))
		.route("/sign", post(sign))
		.route("/verify", post(verify))
		.route("/resolve", post(resolve))
		.route("/metrics", get(metrics_endpoint))
}

fn parse_alg(s: &str) -> Result<Alg, &'static str> { match s { "dilithium5" => Ok(Alg::Dilithium5), "dilithium3" => Ok(Alg::Dilithium3), _ => Err("UNSUPPORTED_ALG") } }

async fn gen_key(State(st): State<AppState>, Json(req): Json<KeyGenReq>) -> Result<Json<KeyGenResp>, ApiError> {
	let alg = parse_alg(&req.alg).map_err(|code| ApiError::bad_request(code))?;
	let (pk, sk) = SoftwareSigner::keypair(alg).map_err(ApiError::internal)?;
	let address = derive_address(&pk);
	let rec = st.store.generate(alg, pk.clone(), sk, address.clone());
	let resp = KeyGenResp { key_id: rec.key_id.clone(), address, pubkey: general_purpose::STANDARD.encode(&pk), alg: alg.as_str().to_string(), created_at: rec.created_at };
	Ok(Json(resp))
}

async fn sign(State(st): State<AppState>, Json(req): Json<SignReq>) -> Result<Json<SignResp>, ApiError> {
	let start = Instant::now();
	let digest = general_purpose::STANDARD.decode(&req.digest).map_err(|_| ApiError::bad_request("INVALID_BASE64_DIGEST"))?;
	let ctx = general_purpose::STANDARD.decode(&req.context_binding).map_err(|_| ApiError::bad_request("INVALID_BASE64_CONTEXT"))?;
	let rec = st.store.get(&req.key_id).ok_or_else(|| ApiError::not_found("KEY_NOT_FOUND"))?;
	next_nonce_strict(&rec, req.nonce).map_err(|_| ApiError::conflict("NONCE_OUT_OF_ORDER"))?;
	let sig = SoftwareSigner::sign(rec.alg, rec.secret_key.bytes(), &digest, &ctx).map_err(|e| ApiError::bad_request(e.to_string()))?;
	let ctr = rec.usage_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
	st.metrics.sign_total.inc();
	st.metrics.sign_latency.observe(start.elapsed().as_secs_f64() * 1000.0);
	Ok(Json(SignResp { signature: general_purpose::STANDARD.encode(sig), alg: rec.alg.as_str().to_string(), counter: ctr, nonce: req.nonce }))
}

async fn verify(State(st): State<AppState>, Json(req): Json<VerifyReq>) -> Result<Json<VerifyResp>, ApiError> {
	let digest = general_purpose::STANDARD.decode(&req.digest).map_err(|_| ApiError::bad_request("INVALID_BASE64_DIGEST"))?;
	let sig = general_purpose::STANDARD.decode(&req.signature).map_err(|_| ApiError::bad_request("INVALID_BASE64_SIGNATURE"))?;
	let rec = st.store.get(&req.key_id).ok_or_else(|| ApiError::not_found("KEY_NOT_FOUND"))?;
	let valid = SoftwareSigner::verify(rec.alg, rec.public_key.as_ref(), &digest, &sig).map_err(ApiError::internal)?;
	if !valid { st.metrics.verify_fail.with_label_values(&[rec.alg.as_str()]).inc(); }
	Ok(Json(VerifyResp { valid, alg: rec.alg.as_str().to_string() }))
}

async fn resolve(Json(req): Json<ResolveReq>) -> Result<Json<ResolveResp>, ApiError> {
	let _alg = parse_alg(&req.alg).map_err(ApiError::bad_request)?;
	let pk = base64::engine::general_purpose::STANDARD.decode(req.pubkey).map_err(|_| ApiError::bad_request("INVALID_BASE64_PUBKEY"))?;
	let address = derive_address(&pk);
	Ok(Json(ResolveResp { address, alg: req.alg }))
}

async fn metrics_endpoint(State(st): State<AppState>) -> Json<serde_json::Value> { Json(st.metrics.registry_gather()) }

#[derive(Serialize)]
struct ErrorBody { error_code: String, message: String }

enum ApiErrorKind { BadRequest, NotFound, Conflict, Internal }

struct ApiError { kind: ApiErrorKind, code: String }

impl ApiError {
	fn bad_request<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::BadRequest, code: code.into() } }
	fn not_found<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::NotFound, code: code.into() } }
	fn conflict<S: Into<String>>(code: S) -> Self { Self { kind: ApiErrorKind::Conflict, code: code.into() } }
	fn internal<E: std::fmt::Debug>(e: E) -> Self { tracing::error!(?e, "internal error"); Self { kind: ApiErrorKind::Internal, code: "INTERNAL".into() } }
}

impl From<anyhow::Error> for ApiError { fn from(e: anyhow::Error) -> Self { Self::internal(e) } }

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let status = match self.kind { ApiErrorKind::BadRequest => StatusCode::BAD_REQUEST, ApiErrorKind::NotFound => StatusCode::NOT_FOUND, ApiErrorKind::Conflict => StatusCode::CONFLICT, ApiErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR };
		let body = Json(ErrorBody { error_code: self.code.clone(), message: self.code });
		(status, body).into_response()
	}
}

fn init_tracing() { let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")); fmt().with_env_filter(filter).json().init(); }
