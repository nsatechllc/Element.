/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
#![allow(dead_code)]
#[cfg(feature = "grpc")] pub mod server {
    use std::sync::Arc;
    use tonic::{Request, Response, Status};
    use crate::{store::{KeyStore, next_nonce_strict}, metrics::Metrics, signer::{ActiveSigner, SignerBackend}, types::Alg};
    use base64::{engine::general_purpose, Engine};
    use crate::kem::kyber::{KyberKEM, KyberStrength};
    use crate::pb::{element_signer_server::{ElementSigner, ElementSignerServer}, *};

    pub struct GrpcState { pub metrics: Arc<Metrics>, pub store: Arc<KeyStore> }
    impl GrpcState { pub fn new(metrics: Arc<Metrics>, store: Arc<KeyStore>) -> Self { Self { metrics, store } } }

    pub struct GrpcService { state: Arc<GrpcState> }
    impl GrpcService { pub fn new(state: Arc<GrpcState>) -> Self { Self { state } } }

    fn parse_alg(a: &str) -> Result<Alg, Status> { match a { "dilithium5" => Ok(Alg::Dilithium5), "dilithium3" => Ok(Alg::Dilithium3), _ => Err(Status::invalid_argument("UNSUPPORTED_ALG")) } }

    fn kyber_strength(s: &str) -> KyberStrength { match s { "kyber1024" => KyberStrength::Kyber1024, _ => KyberStrength::Kyber768 } }

    #[tonic::async_trait]
    impl ElementSigner for GrpcService {
        async fn generate_key(&self, req: Request<GenerateKeyRequest>) -> Result<Response<GenerateKeyResponse>, Status> {
            let r = req.into_inner(); let alg = parse_alg(&r.algorithm)?; let (pk, sk) = ActiveSigner::keypair(alg).map_err(|_| Status::internal("KEYPAIR_FAIL"))?; let address = crate::address::derive_address(&pk); let rec = self.state.store.generate(alg, pk.clone(), sk, address); Ok(Response::new(GenerateKeyResponse { key_id: rec.key_id.clone(), pubkey_b64: general_purpose::STANDARD.encode(pk), algorithm: alg.as_str().into(), created_at: rec.created_at })) }
        async fn sign_digest(&self, req: Request<SignDigestRequest>) -> Result<Response<SignDigestResponse>, Status> { let r = req.into_inner(); let rec = self.state.store.get(&r.key_id).ok_or(Status::not_found("KEY_NOT_FOUND"))?; if r.digest32.len()!=32 || r.context32.len()!=32 { return Err(Status::invalid_argument("LENGTH")); } next_nonce_strict(&rec, r.nonce).map_err(|_| Status::failed_precondition("NONCE"))?; let sig = ActiveSigner::sign(rec.alg, rec.secret_key.bytes(), &r.digest32, &r.context32).map_err(|_| Status::internal("SIGN_FAIL"))?; let ctr = rec.usage_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst)+1; self.state.metrics.sign_total.inc(); Ok(Response::new(SignDigestResponse { signature: sig, algorithm: rec.alg.as_str().into(), counter: ctr, nonce: r.nonce })) }
        async fn verify_signature(&self, req: Request<VerifySignatureRequest>) -> Result<Response<VerifySignatureResponse>, Status> { let r = req.into_inner(); let rec = self.state.store.get(&r.key_id).ok_or(Status::not_found("KEY_NOT_FOUND"))?; if r.digest32.len()!=32 || r.context32.len()!=32 { return Err(Status::invalid_argument("LENGTH")); } let mut m = Vec::with_capacity(64); m.extend_from_slice(&r.digest32); m.extend_from_slice(&r.context32); let valid = ActiveSigner::verify(rec.alg, rec.public_key.as_ref(), &m, &r.signature).map_err(|_| Status::internal("VERIFY_ERR"))?; if !valid { self.state.metrics.verify_fail.with_label_values(&[rec.alg.as_str()]).inc(); } Ok(Response::new(VerifySignatureResponse { valid, algorithm: rec.alg.as_str().into() })) }
        async fn kyber_key_pair(&self, req: Request<KyberKeyPairRequest>) -> Result<Response<KyberKeyPairResponse>, Status> { let r = req.into_inner(); let st = kyber_strength(&r.strength); let kem = KyberKEM::new(st).map_err(|_| Status::internal("KEM_INIT"))?; let (pk, sk) = kem.keypair().map_err(|_| Status::internal("KEM_KEYPAIR"))?; Ok(Response::new(KyberKeyPairResponse { public_key: pk, secret_key: sk, strength: r.strength })) }
        async fn kyber_encapsulate(&self, req: Request<KyberEncapsulateRequest>) -> Result<Response<KyberEncapsulateResponse>, Status> { let r = req.into_inner(); let st = kyber_strength(&r.strength); let kem = KyberKEM::new(st).map_err(|_| Status::internal("KEM_INIT"))?; let (ct, ss) = kem.encapsulate(&r.peer_public_key).map_err(|_| Status::invalid_argument("KEM_ENCAPS"))?; Ok(Response::new(KyberEncapsulateResponse { ciphertext: ct, shared_secret: ss, strength: r.strength })) }
        async fn kyber_decapsulate(&self, req: Request<KyberDecapsulateRequest>) -> Result<Response<KyberDecapsulateResponse>, Status> { let r = req.into_inner(); let st = kyber_strength(&r.strength); let kem = KyberKEM::new(st).map_err(|_| Status::internal("KEM_INIT"))?; let ss = kem.decapsulate(&r.secret_key, &r.ciphertext).map_err(|_| Status::invalid_argument("KEM_DECAPS"))?; Ok(Response::new(KyberDecapsulateResponse { shared_secret: ss, strength: r.strength })) }
    }

    pub fn into_server(svc: GrpcService) -> ElementSignerServer<GrpcService> { ElementSignerServer::new(svc) }
}

#[cfg(not(feature = "grpc"))]
pub mod server { /* gRPC disabled */ }