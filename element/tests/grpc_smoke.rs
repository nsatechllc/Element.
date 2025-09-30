/*
 Automated · Intelligent · Natural
  - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
#![cfg(all(feature = "grpc", feature = "pqc"))]
use element::{metrics::Metrics, store::KeyStore, types::Alg, signer::{ActiveSigner, SignerBackend}};
use std::{sync::Arc, net::SocketAddr, time::Duration};
use tokio::time::sleep;
use tonic::transport::Channel;

// Re-import generated proto via including the OUT_DIR (bin style) because tests compile as separate crates.
mod pb { include!(concat!(env!("OUT_DIR"), "/element.v1.rs")); }
use pb::{element_signer_client::ElementSignerClient, GenerateKeyRequest, SignDigestRequest, VerifySignatureRequest};

#[tokio::test]
async fn grpc_sign_verify_roundtrip() {
    // Start a minimal gRPC server in background using the binary modules.
    use element::grpc::server::{GrpcState, GrpcService, into_server};
    use tonic::transport::Server;

    let addr: SocketAddr = "127.0.0.1:55051".parse().unwrap();
    let metrics = Arc::new(Metrics::new());
    let store = Arc::new(KeyStore::new());
    let gstate = Arc::new(GrpcState::new(metrics.clone(), store.clone()));
    let svc = GrpcService::new(gstate);

    tokio::spawn(async move {
        Server::builder().add_service(into_server(svc)).serve(addr).await.unwrap();
    });

    // Allow server to bind.
    sleep(Duration::from_millis(150)).await;

    let channel = Channel::from_shared(format!("http://{}", addr)).unwrap().connect().await.unwrap();
    let mut client = ElementSignerClient::new(channel);

    // Generate key
    let resp = client.generate_key(GenerateKeyRequest { algorithm: "dilithium5".into() }).await.unwrap().into_inner();
    assert_eq!(resp.algorithm, "dilithium5");
    let key_id = resp.key_id;

    // Prepare 32-byte digest & context
    let digest = [0xABu8; 32];
    let context = [0xCDu8; 32];

    // Sign
    let sig_resp = client.sign_digest(SignDigestRequest { key_id: key_id.clone(), digest32: digest.to_vec(), context32: context.to_vec(), nonce: 1 }).await.unwrap().into_inner();
    assert_eq!(sig_resp.nonce, 1);

    // Verify
    let ver_resp = client.verify_signature(VerifySignatureRequest { key_id, digest32: digest.to_vec(), context32: context.to_vec(), signature: sig_resp.signature }).await.unwrap().into_inner();
    assert!(ver_resp.valid);
}
