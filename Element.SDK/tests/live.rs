//! Ignored live integration test hitting the real Element service.
//! Enable with ELEMENT_BASE_URL env var and run with --ignored.

use element_sdk::*;
use sha3::{Digest, Sha3_256};
use base64::Engine; // bring encode/decode trait into scope

fn base_url() -> Option<String> { std::env::var("ELEMENT_BASE_URL").ok() }

#[tokio::test]
#[ignore]
async fn element_live() {
    let Some(url) = base_url() else { eprintln!("ELEMENT_BASE_URL not set; skipping live test"); return; };
    let client = ElementClient::builder(url).build().expect("build client");

    // 1. Generate key
    let key = client.generate_key(Algorithm::Dilithium5).await.expect("keygen");
    assert_eq!(key.alg, "dilithium5");

    // 2. Kyber key pair (client side)
    let kp = client.kyber_keypair(Some("kyber768")).await.expect("kyber keypair");

    // 3. Derive CBID with tag
    let tag_b64 = base64::engine::general_purpose::STANDARD.encode(b"sdk-live-test");
    let derive = CbidDeriveRequest { kem_strength: Some("kyber768".into()), peer_pubkey: kp.pubkey.clone(), tag: Some(tag_b64) };
    let cbid_resp = client.derive_cbid(derive).await.expect("cbid derive");
    assert_eq!(cbid_resp.cbid.len(), 64);

        // 4. Issue session token (if service enforces)
        let cbid_hex = &cbid_resp.cbid;
        let session = client.issue_session(SessionIssueRequest { cbid: cbid_hex.clone(), ttl_secs: Some(600) }).await.expect("issue session");
        client.set_session_token(session.token.clone());

        // 5. Sign digest
    let digest = Sha3_256::digest(b"integration-test-digest");
    let mut digest32 = [0u8;32]; digest32.copy_from_slice(&digest);

    let cbid_bytes = cbid_resp.cbid_bytes().expect("cbid bytes");
    let sign_req = SignDigestRequest::from_bytes(key.key_id.clone(), digest32, Some(cbid_bytes), 1);
    let sig = client.sign_digest(sign_req).await.expect("sign");
    assert_eq!(sig.nonce, 1);


        // 6. Batch sign nonce 2 & 3
        let mut d2 = [0u8;32]; d2.copy_from_slice(&Sha3_256::digest(b"batch-two"));
        let mut d3 = [0u8;32]; d3.copy_from_slice(&Sha3_256::digest(b"batch-three"));
    let item2 = SignItemRequest::from_bytes(key.key_id.clone(), d2, cbid_bytes, 2);
    let item3 = SignItemRequest::from_bytes(key.key_id.clone(), d3, cbid_bytes, 3);
        let batch = client.batch_sign(vec![item2, item3]).await.expect("batch sign");
        assert_eq!(batch.results.len(), 2);
        assert!(batch.results.iter().all(|r| r.status == "OK"));

        // 7. Verify original signature
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig.signature.clone()).unwrap();
        let verify_req = VerifyRequest::from_bytes(key.key_id.clone(), digest32, sig_bytes, cbid_bytes);
        let v = client.verify(verify_req).await.expect("verify");
    assert!(v.valid);
}
