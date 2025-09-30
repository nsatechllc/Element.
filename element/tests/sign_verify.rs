/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
// (removed unused import) intentionally left blank

// Very lightweight integration sanity test (requires server running separately in CI or spawn?).
// For now just checks base64 concatenation logic locally by invoking signer backend directly when pqc feature enabled.
#[cfg(feature = "pqc")]
#[test]
fn pqc_dilithium_sign_roundtrip() {
    use element::signer::{ActiveSigner, SignerBackend};
    use element::types::Alg;
    let (pk, sk) = ActiveSigner::keypair(Alg::Dilithium5).expect("keypair");
    let digest = [0u8;32];
    let ctx = [1u8;32];
    let sig = ActiveSigner::sign(Alg::Dilithium5, &sk, &digest, &ctx).expect("sign");
    assert!(ActiveSigner::verify(Alg::Dilithium5, &pk, &[0u8;32], &sig).unwrap_or(false) == false, "raw digest alone shouldn't verify (needs combined)");
    let mut combined = Vec::with_capacity(64); combined.extend_from_slice(&digest); combined.extend_from_slice(&ctx);
    assert!(ActiveSigner::verify(Alg::Dilithium5, &pk, &combined, &sig).unwrap(), "combined should verify");
}
