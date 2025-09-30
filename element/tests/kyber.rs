/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
#[cfg(feature = "pqc")]
#[test]
fn kyber_roundtrip() {
    use element::kem::kyber::{KyberKEM, KyberStrength};
    let kem = KyberKEM::new(KyberStrength::Kyber768).expect("init kyber");
    let (pk, sk) = kem.keypair().expect("keypair");
    let (ct, ss1) = kem.encapsulate(&pk).expect("encap");
    let ss2 = kem.decapsulate(&sk, &ct).expect("decap");
    assert_eq!(ss1, ss2, "shared secrets differ");
}
