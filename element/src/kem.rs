/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
#[cfg(feature = "pqc")]
pub mod kyber {
    use anyhow::{Result, anyhow};
    use oqs::kem::{Kem, Algorithm};

    pub enum KyberStrength { Kyber768, Kyber1024 }

    fn map_alg(s: KyberStrength) -> Algorithm {
        match s { KyberStrength::Kyber768 => Algorithm::Kyber768, KyberStrength::Kyber1024 => Algorithm::Kyber1024 }
    }

    pub struct KyberKEM { kem: Kem }
    impl KyberKEM {
        pub fn new(strength: KyberStrength) -> Result<Self> { let kem = Kem::new(map_alg(strength)).map_err(|e| anyhow!("kyber_init: {e:?}"))?; Ok(Self { kem }) }
        pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> { let (pk, sk) = self.kem.keypair().map_err(|e| anyhow!("kyber_keypair: {e:?}"))?; Ok((pk.as_ref().to_vec(), sk.as_ref().to_vec())) }
        pub fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> { let pk_ref = self.kem.public_key_from_bytes(pk).ok_or_else(|| anyhow!("INVALID_PUBKEY_LEN"))?; let (ct, ss) = self.kem.encapsulate(&pk_ref).map_err(|e| anyhow!("kyber_encaps: {e:?}"))?; Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec())) }
        pub fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> { let sk_ref = self.kem.secret_key_from_bytes(sk).ok_or_else(|| anyhow!("INVALID_SECKEY_LEN"))?; let ct_ref = self.kem.ciphertext_from_bytes(ct).ok_or_else(|| anyhow!("INVALID_CT_LEN"))?; let ss = self.kem.decapsulate(&sk_ref, &ct_ref).map_err(|e| anyhow!("kyber_decaps: {e:?}"))?; Ok(ss.as_ref().to_vec()) }
    }

    // Channel Binding ID derivation: SHA3-256(ss || context_tag)
    pub fn derive_cbid(shared_secret: &[u8], tag: &[u8]) -> String { use sha3::{Digest, Sha3_256}; let mut h = Sha3_256::new(); h.update(shared_secret); h.update(tag); hex::encode(h.finalize()) }
}

#[cfg(not(feature = "pqc"))]
pub mod kyber { /* feature disabled placeholder */ }
