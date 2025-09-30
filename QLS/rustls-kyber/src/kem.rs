//! Kyber KEM abstraction wrapping the `oqs` crate.
//! Provides fallbacks when compiled in `stub` mode.

use tracing::instrument;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KemError {
    #[error("oqs disabled (stub mode)")] 
    Stub,
    #[error("liboqs initialization failed: {0}")] 
    Init(String),
    #[error("keypair generation failed: {0}")] 
    Keypair(String),
    #[error("encapsulate failed: {0}")] 
    Encaps(String),
    #[error("decapsulate failed: {0}")] 
    Decaps(String),
}

pub struct KyberKeypair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>, // zeroized on drop
}

impl Drop for KyberKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.public.zeroize();
        self.secret.zeroize();
    }
}

pub struct SharedSecret(Vec<u8>);
impl SharedSecret { pub fn as_bytes(&self) -> &[u8] { &self.0 } }
impl Drop for SharedSecret { fn drop(&mut self) { use zeroize::Zeroize; self.0.zeroize(); } }

#[cfg(not(feature = "stub"))]
mod real {
    use super::*;
    use oqs::kem::{Kem, Algorithm};

    pub struct KyberKem { inner: Kem }

    impl KyberKem {
        pub fn new() -> Result<Self, KemError> {
            let inner = Kem::new(Algorithm::Kyber768).map_err(|e| KemError::Init(e.to_string()))?;
            Ok(Self { inner })
        }

        #[instrument(level="trace", skip_all)]
        pub fn keypair(&self) -> Result<KyberKeypair, KemError> {
            let (pk, sk) = self.inner.keypair().map_err(|e| KemError::Keypair(e.to_string()))?;
            Ok(KyberKeypair { public: pk.as_ref().to_vec(), secret: sk.as_ref().to_vec() })
        }

        #[instrument(level="trace", skip(self, public))]
        pub fn encapsulate(&self, public: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> {
            let pk_ref = self.inner.public_key_from_bytes(public).ok_or_else(|| KemError::Encaps("bad public key bytes".into()))?;
            let (ct, ss) = self.inner.encapsulate(&pk_ref).map_err(|e| KemError::Encaps(e.to_string()))?;
            Ok((ct.as_ref().to_vec(), SharedSecret(ss.as_ref().to_vec())))
        }

        #[instrument(level="trace", skip(self, secret, ciphertext))]
        pub fn decapsulate(&self, secret: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, KemError> {
            let sk_ref = self.inner.secret_key_from_bytes(secret).ok_or_else(|| KemError::Decaps("bad secret key bytes".into()))?;
            let ct_ref = self.inner.ciphertext_from_bytes(ciphertext).ok_or_else(|| KemError::Decaps("bad ciphertext bytes".into()))?;
            let ss = self.inner.decapsulate(&sk_ref, &ct_ref).map_err(|e| KemError::Decaps(e.to_string()))?;
            Ok(SharedSecret(ss.as_ref().to_vec()))
        }
    }

    pub use KyberKem as Impl;
}

#[cfg(feature = "stub")]
mod stub {
    use super::*;
    pub struct KyberKem;
    impl KyberKem { pub fn new() -> Result<Self, KemError> { Ok(Self) } }
    impl KyberKem {
        pub fn keypair(&self) -> Result<KyberKeypair, KemError> { Err(KemError::Stub) }
        pub fn encapsulate(&self, _public: &[u8]) -> Result<(Vec<u8>, SharedSecret), KemError> { Err(KemError::Stub) }
        pub fn decapsulate(&self, _secret: &[u8], _ciphertext: &[u8]) -> Result<SharedSecret, KemError> { Err(KemError::Stub) }
    }
    pub use KyberKem as Impl;
}

#[cfg(not(feature = "stub"))]
pub use real::Impl;
#[cfg(feature = "stub")]
pub use stub::Impl;
