/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
use crate::types::Alg;
use anyhow::{Result, bail};
use rand::{RngCore, rngs::OsRng};

/// Abstraction for signing backend.
pub trait SignerBackend: Send + Sync + 'static {
	fn keypair(alg: Alg) -> Result<(Vec<u8>, Vec<u8>)>;
	fn sign(alg: Alg, sk: &[u8], digest: &[u8], context: &[u8]) -> Result<Vec<u8>>;
	fn verify(alg: Alg, pk: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Placeholder software signer (non-cryptographic) used when pqc feature disabled.
pub struct SoftwareSigner;
impl SignerBackend for SoftwareSigner {
	fn keypair(_alg: Alg) -> Result<(Vec<u8>, Vec<u8>)> {
		let mut pk = vec![0u8; 64];
		let mut sk = vec![0u8; 128];
		OsRng.fill_bytes(&mut pk);
		OsRng.fill_bytes(&mut sk);
		Ok((pk, sk))
	}
	fn sign(_alg: Alg, _sk: &[u8], digest: &[u8], context: &[u8]) -> Result<Vec<u8>> {
		if digest.len() != 32 { bail!("DIGEST_LENGTH_INVALID"); }
		if context.len() != 32 { bail!("CONTEXT_REQUIRED"); }
		let mut sig = vec![0u8; 80];
		OsRng.fill_bytes(&mut sig);
		Ok(sig)
	}
	fn verify(_alg: Alg, _pk: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool> {
		if digest.len() != 32 || signature.is_empty() { return Ok(false); }
		Ok(true)
	}
}

#[cfg(feature = "pqc")]
pub struct OqsSigner;

#[cfg(feature = "pqc")]
impl SignerBackend for OqsSigner {
	fn keypair(alg: Alg) -> Result<(Vec<u8>, Vec<u8>)> {
		use oqs::sig::{Sig, Algorithm};
		let algorithm = match alg { Alg::Dilithium5 => Algorithm::Dilithium5, Alg::Dilithium3 => Algorithm::Dilithium3 };
		let sig = Sig::new(algorithm).map_err(|e| anyhow::anyhow!("oqs_init: {e}"))?;
		let (pk, sk) = sig.keypair().map_err(|e| anyhow::anyhow!("oqs_keypair: {e}"))?;
		Ok((pk.as_ref().to_vec(), sk.as_ref().to_vec()))
	}
	fn sign(alg: Alg, sk: &[u8], digest: &[u8], context: &[u8]) -> Result<Vec<u8>> {
		use oqs::sig::{Sig, Algorithm};
		if digest.len() != 32 { bail!("DIGEST_LENGTH_INVALID"); }
		if context.len() != 32 { bail!("CONTEXT_REQUIRED"); }
		let algorithm = match alg { Alg::Dilithium5 => Algorithm::Dilithium5, Alg::Dilithium3 => Algorithm::Dilithium3 };
		let sig = Sig::new(algorithm).map_err(|e| anyhow::anyhow!("oqs_init: {e}"))?;
		let sk_ref = sig.secret_key_from_bytes(sk).ok_or_else(|| anyhow::anyhow!("SECRET_KEY_LEN"))?;
		// Bind context by signing digest || context
		let mut m = Vec::with_capacity(64);
		m.extend_from_slice(digest);
		m.extend_from_slice(context);
		let signature = sig.sign(&m, sk_ref).map_err(|e| anyhow::anyhow!("oqs_sign: {e}"))?;
		Ok(signature.as_ref().to_vec())
	}
	fn verify(alg: Alg, pk: &[u8], digest_and_ctx: &[u8], signature: &[u8]) -> Result<bool> {
		use oqs::sig::{Sig, Algorithm};
		if digest_and_ctx.len() != 64 { return Ok(false); }
		let algorithm = match alg { Alg::Dilithium5 => Algorithm::Dilithium5, Alg::Dilithium3 => Algorithm::Dilithium3 };
		let sig = Sig::new(algorithm).map_err(|e| anyhow::anyhow!("oqs_init: {e}"))?;
		let pk_ref = sig.public_key_from_bytes(pk).ok_or_else(|| anyhow::anyhow!("PUBLIC_KEY_LEN"))?;
		let sig_ref = sig.signature_from_bytes(signature).ok_or_else(|| anyhow::anyhow!("SIGNATURE_LEN"))?;
		Ok(sig.verify(digest_and_ctx, sig_ref, pk_ref).is_ok())
	}
}

/// Type alias selecting backend
#[cfg(feature = "pqc")]
pub type ActiveSigner = OqsSigner;
/// Fallback when pqc feature disabled
#[cfg(not(feature = "pqc"))]
pub type ActiveSigner = SoftwareSigner;