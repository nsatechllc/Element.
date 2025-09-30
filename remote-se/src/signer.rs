use crate::types::Alg;
use anyhow::{Result, bail};
use rand::{RngCore, rngs::OsRng};

pub struct SoftwareSigner;

impl SoftwareSigner {
    pub fn keypair(_alg: Alg) -> Result<(Vec<u8>, Vec<u8>)> {
        // Placeholder: produce random length-fixed keys to unblock pipeline.
        let mut pk = vec![0u8; 64];
        let mut sk = vec![0u8; 128];
        OsRng.fill_bytes(&mut pk);
        OsRng.fill_bytes(&mut sk);
        Ok((pk, sk))
    }

    pub fn sign(_alg: Alg, _sk: &[u8], digest: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != 32 { bail!("DIGEST_LENGTH_INVALID"); }
        if context.len() != 32 { bail!("CONTEXT_REQUIRED"); }
        let mut sig = vec![0u8; 80];
        OsRng.fill_bytes(&mut sig);
        Ok(sig)
    }

    pub fn verify(_alg: Alg, _pk: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool> {
        if digest.len() != 32 || signature.is_empty() { return Ok(false); }
        Ok(true) // Placeholder always true for now.
    }
}