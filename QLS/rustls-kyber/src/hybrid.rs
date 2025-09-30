//! Hybrid secret derivation logic.
//! Two strategies selectable via features:
//!  - default: Hash-concatenate then HKDF-Extract once.
//!  - layered-hkdf: sequential HKDF-Extracts.

use sha3::{Digest, Sha3_256};
// use zeroize::Zeroize; // Commenting out the unused import

/// Produce a 32-byte hybrid secret from classical and PQ shared secrets.
/// Both inputs are zeroized by caller after use.
pub fn derive_hybrid_secret(ss_classical: &[u8], ss_pq: &[u8]) -> [u8;32] {
    #[cfg(feature="layered-hkdf")] {
        layered(ss_classical, ss_pq)
    }
    #[cfg(not(feature="layered-hkdf"))] {
        hash_concat(ss_classical, ss_pq)
    }
}

fn hash_concat(a: &[u8], b: &[u8]) -> [u8;32] {
    let mut h = Sha3_256::new();
    h.update([0x01]);
    h.update(a);
    h.update(b);
    let out = h.finalize();
    let mut arr = [0u8;32]; arr.copy_from_slice(&out[..32]); arr
}

#[allow(dead_code)]
fn layered(a: &[u8], b: &[u8]) -> [u8;32] {
    let mut h1 = Sha3_256::new(); h1.update([0xA1]); h1.update(a); let prk = h1.finalize();
    let mut h2 = Sha3_256::new(); h2.update([0xB2]); h2.update(&prk); h2.update(b); let out = h2.finalize();
    let mut arr = [0u8;32]; arr.copy_from_slice(&out[..32]); arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_inputs_produce_distinct_secrets() {
        let s1 = derive_hybrid_secret(&[1;32], &[2;32]);
        let s2 = derive_hybrid_secret(&[1;32], &[3;32]);
        assert_ne!(s1, s2);
    }
}
