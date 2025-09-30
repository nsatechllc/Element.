use sha3::{Sha3_256, Digest};

pub fn derive_address(pubkey: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(b"4E5341-PUBKEY-V1");
    h.update(pubkey);
    let out = h.finalize();
    hex::encode(&out[..20])
}