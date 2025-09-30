/*
 Automated · Intelligent · Natural
 - Element. by NSA TECHNOLOGIES

 Author: Daniel J. Sopher
 © Copyright 2018, 2025. All Rights Reserved.
*/
use sha2::{Sha256, Digest};
pub fn derive_address(pubkey: &[u8]) -> String {
	// Per blockchain spec: address = lower-case hex of SHA256(pubkey)
	let mut hasher = Sha256::new();
	hasher.update(pubkey);
	let out = hasher.finalize();
	hex::encode(out)
}