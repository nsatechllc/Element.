// Utility helpers

#[allow(dead_code)]
pub fn validate_digest_32(bytes: &[u8]) -> bool { bytes.len() == 32 }

#[allow(dead_code)]
pub fn cbid_hex_to_bytes(hex64: &str) -> Result<[u8;32], String> {
	if hex64.len() != 64 { return Err("cbid hex length != 64".into()); }
	let mut out = [0u8;32];
	for i in 0..32 { out[i] = u8::from_str_radix(&hex64[i*2..i*2+2], 16).map_err(|e| e.to_string())?; }
	Ok(out)
}
