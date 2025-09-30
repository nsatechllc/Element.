Element.SDK
===========

Rust client SDK for the NSA Technologies Element remote secure element ("Element.") service.

Status: Alpha (HTTP JSON subset implemented: /keys, /sign, /sign/batch, /verify, /resolve, Kyber KEM, /cbid/derive, /session/issue, /health, /ready)

Features (crate features):
- http (default): enable HTTP transport via reqwest (aliased as `request`).
- retry (default): simple exponential backoff for idempotent ops.
- structured-scope (future): sign scope builder & /sign/scope integration.
- quic / grpc (placeholders).
- metrics-json (placeholder parser).

Quick Start:
```rust,ignore
use element_sdk::{ElementClient, Algorithm, SignDigestRequest};
use sha3::{Digest, Sha3_256};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElementClient::builder("https://api.nsatech.io").build()?;
    let key = client.generate_key(Algorithm::Dilithium5).await?;
    // Derive CBID (example tag + local Kyber pair omitted for brevity; usually call kyber_keypair then derive_cbid)
    // For tests you may already have a CBID; here we just fake a 32B context for illustration only.
    let cbid = [0u8;32];
    let digest = Sha3_256::digest(b"example");
    let req = SignDigestRequest { key_id: key.key_id.clone(), digest32: digest.into(), context_binding32: cbid, nonce: 1 };
    let sig = client.sign_digest(req).await?;
    println!("signature bytes: {}", sig.signature.len());
    Ok(())
}
```

Live Integration Test:
Set environment variables before running:
```
export ELEMENT_BASE_URL=https://api.nsatech.io
# optional: ELEMENT_FORCE_KEY_ALG=dilithium5
```
Run:
```
cargo test -p element-sdk -- --ignored --nocapture element_live
```

Security Notes:
- Always supply a 32-byte CBID context when signing (from /cbid/derive or QUIC overlay). Zero bytes are NOT valid in production.
- Track nonces; the first accepted nonce is 1 and increments by 1.

Roadmap Alignment:
P0: Structured scope signing, nonce introspection, audit log streaming (pending server features).

License: Proprietary (internal use only).
# Element.SDK (Rust)

Async Rust client for the NSA Technologies Element remote secure element.

## Features
- Key generation (Dilithium5 / Dilithium3)
- Signing & batch signing with nonce tracking helper
- Signature verification
- Kyber KEM (keypair, encapsulate, decapsulate)
- CBID derivation (HTTP path)
- Session token issuance
- Health / readiness queries

Planned:
- Structured sign scope builder & endpoint
- QUIC overlay derivation
- gRPC streaming sign
- Metrics JSON parsing

## Quick Start
```rust,no_run
use element_sdk::{ElementClient, Algorithm, SignDigestRequest};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha3::{Digest, Sha3_256};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElementClient::builder("https://api.nsatech.io").build()?;

    // 1. Generate key
    let key = client.generate_key(Algorithm::Dilithium5).await?;

    // 2. Derive CBID (simplified placeholder - real flow: Kyber key pair then /cbid/derive)
    // here we assume you already have a peer public key and tag

    // 3. Prepare digest (32 bytes)
    let message = b"example message";
    let digest = Sha3_256::digest(message);
    let digest_b64 = STANDARD.encode(&digest);

    // 4. Context binding (use CBID bytes base64); for demo reuse digest (NOT for production)
    let ctx_b64 = digest_b64.clone();

    // 5. Sign nonce 1
    let sig = client.sign_digest(SignDigestRequest {
        key_id: key.key_id.clone(),
        digest: digest_b64,
        context_binding: Some(ctx_b64),
        nonce: 1,
    }).await?;

    println!("signature alg={} len={} nonce={}", sig.alg, sig.signature.len(), sig.nonce);
    Ok(())
}
```

## Nonce Tracking
The SDK records `next_expected` locally after each successful sign. This is advisory only; the server remains authoritative.

## Error Handling
`Error` enum categorizes protocol-level issues (nonce out of order, key not found, etc.). For 429 rate limits you receive `Error::RateLimited` (retry strategy left to caller).

## License
Proprietary — internal use only.
