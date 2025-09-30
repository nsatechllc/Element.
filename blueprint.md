# GCP-SE: Remote Secure Element API for 4E5341

**Purpose:**
A containerized Remote Secure Element (SE) service providing cryptographic key management, signing, verification, and address resolution for 4E5341. Designed for GCP Cloud Run (or similar), with a migration path to hardware HSM or cloud KMS in production.

NOTE: A comprehensive token & role authorization model (Client Token, Machine Capability Token (MCT), Operator Presence Token (OPT), Compliance Token (CTA), Custody Confirmation Token (CCT)) plus verification responsibility matrix now lives in `REMOTE-SE.md`. This file keeps the core API surface; see the companion document for extended security semantics.

---

## 1. Overview
- **Endpoint:** `https://api.nsatech.io` (stable base URL).
- **Deployment:** Containerized Rust service; backend pluggable (software PQC now, hardware HSM later).
- **Security Notice:** Current environment uses in-memory software keys. Do not use for high-value production assets until hardware isolation & attestation are enabled.

---


## 2. API Endpoints (MVP Scope)

### 2.1 Health & Capabilities
- `GET /health` — Liveness/readiness probe.
- `GET /capabilities` — Supported algorithms, key types, limits.

### 2.2 Key Management
- `POST /keys` — Generate a new keypair.
  - Request: `{ "alg": "dilithium5" | "dilithium3", "role": "client" | "machine" | "operator" }`
  - Response: `{ "key_id": "...", "pubkey": "base64", "alg": "...", "created_at": "..." }`

- `GET /keys/{key_id}` — Fetch public key and metadata.
  - Response: `{ "key_id": "...", "pubkey": "base64", "alg": "...", "created_at": "...", "usage_count": N }`

### 2.3 Signing
- `POST /sign` — Sign a digest with a key.
  - Request:
    ```json
    {
      "key_id": "...",
      "digest": "base64",                  // 32-byte canonical scope digest
      "context_binding": "base64",          // 32-byte CBID
      "nonce": N
    }
    ```
  - Response:
    ```json
    { "signature": "base64", "alg": "...", "counter": N }
    ```

### 2.4 Verification
### 2.5 Batch Signing (NEW)
_Interface contract only: the batch signing operation is performed by an EXTERNAL Remote Secure Element service. This repository does not build or run that service here._
- `POST /batch/sign` — Sign multiple digests (same or mixed keys) atomically per item.
  - Request:
    ```json
    {
      "requests": [
        { "key_id": "k1", "digest": "base6432", "context_binding": "base6432", "nonce": 11 },
        { "key_id": "k2", "digest": "base6432", "context_binding": "base6432", "nonce": 7 }
      ]
    }
    ```
  - Response (per-item result array):
    ```json
    {
      "results": [
        { "key_id": "k1", "ok": true,  "signature": "...", "alg": "dilithium5", "counter": 11, "nonce": 11 },
        { "key_id": "k2", "ok": false, "error_code": "NONCE_OUT_OF_ORDER", "message": "nonce mismatch", "nonce": 7 }
      ]
    }
    ```
  - Notes:
    - Partial success supported; failing items do not roll back successful ones.
    - Nonces enforced per key; caller must supply correct expected nonce.
    - Intended for high-throughput consensus & compliance batching.

### 2.6 gRPC Service Definition (MVP)
_gRPC proto is provided solely as the external contract for the Remote-SE deployed elsewhere; no gRPC server is compiled in this codebase presently._
```protobuf
syntax = "proto3";
package se.v1;

service RemoteSE {
  rpc GenerateKey(GenerateKeyRequest) returns (KeyInfo);
  rpc GetKey(GetKeyRequest) returns (KeyInfo);
  rpc Sign(SignRequest) returns (SignResponse);
  rpc BatchSign(BatchSignRequest) returns (BatchSignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Resolve(ResolveRequest) returns (ResolveResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
  // Future: streaming
  rpc StreamSign(stream SignRequest) returns (stream SignResponse);
}

message GenerateKeyRequest { string alg = 1; string role = 2; }
message GetKeyRequest { string key_id = 1; }
message KeyInfo { string key_id = 1; bytes pubkey = 2; string alg = 3; string created_at = 4; uint64 usage_count = 5; }
message SignRequest { string key_id = 1; bytes digest = 2; bytes context_binding = 3; uint64 nonce = 4; }
message SignResponse { bytes signature = 1; string alg = 2; uint64 counter = 3; uint64 nonce = 4; }
message BatchSignRequest { repeated SignRequest requests = 1; }
message BatchSignResult { string key_id = 1; bool ok = 2; bytes signature = 3; string alg = 4; uint64 counter = 5; string error_code = 6; string message = 7; uint64 nonce = 8; }
message BatchSignResponse { repeated BatchSignResult results = 1; }
message VerifyRequest { string key_id = 1; bytes digest = 2; bytes signature = 3; }
message VerifyResponse { bool valid = 1; string alg = 2; }
message ResolveRequest { bytes pubkey = 1; string alg = 2; }
message ResolveResponse { string address = 1; string alg = 2; }
message HealthRequest {}
message HealthResponse { string status = 1; }
```

### 2.7 oqs-rs Usage
- The EXTERNAL Remote-SE implementation SHOULD use `oqs` crate for Dilithium key generation & signing (consistent with Section 10 guidance). This repository does not link `oqs` directly for the service.
- Kyber integration currently limited to transport handshake (TLS exporter) — session secret not exposed to app layer.
- Pre-hash rule: clients supply 32-byte digest (SHA3-256 of canonical scope). Server re-mixes digest+context only internally if needed for signature seeds; clients verify using the same canonical digest.

- `POST /verify` — Verify a signature.
  - Request: `{ "key_id": "...", "digest": "base64", "signature": "base64" }`
  - Response: `{ "valid": true | false, "alg": "..." }`

### 2.8 Address Resolution
- `POST /resolve` — Resolve a public key to a 4E5341 address.
  - Request: `{ "pubkey": "base64", "alg": "..." }`
  - Response: `{ "address": "hex", "alg": "..." }`

### 2.9 Attestation (Future)
- `POST /attest` — Return a signed attestation blob (for TEE/HSM migration).

---

> Note: Biometric, LBM, and advanced token endpoints will be added after the cryptographic core is validated and deployed at scale.

## 3. Data Model
- **key_id:** Unique string (UUID or random).
- **pubkey:** Base64-encoded public key bytes.
- **alg:** "dilithium5", "dilithium3", etc.
- **digest:** 32-byte SHA3-256 or protocol digest (base64).
- **signature:** Base64-encoded signature bytes.
- **context_binding:** 32-byte channel binding ID (base64, required for sign).
- **nonce:** Monotonic per key/caller (prevents replay).
- **address:** 4E5341 address (hex, protocol-specific derivation).

---

## 4. Security & Deployment Notes
- **Devnet:**
  - Deploy on GCP Cloud Run (512MB RAM, 1 vCPU, min-instances=0).
  - Store keys in RAM; optionally bootstrap from GCP Secret Manager.
  - Restrict access (IP allowlist, mTLS, or GCP IAM).
  - Add synthetic latency (env var) to simulate HSM delays if needed.
- **Production:**
  - Swap backend for real HSM/KMS (PKCS#11, Cloud KMS, etc.).
  - Enforce hardware-backed attestation and key residency.
  - Keep API contract unchanged for seamless migration.
- **Audit:**
  - Log all operations (keygen, sign, verify) with timestamp, key_id, caller, and result.
  - Expose Prometheus metrics at `/metrics` (optional).

---

## 5. Example Usage (4E5341 Integration)

### Key Generation
```json
POST https://api.nsatech.io/keys
{ "alg": "dilithium5", "role": "client" }
```
Response:
```json
{ "key_id": "abc123", "pubkey": "...", "alg": "dilithium5", "created_at": "2025-09-29T12:00:00Z" }
```

### Signing
```json
POST https://api.nsatech.io/sign
{ "key_id": "abc123", "digest": "...", "context_binding": "...", "nonce": 42 }
```
Response:
```json
{ "signature": "...", "alg": "dilithium5", "counter": 43 }
```

### Verification
```json
POST https://api.nsatech.io/verify
{ "key_id": "abc123", "digest": "...", "signature": "..." }
```
Response:
```json
{ "valid": true, "alg": "dilithium5" }
```

### Address Resolution
```json
POST https://api.nsatech.io/resolve
{ "pubkey": "...", "alg": "dilithium5" }
```
Response:
```json
{ "address": "4e5341deadbeef...", "alg": "dilithium5" }
```

---

## 6. Migration to Real HSM
- Keep API contract stable.
- Implement backend trait for HSM/KMS.
- Add attestation endpoint for hardware proof.
- Update deployment to use hardware-backed keys.

---

## 7. Implementation Architecture (Detailed)
### 7.1 High-Level Components
| Component | Responsibility | Notes |
|-----------|----------------|-------|
| HTTP/gRPC Frontend | Parses requests, validates shape, auth | Prefer gRPC (tonic) for internal; HTTP JSON adapter optional |
| Key Manager | In-memory registry of key metadata & counters | Backed by DashMap / RwLock; pluggable persistence later |
| Signer Backend | Produces Dilithium signatures via `crypto-pqc` | Interface allows swap to hardware HSM/KMS |
| Nonce / Replay Guard | Ensures monotonic nonce per (key_id, caller) | LRU or hash map with periodic cleanup |
| Address Resolver | Deterministic derivation from public key | Canonical hash + truncation rules (see 7.5) |
| Metrics & Audit | Exposes Prometheus + structured logs | Include correlation_id, latency buckets |
| Policy Layer (Optional) | Enforce signing context constraints | Eg: role-based allowed digest prefix or domain tag |

### 7.2 Request Lifecycle (Sign)
1. Auth (mTLS / bearer) validated.
2. Deserialize & syntactic validation (fields present, base64 decode).
3. Lookup key (O(1)) -> ensure status=active.
4. Verify `digest.len == 32` (or allowed lengths list) & `context_binding.len == 32`.
5. Nonce check: expected_nonce = last_nonce+1 OR >= last_nonce+1 (choose strict increment for deterministic ordering). Reject otherwise.
6. Construct internal message `SignJob { key_id, digest, context_binding, nonce, alg }`.
7. Signer backend produces signature `sig`.
8. Increment usage_count, update last_nonce, signing_counter.
9. Emit audit log & metrics.
10. Return response.

### 7.3 Internal Crate Layout (Proposed `remote-se`)
```
remote-se/
  Cargo.toml
  src/
    main.rs             # bootstrap (config, server start)
    api.rs              # request/response DTOs + route handlers
    service.rs          # KeyManager / SignerBackend traits
    signer_sw.rs        # SoftwareDilithium backend (crypto-pqc)
    store.rs            # In-memory key store implementation
    nonce.rs            # Nonce + replay guard
    address.rs          # Address derivation logic
    metrics.rs          # Prometheus counters/histograms
    auth.rs             # (optional) header/mTLS auth
    config.rs           # Load env vars -> Config struct
    errors.rs           # Unified error => API mapping
```

### 7.4 Traits
```rust
pub trait SignerBackend: Send + Sync {
    fn generate_key(&self, alg: Alg) -> Result<KeyRecord>;
    fn sign(&self, key: &KeyRecord, digest: &[u8], context: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key: &KeyRecord, digest: &[u8], sig: &[u8]) -> Result<bool>;
}

pub trait KeyStore: Send + Sync {
    fn create(&self, alg: Alg, role: Role) -> Result<KeyRecord>;
    fn get(&self, key_id: &str) -> Option<KeyRecord>;
    fn update_usage(&self, key_id: &str, nonce: u64);
}
```

### 7.5 Address Derivation (Canonical)
Deterministic mapping from PQC public key to 4E5341 address:
```
1. pubkey_bytes = raw Dilithium public key (without algorithm tag)
2. address_hash = SHA3-256( b"4E5341-PUBKEY-V1" || pubkey_bytes )
3. address = hex( address_hash[0..20] )   # 160-bit shorten (similar to Ethereum style) OR protocol-defined length.
```
Rationale: Domain separation prevents collision with other hash usages; truncation yields a compact fixed-length identifier.

### 7.6 Error Codes (JSON field `error_code`)
| Code | Meaning | HTTP |
|------|---------|------|
| INVALID_REQUEST | Malformed JSON / base64 decode error | 400 |
| UNSUPPORTED_ALG | Algorithm not supported | 400 |
| KEY_NOT_FOUND | key_id unknown | 404 |
| KEY_RETIRED | Key no longer active | 410 |
| NONCE_OUT_OF_ORDER | Nonce replay or gap violation | 409 |
| DIGEST_LENGTH_INVALID | Digest size unsupported | 400 |
| CONTEXT_REQUIRED | Missing context_binding | 400 |
| SIGNATURE_INVALID | Provided signature fails verify | 422 |
| RATE_LIMIT | Rate limit exceeded | 429 |
| INTERNAL | Unexpected server failure | 500 |

Error JSON structure:
```json
{ "error_code": "NONCE_OUT_OF_ORDER", "message": "expected nonce 44 got 42" }
```

### 7.7 Metrics (Prometheus)
| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| se_requests_total | counter | method, status | All API requests |
| se_sign_latency_ms | histogram | alg | End-to-end sign latency |
| se_sign_active | gauge |  | Current in-flight sign ops |
| se_key_count | gauge | alg | Keys loaded |
| se_replay_reject_total | counter |  | Nonce/ciphertext rejections |
| se_verify_fail_total | counter | alg | Failed verifications |
| se_entropy_check_fail_total | counter |  | RNG anomalies (future) |
| se_keygen_total | counter | alg, role | Keys generated |
| se_rate_limit_total | counter | method | Rate limited requests |

### 7.8 Environment Variables
| Variable | Purpose | Default |
|----------|---------|---------|
| SE_LISTEN_ADDR | Bind address | 0.0.0.0:8080 |
| SE_REQUIRE_CONTEXT | Enforce context_binding presence | true |
| SE_STRICT_NONCE | Enforce strictly incrementing nonce | true |
| SE_MAX_KEYS | Soft cap on key count | 10000 |
| SE_LATENCY_JITTER_MS | Random artificial delay (0..J) | 0 |
| SE_RATE_LIMIT_QPS | Global soft QPS (0=unlimited) | 0 |
| SE_LOG_LEVEL | tracing level | info |
| SE_ENABLE_METRICS | Expose /metrics | true |
| SE_DISABLE_KEY_EXPORT | Hide public key fetch (hardening) | false |
| SE_ALLOWED_ALGS | CSV of allowed alg IDs | dilithium5,dilithium3 |

### 7.9 Concurrency & Performance
Expected operations are CPU-light for mock/software PQC; use:
- `tokio` runtime multi-threaded; CPU-bound hot spots (future real Dilithium) can be offloaded to a dedicated rayon thread pool if needed.
- Avoid long-lived locks: KeyStore retrieval O(1) (DashMap), per-key update uses entry API updating counters atomically.
- Nonce tracking: store last_nonce as AtomicU64 inside KeyRecord; compare-and-swap pattern for strict sequencing.

### 7.10 KeyRecord (In-Memory)
```rust
pub struct KeyRecord {
  pub key_id: String,
  pub alg: Alg,
  pub role: Role,
  pub public_key: Vec<u8>,
  pub secret_ref: SecretHandle, // opaque; inside backend
  pub created_at: i64,
  pub usage_count: AtomicU64,
  pub last_nonce: AtomicU64,
  pub status: AtomicU8, // 0 active, 1 retiring, 2 retired
}
```

### 7.11 Signing Flow Pseudocode
```rust
fn sign(req: SignRequest) -> ApiResult<SignResponse> {
  let key = store.get(&req.key_id).ok_or(err(KEY_NOT_FOUND))?;
  ensure_alg_allowed(key.alg)?;
  if config.require_context && req.context_binding.len() != 32 { return Err(err(CONTEXT_REQUIRED)); }
  if req.digest.len() != 32 { return Err(err(DIGEST_LENGTH_INVALID)); }
  let expected = key.last_nonce.load(Ordering::Relaxed)+1;
  if config.strict_nonce && req.nonce != expected { return Err(err(NONCE_OUT_OF_ORDER).with_msg(format!("expected {expected} got {}", req.nonce))); }
  if key.last_nonce.compare_exchange(expected-1, req.nonce, Ordering::SeqCst, Ordering::SeqCst).is_err() { return Err(err(NONCE_OUT_OF_ORDER)); }
  let sig = signer.sign(&key, &req.digest, &req.context_binding)?;
  let ctr = key.usage_count.fetch_add(1, Ordering::SeqCst)+1;
  metrics.record_sign_latency(start.elapsed());
  Ok(SignResponse { signature: base64(sig), alg: key.alg, counter: ctr })
}
```

### 7.12 Verification Flow Pseudocode
```rust
fn verify(req: VerifyRequest) -> ApiResult<VerifyResponse> {
  let key = store.get(&req.key_id).ok_or(err(KEY_NOT_FOUND))?;
  if req.digest.len() != 32 { return Ok(VerifyResponse { valid: false, alg: key.alg }); }
  let valid = signer.verify(&key, &req.digest, &req.signature_bytes)?;
  if !valid { metrics.inc_verify_fail(key.alg); }
  Ok(VerifyResponse { valid, alg: key.alg })
}
```

### 7.13 Integration Points with 4E5341
| Layer | Interaction |
|-------|-------------|
| Transport (PQC handshake) | Supplies channel_binding (CBID) to `context_binding` for sign requests |
| Envelope (multi-sig) | Calls `/sign` for each role’s key; verifies via `/verify` or local verifier with fetched pubkeys |
| Consensus | Uses `/resolve` to map validator pubkeys to addresses for staking / membership tables |
| Governance | Key rotation -> `/keys/{id}/rotate` (future) |

### 7.14 Testing Strategy
| Test | Description | Tool |
|------|-------------|------|
| Unit: keygen/sign/verify | Deterministic usage counters, nonce sequencing | cargo test |
| Property: address uniqueness | 100k random keys -> no collisions | quickcheck/proptest |
| Load: sign QPS | Sustain configured QPS with latency < target | k6 / vegeta |
| Replay rejection | Reuse nonce -> 409 NONCE_OUT_OF_ORDER | integration test |
| Context enforcement | Omit context when required -> 400 | integration test |
| Migration contract | Record OpenAPI spec checksum | CI step |

### 7.15 Migration Plan Hooks
Implement `SignerBackend` for hardware:
```rust
pub struct HsmBackend { /* vendor client */ }
impl SignerBackend for HsmBackend { /* map calls to PKCS#11 */ }
```
Add feature flag:
```
[features]
software-backend = []
hsm-backend = ["pkcs11"]
```

### 7.16 Observability (Log Fields)
`ts level=info event=sign key_id=abc123 alg=dilithium5 nonce=42 latency_ms=1.2 cbid=hex8 result=ok`

### 7.17 Hardening Roadmap (Post-Devnet)
- Encrypted key wrapping with TPM-sealed master key.
- Periodic entropy health checks on RNG output.
- Attestation token (TEE/HSM) embedding algorithm ID + key manifest hash.
- Rate limiting by role & IP.
- Differential privacy on aggregated metrics (optional).

## 8. References
- [GCP Cloud Run Docs](https://cloud.google.com/run/docs)
- [Dilithium (NIST PQC)](https://pq-crystals.org/dilithium/)
- [PKCS#11 Standard](https://www.oasis-open.org/standards#pkcs11v3.0)

---

**Status:** Draft v1.2 — 2025-09-29 (Added Debian 12 PQC-HSM deployment & QUIC Kyber-TLS instructions)

## 9. Transport Integration (QUIC + Kyber + Dilithium)
This service MUST only be accessed over PQC QUIC.

### 9.1 ALPN & Protocol
- ALPN: `se.v1` (HTTP/3 + JSON or gRPC).
- Reject non-QUIC or non-PQC TLS handshakes.

### 9.2 Handshake & Channel Binding
`raw_export = tls_exporter(label="EXPORTER-4E5341", context="", length=64)`  
`CBID = SHA3-256( "4E5341-CBID-V1" || raw_export )[:32]`  
### 9.3 Required Ciphersuite (Conceptual)
`TLS_PQ_DILITHIUM5_KYBER1024_SHA3_256_AES256GCM`  
Fallback: `...DILITHIUM3_KYBER768...` (logs downgrade event, allowed only during authorized fallback window).

### 9.4 Connection Policy
- Rotate after 10k sign ops or 15m.
- Abort and rebuild if exporter/CBID changes mid-request (never reuse partial scope).
- Limit concurrent signing streams (config) to avoid starvation.

### 9.5 Security Checks
| Check | Action |
|-------|--------|
| Missing context_binding | 400 CONTEXT_REQUIRED |
| Wrong length (≠32 bytes decoded) | 400 INVALID_REQUEST |
| Mixed CBIDs within one composite operation | 409 NONCE_OUT_OF_ORDER (treat as tamper) |
| Classical TLS suite negotiated | 403 DOWNGRADE_FORBIDDEN |

### 9.6 Metrics Additions
- `se_quic_handshake_ms` (histogram)
- `se_quic_active_conns`
- `se_quic_rehandshakes_total`
- `se_quic_downgrade_attempt_total`

### 9.7 Logging
`ts level=info event=quic_handshake peer=clientX algs="D5+K1024" cbid=abcd1234 latency_ms=7`  
Downgrade or suite mismatch: `level=warn event=quic_downgrade proposed_suite=... action=reject`.

### 9.8 Development Steps (Service Side)
1. Integrate quinn/quiche + OQS provider.  
2. Implement exporter CBID derivation helper.  
3. Enforce ALPN & suite filtering early in handshake callback.  
4. Expose CBID to request context (middleware).  
5. Validate presence & length before hitting handlers.  
6. Emit metrics + structured logs.  

### 9.9 Client SDK Expectations
API sample (Rust pseudo):
```
let chan = SeChannel::connect(endpoint_config).await?; // performs PQC QUIC handshake
let cbid = chan.cbid();
let lbm = chan.issue_lbm(intent_id, live_sample).await?; // POST /biometric/match
let sig_client = chan.sign_client(scope_digest, tokens.clone()).await?;
```

### 9.10 Open Questions
- gRPC streaming for batch sign? (If yes: add `/stream/sign` with per-frame CBID integrity).  
- Should CBID incorporate algo tuple? (e.g., domain tag includes `D5-K1024`).

See `REMOTE-SE.md` for token interplay details.

---

*This document will be updated as the implementation proceeds. For questions or changes, contact the 4E5341 engineering team.*

---

## 10. Debian 12 Implementation Guide (PQC-HSM Node)
This section provides step-by-step instructions for engineers to deploy the PQC-HSM (Remote SE) node on **Debian 12 (Bookworm)** using **QUIC with Kyber KEM + Dilithium signatures**. The initial deployment uses software implementations (liboqs) and provides the network API required for `generate`, `sign`, and `verify`.

### 10.1 High-Level Build Flow
1. Install system prerequisites.
2. Build & install liboqs (Kyber + Dilithium).
3. Build OpenSSL 3 with the OQS provider (optional path A) OR link Rust oqs-rs (path B).
4. Build the `remote-se` service (Rust) with PQC feature enabled.
5. Generate PQC certificate (Dilithium) + configure QUIC endpoint.
6. Launch service (Cloud Run or local) using QUIC-only listener.
7. Integrate blockchain node / clients via hsm-client or direct QUIC JSON/gRPC.

### 10.2 System Packages
Run on a fresh Debian 12 host (container base or VM):
```
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git curl wget \\
  libssl-dev clang llvm libclang-dev python3 python3-pip python3-venv zlib1g-dev \\
  libprotobuf-dev protobuf-compiler
```

### 10.3 Install liboqs (Software PQC Primitives)
```
git clone https://github.com/open-quantum-safe/liboqs.git --branch main --depth 1
cd liboqs
mkdir build && cd build
cmake -GNinja -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DOQS_ENABLE_KEM_KYBER=ON -DOQS_ENABLE_SIG_DILITHIUM=ON ..
ninja
sudo ninja install
sudo ldconfig
```

### 10.4 (Path A) OpenSSL 3 + OQS Provider (Optional for TLS Layer)
If using OpenSSL OQS provider for Kyber/Dilithium ciphersuites:
```
git clone https://github.com/open-quantum-safe/oqs-provider.git --depth 1
cd oqs-provider
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
sudo ninja install
sudo ldconfig
```
At runtime export (example):
```
export OQS_PROVIDER="/usr/local/lib/oqsprovider.so"
```

### 10.5 (Path B) Rust oqs-rs Integration
- Add to `Cargo.toml` of `remote-se` (example, to be refined during integration):
```
oqs = { version = "0.9", features=["kyber","dilithium"] }
```
- Use oqs to: generate Dilithium keys, sign digests; generate ephemeral Kyber KEM material for session keys (if implementing custom QUIC handshake augmentations).

### 10.6 QUIC Stack Choices
| Option | Library | PQC Strategy | Notes |
|--------|---------|-------------|-------|
| A | quinn + oqs-rs | Custom channel binding using exporter; classical TLS for transport then PQC overlay (interim) | Fast to stand-up; hybrid phase only |
| B | quiche (ngtcp2) + OQS OpenSSL | Native PQC handshake in TLS layer (Kyber KEM + Dilithium auth) | Closer to final design |
| C | oqs-tls fork + quiche | Full PQC in TLS stack (pure) | More engineering effort |

MVP Recommendation: Start with Option B if OQS provider integration is stable; fallback to Option A with a clear migration path.

### 10.7 Channel Binding (CBID) Implementation
1. After TLS handshake, call exporter with label `EXPORTER-4E5341` length 64.
2. Compute: `CBID = SHA3-256( "4E5341-CBID-V1" || exporter_secret )[:32]`.
3. Expose CBID in request context; require clients to supply base64(CBID) in `/sign` requests.
4. Reject if CBID mismatch or absent.

### 10.8 Service Configuration (Environment)
| Variable | Description | Example |
|----------|-------------|---------|
| SE_LISTEN_ADDR | QUIC listen address | 0.0.0.0:8443 |
| SE_ALLOWED_ALGS | Allowed Dilithium levels | dilithium5,dilithium3 |
| SE_STRICT_NONCE | Enforce monotonic nonce | true |
| SE_REQUIRE_CONTEXT | Require CBID context_binding | true |
| SE_LOG_LEVEL | tracing level | info |
| SE_METRICS_ADDR | Optional HTTP metrics listener | 0.0.0.0:9090 |
| OQS_PROVIDER | Path to oqs provider (if Option B) | /usr/local/lib/oqsprovider.so |

### 10.9 Key Generation (Pseudocode with oqs-rs)
```rust
use oqs::sig::Sig;
let alg = oqs::sig::Algorithm::Dilithium5; // or Dilithium3
let sig = Sig::new(alg)?;
let (pk, sk) = sig.keypair()?; // pk, sk: Vec<u8>
// Store sk in memory (DashMap) with key_id
```

### 10.10 Signing (Pseudocode)
```rust
let sig = Sig::new(alg)?; // same alg as key
let signature = sig.sign(digest_bytes, &secret_key_bytes)?;
```
Digest requirement: 32 bytes (already hashed externally). If larger raw message, specify domain-tagged SHA3-256 pre-hash before calling sign.

### 10.11 Verification (Pseudocode)
```rust
let sig = Sig::new(alg)?;
let valid = sig.verify(digest_bytes, &signature_bytes, &public_key_bytes).is_ok();
```

### 10.12 Address Derivation Implementation
```rust
use sha3::{Sha3_256, Digest};
let mut h = Sha3_256::new();
h.update(b"4E5341-PUBKEY-V1");
h.update(&public_key_bytes);
let hash = h.finalize();
let address_hex = hex::encode(&hash[..20]);
```

### 10.13 QUIC Server Skeleton (quiche example outline)
```
loop {
  accept_conn();
  while stream_event { match op { SIGN => handle_sign(); ... } }
}
```
Use one stream per logical request; small JSON messages (≤2KB typical) minimize head-of-line risk.

### 10.14 Client Interaction Pattern
1. Open QUIC connection (ALPN `se.v1`).
2. Export CBID.
3. For each signing request:
   - Pre-hash canonical scope to 32-byte digest.
   - Send JSON over a fresh or reused bidirectional stream: `{ op: "sign", key_id, digest: base64, context_binding: base64(CBID), nonce }`.
   - Receive `{ ok:true, data:{ signature, alg, counter } }`.
4. For verify: similar with `op: "verify"`.
5. For keygen: `op: "generate_key"` (alg, role).

### 10.15 Error Mapping Reference (QUIC Frame Protocol)
| Code | Condition | Action |
|------|-----------|--------|
| INVALID_REQUEST | Malformed JSON / base64 | Close stream |
| KEY_NOT_FOUND | Unknown key_id | 404 semantic in error body |
| NONCE_OUT_OF_ORDER | Replay / gap | Caller resync nonce |
| DIGEST_LENGTH_INVALID | Digest != 32 | Fix client hashing |
| CONTEXT_REQUIRED | CBID missing/len mismatch | Recompute CBID |
| UNSUPPORTED_ALG | Alg not allowed | Client fallback or abort |
| INTERNAL | Unexpected | Retry with backoff |

### 10.16 Deployment on Cloud Run (Example)
1. Build container:
```
docker build -t gcr.io/<project>/remote-se:0.1 .
docker push gcr.io/<project>/remote-se:0.1
```
2. Deploy:
```
gcloud run deploy remote-se \
  --image gcr.io/<project>/remote-se:0.1 \
  --platform managed \
  --region <region> \
  --allow-unauthenticated=false \
  --cpu=1 --memory=512Mi \
  --set-env-vars SE_ALLOWED_ALGS=dilithium5,dilithium3,SE_STRICT_NONCE=true
```
3. (If HTTP/3 QUIC not yet GA for Cloud Run) use internal VPC + sidecar QUIC gateway or run on GKE autopilot node pools with Load Balancer enabling UDP 443.

### 10.17 Observability Setup
- Metrics exporter (HTTP) scraped by Prometheus (if allowed by environment).  
- Tracing: emit JSON logs to stdout; Cloud Logging sink filters on `event=sign`.
- Key metrics alerts: `(se_sign_latency_ms_p95 > threshold)` and `(se_downgrade_attempt_total > 0)`.

### 10.18 Load Testing Checklist
| Test | Target |
|------|--------|
| Single-core sign throughput | Baseline ops/sec recorded |
| 32-byte digest latency p95 | < X ms (define) |
| Nonce replay attempt | Rejected 100% |
| Parallel connections (N=1000) | No handshake failures |
| Downgrade attempt (classical) | Connection rejected |

### 10.19 Migration Path to Hardware HSM
- Replace SoftwareSigner with PKCS#11-backed SignerBackend.
- Offload keygen/sign to hardware slots; keep API stable.
- Introduce `/attest` returning hardware quote.

### 10.20 Outstanding Decisions (Mark Before Production)
| Item | Decision Needed |
|------|-----------------|
| Final Kyber parameter (768 vs 1024) | TBD performance vs security margin |
| Batch/stream sign endpoint | Add `/stream/sign` proto spec |
| PQC cert rotation interval | Define ops or time-based policy |
| Exporter label changes for versioning | Reserve v2 tag |

---

## 11. Client Examples (QUIC JSON Frames)
Example sign request frame (one stream):
```json
{
  "op": "sign",
  "key_id": "k_123",
  "digest": "BASE64_32B",
  "context_binding": "BASE64_32B",
  "nonce": 42
}
```
Response:
```json
{ "ok": true, "data": { "signature": "BASE64_SIG", "alg": "dilithium5", "counter": 42 } }
```
Error example:
```json
{ "ok": false, "error": { "code": "NONCE_OUT_OF_ORDER", "message": "nonce mismatch" } }
```

## 12. Summary
This guide enables engineers to deploy a PQC-HSM node providing Dilithium signing and Kyber-based secure transport over QUIC on Debian 12. The API surface is minimal (key lifecycle + sign/verify/resolve) and will be extended with biometric and advanced token flows post-MVP. Follow migration steps to transition from software-only primitives to hardware-backed keys without breaking client integrations.