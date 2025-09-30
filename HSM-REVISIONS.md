# NSA Technologies Element API Integration Manual

Audience: Third-party server or service integrating with the Post-Quantum Remote Secure Element hosted at `https://api.nsatech.io`.

## 1. Overview
The Element API provides post-quantum (PQC) key management, signing, verification, Kyber KEM operations, and channel binding derivation. All cryptographic primitives use NIST candidate/finalist algorithms via `liboqs` (Dilithium, Kyber). The service returns JSON over HTTPS and (optionally) gRPC for high-throughput internal channels.

### 1.1 Roles vs Tokens Clarification (2025-09-30 Addendum)
Element DOES NOT authoritatively determine business or monetary permissions. Role & capability governance (e.g., mint, burn, branch admin) is defined on-ledger per `ROLES_PERMISSIONS.md`. Element enforces:
* Key custody & non-exportability
* Monotonic nonce counters per key
* Domain-tag + role_class inclusion in sign scope (once client supplies)
* Context binding (CBID) integrity

Treasury / exchange tokens (reserve attestations, settlement proofs, liquidity attest) are AUDIT artifacts **after** a permissioned operation is validated, not sources of permission themselves. Clients must first have validator-accepted capabilities; only then are associated monetary tokens emitted / signed. This separation prevents conflating evidence with authorization and reduces the blast radius of any HSM-side logic fault.

## 2. Base URL
```
https://api.nsatech.io
```
All examples assume this base.

## 3. Data Encoding Conventions
- Binary values (keys, digests, signatures, shared secrets, ciphertexts) are Base64 encoded strings in HTTP JSON.
- Hex values (addresses, cbid) are lowercase hex without `0x`.
- Digests must be exactly 32 bytes (SHA3-256 or domain-specific pre-hash) before Base64 encoding.
- Context binding values (if required) are 32-byte channel binding IDs (CBID) encoded in Base64.

## 4. Key Lifecycle
### 4.1 Generate Key
POST `/keys`
```json
{ "alg": "dilithium5" }
```
Response:
```json
{ "key_id": "<id>", "pubkey": "<Base64>", "alg": "dilithium5", "created_at": 1727600000 }
```
Notes:
- Supported algorithms (current): `dilithium5`, `dilithium3` (check service readiness `/ready`).
- Private keys never leave the service.

### 4.2 Key Identification
- `key_id` is opaque; treat as stable until revoked or rotated (future endpoints may add revoke/rotate operations).

## 5. Signing
POST `/sign`
```json
{
  "key_id": "<key_id>",
  "digest": "<Base64 32B>",
  "context_binding": "<Base64 32B>",
  "nonce": 1
}
```
Response:
```json
{ "signature": "<Base64>", "alg": "dilithium5", "counter": 1, "nonce": 1 }
```
Rules:
- `nonce` must increase strictly per key (monotonic). First accepted nonce is `1`.
- `context_binding` must be present and 32 bytes (Base64-encoded) when PQC feature is active.
- Digest length check enforced (32 bytes). Use SHA3-256 or protocol-defined digest.

### 5.1 Batch Signing
POST `/sign/batch`
```json
{ "items": [ { "key_id": "k1", "digest": "...", "context_binding": "...", "nonce": 11 } ] }
```
Response is per-item with status. Failed items contain empty `signature` and `status` code.

## 6. Verification
POST `/verify`
```json
{ "key_id": "<key_id>", "digest": "<Base64 32B>", "signature": "<Base64>", "context_binding": "<Base64 32B>" }
```
Response:
```json
{ "valid": true, "alg": "dilithium5" }
```

## 7. Address Resolution
POST `/resolve`
```json
{ "pubkey": "<Base64 pubkey>", "alg": "dilithium5" }
```
Response:
```json
{ "address": "<hex20>", "alg": "dilithium5" }
```

## 8. Kyber KEM Operations
### 8.1 Generate Kyber Key Pair
POST `/kem/kyber/keypair`
```json
{ "strength": "kyber768" }
```
Response returns Base64 public and secret keys (secret for client-side decapsulation use—store securely).

### 8.2 Encapsulate
POST `/kem/kyber/encapsulate`
```json
{ "strength": "kyber768", "peer_pubkey": "<Base64>" }
```
Response includes `ciphertext` and `shared_secret` (Base64).

### 8.3 Decapsulate
POST `/kem/kyber/decapsulate`
```json
{ "strength": "kyber768", "secret_key": "<Base64>", "ciphertext": "<Base64>" }
```
Response returns shared secret (must match encapsulation peer).

## 9. Channel Binding ID (CBID)
### 9.1 Derivation Endpoint (LIVE BEHAVIOR)
POST `/cbid/derive`
```json
{ "kem_strength": "kyber768", "peer_pubkey": "<Base64>", "tag": "<Base64 tag up to 64B>" }
```
NOTE: The `tag` field is REQUIRED for the HTTP `/cbid/derive` endpoint. It MUST be Base64-encoded and decode to at most 64 raw bytes. The server will return `INVALID_BASE64_TAG` on decode errors and `TAG_TOO_LONG` when the decoded tag exceeds 64 bytes. CBID is computed as SHA3-256(shared_secret || tag_bytes).

Response:
```json
{ "cbid": "<hex64>", "ciphertext": "<Base64>" }
```
How to use (HTTP path):
1. Generate Kyber key pair: `POST /kem/kyber/keypair` or locally.
2. (Optional) Base64-encode a domain `tag` (≤64 raw bytes before Base64). If you do not need a domain tag, omit the `tag` field and the service will use an empty tag for CBID derivation.
3. Call `/cbid/derive` with `peer_pubkey` and optional `kem_strength` and `tag`.
4. Receive `ciphertext` & `cbid` (server view). Locally decapsulate `ciphertext` with your Kyber secret key → `shared_secret`.
5. Recompute `cbid_local = hex( SHA3-256( shared_secret || tag_bytes ) )`. MUST match server `cbid`.
6. Use the hex CBID to obtain a session token (see §10) and as the logical channel binding.

Troubleshooting:
| Symptom | Cause | Resolution |
|---------|-------|------------|
| 422 missing field `tag` | Tag omitted | Always supply a Base64 tag |
| TAG_TOO_LONG | >64 raw bytes pre-Base64 | Shorten tag |
| INVALID_BASE64_* | Bad encoding / whitespace | Re-encode without newlines |

Python recompute snippet:
```python
import hashlib, base64
shared_secret = b"..."  # Kyber decapsulation output
tag_b64 = "aW50ZWdyYXRpb24tY2hhbm5lbA=="
tag = base64.b64decode(tag_b64)
cbid = hashlib.sha3_256(shared_secret + tag).hexdigest()
```

## 10. Session Tokens (Signing Authorization)
When `SE_REQUIRE_SESSION_TOKEN=1` the service REQUIRES a session token for `/sign`, `/sign/batch`, and `/verify`.

### 10.1 Issue Token
POST `/session/issue`
```json
{ "cbid": "<hex64>", "ttl_secs": 600 }
```
Response:
```json
{ "token": "<Base64 opaque>", "expires_at": 1727600900 }
```
Headers for subsequent protected calls:
`Authorization: Bearer <token>` (preferred) or `X-SE-Session: <token>`.

### 10.2 Failure Modes
| HTTP | error_code | Meaning |
|------|-----------|---------|
| 401  | SESSION_INVALID | Missing / expired / unknown token |
| 400  | TOKEN_STORE_UNINIT | Internal token store not ready (rare) |

### 10.3 Rotation
Re-issue before expiry; old token remains until TTL. Rotating CBID (new Kyber key/tag) logically separates sessions.

### 10.4 Example End-to-End (Live 2025-09-29)
1. `/kem/kyber/keypair` → obtain `pubkey`, `secret_key`.
2. `/cbid/derive` with `peer_pubkey`, `tag` → get `cbid` + `ciphertext`.
3. (Optional) Locally verify CBID.
4. `/session/issue` with `cbid` → token.
5. `/sign` (nonce=1) with headers `Authorization: Bearer <token>`.
6. `/verify` (same digest/signature/context).
7. `/sign/batch` with nonces 2,3 → status OK; reuse nonce 3 returns `NONCE_OUT_OF_ORDER`.

Live sample summary:
```json
{
  "cbid_derive": 200,
  "session_issue": 200,
  "sign_nonce1": 200,
  "batch_sign_statuses": ["OK","OK"],
  "nonce_reuse": "NONCE_OUT_OF_ORDER"
}
```

## 11. Rate Limiting Headers
Every successful `/sign` and `/verify` response includes:
```
X-RateLimit-Limit: <capacity>
X-RateLimit-Remaining: <tokens_left>
X-RateLimit-Policy: global;window=1s
```
Handle 429 or per-item `RATE_LIMIT` statuses with backoff (e.g., exponential starting at 50ms).

## 12. Metrics & Health
- `GET /health` returns plain `ok`.
- `GET /ready` returns JSON including `allowed_algs`, build metadata.
- `GET /metrics/text` Prometheus exposition (scrape interval >= 10s recommended).

## 13. Error Handling
Error body shape:
```json
{ "error_code": "NONCE_OUT_OF_ORDER", "message": "NONCE_OUT_OF_ORDER" }
```
Common codes: `ALG_NOT_ALLOWED`, `NONCE_OUT_OF_ORDER`, `INVALID_BASE64_DIGEST`, `INVALID_LENGTH`, `KEY_NOT_FOUND`, `RATE_LIMIT`.

## 14. Security Considerations
- Always validate that `digest` is derived from canonical domain context (avoid signing arbitrary input).
- Protect Kyber secret keys (client side) used for decapsulation—treat as sensitive as private signing keys.
- Monitor for `verify` failures spike (possible tampering or misuse).
- Rotate keys periodically (future endpoint) by generating new keys & updating upstream trust stores.

## 15. Suggested Client Workflow (Updated for Session Tokens)
1. Key provisioning: call `/keys` once, persist `key_id` & `pubkey`.
2. Pre-hash domain-specific messages to 32-byte digest.
3. For each sign operation:
   - Ensure fresh or valid CBID (optionally derive via `/cbid/derive`).
   - Maintain client-side expected nonce (start at 1; increment after accepted sign).
   - Submit `/sign`.
4. Verify returned signature when required for audit or replication.

## 16. Example Curl Commands
```bash
# Generate key
echo '{"alg":"dilithium5"}' | curl -s -X POST https://api.nsatech.io/keys -H 'Content-Type: application/json' -d @- | jq

# Sign (digest/context 32 zero bytes example ONLY for demo)
DIG=$(python3 - <<'PY'
import base64;print(base64.b64encode(b'\x00'*32).decode())
PY
)
CTX=$DIG
curl -s -X POST https://api.nsatech.io/sign -H 'Content-Type: application/json' \
  -d '{"key_id":"<key_id>","digest":"'"$DIG"'","context_binding":"'"$CTX"'","nonce":1}' | jq
```

## 17. gRPC Notes
If gRPC enabled, use proto service `element.v1.ElementSigner` (see API blueprint). Advantages: lower encoding overhead and streaming extensions (future). Ensure TLS termination or mTLS upstream if exposed beyond internal network.

## 17.1 QUIC Overlay (Experimental / Preferred Low-Latency Path)
When the QUIC overlay feature is enabled (`quic-overlay` build feature + `SE_QUIC_ADDR` set), a parallel QUIC listener performs a Kyber KEM-based handshake to derive a shared secret and CBID. This can be used by advanced clients to:
1. Obtain the server Kyber public key (uni stream A).
2. Send encapsulated ciphertext (+ optional tag) (uni stream B).
3. Receive confirmation: `cbid_short`, AEAD test ciphertext (uni stream C).

### 17.1.1 Handshake Summary
Server → Client: length-prefixed Kyber public key.
Client → Server: ciphertext length (u16) || ciphertext || tag_len(u8) || tag (optional).
Server decapsulates → shared_secret, derives:
- Session AEAD key = HKDF-SHA3(shared_secret, salt=tag, info="quic-overlay-v1")
- CBID = SHA3-256(shared_secret || tag) (hex64)
Server → Client: cbid_short_len || cbid_short (hex32) || nonce(12) || test_cipher_len(u16) || AEAD(test).

### 17.1.2 Client Requirements
- Implement QUIC client (quinn or another RFC 9000 compliant stack).
- Support Kyber768 (current default) for encapsulation.
- Provide optional tag ≤ 64 bytes to domain-separate different logical channels.
- Validate test AEAD decrypts to "ok" to confirm key sync.

### 17.1.3 Bridging to HTTP Session Tokens
If you wish to use HTTP `/sign` with session enforcement, you can:
1. Perform QUIC KEM handshake, compute/receive CBID.
2. Call HTTPS `/session/issue` with the full CBID to mint token.
3. Use Authorization: Bearer token for subsequent HTTP requests.

### 17.1.4 Security & Caveats
- Prototype: no replay nonce store or key rotation cadence yet—treat for controlled environments.
- AEAD currently limited to a handshake confirmation frame; full data channel framing TBD.
- QUIC listener may not be behind the same TLS termination as HTTPS; plan firewall and rate-limit externally.

### 17.1.5 Fallback Strategy
If QUIC unavailable (e.g., network blocks UDP), clients should directly use HTTPS + `/cbid/derive` for channel binding.

## 18. Versioning & Backwards Compatibility
- Minor, non-breaking additions (new fields/endpoints) will not change existing semantics.
- Breaking changes communicated with versioned host path (future `/v2/`) or Accept header negotiation.

## 19. Troubleshooting (Augmented)
Additional signing-specific issues:
| Symptom | Cause | Action |
|---------|-------|--------|
| 401 SESSION_INVALID | Missing/expired token | Renew `/session/issue` |
| 409 NONCE_OUT_OF_ORDER | Reused or skipped nonce | Sync local counter; start at 1 |
| CONTEXT_REQUIRED | Missing `context_binding` | Supply Base64(32B CBID binary) |
| INVALID_BASE64_PUBKEY | Corrupt Kyber key | Re-generate key pair |
| Symptom | Probable Cause | Action |
|---------|----------------|--------|
| 400 INVALID_BASE64_DIGEST | Not base64 or wrong length | Confirm 32-byte digest pre-hash and encode correctly |
| 409 NONCE_OUT_OF_ORDER | Nonce reused or skipped | Sync client nonce with server; track last accepted |
| 429 RATE_LIMIT | Burst exceeded | Backoff & retry after jitter delay |
| Signature invalid remotely | Wrong context or digest | Ensure identical digest & context on verify |

## 20. (Moved Above) Session Tokens & Auth
Section moved to §10 for clarity in updated ordering.
When the service sets `SE_REQUIRE_SESSION_TOKEN=1`, signing and verification endpoints require a valid session token bound to a Channel Binding ID (CBID).

### 19.1 Flow Summary
1. Derive or obtain a CBID (via `/cbid/derive` or out-of-band Kyber exchange).
2. Issue token:
   POST `/session/issue` `{ "cbid": "<hex64>", "ttl_secs": 900 }`
3. Receive `{ "token": "<Base64>", "expires_at": <unix> }`.
4. Use the token on protected calls with either:
   - `Authorization: Bearer <token>` (preferred)
   - `X-SE-Session: <token>` (fallback)
5. Renew before expiry; tokens remain valid until `expires_at`.

### 19.2 Expiry & Reaping
- Max TTL: 3600 seconds.
- Background reaper purges expired tokens ~every 30 seconds; metric `se_session_tokens` reflects active count.

### 19.3 Error Cases
| HTTP Status | error_code        | Meaning                                    |
|-------------|-------------------|--------------------------------------------|
| 401         | SESSION_INVALID    | Missing, expired, or unknown token         |
| 400         | TOKEN_STORE_UNINIT | Rare initialization issue (contact support)|

### 19.4 Security Notes
- Tokens are opaque; no client-side parsing—treat as secrets.
- Scope is implicitly the CBID; rotate CBID (new KEM exchange) to invalidate prior linkage.
- Avoid embedding tokens in URLs or logs; use headers.

### 19.5 Example
```bash
CBID="<hex64>" # from /cbid/derive
TOKEN=$(curl -s -X POST https://api.nsatech.io/session/issue -H 'Content-Type: application/json' \
  -d '{"cbid":"'"$CBID"'","ttl_secs":600}' | jq -r .token)
curl -s -X POST https://api.nsatech.io/sign -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key_id":"<key>","digest":"<Base6432>","context_binding":"<Base6432>","nonce":1}'
```

## 21. Future Extensions
- Key rotation & retirement endpoints.
- QUIC encrypted message channel with AEAD framed protocol (expanded message API).
- Hardware HSM / attestation integration.
- Federation & multi-region replication.

## 22. Contact
For integration support or reporting issues: engineering@nsatech.io

---
Revision: 2025-09-29 (session tokens documented; tag required; roadmap aligned)

---
## 23. Proposed Enhancements / Customization Requests (2025-09-30)

This section enumerates feature gaps relative to the broader 4E5341 blueprint (roles, governance, admission pipeline) and formalizes requests for the Element service roadmap. Each item includes a short rationale and a suggested minimal API surface. Prioritize by Tier: P0 (needed for first validator vertical slice), P1 (improves robustness / observability), P2 (future / optimization / nice‑to‑have).

### Summary Table
| ID | Tier | Title | Outcome |
|----|------|-------|---------|
| FEAT-01 | P0 | Structured Sign Scope Endpoint | HSM hashes canonical sign scope internally → reduces client misuse risk |
| FEAT-02 | P0 | Nonce Introspection API | Clients resync nonce counters safely to avoid stalls |
| FEAT-03 | P0 | Deterministic Audit Log Export | External audit + replay analysis of HSM activity |
| FEAT-04 | P0 | Fallback Mode Status & Reason | Chain can embed mode in block metadata deterministically |
| FEAT-05 | P0 | QUIC CBID Path Parity + Tag Optionality | Align HTTP & QUIC derivation semantics (tag optional) |
| FEAT-06 | P1 | Session Introspection / Refresh Endpoint | Graceful token renewal before expiry |
| FEAT-07 | P1 | Bulk Nonce Prefetch (Multi-Key) | Reduce RTT for many validator keys |
| FEAT-08 | P1 | Rate Limit Status Endpoint | Adaptive client backoff; avoid wasted sign attempts |
| FEAT-09 | P1 | gRPC Streaming SignDigest | Lower latency & CPU under high RPS (RSE-12) |
| FEAT-10 | P1 | Key Rotation API (+ staged deactivation) | Safe key evolution without downtime |
| FEAT-11 | P1 | Attestation Endpoint (RSE-13) | Remote trust in SE runtime & build provenance |
| FEAT-12 | P1 | Metrics: per-key sign rate & nonce OOO counters | Fine-grained monitoring & anomaly detection |
| FEAT-13 | P2 | Dry-Run Sign (nonce validation without signature) | Early detection of nonce skew before consuming counter |
| FEAT-14 | P2 | Bulk Verify Endpoint | Lower overhead for mass verification workflows |
| FEAT-15 | P2 | Threshold / Multi-Partial Sign Precursor | Foundation for future aggregated / threshold signatures |
| FEAT-16 | P2 | Audit Log Streaming (server‑sent events) | Near-real-time monitoring & forensics |

### Detailed Descriptions

#### FEAT-01 Structured Sign Scope Endpoint (P0)
Problem: Current `/sign` expects a pre-hashed 32-byte digest. Risk of clients hashing incorrectly or omitting mandatory fields (domain tag, role_class, epoch). Blueprint mandates canonical sign scope ordering.
Proposal: New endpoint `/sign/scope` accepting structured JSON:
```
POST /sign/scope
{
  "key_id": "...",
  "domain_tag": "COMM-TX-V1|NET-MONETARY-V1", 
  "role_class": "Branch|Organisation|Network|Validator|Machine|Operator|Compliance|Client",
  "role_id": "hex|numeric",
  "cap_epoch_id": 123,           // optional where applicable
  "block_height": 456789,        // optional (governance / consensus)
  "cbid": "<hex64>",            // context binding, already derived
  "nonce": 17,
  "proof_cid": "bafy...",       // optional
  "tx_digest": "hex|base64"     // optional raw tx digest to fold in
}
```
Server constructs canonical SHA3-256(sign_scope_fields) value internally and signs it (no raw digest supplied by client). Returns same shape as `/sign` plus an echo of the computed `scope_hash` (hex) for client-side audit.

#### FEAT-02 Nonce Introspection API (P0)
Endpoint: `GET /keys/{key_id}/nonce` → `{ "key_id": "...", "next_nonce": 42 }`.
Use: Recover from client crashes or lost local state without trial-and-error sign attempts. Batch variant: `POST /keys/nonce/query` with list of key_ids.

#### FEAT-03 Deterministic Audit Log Export (P0)
Endpoint: `GET /audit/stream?since=<ts>&cursor=<token>` returning chronological records (JSON lines):
```
{ "ts": 1727601001, "event": "sign", "key_id": "...", "nonce": 12, "alg": "dilithium5", "cbid_prefix": "4b9ea1d0", "scope_hash": "..." }
```
Supports pagination via `cursor`. Enables independent reconstruction of signing timeline matching ledger state.

#### FEAT-04 Fallback Mode Status & Reason (P0)
Endpoint: `GET /crypto/mode` → `{ "primary_alg": "dilithium5", "active_alg": "dilithium5|dilithium3", "mode": "NORMAL|FALLBACK", "reason": "throughput_floor|latency_slo|manual_override|none", "since": 1727600000 }`.
Chain consensus component can poll & embed status into periodic metadata; auditors verify fallback triggers.

#### FEAT-05 QUIC CBID Parity & Tag Handling (P0)
Action: Evaluate parity between QUIC and HTTP CBID derivation. QUIC handshake allows an optional tag at the transport layer; however, HTTP `/cbid/derive` currently requires an explicit Base64 `tag` field. If a future change makes HTTP accept omitted tags, it must be coordinated with SDKs and rolled out behind a feature flag with clear deprecation windows. Expose server Kyber public key via `GET /kem/kyber/server_pubkey` for out-of-band prefetch as planned.

#### FEAT-06 Session Introspection / Refresh (P1)
Endpoint: `GET /session/{token_id}` → `{ "expires_at": ..., "cbid": "..." }` and `POST /session/refresh` (supply token, optional new ttl). Avoids abrupt expiry mid multi-sig sequence.

#### FEAT-07 Bulk Nonce Prefetch (P1)
`POST /keys/nonce/prefetch` with up to N key_ids → returns array of next_nonce values; reduces RTT for consensus nodes managing many validator / committee keys.

#### FEAT-08 Rate Limit Status (P1)
`GET /limits` → `{ "sign_per_sec_capacity": 5000, "sign_remaining": 4875, "window_ms": 1000 }`. Enables adaptive pacing rather than reactive 429 handling.

#### FEAT-09 gRPC Streaming SignDigest (P1)
gRPC method `stream SignStream (SignRequest) returns (SignResponse)` enabling bidirectional streaming; amortizes per-request overhead for high throughput sign pipelines (RSE-12).

#### FEAT-10 Key Rotation API (P1)
`POST /keys/{key_id}/rotate` → generates new key (returns new `key_id_new`) while old remains valid until `deactivate_at`; separate `POST /keys/{old_id}/finalize` to force early retirement. Audit log entries must show linkage.

#### FEAT-11 Attestation Endpoint (P1)
`GET /attestation/se` → returns `{ "hw_model": "...", "firmware_ver": "...", "oqs_ver": "...", "build_git": "...", "attestation_sig": "Base64" }` where `attestation_sig` is a Dilithium5 signature over a canonical claims object. Future: integrate TEE / Primus measurement root.

#### FEAT-12 Enhanced Metrics (P1)
Add Prom metrics:
```
se_key_sign_total{key_id,alg}
se_key_last_nonce{key_id}
se_sign_oood_total{key_id}
se_session_active_tokens
se_crypto_mode{alg}
```
Plus histogram: `se_sign_latency_ms_bucket` and `se_batch_sign_item_latency_ms_bucket`.

#### FEAT-13 Dry-Run Sign (P2)
`POST /sign/dryrun` same body as `/sign` but returns only `{ "ok": true, "expected_counter": X }` without consuming nonce or producing signature. Accept only if provided nonce == current next_nonce (or future policy to allow preview next).

#### FEAT-14 Bulk Verify (P2)
`POST /verify/batch` with array—returns per-item validity. Offloads CPU from application layer when verifying large historical bundles.

#### FEAT-15 Threshold / Partial Sign (P2)
Prepare endpoints to produce partial signature shares: `POST /sign/partial` returning `{ share, share_id, group_id }` leading to future combine operation. Placeholder only until lattice-based threshold implementation stabilized.

#### FEAT-16 Audit Log Streaming (P2)
Server-Sent Events endpoint `/audit/stream/live` pushing real-time sign / rotate / mode-change events (bounded rate, auth required). Facilitates SOC / monitoring dashboards.

### JSON Schema Considerations
All new endpoints should publish a versioned JSON Schema (e.g., `/schema/sign-scope-v1.json`) to allow SDK codegen & strict client validation.

### Security Considerations
* Structured scope signing (FEAT-01) reduces attack surface for digest substitution or accidental omission of fields mandated by ledger validation rules.
* Nonce introspection (FEAT-02) must be auth‑protected (require session token + key ownership) to avoid key enumeration side-channel.
* Audit export & streaming (FEAT-03/16) must support redaction or filter on tenant/role to prevent disclosure of high-frequency pattern data to unauthorized clients.
* Key rotation (FEAT-10) audit trail must be **append-only**; rotation linking object includes `{ old_key_id, new_key_id, rotated_at, deactivation_epoch }` hashed into attestation log.

### Backwards Compatibility Guidelines
Add new endpoints without altering existing request/response contracts. Where existing endpoint semantics evolve (e.g., optional `tag` in `/cbid/derive`), maintain old behavior behind explicit feature flag until all SDKs updated. Provide deprecation header: `Deprecation: version="2025-10-15", removal="2025-12-01"` once safe.

### SDK Impact (RSE-3)
Planned `remote_se` Rust crate APIs reflecting requested features (subset initially):
```
open_channel_quic() -> Channel { cbid, mode }
derive_cbid_http(tag: Option<&[u8]>) -> Cbid
issue_session(cbid, ttl) -> SessionToken
sign_scope(params: SignScopeParams) -> SignatureResult
get_nonce(key_id) -> u64
stream_sign(request_iter) -> impl Stream<Item=SignatureResult>
rotate_key(key_id) -> KeyRotationOutcome
attestation() -> AttestationReport
```
Future updates add partial sign, dry-run, batch verify once server implements.

### Prioritization Rationale
P0 items unblock building a ledger-integrated admission pipeline with deterministic, auditable sign semantics and robust recovery from state loss. P1 adds operational resilience, observability, and lifecycle management. P2 prepares for scalability and advanced cryptographic evolution without constraining initial design.

---

---
### Appendix: Live Endpoint Inventory (Cross-Reference API Blueprint)
| Endpoint | Purpose | Auth Requirement |
|----------|---------|------------------|
| POST /keys | Generate Dilithium key | Token (if service enforces globally; currently open) |
| POST /sign | Sign digest (nonce) | Session token required |
| POST /sign/batch | Batch sign | Session token required |
| POST /verify | Verify signature | Session token required |
| POST /resolve | Address derivation | None / token (future) |
| POST /kem/kyber/keypair | Generate Kyber pair | None |
| POST /kem/kyber/encapsulate | KEM encapsulate | None |
| POST /kem/kyber/decapsulate | KEM decapsulate | None |
| POST /cbid/derive | Derive CBID (Kyber) | None |
| POST /session/issue | Mint session token | None (but CBID must exist) |
| GET /health | Liveness | None |
| GET /ready | Readiness / alg list | None |
| GET /metrics / /metrics/text | Metrics | Ops restricted (future) |

### Roadmap Alignment Markers
Roadmap IDs (see `blueprint.md §10.6.11`): RSE-1..RSE-13. This document currently satisfies RSE-1 (validation) & RSE-2 (documentation sync). Next engineering tasks: RSE-3 (client SDK) and RSE-4 (consensus integration).

### CI Smoke Test
Integration script `scripts/hsm_smoketest.py` executes the validated flow and should be wired into CI to fail on regression (missing field, status drift, nonce sequencing error).