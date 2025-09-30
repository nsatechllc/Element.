# NSA Technologies Element API Integration Manual

Audience: Third-party server or service integrating with the Post-Quantum Remote Secure Element hosted at `https://api.nsatech.io`.

## 1. Overview
The Element API provides post-quantum (PQC) key management, signing, verification, Kyber KEM operations, and channel binding derivation. All cryptographic primitives use NIST candidate/finalist algorithms via `liboqs` (Dilithium, Kyber). The service returns JSON over HTTPS and (optionally) gRPC for high-throughput internal channels.

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
### 9.1 Derivation Endpoint
POST `/cbid/derive`
```json
{ "kem_strength": "kyber768", "peer_pubkey": "<Base64>", "tag": "<Base64 tag up to 64B>" }
```
Response:
```json
{ "cbid": "<hex64>", "ciphertext": "<Base64>" }
```
How to use:
1. Caller supplies remote peer Kyber public key.
2. Service encapsulates, outputs ciphertext & shared secret-derived CBID.
3. The `tag` field is REQUIRED. It MUST be Base64-encoded and decode to at most 64 raw bytes. The server will reject requests that omit `tag` or provide invalid Base64 or an oversized decoded tag. The CBID is computed as CBID = SHA3-256(shared_secret || tag_bytes). Include the CBID (hex) as the `context_binding` input for signing requests to bind them to that KEM exchange.

Errors to expect for malformed tags: `INVALID_BASE64_TAG` (when `tag` is not valid Base64) and `TAG_TOO_LONG` (when decoded tag exceeds 64 bytes).

## 10. Rate Limiting Headers
Every successful `/sign` and `/verify` response includes:
```
X-RateLimit-Limit: <capacity>
X-RateLimit-Remaining: <tokens_left>
X-RateLimit-Policy: global;window=1s
```
Handle 429 or per-item `RATE_LIMIT` statuses with backoff (e.g., exponential starting at 50ms).

## 11. Metrics & Health
- `GET /health` returns plain `ok`.
- `GET /ready` returns JSON including `allowed_algs`, build metadata.
- `GET /metrics/text` Prometheus exposition (scrape interval >= 10s recommended).

## 12. Error Handling
Error body shape:
```json
{ "error_code": "NONCE_OUT_OF_ORDER", "message": "NONCE_OUT_OF_ORDER" }
```
Common codes: `ALG_NOT_ALLOWED`, `NONCE_OUT_OF_ORDER`, `INVALID_BASE64_DIGEST`, `INVALID_LENGTH`, `KEY_NOT_FOUND`, `RATE_LIMIT`.

## 13. Security Considerations
- Always validate that `digest` is derived from canonical domain context (avoid signing arbitrary input).
- Protect Kyber secret keys (client side) used for decapsulation—treat as sensitive as private signing keys.
- Monitor for `verify` failures spike (possible tampering or misuse).
- Rotate keys periodically (future endpoint) by generating new keys & updating upstream trust stores.

## 14. Suggested Client Workflow
1. Key provisioning: call `/keys` once, persist `key_id` & `pubkey`.
2. Pre-hash domain-specific messages to 32-byte digest.
3. For each sign operation:
   - Ensure fresh or valid CBID (optionally derive via `/cbid/derive`).
   - Maintain client-side expected nonce (start at 1; increment after accepted sign).
   - Submit `/sign`.
4. Verify returned signature when required for audit or replication.

## 15. Example Curl Commands
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

## 16. gRPC Notes
If gRPC enabled, use proto service `element.v1.ElementSigner` (see API blueprint). Advantages: lower encoding overhead and streaming extensions (future). Ensure TLS termination or mTLS upstream if exposed beyond internal network.

## 16.1 QUIC Overlay (Experimental / Preferred Low-Latency Path)
When the QUIC overlay feature is enabled (`quic-overlay` build feature + `SE_QUIC_ADDR` set), a parallel QUIC listener performs a Kyber KEM-based handshake to derive a shared secret and CBID. This can be used by advanced clients to:
1. Obtain the server Kyber public key (uni stream A).
2. Send encapsulated ciphertext (+ optional tag) (uni stream B).
3. Receive confirmation: `cbid_short`, AEAD test ciphertext (uni stream C).

### 16.1.1 Handshake Summary
Server → Client: length-prefixed Kyber public key.
Client → Server: ciphertext length (u16) || ciphertext || tag_len(u8) || tag (optional).
Server decapsulates → shared_secret, derives:
- Session AEAD key = HKDF-SHA3(shared_secret, salt=tag, info="quic-overlay-v1")
- CBID = SHA3-256(shared_secret || tag) (hex64)
Server → Client: cbid_short_len || cbid_short (hex32) || nonce(12) || test_cipher_len(u16) || AEAD(test).

### 16.1.2 Client Requirements
- Implement QUIC client (quinn or another RFC 9000 compliant stack).
- Support Kyber768 (current default) for encapsulation.
- Provide optional tag ≤ 64 bytes to domain-separate different logical channels.
- Validate test AEAD decrypts to "ok" to confirm key sync.

### 16.1.3 Bridging to HTTP Session Tokens
If you wish to use HTTP `/sign` with session enforcement, you can:
1. Perform QUIC KEM handshake, compute/receive CBID.
2. Call HTTPS `/session/issue` with the full CBID to mint token.
3. Use Authorization: Bearer token for subsequent HTTP requests.

### 16.1.4 Security & Caveats
- Prototype: no replay nonce store or key rotation cadence yet—treat for controlled environments.
- AEAD currently limited to a handshake confirmation frame; full data channel framing TBD.
- QUIC listener may not be behind the same TLS termination as HTTPS; plan firewall and rate-limit externally.

### 16.1.5 Fallback Strategy
If QUIC unavailable (e.g., network blocks UDP), clients should directly use HTTPS + `/cbid/derive` for channel binding.

## 17. Versioning & Backwards Compatibility
- Minor, non-breaking additions (new fields/endpoints) will not change existing semantics.
- Breaking changes communicated with versioned host path (future `/v2/`) or Accept header negotiation.

## 18. Troubleshooting
| Symptom | Probable Cause | Action |
|---------|----------------|--------|
| 400 INVALID_BASE64_DIGEST | Not base64 or wrong length | Confirm 32-byte digest pre-hash and encode correctly |
| 409 NONCE_OUT_OF_ORDER | Nonce reused or skipped | Sync client nonce with server; track last accepted |
| 429 RATE_LIMIT | Burst exceeded | Backoff & retry after jitter delay |
| Signature invalid remotely | Wrong context or digest | Ensure identical digest & context on verify |

## 19. Session Tokens & Auth
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

## 20. Future Extensions
- Key rotation & retirement endpoints.
- QUIC encrypted message channel with AEAD framed protocol (expanded message API).
- Hardware HSM / attestation integration.
- Federation & multi-region replication.

## 20. Contact
For integration support or reporting issues: engineering@nsatech.io

---
Revision: 2025-09-29 (session tokens documented)
