Rustls + Kyber (Hybrid PQ) Integration
=====================================

Goal: Provide an integration layer (prototype) to enable a hybrid key exchange (X25519 + Kyber768) in the TLS 1.3 handshake using rustls as the base.

Phases
------
1. Fork rustls (or feature-gate patches) to add a new NamedGroup identifier for Kyber768 and Hybrid(X25519,Kyber768).
2. Implement extension advertisement logic in ClientHello and server selection for hybrid group.
3. Perform classical X25519 ECDHE as normal and in parallel run Kyber KEM to derive `ss_pq`.
4. Combine secrets: HKDF-Extract over `concat(ss_classical || ss_pq)` to produce the TLS 1.3 early secret (or use a dedicated hybrid secret combiner pre-Extract).
5. Maintain transcript binding; include both key shares in the transcript hash (already covered by standard TLS encoding of extensions) and add a downgrade sentinel.
6. Add tests comparing handshake transcript with/without PQ to ensure only intended deltas.

Repository Structure (planned)
------------------------------
- fork/                 (optional embedded rustls fork if patching in-tree)
- patches/              (git-format patches applied to upstream rustls)
- src/
  - hybrid.rs           (hybrid secret combiner logic, HKDF helper)
  - kem.rs              (Kyber abstraction using `oqs` crate)
  - group_registry.rs   (registration of new NamedGroup codes)
  - verifier.rs         (downgrade detection / policy enforcement)
- tests/
  - hybrid_kex.rs       (unit tests for secret combination)
  - transcript.rs       (assert transcript differences minimal)
  - interop/            (future: interop test harness with OpenSSL+OQS)

NamedGroup Allocation (Experimental)
------------------------------------
IANA space is fixed; for experimentation we choose GREASE-style values:
- Kyber768 (temp): 0x2F30
- X25519_Kyber768_Hybrid: 0x2F31

These must not ship to production without IANA allocation / proper negotiation fallback.

Secret Derivation Strategy
--------------------------
Given:
- ss_ecdh: 32 bytes (X25519)
- ss_pq:   32 bytes (Kyber768 shared secret length may be 32)

We define hybrid_secret = SHA3-256( 0x01 || ss_ecdh || ss_pq )
Then feed into standard TLS 1.3: early_secret = HKDF-Extract(0, hybrid_secret)

Alternative (closer to some hybrid drafts): early_secret = HKDF-Extract( HKDF-Extract(0, ss_ecdh), ss_pq ). We will implement both behind a feature flag.

Downgrade Protection
--------------------
Client records hash H = SHA256(list_of_supported_hybrid_groups_serialization) and sends it in a dedicated experimental extension `hybrid_negotiation_hash`.
Server echoes H if selecting a non-hybrid classical group; mismatch => abort to prevent silent stripping.

Testing Plan
------------
1. Unit: Ensure hybrid_secret differs if either constituent secret changes (bit flip test). 
2. Property: Use proptest to assert no collisions across random (ss_ecdh, ss_pq) pairs within sampled domain.
3. Integration: Two clients (classical-only vs hybrid-enabled) connecting to patched server— verify negotiated group and secrets length.
4. Interop (later): Attempt handshake with oqs-openssl hybrid server; if mismatch, log full transcript bytes.

Performance Bench Hooks
-----------------------
Expose feature `bench` to collect timings via `std::time::Instant` for:
- Kyber keypair
- Kyber encapsulate / decapsulate
- Hybrid secret combine

Results exported as JSON to stdout when `HYBRID_BENCH=1` env var set.

Security Considerations
-----------------------
- Ensure zeroize of ss_pq, ss_ecdh once hybrid_secret derived.
- Avoid branching on secret bytes; use constant-time compare where needed.
- DO NOT log raw secrets; only truncated hashes.

Next Actions
------------
- Add Cargo.toml
- Implement `kem.rs` wrapper (oqs-based) with graceful feature gate if liboqs absent.
- Implement hybrid derivation function and tests.
- Prepare patch script applying group additions to rustls fork.

