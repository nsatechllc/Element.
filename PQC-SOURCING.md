# PQC Sourcing & Integration Guide (lib-pqs)

This document captures the vetted sources, pinning, build flags, and integration pattern for the Element service's post-quantum cryptography layer ("lib-pqs"). It aligns with the roadmap to support CRYSTALS-Dilithium (signatures) and CRYSTALS-Kyber (KEM) while keeping a minimal, auditable supply chain.

## Scope
- Production software-only baseline using liboqs via Rust `oqs` crate.
- Future pluggable replacement by hardware HSM / KMS without changing higher-level service contracts.

## Upstream Components
| Component | URL | License | Purpose |
|-----------|-----|---------|---------|
| liboqs | https://github.com/open-quantum-safe/liboqs | Apache-2.0 | C implementations of NIST PQC finalists (Dilithium, Kyber). |
| oqs-provider | https://github.com/open-quantum-safe/oqs-provider | Apache-2.0 | OpenSSL 3 provider for PQ/TLS hybrid ciphersuites (optional QUIC/TLS path). |
| liboqs-rust (`oqs` crate) | https://github.com/open-quantum-safe/liboqs-rust | MIT/Apache-2.0 | Safe(ish) Rust bindings for liboqs. |

Alternate references (audit/comparison only): PQClean, pq-crystals/dilithium, pq-crystals/kyber.

## Pinning Strategy
| Item | Action |
|------|--------|
| liboqs commit | Record `git rev-parse HEAD` in `supply-chain.lock` (to be created). |
| oqs-provider commit | Same as above when provider used. |
| Crate version | Pin `oqs = 0.9.x` in `Cargo.toml`. |
| Build artifact hashes | Capture SHA256 of installed `liboqs.so` & `oqsprovider.so` in CI logs. |
| Upgrade procedure | Treat as change request; rerun diff of exported symbols (`nm -D`). |

## Minimal Build (Debian 12)
```bash
# liboqs
git clone https://github.com/open-quantum-safe/liboqs.git --branch main --depth 1
cd liboqs && mkdir build && cd build
cmake -GNinja -DOQS_USE_OPENSSL=ON \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_ENABLE_SIG_DILITHIUM=ON \
      -DOQS_ENABLE_KEM_KYBER=ON \
      -DOQS_ENABLE_SIG_FALCON=OFF \
      -DOQS_ENABLE_SIG_SPHINCS=OFF ..
ninja
sudo ninja install && sudo ldconfig
```
Optional provider:
```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git --depth 1
cd oqs-provider && mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
sudo ninja install && sudo ldconfig
```

## Runtime Variables (if using provider)
```bash
export OQS_PROVIDER=/usr/local/lib/oqsprovider.so
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
```

## Rust Integration
`element/Cargo.toml` feature:
```toml
pqc = ["dep:oqs", "software"]
```
Use: enable with `--features pqc` to activate real Dilithium signer (fallback is non-crypto placeholder). Example code path in `signer.rs` (trait + `OqsSigner`).

## Algorithm Allowlist
Environment suggestion (future):
```
SE_ALLOWED_ALGS=dilithium5,dilithium3
```
Reject any request for algorithms outside allowlist early.

## Context Binding
Signatures include a 32-byte digest and a 32-byte context binding value concatenated (`digest || context`) before signing (when PQC backend enabled). This prevents cross-context replay.

## Hardening Checklist
- [ ] Disable all unused algorithms at build (`-DOQS_ENABLE_*`).
- [ ] Enforce allowlist at API layer.
- [ ] Zeroize secret key bytes after use (future: when persistent keys not stored raw in memory).
- [ ] Structured logging of any downgrade or unsupported algorithm attempt.
- [ ] Property tests for address collision and nonce sequencing.

## Migration to Hardware
Abstracted by `SignerBackend` trait. Hardware backend will implement the same interface; service logic remains unchanged.

## Open Items
| Item | Status |
|------|--------|
| Kyber KEM integration (CBID derivation) | Pending |
| Prometheus metrics for algorithm usage | Pending |
| supply-chain.lock manifest | Pending |
| Repro build CI job | Pending |

---
Generated: 2025-09-29
