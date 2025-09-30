# Element Service

Internal cryptographic signing & KEM service with PQC support (Dilithium, Kyber).

## Features
- HTTP JSON API (keys, sign, batch sign, verify, Kyber KEM, CBID derivation)
- Optional gRPC interface
- Prometheus metrics `/metrics/text`
- Rate limiting (token bucket) with headers
- Audit logging (structured JSON via tracing)

## Quick Start (Local)
```
cargo run --features pqc,grpc --bin element-bin
```

## Docker
```
docker build -t element:dev .
# Run backend only (pair with Caddy reverse proxy for TLS)
docker run --rm -p 8080:8080 element:dev
```

## Environment Variables
- SE_LISTEN_ADDR (default 0.0.0.0:8080)
- SE_ALLOWED_ALGS (comma list, default dilithium5,dilithium3)
- SE_RATE_CAPACITY (default 500)
- SE_RATE_FILL_PER_SEC (default 500)
- SE_GRPC_ADDR (if grpc feature enabled; default 0.0.0.0:50051)

Development
- An `.env` file is read by some dev tooling; a simple `.env` is included to enable Rust backtraces during local tests:

```
RUST_BACKTRACE=1
```

## Metrics Added
- se_sign_total
- se_sign_latency_ms
- se_sign_by_alg_total{alg}
- se_verify_fail_total{alg}
- se_rate_limited_total
- se_batch_size (histogram)
- se_build_info (gauge=1)

## Readiness & Health
- /health : liveness
- /ready  : readiness + feature flags

## Roadmap
1. QUIC overlay handshake with Kyber ephemeral KEM -> channel binding (future feature flag).
2. OTel traces & request IDs.
3. Hardware key integration.

