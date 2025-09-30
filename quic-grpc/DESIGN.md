Design: gRPC over HTTP/3 with PQC (Kyber) in TLS
================================================

Goal
----
Prototype gRPC traffic over QUIC/HTTP3 with a post-quantum key-exchange (Kyber) integrated into the TLS handshake (KyberTLS). Deliver a decision-ready artifact describing dependencies, a minimal prototype plan, and fallback routes.

Options
-------
1. Proxy approach (fast proof-of-concept)
   - Keep `tonic` (gRPC over HTTP/2) server unchanged.
   - Front with an HTTP/3-capable reverse proxy (Envoy, Caddy, or NGINX with HTTP/3) that supports a PQC-capable TLS backend (OQS-OpenSSL or rustls-oqs).
   - Proxy either: terminate TLS at the proxy and forward to local gRPC or use h2/h3 bridging.
   - Pros: minimal server changes, quick validation, isolates PQC TLS work to proxy.
   - Cons: TLS KEX is between client and proxy only; intra-host gRPC remains classical.

2. Native approach (deep prototype)
   - Use a QUIC stack that supports custom TLS backends (quinn with rustls-oqs or a custom quiche build against OQS-OpenSSL).
   - Run gRPC-over-HTTP/3 natively if client and server gRPC stacks support HTTP/3 (this area is still experimental for many languages).
   - Pros: full transport-level PQC for gRPC traffic.
   - Cons: requires building liboqs + TLS stack + experimental gRPC layers — longer and riskier.

Dependencies & candidates
-------------------------
- liboqs (C library) — provides Kyber algorithms.
- OQS-OpenSSL (OpenSSL fork) — integrates OQS KEMs into OpenSSL. Good if using C-based proxies (Envoy with OpenSSL support, or NGINX with custom build).
- rustls-oqs (Rust bindings) — experimental; would integrate with quinn/rustls stacks.
- quinn (QUIC in Rust) — solid QUIC stack; integrates with rustls.
- quiche (QUIC by Cloudflare) — alternative QUIC stack; uses BoringSSL/OpenSSL bridge.
- Envoy or Caddy — HTTP/3-capable proxies; Envoy can be built to use OQS-OpenSSL.

Prototype plan (proxy approach — recommended first)
-------------------------------------------------
1. Build or obtain a TLS-capable proxy with PQC KEX support:
   - Option A: Build Envoy with OQS-OpenSSL
   - Option B: Use Caddy + OQS-OpenSSL (if Caddy supports linking)
2. Deploy a `tonic` gRPC server listening on localhost:50051 (unchanged).
3. Configure the proxy to terminate HTTP/3 + KyberTLS and reverse-proxy to the local `tonic` server (h2 to backend).
4. Write a small gRPC client that uses HTTP/3 + the PQC-enabled TLS stack to connect to the proxy endpoint and make RPCs.

Prototype plan (native approach — if you want full-stack)
--------------------------------------------------------
1. Evaluate rustls-oqs maturity. If suitable, build a `quinn` server that uses rustls-oqs for the TLS backend.
2. Implement an HTTP/3-compatible gRPC layer or use a proxy shim that converts h3->h2 with preserved security attributes.
3. Build and test client & server with hybrid KEX (classical + Kyber) to avoid downgrades.

Testing & CI
-----------
- Add small integration tests that:
  - Validate TLS handshake includes Kyber KEX (look at server-side handshake logs)
  - Make a simple unary RPC and verify response.
- For local CI: run the proxy + server + client in a containerized compose for repeatable testing.

Risks & mitigations
-------------------
- Building liboqs, OQS-OpenSSL can be heavy and require C toolchains + CGO for some stacks. Mitigate: use prebuilt packages or a dev container.
- rustls-oqs may be unstable; use hybrid KEX with classical fallback.

Deliverables
------------
- A short branch with a `tonic` server + envoy/Caddy proxy configured for HTTP/3 with OQS-OpenSSL (proxy approach).
- A small client demonstrating an RPC over the secure PQC transport.
- A decision note listing the exact package versions & build commands.
