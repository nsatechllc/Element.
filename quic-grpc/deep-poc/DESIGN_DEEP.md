Deep POC: Native QUIC + KyberTLS for gRPC traffic
================================================

Goal
----
Produce a native prototype where the transport (QUIC/HTTP3) uses a Kyber-capable TLS handshake (hybrid classical+Kyber KEX) so gRPC traffic enjoys PQC key exchange. Deliverables:
- A reproducible build (dev container) that compiles liboqs and a TLS backend (rustls-oqs or OQS-OpenSSL).
- A minimal quinn-based server and client that perform a KEM-based handshake and exchange a simple SignDigest RPC over a lightweight HTTP/3 or framed protocol.

Important constraints
---------------------
- gRPC-over-HTTP/3 support in mainstream Rust stacks is still experimental. For the PoC we'll implement a lightweight RPC API over QUIC/HTTP3 (or use a simple custom frame-over-QUIC) that mirrors the `SignDigest` proto and proves the transport-level PQC.
- Building liboqs + rustls-oqs may require a C toolchain and takes time; the Dockerfile will encapsulate the steps.

High-level steps
----------------
1. Build container image with liboqs and rust toolchain.
2. Attempt to compile rustls-oqs or a rust wrapper that enables Kyber in rustls; if not available, build quinn linked to a custom OpenSSL (OQS-OpenSSL) and use a quiche-like integration path.
3. Implement server that listens with QUIC and accepts a KEM handshake message on a control stream (for demonstration), then establishes AEAD and exchanges a SignDigest request/response.
4. Provide a client that performs the handshake, derives CBID, and calls the SignDigest RPC.

Acceptance criteria
-------------------
- Container builds successfully and produces an image with liboqs and the rust project compiled.
- Server starts and accepts a client handshake, deriving a shared secret and returning a CBID; client verifies CBID.
- The SignDigest RPC flow completes successfully over the QUIC channel.

Notes
-----
This POC focuses on transport PQC (Kyber). Full gRPC integration (tonic over HTTP/3) is left for follow-up after the core transport is validated.
