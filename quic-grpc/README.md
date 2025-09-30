gRPC over QUIC (HTTP/3) + KyberTLS — Prototype guidance
=========================================================

This folder contains a design and minimal artifacts to prototype gRPC running on QUIC/HTTP3 with a PQC-capable TLS (Kyber) key exchange. The goal is a clear, practical path to an experimental prototype and decision points for production readiness.

Files
- `DESIGN.md` — design, tradeoffs, and recommended approach.
- `proto/element.proto` — minimal proto matching `element.v1.ElementSigner` (subset) for a prototype.

Next steps (pick one):
- I can implement a small Rust prototype that uses `tonic` (gRPC over HTTP/2) as a baseline, then show how to front it with HTTP/3 using a proxy (Envoy/NGINX) to validate end-to-end flows.
- Or I can implement a native gRPC-over-HTTP/3 path using a QUIC stack (quinn/quiche) + a TLS backend compiled with OQS (OQS-OpenSSL or rustls-oqs) — this requires building liboqs and is more involved.

If you want me to prototype now, say which: "proxy approach" (fast) or "native HTTP/3 + KyberTLS" (deeper research + longer build).
