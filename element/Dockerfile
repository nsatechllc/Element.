# Multi-stage build for element service
FROM rust:1.81 as builder
WORKDIR /app
# Cache deps
ARG BUILD_FEATURES="pqc,grpc,quic-overlay"
ENV BUILD_FEATURES=${BUILD_FEATURES}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs .
COPY proto ./proto
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --features ${BUILD_FEATURES}

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/release/element-bin /app/element
EXPOSE 8080 50051
ENV SE_LISTEN_ADDR=0.0.0.0:8080 \
    RUST_LOG=info \
    SE_REQUIRE_SESSION_TOKEN=1 \
    SE_ALLOWED_ALGS=dilithium5,dilithium3
# Optional: enable QUIC overlay via SE_QUIC_ADDR=0.0.0.0:8443 (requires UDP 8443 and quic-overlay feature)
USER nonroot
ENTRYPOINT ["/app/element"]
