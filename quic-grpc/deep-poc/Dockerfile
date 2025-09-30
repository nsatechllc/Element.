FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git cmake ninja-build pkg-config libssl-dev clang curl ca-certificates \
    python3 python3-pip libclang-dev gcc g++ unzip wget libz-dev libelf-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /opt/liboqs && \
    cd /opt/liboqs && mkdir build && cd build && cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && ninja && ninja install

# Placeholder for building rustls-oqs or OQS-OpenSSL if needed
WORKDIR /work

# (quic-demo removed) leaving image at /work for future build steps
CMD ["/bin/bash"]
