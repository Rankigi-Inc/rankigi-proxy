###############################################################################
# Build stage
###############################################################################
FROM rust:1.95-slim AS builder

WORKDIR /build

# Cache deps in their own layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release \
    && rm -rf src target/release/deps/rankigi_proxy* target/release/rankigi-proxy*

# Real build.
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked --bin rankigi-proxy \
    && strip target/release/rankigi-proxy

###############################################################################
# Runtime — distroless static. No shell, no package manager. Binary only.
###############################################################################
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/target/release/rankigi-proxy /usr/local/bin/rankigi-proxy

# Default port; override via RANKIGI_PROXY_PORT.
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rankigi-proxy"]
