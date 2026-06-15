# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.82-slim AS builder

# Build dependencies only (layer-cache friendly)
WORKDIR /build

# Install system packages needed by iroh / ring / OpenSSL transitive deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first so `cargo fetch` is cached independently of source
COPY Cargo.toml Cargo.lock ./

# Create a stub lib so Cargo can resolve the workspace without full source
RUN mkdir -p src && echo "// stub" > src/lib.rs

# Pre-fetch all dependencies (cached unless Cargo.{toml,lock} changes)
RUN cargo fetch

# Now copy the real source
COPY src ./src

# Compile the service binary with both required features, release profile
RUN cargo build --release --features service,sync --bin did-crdt-service

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Runtime CA certs (needed for TLS in iroh P2P connections)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for least-privilege operation
RUN useradd --system --no-create-home --uid 1001 did-crdt

WORKDIR /app

COPY --from=builder /build/target/release/did-crdt-service /app/did-crdt-service

# Persistent storage can be bind-mounted here
VOLUME ["/data"]

USER did-crdt

# ── Configuration via environment variables ───────────────────────────────────
# LISTEN_ADDR  — TCP bind address          (default: 0.0.0.0:8080)
# PEERS        — comma-separated peer list (default: empty)
# STORAGE_PATH — persistent store path     (default: in-memory)
ENV LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["/app/did-crdt-service"]
