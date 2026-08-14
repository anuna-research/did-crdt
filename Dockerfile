# ── Stage 1: builder ──────────────────────────────────────────────────────────
# Pinned to a bookworm-based toolchain so the produced binary links against the
# same glibc as the bookworm-slim runtime below.
FROM rust:1.96-slim-bookworm AS builder

WORKDIR /build

# System packages needed by transitive native deps:
#   openssl-sys → pkg-config, libssl-dev
#   ring        → cc, perl
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        build-essential \
        perl \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency compilation is cached independently of source.
COPY Cargo.toml Cargo.lock ./

# Cargo parses the *whole* manifest before it will fetch or build anything, and
# it errors on any `[[bin]]`/`[[bench]]`/`[[example]]` whose file is missing.
# Every declared target therefore needs a stub at this layer, not just the lib.
RUN mkdir -p src/bin benches examples \
    && echo "// stub" > src/lib.rs \
    && for f in src/bin/did-crdt-service.rs \
                src/bin/pkarr-relay-stub.rs \
                benches/merge.rs \
                benches/resolve.rs \
                examples/two_node_demo.rs; do \
           echo "fn main() {}" > "$f"; \
       done

# Compile the full dependency graph against the stubs. This is the expensive
# layer (iroh + friends) and it is invalidated only by Cargo.{toml,lock}.
RUN cargo build --release --locked --features service,sync --bin did-crdt-service

# Now the real source. Only the did-crdt crate itself recompiles.
COPY src ./src

# COPY refreshes mtimes, but touch the crate roots explicitly so Cargo cannot
# reuse the stub fingerprint.
RUN touch src/lib.rs src/bin/did-crdt-service.rs \
    && cargo build --release --locked --features service,sync --bin did-crdt-service

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# CA certs for the pkarr HTTPS relay and iroh TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --uid 1001 did-crdt

WORKDIR /app

COPY --from=builder /build/target/release/did-crdt-service /app/did-crdt-service

# Fly mounts volumes root-owned, so the unprivileged user cannot write to the
# mountpoint as-is. Start as root purely to fix ownership, then drop privileges
# before exec'ing the service — the process itself never runs as root.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'if [ -d /data ]; then chown -R 1001:1001 /data; fi' \
    'exec setpriv --reuid=1001 --regid=1001 --init-groups /app/did-crdt-service "$@"' \
    > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

VOLUME ["/data"]

# ── Configuration via environment variables ───────────────────────────────────
# LISTEN_ADDR  — TCP bind address          (default: 0.0.0.0:8080)
# PEERS        — comma-separated peer list (default: empty)
# STORAGE_PATH — persistent store dir      (default: unset ⇒ in-memory only)
ENV LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
