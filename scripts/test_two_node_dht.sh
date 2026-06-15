#!/usr/bin/env bash
# Cross-process E2E test: DHT discovery + cold-start bootstrap across two nodes.
#
# What this tests:
#   1. Node A creates a DID and publishes a pkarr TXT record to the relay stub.
#   2. Node B starts cold (no PEERS, empty store) and resolves the same DID.
#   3. Node B's cold_start_bootstrap finds node A via DHT, fetches the genesis
#      bundle over iroh gossip, and returns the document.
#
# Prerequisites: cargo, jq
# Usage: bash scripts/test_two_node_dht.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$REPO_ROOT/target/debug"

RELAY_LOG=$(mktemp /tmp/relay.XXXXXX.log)
NODE_A_LOG=$(mktemp /tmp/node_a.XXXXXX.log)
NODE_B_LOG=$(mktemp /tmp/node_b.XXXXXX.log)
RELAY_PID="" NODE_A_PID="" NODE_B_PID=""

cleanup() {
    [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
    [[ -n "$NODE_A_PID" ]] && kill "$NODE_A_PID" 2>/dev/null || true
    [[ -n "$NODE_B_PID" ]] && kill "$NODE_B_PID" 2>/dev/null || true
    rm -f "$RELAY_LOG" "$NODE_A_LOG" "$NODE_B_LOG"
}
trap cleanup EXIT INT TERM

# ── Build ─────────────────────────────────────────────────────────────────────

echo "[1/6] Building binaries..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --features service,sync 2>&1 | tail -5

# ── Start relay stub ──────────────────────────────────────────────────────────

echo "[2/6] Starting pkarr-relay-stub..."
"$TARGET/pkarr-relay-stub" >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!

RELAY_URL=$(timeout 5 bash -c \
    "until grep -m1 '^READY ' \"$RELAY_LOG\" 2>/dev/null; do sleep 0.1; done" \
    | awk '{print $2}')
if [[ -z "$RELAY_URL" ]]; then
    echo "FAIL: relay stub did not print READY within 5 s" >&2
    exit 1
fi
echo "      relay at $RELAY_URL"

# ── Start node A ──────────────────────────────────────────────────────────────

echo "[3/6] Starting node A..."
LISTEN_ADDR=127.0.0.1:0 \
DHT_RELAY_URL="$RELAY_URL" \
RESOLVE_TIMEOUT_MS=30000 \
    "$TARGET/did-crdt-service" >"$NODE_A_LOG" 2>&1 &
NODE_A_PID=$!

NODE_A_URL=$(timeout 10 bash -c \
    "until grep -m1 '^READY ' \"$NODE_A_LOG\" 2>/dev/null; do sleep 0.1; done" \
    | awk '{print $2}')
if [[ -z "$NODE_A_URL" ]]; then
    echo "FAIL: node A did not print READY within 10 s" >&2
    cat "$NODE_A_LOG" >&2
    exit 1
fi
echo "      node A at $NODE_A_URL"

# ── Create DID on node A ──────────────────────────────────────────────────────

echo "[4/6] Creating DID on node A..."
CREATE_RESPONSE=$(curl -sf -X POST "$NODE_A_URL/dids" \
    -H 'Content-Type: application/json' \
    -d '{"publicKeyMultibase":"zDnaeWJjH6LKtrKLPNTDnFjaAVBxzNxDGURmHuuVHCEF1KPfP"}')
DID=$(echo "$CREATE_RESPONSE" | jq -r '.did')
if [[ -z "$DID" || "$DID" == "null" ]]; then
    echo "FAIL: could not create DID on node A" >&2
    echo "$CREATE_RESPONSE" >&2
    exit 1
fi
echo "      created DID: $DID"

# Give the DHT publish a moment to complete before node B tries to resolve.
sleep 0.5

# ── Start node B ──────────────────────────────────────────────────────────────

echo "[5/6] Starting node B (cold — no PEERS, empty store)..."
LISTEN_ADDR=127.0.0.1:0 \
DHT_RELAY_URL="$RELAY_URL" \
RESOLVE_TIMEOUT_MS=30000 \
    "$TARGET/did-crdt-service" >"$NODE_B_LOG" 2>&1 &
NODE_B_PID=$!

NODE_B_URL=$(timeout 10 bash -c \
    "until grep -m1 '^READY ' \"$NODE_B_LOG\" 2>/dev/null; do sleep 0.1; done" \
    | awk '{print $2}')
if [[ -z "$NODE_B_URL" ]]; then
    echo "FAIL: node B did not print READY within 10 s" >&2
    cat "$NODE_B_LOG" >&2
    exit 1
fi
echo "      node B at $NODE_B_URL"

# ── Resolve DID on node B ─────────────────────────────────────────────────────

echo "[6/6] Resolving DID on node B via DHT cold-start..."
# cold_start_bootstrap runs synchronously inside the GET handler (bounded by
# RESOLVE_TIMEOUT_MS); curl --retry covers transient failures around startup.
RESOLVE_RESPONSE=$(curl -sf \
    --retry 20 --retry-delay 1 --retry-all-errors \
    --max-time 35 \
    "$NODE_B_URL/$DID") || {
    echo "FAIL: node B could not resolve DID within timeout" >&2
    echo "node B log:" >&2
    cat "$NODE_B_LOG" >&2
    exit 1
}

RESOLVED_ID=$(echo "$RESOLVE_RESPONSE" | jq -r '.didDocument.id // empty')
if [[ "$RESOLVED_ID" != "$DID" ]]; then
    echo "FAIL: resolved document id '$RESOLVED_ID' does not match expected '$DID'" >&2
    echo "$RESOLVE_RESPONSE" >&2
    exit 1
fi

echo ""
echo "PASS: node B resolved $DID via DHT cold-start bootstrap"
