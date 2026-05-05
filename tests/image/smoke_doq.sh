#!/usr/bin/env bash
# DoQ smoke test — verifies that the heimdall container serves DNS-over-QUIC
# (RFC 9250) over QUIC v1 with valid stream framing.
# Sprint 48 task #546.
#
# Usage:
#   tests/image/smoke_doq.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DoQ to respond (default: 15)
#   DOQ_PORT        Host UDP port mapped to the container DoQ listener (default: 8853)
#
# Requires: docker, openssl, kdig (knot-dnsutils ≥ 3.0 with QUIC/DoQ support)
# QUIC is UDP-based; on macOS/colima UDP port mapping is unreliable so the
# test is auto-skipped (SKIP_DOQ=1) unless running on Linux.

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DOQ_PORT="${DOQ_PORT:-8853}"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."

# ── Platform detection ────────────────────────────────────────────────────────
# QUIC uses UDP; colima does not forward UDP ports reliably on macOS.
SKIP_DOQ="${SKIP_DOQ:-0}"
if [[ "$(uname -s)" == "Darwin" && "${SKIP_DOQ}" != "1" ]]; then
    SKIP_DOQ=1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v openssl >/dev/null || fail "openssl not found in PATH"

if [[ "$SKIP_DOQ" == "1" ]]; then
    skip "DoQ smoke skipped (macOS/colima: UDP port mapping unreliable; CI on Linux covers this)"
    exit 0
fi

command -v kdig >/dev/null || fail "kdig not found in PATH (install knot-dnsutils ≥ 3.0 with QUIC support)"

# Verify kdig has QUIC/DoQ support (kdig --help output contains 'quic').
if ! kdig --help 2>&1 | grep -qi "quic"; then
    skip "kdig does not report QUIC support (install knot-dnsutils ≥ 3.0 built with QUIC)"
    exit 0
fi

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Generate test PKI ─────────────────────────────────────────────────────────

PKI_DIR=$(mktemp -d)

CA_KEY="$PKI_DIR/ca-key.pem"
CA_CERT="$PKI_DIR/ca-cert.pem"
SERVER_KEY="$PKI_DIR/server-key.pem"
SERVER_CSR="$PKI_DIR/server.csr"
SERVER_CERT="$PKI_DIR/server-cert.pem"
SAN_CNF="$PKI_DIR/san.cnf"
DOQ_CFG="$PKI_DIR/heimdall-doq.toml"

info "Generating test PKI in $PKI_DIR"

openssl genrsa -out "$CA_KEY" 2048 2>/dev/null
openssl req -new -x509 -days 365 \
    -key "$CA_KEY" -out "$CA_CERT" \
    -subj "/CN=Heimdall Smoke Test CA" 2>/dev/null

openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/CN=127.0.0.1" 2>/dev/null

cat > "$SAN_CNF" <<'EOF'
[SAN]
subjectAltName=IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -days 365 \
    -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" \
    -extfile "$SAN_CNF" -extensions SAN 2>/dev/null

info "Test PKI generated"

# ── Write DoQ config ──────────────────────────────────────────────────────────

cat > "$DOQ_CFG" <<EOF
# Configuration for DoQ smoke test (task #546).
# DoQ listener only; serves example.com from a test zone.

[[listeners]]
address   = "0.0.0.0"
port      = ${DOQ_PORT}
transport = "doq"
tls_cert  = "/etc/heimdall/tls/server-cert.pem"
tls_key   = "/etc/heimdall/tls/server-key.pem"

[roles]
authoritative = true

[zones]
[[zones.zone_files]]
origin = "example.com."
path   = "/etc/heimdall/zones/example.com.zone"

[cache]
capacity     = 256
min_ttl_secs = 1
max_ttl_secs = 300

[rate_limit]
enabled = false

[observability]
metrics_addr = "127.0.0.1"
metrics_port = 9090

[admin]
admin_port = 9091
EOF

# ── Start container ───────────────────────────────────────────────────────────

CONTAINER_ID=""
cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        info "Stopping container $CONTAINER_ID"
        docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
        docker rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$PKI_DIR"
}
trap cleanup EXIT

info "Starting $IMAGE with DoQ listener on port ${DOQ_PORT}/udp"
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DOQ_PORT}:${DOQ_PORT}/udp" \
    -v "${DOQ_CFG}:/etc/heimdall/heimdall.toml:ro" \
    -v "${SERVER_CERT}:/etc/heimdall/tls/server-cert.pem:ro" \
    -v "${SERVER_KEY}:/etc/heimdall/tls/server-key.pem:ro" \
    -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for DoQ readiness ────────────────────────────────────────────────────
# Poll with kdig --quic until NOERROR or timeout.

info "Waiting up to ${READY_TIMEOUT}s for DoQ port ${DOQ_PORT}/udp to respond..."
ELAPSED=0
while true; do
    DOQ_CHECK=$(kdig +quic +noall +comments \
        @127.0.0.1 -p "${DOQ_PORT}" \
        --tls-ca="${CA_CERT}" \
        "${EXPECTED_ZONE}" A 2>/dev/null \
        | grep "status:" | sed 's/.*status: \([A-Z]*\).*/\1/' || true)

    if [[ "$DOQ_CHECK" == "NOERROR" ]]; then
        pass "DoQ port ${DOQ_PORT}/udp is responding (NOERROR)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        info "Container logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -30
        fail "DoQ port ${DOQ_PORT}/udp did not respond with NOERROR within ${READY_TIMEOUT}s (last: ${DOQ_CHECK:-no response})"
    fi
    sleep 1
done

# ── DoQ query: example.com A ──────────────────────────────────────────────────

info "DoQ QUIC v1: kdig +quic @127.0.0.1 -p ${DOQ_PORT} ${EXPECTED_ZONE} A"
DOQ_FLAGS=$(kdig +quic +noall +comments \
    @127.0.0.1 -p "${DOQ_PORT}" \
    --tls-ca="${CA_CERT}" \
    "${EXPECTED_ZONE}" A 2>&1)
DOQ_RDATA=$(kdig +quic +short \
    @127.0.0.1 -p "${DOQ_PORT}" \
    --tls-ca="${CA_CERT}" \
    "${EXPECTED_ZONE}" A 2>&1)

info "DoQ status: $(echo "$DOQ_FLAGS" | grep 'status:' || echo 'none')"

echo "$DOQ_FLAGS" | grep -q "NOERROR"  || fail "DoQ: expected NOERROR\n$DOQ_FLAGS"
echo "$DOQ_FLAGS" | grep -qi "\baa\b"  || fail "DoQ: expected AA flag\n$DOQ_FLAGS"
echo "$DOQ_RDATA" | grep -q "${EXPECTED_IP}" \
    || fail "DoQ: expected RDATA ${EXPECTED_IP}, got: ${DOQ_RDATA}"
pass "DoQ QUIC v1: NOERROR + AA + RDATA ${EXPECTED_IP}"

# ── QUIC v2 rejection note ────────────────────────────────────────────────────
# RFC 9250 requires QUIC v1. Heimdall only accepts QUIC v1; kdig does not
# expose a --quic-version flag to force QUIC v2. The rejection is inherently
# enforced by quinn's version negotiation: a QUIC v2 InitialPacket produces
# a VERSION_NEGOTIATION response listing v1, which is a rejection. There is
# no readily available CLI tool to inject a QUIC v2 packet; this is covered
# by the DoQ hardening integration tests (task #581).

info "QUIC v2 rejection: enforced by quinn VERSION_NEGOTIATION (covered by task #581 integration tests)"

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All DoQ smoke checks passed for image: $IMAGE"
