#!/usr/bin/env bash
# DoT smoke test — verifies that the heimdall container serves DNS-over-TLS
# (RFC 7858) with TLS 1.3 and rejects TLS 1.2 connections.
# Sprint 48 task #484.
#
# Usage:
#   tests/image/smoke_dot.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DoT to respond (default: 15)
#   DOT_PORT        Host port mapped to the container DoT listener (default: 8853)
#
# Requires: docker, openssl, kdig (knot-dnsutils / knot)

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DOT_PORT="${DOT_PORT:-8853}"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v openssl >/dev/null || fail "openssl not found in PATH"
command -v kdig    >/dev/null || fail "kdig not found in PATH (install knot-dnsutils or knot)"

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Generate test PKI ─────────────────────────────────────────────────────────

PKI_DIR=$(mktemp -d)
cleanup_pki() { rm -rf "$PKI_DIR"; }

CA_KEY="$PKI_DIR/ca-key.pem"
CA_CERT="$PKI_DIR/ca-cert.pem"
SERVER_KEY="$PKI_DIR/server-key.pem"
SERVER_CSR="$PKI_DIR/server.csr"
SERVER_CERT="$PKI_DIR/server-cert.pem"
SAN_CNF="$PKI_DIR/san.cnf"
DOT_CFG="$PKI_DIR/heimdall-dot.toml"

info "Generating test PKI in $PKI_DIR"

# Root CA
openssl genrsa -out "$CA_KEY" 2048 2>/dev/null
openssl req -new -x509 -days 365 \
    -key "$CA_KEY" -out "$CA_CERT" \
    -subj "/CN=Heimdall Smoke Test CA" 2>/dev/null

# Server key + CSR
openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/CN=localhost" 2>/dev/null

# SAN extension. Includes DNS:localhost (required because RFC 6066 §3 forbids
# IP-literal Server Name Indication; rustls follows the spec and ignores or
# rejects ServerName extensions that carry an IPv4/IPv6 address). The IP SAN
# is kept in addition so any client that still validates against the literal
# 127.0.0.1 (the connect target) continues to succeed.
cat > "$SAN_CNF" <<'EOF'
[SAN]
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

# Sign server cert
openssl x509 -req -days 365 \
    -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" \
    -extfile "$SAN_CNF" -extensions SAN 2>/dev/null

# The container runs as the distroless `nonroot` user (UID 65532) and mounts
# the PKI files read-only via bind volumes.  openssl creates the key with mode
# 0600, which the container user cannot read; widen the permissions on these
# ephemeral test artefacts so the bind mount remains readable inside the
# container.  The PKI exists only for the duration of this smoke test.
chmod 0644 "$CA_KEY" "$CA_CERT" "$SERVER_KEY" "$SERVER_CERT"

info "Test PKI generated"

# ── Write DoT config ──────────────────────────────────────────────────────────

cat > "$DOT_CFG" <<EOF
# Configuration for DoT smoke test (task #484).
# DoT listener only; serves example.com from a test zone.

[[listeners]]
address   = "0.0.0.0"
port      = ${DOT_PORT}
transport = "dot"
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
    cleanup_pki
}
trap cleanup EXIT

info "Starting $IMAGE with DoT listener on port ${DOT_PORT}"
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DOT_PORT}:${DOT_PORT}/tcp" \
    -v "${DOT_CFG}:/etc/heimdall/heimdall.toml:ro" \
    -v "${SERVER_CERT}:/etc/heimdall/tls/server-cert.pem:ro" \
    -v "${SERVER_KEY}:/etc/heimdall/tls/server-key.pem:ro" \
    -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for DoT port to accept TCP connections ───────────────────────────────

info "Waiting up to ${READY_TIMEOUT}s for DoT port ${DOT_PORT} to accept connections..."
# Probe via kdig instead of openssl s_client: rustls is TLS-1.3-only and requires
# SNI; openssl s_client without an explicit -servername stalls the handshake on
# IP-literal connects, which manifested as a 15-s timeout even after the listener
# was bound. kdig uses dig-style "+option" syntax for its TLS extras (the GNU
# long-option form "--tls-hostname=" is not recognised — kdig treats it as a
# parse error and prints help, which previously hid behind a stderr redirect).
# We pass +tls-hostname=localhost (matching the DNS:localhost SAN on the test
# cert) because RFC 6066 §3 forbids IP-literal SNI and rustls enforces that
# restriction.
LAST_KDIG_ERR=""
ELAPSED=0
while true; do
    if KDIG_ERR=$(kdig +tls +retry=1 +timeout=1 \
            @127.0.0.1 -p "${DOT_PORT}" \
            +tls-ca="${CA_CERT}" \
            +tls-hostname=localhost \
            +short \
            "${EXPECTED_ZONE}" A 2>&1) ; then
        pass "DoT port ${DOT_PORT} accepts TLS queries (readiness)"
        break
    fi
    LAST_KDIG_ERR="$KDIG_ERR"
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        info "Last kdig output:"
        printf '  %s\n' "$LAST_KDIG_ERR"
        info "Container status: $(docker inspect -f '{{.State.Status}} (exited: {{.State.ExitCode}})' "$CONTAINER_ID" 2>&1 || echo unknown)"
        info "Container logs (tail 60):"
        docker logs "$CONTAINER_ID" 2>&1 | tail -60
        fail "DoT port ${DOT_PORT} did not accept TLS connections within ${READY_TIMEOUT}s"
    fi
    sleep 1
done

# ── DoT TLS 1.3 query ─────────────────────────────────────────────────────────

info "DoT TLS 1.3: kdig +tls @127.0.0.1 -p ${DOT_PORT} ${EXPECTED_ZONE} A"
DOT_FLAGS=$(kdig +tls +noall +comments \
    @127.0.0.1 -p "${DOT_PORT}" \
    +tls-ca="${CA_CERT}" \
    +tls-hostname=localhost \
    "${EXPECTED_ZONE}" A 2>&1)
DOT_RDATA=$(kdig +tls +short \
    @127.0.0.1 -p "${DOT_PORT}" \
    +tls-ca="${CA_CERT}" \
    +tls-hostname=localhost \
    "${EXPECTED_ZONE}" A 2>&1)

info "DoT status: $(echo "$DOT_FLAGS" | grep 'status:' || echo 'none')"

echo "$DOT_FLAGS" | grep -q "NOERROR"  || fail "DoT: expected NOERROR\n$DOT_FLAGS"
echo "$DOT_FLAGS" | grep -qi "\baa\b"  || fail "DoT: expected AA flag\n$DOT_FLAGS"
echo "$DOT_RDATA" | grep -q "${EXPECTED_IP}" \
    || fail "DoT: expected RDATA ${EXPECTED_IP}, got: ${DOT_RDATA}"
pass "DoT TLS 1.3: NOERROR + AA + RDATA ${EXPECTED_IP}"

# ── TLS 1.2 rejection ─────────────────────────────────────────────────────────
# heimdall is configured with TLS 1.3-only (rustls builder_with_protocol_versions(&[TLS13])).
# A TLS 1.2 ClientHello must result in a handshake failure.

info "TLS 1.2 rejection: openssl s_client -tls1_2 against port ${DOT_PORT}"
TLS12_OUT=$(echo "" | timeout 5 openssl s_client \
    -connect "127.0.0.1:${DOT_PORT}" \
    -tls1_2 \
    -quiet 2>&1 || true)

if echo "$TLS12_OUT" | grep -qiE "handshake failure|protocol version|alert|ssl alert|no protocols|connection refused|errno|error"; then
    pass "TLS 1.2 rejected by server (no shared protocol)"
elif echo "$TLS12_OUT" | grep -q "CONNECTED"; then
    fail "TLS 1.2 should have been rejected but TLS handshake succeeded\n$TLS12_OUT"
else
    # Connection closed without a successful handshake is also a rejection.
    pass "TLS 1.2 rejected by server (connection closed without handshake)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All DoT smoke checks passed for image: $IMAGE"
