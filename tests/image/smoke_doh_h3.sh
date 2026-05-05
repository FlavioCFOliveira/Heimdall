#!/usr/bin/env bash
# DoH HTTP/3 smoke test — verifies that the heimdall container serves
# DNS-over-HTTPS (RFC 8484) over HTTP/3 (QUIC) for GET and POST, and that
# DoH/H2 responses include an Alt-Svc header advertising the H3 endpoint.
# Sprint 48 task #486.
#
# Usage:
#   tests/image/smoke_doh_h3.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DoH to respond (default: 15)
#   DOH_H2_PORT     Host port mapped to the container DoH/H2 listener (default: 8444)
#   DOH_H3_PORT     Host port mapped to the container DoH/H3 QUIC listener (default: 8445)
#
# Requires: docker, openssl, curl (with HTTP/3+QUIC via ngtcp2 or quiche), python3
# If curl lacks HTTP/3 support the H3 query checks are skipped with a SKIP notice;
# the Alt-Svc check from the H2 path always runs.

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DOH_H2_PORT="${DOH_H2_PORT:-8444}"
DOH_H3_PORT="${DOH_H3_PORT:-8445}"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."
DOH_PATH="/dns-query"

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Detect HTTP/3 support in curl ─────────────────────────────────────────────

CURL_HAS_H3=0
if curl --version 2>&1 | grep -qiE "nghttp3|ngtcp2|quiche|HTTP3|http/3"; then
    CURL_HAS_H3=1
fi

# ── Detect macOS: QUIC uses UDP; colima UDP port mapping is unreliable ────────
SKIP_H3="${SKIP_H3:-0}"
if [[ "$(uname -s)" == "Darwin" && "$SKIP_H3" != "1" ]]; then
    SKIP_H3=1
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v openssl >/dev/null || fail "openssl not found in PATH"
command -v curl    >/dev/null || fail "curl not found in PATH"
command -v python3 >/dev/null || fail "python3 not found in PATH"

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Generate test PKI ─────────────────────────────────────────────────────────

PKI_DIR=$(mktemp -d)

CA_KEY="$PKI_DIR/ca-key.pem"
CA_CERT="$PKI_DIR/ca-cert.pem"
SERVER_KEY="$PKI_DIR/server-key.pem"
SERVER_CSR="$PKI_DIR/server.csr"
SERVER_CERT="$PKI_DIR/server-cert.pem"
SAN_CNF="$PKI_DIR/san.cnf"
DOH_CFG="$PKI_DIR/heimdall-doh-h3.toml"

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

# ── Write DoH H2 + H3 config ──────────────────────────────────────────────────
# DoH/H2 listener: TCP, advertises H3 via Alt-Svc.
# DoH/H3 listener: QUIC/UDP, same cert/key.

cat > "$DOH_CFG" <<EOF
# Configuration for DoH HTTP/3 smoke test (task #486).
# Both H2 and H3 listeners on separate ports; H2 advertises H3 via Alt-Svc.

[[listeners]]
address   = "0.0.0.0"
port      = ${DOH_H2_PORT}
transport = "doh"
tls_cert  = "/etc/heimdall/tls/server-cert.pem"
tls_key   = "/etc/heimdall/tls/server-key.pem"
alt_svc   = "h3=\":${DOH_H3_PORT}\""

[[listeners]]
address   = "0.0.0.0"
port      = ${DOH_H3_PORT}
transport = "doh3"
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

# ── Build DNS wire-format query ───────────────────────────────────────────────

QUERY_B64=$(python3 - <<'PYEOF'
import struct, base64, sys
header   = struct.pack('>HHHHHH', 0xABCD, 0x0100, 1, 0, 0, 0)
qname    = b'\x07example\x03com\x00'
question = qname + struct.pack('>HH', 1, 1)
wire     = header + question
print(base64.urlsafe_b64encode(wire).decode().rstrip('='), end='')
PYEOF
)

QUERY_WIRE_FILE="$PKI_DIR/query.bin"
python3 - "$QUERY_WIRE_FILE" <<'PYEOF'
import struct, sys
wire_path = sys.argv[1]
header   = struct.pack('>HHHHHH', 0xABCD, 0x0100, 1, 0, 0, 0)
qname    = b'\x07example\x03com\x00'
question = qname + struct.pack('>HH', 1, 1)
with open(wire_path, 'wb') as f:
    f.write(header + question)
PYEOF

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

info "Starting $IMAGE with DoH/H2 on port ${DOH_H2_PORT} and DoH/H3 on port ${DOH_H3_PORT}"
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DOH_H2_PORT}:${DOH_H2_PORT}/tcp" \
    -p "127.0.0.1:${DOH_H3_PORT}:${DOH_H3_PORT}/udp" \
    -v "${DOH_CFG}:/etc/heimdall/heimdall.toml:ro" \
    -v "${SERVER_CERT}:/etc/heimdall/tls/server-cert.pem:ro" \
    -v "${SERVER_KEY}:/etc/heimdall/tls/server-key.pem:ro" \
    -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for DoH/H2 readiness ─────────────────────────────────────────────────

info "Waiting up to ${READY_TIMEOUT}s for DoH/H2 port ${DOH_H2_PORT}..."
ELAPSED=0
while true; do
    HTTP_CODE=$(curl --silent --output /dev/null \
        --write-out "%{http_code}" \
        --http2 \
        --cacert "$CA_CERT" \
        --max-time 2 \
        "https://127.0.0.1:${DOH_H2_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
        -H "Accept: application/dns-message" 2>/dev/null || true)
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "DoH/H2 port ${DOH_H2_PORT} is ready (HTTP 200)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        info "Container logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -30
        fail "DoH/H2 port ${DOH_H2_PORT} did not respond within ${READY_TIMEOUT}s (last: ${HTTP_CODE:-none})"
    fi
    sleep 1
done

# ── Alt-Svc check from H2 path ────────────────────────────────────────────────

info "Alt-Svc check: GET via DoH/H2, verify Alt-Svc header advertises H3"
TMPHDRS="$PKI_DIR/h2-headers.txt"
curl --silent \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    -D "$TMPHDRS" \
    -o /dev/null \
    "https://127.0.0.1:${DOH_H2_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
    -H "Accept: application/dns-message"

ALT_SVC_VAL=$(grep -i "^alt-svc:" "$TMPHDRS" | tr -d '\r\n' | sed 's/[Aa][Ll][Tt]-[Ss][Vv][Cc]: //')
info "Alt-Svc: $ALT_SVC_VAL"

[[ -n "$ALT_SVC_VAL" ]] \
    || fail "Alt-Svc header absent from DoH/H2 response"
echo "$ALT_SVC_VAL" | grep -q "h3=" \
    || fail "Alt-Svc does not advertise h3; got: $ALT_SVC_VAL"
pass "Alt-Svc header present in DoH/H2 response: $ALT_SVC_VAL"

# ── DoH H3 GET + POST ─────────────────────────────────────────────────────────

if [[ "$SKIP_H3" == "1" ]]; then
    skip "DoH/H3 query checks skipped (macOS/colima: UDP port mapping unreliable; CI on Linux covers this)"
elif [[ "$CURL_HAS_H3" == "0" ]]; then
    skip "DoH/H3 query checks skipped (curl not built with HTTP/3 support; install curl+ngtcp2 or curl+quiche)"
else
    RESPONSE_FILE="$PKI_DIR/response-h3.bin"

    # ── H3 GET ────────────────────────────────────────────────────────────────
    info "DoH/H3 GET: curl --http3"
    TMPHDRS_H3="$PKI_DIR/h3-get-headers.txt"
    curl --silent \
        --http3 \
        --cacert "$CA_CERT" \
        --max-time 10 \
        -D "$TMPHDRS_H3" \
        -o "$RESPONSE_FILE" \
        "https://127.0.0.1:${DOH_H3_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
        -H "Accept: application/dns-message"

    H3_STATUS=$(grep -i "^HTTP/" "$TMPHDRS_H3" | head -1 | grep -o "[0-9]*$" | head -1 || echo "000")
    H3_CT=$(grep -i "^content-type:" "$TMPHDRS_H3" | tr -d '\r\n' | sed 's/.*: //')
    H3_CC=$(grep -i "^cache-control:" "$TMPHDRS_H3" | tr -d '\r\n' | sed 's/.*: //')

    info "H3 GET status: $H3_STATUS Content-Type: $H3_CT Cache-Control: $H3_CC"

    [[ "$H3_STATUS" == "200" ]] \
        || fail "DoH/H3 GET: expected HTTP 200, got $H3_STATUS"
    echo "$H3_CT" | grep -q "application/dns-message" \
        || fail "DoH/H3 GET: expected Content-Type application/dns-message, got: $H3_CT"
    echo "$H3_CC" | grep -q "max-age=" \
        || fail "DoH/H3 GET: expected Cache-Control max-age=<TTL>, got: $H3_CC"

    python3 - "$RESPONSE_FILE" "$EXPECTED_IP" <<'PYEOF'
import struct, sys, ipaddress
data = open(sys.argv[1], 'rb').read()
if len(data) < 12: sys.exit(f"FAIL: response too short ({len(data)} bytes)")
flags = struct.unpack('>H', data[2:4])[0]
if not (flags >> 15) & 1: sys.exit("FAIL: QR bit not set")
if flags & 0x0F != 0: sys.exit(f"FAIL: RCODE={flags & 0x0F}")
if ipaddress.IPv4Address(sys.argv[2]).packed not in data[12:]: sys.exit(f"FAIL: RDATA {sys.argv[2]} not found")
print(f"OK: QR=1 RCODE=0 RDATA={sys.argv[2]}")
PYEOF
    pass "DoH/H3 GET: HTTP 200 + application/dns-message + Cache-Control + valid DNS response"

    # ── H3 POST ───────────────────────────────────────────────────────────────
    info "DoH/H3 POST: curl --http3"
    TMPHDRS_H3P="$PKI_DIR/h3-post-headers.txt"
    RESPONSE_POST="$PKI_DIR/response-h3-post.bin"
    curl --silent \
        --http3 \
        --cacert "$CA_CERT" \
        --max-time 10 \
        -X POST \
        -H "Content-Type: application/dns-message" \
        -H "Accept: application/dns-message" \
        --data-binary "@${QUERY_WIRE_FILE}" \
        -D "$TMPHDRS_H3P" \
        -o "$RESPONSE_POST" \
        "https://127.0.0.1:${DOH_H3_PORT}${DOH_PATH}"

    H3P_STATUS=$(grep -i "^HTTP/" "$TMPHDRS_H3P" | head -1 | grep -o "[0-9]*$" | head -1 || echo "000")
    H3P_CT=$(grep -i "^content-type:" "$TMPHDRS_H3P" | tr -d '\r\n' | sed 's/.*: //')

    [[ "$H3P_STATUS" == "200" ]] \
        || fail "DoH/H3 POST: expected HTTP 200, got $H3P_STATUS"
    echo "$H3P_CT" | grep -q "application/dns-message" \
        || fail "DoH/H3 POST: expected Content-Type application/dns-message, got: $H3P_CT"

    python3 - "$RESPONSE_POST" "$EXPECTED_IP" <<'PYEOF'
import struct, sys, ipaddress
data = open(sys.argv[1], 'rb').read()
if len(data) < 12: sys.exit(f"FAIL: response too short ({len(data)} bytes)")
flags = struct.unpack('>H', data[2:4])[0]
if not (flags >> 15) & 1: sys.exit("FAIL: QR bit not set")
if flags & 0x0F != 0: sys.exit(f"FAIL: RCODE={flags & 0x0F}")
if ipaddress.IPv4Address(sys.argv[2]).packed not in data[12:]: sys.exit(f"FAIL: RDATA {sys.argv[2]} not found")
print(f"OK: QR=1 RCODE=0 RDATA={sys.argv[2]}")
PYEOF
    pass "DoH/H3 POST: HTTP 200 + application/dns-message + valid DNS response"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All DoH H3 smoke checks passed for image: $IMAGE"
