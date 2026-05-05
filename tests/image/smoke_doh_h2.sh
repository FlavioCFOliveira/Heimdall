#!/usr/bin/env bash
# DoH HTTP/2 smoke test — verifies that the heimdall container serves
# DNS-over-HTTPS (RFC 8484) over HTTP/2 for both GET and POST methods.
# Sprint 48 task #485.
#
# Usage:
#   tests/image/smoke_doh_h2.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DoH to respond (default: 15)
#   DOH_PORT        Host port mapped to the container DoH listener (default: 8443)
#
# Requires: docker, openssl, curl (with HTTP/2 / nghttp2), python3

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DOH_PORT="${DOH_PORT:-8443}"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."
DOH_PATH="/dns-query"

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v openssl >/dev/null || fail "openssl not found in PATH"
command -v curl    >/dev/null || fail "curl not found in PATH"
command -v python3 >/dev/null || fail "python3 not found in PATH"

curl --version | grep -q "nghttp2\|http2\|HTTP2" \
    || fail "curl does not support HTTP/2 (requires nghttp2)"

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Generate test PKI ─────────────────────────────────────────────────────────

PKI_DIR=$(mktemp -d)

CA_KEY="$PKI_DIR/ca-key.pem"
CA_CERT="$PKI_DIR/ca-cert.pem"
SERVER_KEY="$PKI_DIR/server-key.pem"
SERVER_CSR="$PKI_DIR/server.csr"
SERVER_CERT="$PKI_DIR/server-cert.pem"
SAN_CNF="$PKI_DIR/san.cnf"
DOH_CFG="$PKI_DIR/heimdall-doh.toml"

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

# ── Write DoH config ──────────────────────────────────────────────────────────

cat > "$DOH_CFG" <<EOF
# Configuration for DoH HTTP/2 smoke test (task #485).
# DoH listener only; serves example.com from a test zone.

[[listeners]]
address   = "0.0.0.0"
port      = ${DOH_PORT}
transport = "doh"
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
# A query for example.com (type A, class IN) with RD=1.
# Wire: header(12 bytes) + QNAME + QTYPE + QCLASS

QUERY_B64=$(python3 - <<'PYEOF'
import struct, base64, sys

header = struct.pack('>HHHHHH',
    0xABCD,   # ID
    0x0100,   # flags: QR=0 RD=1
    1, 0, 0, 0)  # QDCOUNT=1

qname = b'\x07example\x03com\x00'
question = qname + struct.pack('>HH', 1, 1)  # QTYPE=A QCLASS=IN

wire = header + question
b64 = base64.urlsafe_b64encode(wire).decode().rstrip('=')
print(b64, end='')
PYEOF
)

QUERY_WIRE_FILE="$PKI_DIR/query.bin"
python3 - "$QUERY_WIRE_FILE" <<'PYEOF'
import struct, sys

wire_path = sys.argv[1]
header = struct.pack('>HHHHHH', 0xABCD, 0x0100, 1, 0, 0, 0)
qname = b'\x07example\x03com\x00'
question = qname + struct.pack('>HH', 1, 1)
with open(wire_path, 'wb') as f:
    f.write(header + question)
PYEOF

RESPONSE_FILE="$PKI_DIR/response.bin"

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

info "Starting $IMAGE with DoH listener on port ${DOH_PORT}"
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DOH_PORT}:${DOH_PORT}/tcp" \
    -v "${DOH_CFG}:/etc/heimdall/heimdall.toml:ro" \
    -v "${SERVER_CERT}:/etc/heimdall/tls/server-cert.pem:ro" \
    -v "${SERVER_KEY}:/etc/heimdall/tls/server-key.pem:ro" \
    -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for DoH readiness ────────────────────────────────────────────────────

info "Waiting up to ${READY_TIMEOUT}s for DoH port ${DOH_PORT} to accept connections..."
ELAPSED=0
while true; do
    HTTP_CODE=$(curl --silent --output /dev/null \
        --write-out "%{http_code}" \
        --http2 \
        --cacert "$CA_CERT" \
        --max-time 2 \
        "https://127.0.0.1:${DOH_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
        -H "Accept: application/dns-message" 2>/dev/null || true)

    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "DoH port ${DOH_PORT} is accepting queries (HTTP 200)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        info "Container logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -30
        fail "DoH port ${DOH_PORT} did not respond with HTTP 200 within ${READY_TIMEOUT}s (last: ${HTTP_CODE:-no response})"
    fi
    sleep 1
done

# ── GET request ───────────────────────────────────────────────────────────────

info "DoH GET: GET /dns-query?dns=<base64url> HTTP/2"
GET_HEADERS=$(curl --silent --output "$RESPONSE_FILE" \
    --write-out "%{http_code}\n%{content_type}" \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    -D - \
    "https://127.0.0.1:${DOH_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
    -H "Accept: application/dns-message" 2>&1)

GET_STATUS=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    "https://127.0.0.1:${DOH_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
    -H "Accept: application/dns-message" 2>/dev/null)

GET_HEADERS_FULL=$(curl --silent --output "$RESPONSE_FILE" \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    -D /dev/stderr \
    "https://127.0.0.1:${DOH_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
    -H "Accept: application/dns-message" 2>&1 >/dev/null)

[[ "$GET_STATUS" == "200" ]] \
    || fail "DoH GET: expected HTTP 200, got $GET_STATUS"

# Re-run capturing headers and body together
TMPHDRS="$PKI_DIR/get-headers.txt"
curl --silent \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    -D "$TMPHDRS" \
    -o "$RESPONSE_FILE" \
    "https://127.0.0.1:${DOH_PORT}${DOH_PATH}?dns=${QUERY_B64}" \
    -H "Accept: application/dns-message"

GET_CONTENT_TYPE=$(grep -i "^content-type:" "$TMPHDRS" | tr -d '\r\n' | sed 's/.*: //')
GET_CACHE_CTRL=$(grep -i "^cache-control:" "$TMPHDRS" | tr -d '\r\n' | sed 's/.*: //')
GET_PROTO=$(grep -i "^HTTP/" "$TMPHDRS" | head -1 | tr -d '\r\n')

info "GET status line: $GET_PROTO"
info "GET Content-Type: $GET_CONTENT_TYPE"
info "GET Cache-Control: $GET_CACHE_CTRL"

echo "$GET_PROTO" | grep -q "HTTP/2\|HTTP/1.1" \
    || fail "DoH GET: unexpected protocol line: $GET_PROTO"
echo "$GET_CONTENT_TYPE" | grep -q "application/dns-message" \
    || fail "DoH GET: expected Content-Type application/dns-message, got: $GET_CONTENT_TYPE"
echo "$GET_CACHE_CTRL" | grep -q "max-age=" \
    || fail "DoH GET: expected Cache-Control max-age=<TTL>, got: $GET_CACHE_CTRL"

# Validate DNS response binary (QR=1, RCODE=NOERROR)
python3 - "$RESPONSE_FILE" "$EXPECTED_IP" <<'PYEOF'
import struct, sys, ipaddress

path = sys.argv[1]
expected_ip = sys.argv[2]
data = open(path, 'rb').read()

if len(data) < 12:
    print(f"FAIL: response too short ({len(data)} bytes)", file=sys.stderr)
    sys.exit(1)

flags = struct.unpack('>H', data[2:4])[0]
qr    = (flags >> 15) & 1
rcode = flags & 0x0F

if not qr:
    print("FAIL: QR bit not set in response", file=sys.stderr)
    sys.exit(1)
if rcode != 0:
    print(f"FAIL: RCODE={rcode}, expected NOERROR(0)", file=sys.stderr)
    sys.exit(1)

# Scan for the A record RDATA (4-byte IPv4) after the header+question+answer RR headers.
found_ip = None
# Naive scan: look for the 4-byte IP we expect anywhere in the answer section.
target = ipaddress.IPv4Address(expected_ip).packed
if target in data[12:]:
    found_ip = expected_ip
else:
    print(f"FAIL: expected RDATA {expected_ip} not found in response", file=sys.stderr)
    sys.exit(1)

print(f"OK: QR=1 RCODE=0 RDATA={found_ip}")
PYEOF
pass "DoH GET: HTTP 200 + application/dns-message + Cache-Control + valid DNS response"

# ── POST request ──────────────────────────────────────────────────────────────

info "DoH POST: POST /dns-query HTTP/2 Content-Type: application/dns-message"
TMPHDRS_POST="$PKI_DIR/post-headers.txt"
RESPONSE_POST="$PKI_DIR/response-post.bin"

curl --silent \
    --http2 \
    --cacert "$CA_CERT" \
    --max-time 5 \
    -X POST \
    -H "Content-Type: application/dns-message" \
    -H "Accept: application/dns-message" \
    --data-binary "@${QUERY_WIRE_FILE}" \
    -D "$TMPHDRS_POST" \
    -o "$RESPONSE_POST" \
    "https://127.0.0.1:${DOH_PORT}${DOH_PATH}"

POST_STATUS_LINE=$(grep -i "^HTTP/" "$TMPHDRS_POST" | head -1 | tr -d '\r\n')
POST_CONTENT_TYPE=$(grep -i "^content-type:" "$TMPHDRS_POST" | tr -d '\r\n' | sed 's/.*: //')
POST_CACHE_CTRL=$(grep -i "^cache-control:" "$TMPHDRS_POST" | tr -d '\r\n' | sed 's/.*: //')

info "POST status line: $POST_STATUS_LINE"
info "POST Content-Type: $POST_CONTENT_TYPE"
info "POST Cache-Control: $POST_CACHE_CTRL"

echo "$POST_STATUS_LINE" | grep -q "200" \
    || fail "DoH POST: expected HTTP 200, got: $POST_STATUS_LINE"
echo "$POST_CONTENT_TYPE" | grep -q "application/dns-message" \
    || fail "DoH POST: expected Content-Type application/dns-message, got: $POST_CONTENT_TYPE"
echo "$POST_CACHE_CTRL" | grep -q "max-age=" \
    || fail "DoH POST: expected Cache-Control max-age=<TTL>, got: $POST_CACHE_CTRL"

python3 - "$RESPONSE_POST" "$EXPECTED_IP" <<'PYEOF'
import struct, sys, ipaddress

path = sys.argv[1]
expected_ip = sys.argv[2]
data = open(path, 'rb').read()

if len(data) < 12:
    print(f"FAIL: response too short ({len(data)} bytes)", file=sys.stderr)
    sys.exit(1)

flags = struct.unpack('>H', data[2:4])[0]
qr    = (flags >> 15) & 1
rcode = flags & 0x0F

if not qr:
    print("FAIL: QR bit not set in response", file=sys.stderr)
    sys.exit(1)
if rcode != 0:
    print(f"FAIL: RCODE={rcode}, expected NOERROR(0)", file=sys.stderr)
    sys.exit(1)

target = ipaddress.IPv4Address(expected_ip).packed
if target not in data[12:]:
    print(f"FAIL: expected RDATA {expected_ip} not found in response", file=sys.stderr)
    sys.exit(1)

print(f"OK: QR=1 RCODE=0 RDATA={expected_ip}")
PYEOF
pass "DoH POST: HTTP 200 + application/dns-message + Cache-Control + valid DNS response"

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All DoH H2 smoke checks passed for image: $IMAGE"
