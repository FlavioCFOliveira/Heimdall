#!/usr/bin/env bash
# Graceful drain smoke test — verifies that heimdall completes all in-flight
# DNS TCP queries before exiting when it receives SIGTERM (docker stop).
# Sprint 48 task #487.
#
# Usage:
#   tests/image/smoke_drain.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DNS to respond before starting drain (default: 15)
#   DNS_PORT        Host port mapped to the container DNS TCP listener (default: 5301)
#   DRAIN_TIMEOUT   Seconds allowed for graceful drain (docker stop -t) (default: 15)
#   N_QUERIES       Number of concurrent slow TCP queries to send (default: 8)
#
# Requires: docker, dig, python3

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DNS_PORT="${DNS_PORT:-5301}"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-15}"
N_QUERIES="${N_QUERIES:-8}"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v dig     >/dev/null || fail "dig not found in PATH"
command -v python3 >/dev/null || fail "python3 not found in PATH"

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Create a zone file with a large TXT record ────────────────────────────────
# Large responses (> 512 bytes) require TCP. The TXT record contains 255 chars
# to produce a response that is non-trivial to transmit.

WORK_DIR=$(mktemp -d)
DRAIN_ZONE="$WORK_DIR/drain.example.com.zone"
DRAIN_CONFIG="$WORK_DIR/heimdall-drain.toml"

cat > "$DRAIN_ZONE" <<'EOF'
; Drain smoke test zone
$ORIGIN example.com.
$TTL    60
@   IN  SOA ns1.example.com. admin.example.com. (
              2026050502 3600 900 604800 60 )
@   IN  NS  ns1.example.com.
@   IN  A   192.0.2.1
ns1 IN  A   192.0.2.1
www IN  A   192.0.2.1
; Large TXT record to produce a non-trivial TCP response.
big IN  TXT "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EOF

cat > "$DRAIN_CONFIG" <<EOF
# Configuration for graceful drain smoke test (task #487).
# TCP-only listener; authoritative for example.com with a large TXT record.

[[listeners]]
address   = "0.0.0.0"
port      = ${DNS_PORT}
transport = "tcp"

[roles]
authoritative = true

[zones]
[[zones.zone_files]]
origin = "example.com."
path   = "/etc/heimdall/zones/drain.zone"

[cache]
capacity     = 256
min_ttl_secs = 1
max_ttl_secs = 60

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
        info "Force-removing container $CONTAINER_ID"
        docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

info "Starting $IMAGE with TCP listener on port ${DNS_PORT}"
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DNS_PORT}:${DNS_PORT}/tcp" \
    -v "${DRAIN_CONFIG}:/etc/heimdall/heimdall.toml:ro" \
    -v "${DRAIN_ZONE}:/etc/heimdall/zones/drain.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for readiness ────────────────────────────────────────────────────────

info "Waiting up to ${READY_TIMEOUT}s for TCP DNS port ${DNS_PORT}..."
ELAPSED=0
while true; do
    RCODE=$(dig +noall +comments +timeout=2 +tries=1 \
        @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>/dev/null \
        | grep "status:" | sed 's/.*status: \([A-Z]*\).*/\1/' || true)
    if [[ "$RCODE" == "NOERROR" ]]; then
        pass "TCP DNS port ${DNS_PORT} ready (NOERROR)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        docker logs "$CONTAINER_ID" 2>&1 | tail -20
        fail "TCP DNS port ${DNS_PORT} not ready within ${READY_TIMEOUT}s"
    fi
    sleep 1
done

# ── Embed slow TCP DNS client ─────────────────────────────────────────────────
# This Python script opens N concurrent TCP connections, sends a DNS query for
# big.example.com TXT (large response), and reads the response slowly (5ms/byte).
# It exits 0 if all N queries return QR=1 RCODE=NOERROR; exits 1 otherwise.

SLOW_CLIENT="$WORK_DIR/slow_client.py"
cat > "$SLOW_CLIENT" <<'PYEOF'
#!/usr/bin/env python3
"""Concurrent slow DNS TCP client for drain smoke test."""
import socket, struct, sys, threading, time

host  = sys.argv[1]
port  = int(sys.argv[2])
n     = int(sys.argv[3])

# Wire-format query for big.example.com TXT (type 16, class IN)
header   = struct.pack('>HHHHHH', 0xDEAD, 0x0100, 1, 0, 0, 0)
qname    = b'\x03big\x07example\x03com\x00'
question = qname + struct.pack('>HH', 16, 1)
QUERY_WIRE = header + question

results = [None] * n
lock = threading.Lock()

def slow_query(idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(60)
        s.connect((host, port))
        framed = struct.pack('>H', len(QUERY_WIRE)) + QUERY_WIRE
        s.sendall(framed)
        # Read 2-byte length prefix
        lb = b''
        while len(lb) < 2:
            chunk = s.recv(2 - len(lb))
            if not chunk:
                return False
            lb += chunk
        rlen = struct.unpack('>H', lb)[0]
        # Read response body slowly — one byte at a time with a small delay.
        # This keeps the TCP connection open long enough for SIGTERM to arrive.
        body = b''
        while len(body) < rlen:
            chunk = s.recv(1)
            if not chunk:
                return False
            body += chunk
            time.sleep(0.005)  # 5ms per byte → ~0.5s for a 100-byte response
        s.close()
        flags = struct.unpack('>H', body[2:4])[0]
        qr    = (flags >> 15) & 1
        rcode = flags & 0x0F
        return qr == 1 and rcode == 0
    except Exception as exc:
        with lock:
            print(f"Query {idx} exception: {exc}", file=sys.stderr)
        return False

threads = []
for i in range(n):
    t = threading.Thread(target=lambda i=i: results.__setitem__(i, slow_query(i)))
    t.start()
    threads.append(t)

for t in threads:
    t.join(timeout=60)

if all(r is True for r in results):
    print(f"OK: all {n} slow TCP queries returned NOERROR")
    sys.exit(0)
else:
    bad = [i for i, r in enumerate(results) if r is not True]
    print(f"FAIL: queries {bad} failed or timed out; results={results}", file=sys.stderr)
    sys.exit(1)
PYEOF

# ── Launch concurrent slow queries in background ──────────────────────────────

info "Launching ${N_QUERIES} concurrent slow TCP queries (big.example.com TXT)..."
SLOW_LOG="$WORK_DIR/slow_client.log"
python3 "$SLOW_CLIENT" 127.0.0.1 "${DNS_PORT}" "${N_QUERIES}" >"$SLOW_LOG" 2>&1 &
SLOW_PID=$!

# Give the connections a moment to establish before sending SIGTERM.
sleep 0.3

# ── Send SIGTERM via docker stop ──────────────────────────────────────────────
# docker stop -t N sends SIGTERM, then waits N seconds; if not exited by then
# it sends SIGKILL. We want the container to exit gracefully before SIGKILL.

info "Sending docker stop -t ${DRAIN_TIMEOUT} to container $CONTAINER_ID..."
STOP_EXIT=0
docker stop -t "${DRAIN_TIMEOUT}" "$CONTAINER_ID" >/dev/null 2>&1 || STOP_EXIT=$?

info "docker stop returned (exit $STOP_EXIT)"

# ── Wait for slow client to complete ─────────────────────────────────────────

WAIT_TIMEOUT=60
info "Waiting up to ${WAIT_TIMEOUT}s for slow client to finish..."
SLOW_EXIT=0
timeout "${WAIT_TIMEOUT}" bash -c "wait ${SLOW_PID}" 2>/dev/null || SLOW_EXIT=$?

cat "$SLOW_LOG"

[[ "$SLOW_EXIT" == "0" ]] \
    || fail "Slow TCP client failed (exit ${SLOW_EXIT}) — some queries were truncated or lost during drain"
pass "All ${N_QUERIES} concurrent slow TCP queries completed with NOERROR during drain"

# ── Check container exit code ─────────────────────────────────────────────────

CONTAINER_EXIT=$(docker inspect "$CONTAINER_ID" --format='{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
info "Container exit code: ${CONTAINER_EXIT}"

[[ "$CONTAINER_EXIT" == "0" ]] \
    || fail "Container exited with code ${CONTAINER_EXIT} (expected 0 for graceful shutdown)"
pass "Container exited cleanly (code 0)"

# ── Check drain was logged ────────────────────────────────────────────────────
# Heimdall should log a shutdown/drain event when SIGTERM is received.
# This check is advisory — it verifies observability, not correctness.

DRAIN_LOGGED=$(docker logs "$CONTAINER_ID" 2>&1 | grep -ciE "drain|graceful|shutdown|SIGTERM" || true)
if [[ "$DRAIN_LOGGED" -gt 0 ]]; then
    pass "Container logs show drain/shutdown event (${DRAIN_LOGGED} matching lines)"
else
    info "WARNING: no drain/shutdown log lines found — observability gap"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All graceful drain checks passed for image: $IMAGE"
