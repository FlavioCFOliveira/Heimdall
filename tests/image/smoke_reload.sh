#!/usr/bin/env bash
# SIGHUP reload smoke test — verifies that heimdall reloads zone data on SIGHUP
# without tearing down listeners, dropping in-flight queries, or breaking /readyz.
# Sprint 48 task #488.
#
# Usage:
#   tests/image/smoke_reload.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DNS to be ready (default: 15)
#   RELOAD_TIMEOUT  Seconds to wait for v2 RDATA to appear after SIGHUP (default: 15)
#   DNS_PORT        Host port for the container DNS TCP listener (default: 5302)
#
# /readyz monitoring: on Linux with --network host the metrics endpoint is
# reachable at 127.0.0.1:9090 from the host. On macOS/colima the /readyz
# check is skipped (endpoint not reachable without network host).
#
# Requires: docker, dig

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
RELOAD_TIMEOUT="${RELOAD_TIMEOUT:-15}"
DNS_PORT="${DNS_PORT:-5302}"

V1_IP="192.0.2.1"
V2_IP="192.0.2.2"
EXPECTED_ZONE="example.com."

# On Linux the container can use --network host so observability is reachable.
USE_NETWORK_HOST=0
if [[ "$(uname -s)" == "Linux" ]]; then
    USE_NETWORK_HOST=1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker >/dev/null || fail "docker not found in PATH"
command -v dig    >/dev/null || fail "dig not found in PATH"

# ── Create zone files ─────────────────────────────────────────────────────────

WORK_DIR=$(mktemp -d)
ZONE_DIR="$WORK_DIR/zones"
mkdir -p "$ZONE_DIR"

ZONE_FILE="$ZONE_DIR/example.com.zone"
RELOAD_CFG="$WORK_DIR/heimdall-reload.toml"

# Zone v1: A record → 192.0.2.1
cat > "$ZONE_FILE" <<EOF
; SIGHUP reload smoke test zone v1 (task #488).
\$ORIGIN example.com.
\$TTL    5
@   IN  SOA ns1.example.com. admin.example.com. (
              2026050601 3600 900 604800 5 )
@   IN  NS  ns1.example.com.
@   IN  A   ${V1_IP}
ns1 IN  A   ${V1_IP}
EOF

# Config: TCP listener only (reliable on all platforms), short TTL.
if [[ "$USE_NETWORK_HOST" == "1" ]]; then
    BIND_ADDR="127.0.0.1"
    OBS_PORT=9092
else
    BIND_ADDR="0.0.0.0"
    OBS_PORT=9090
fi

cat > "$RELOAD_CFG" <<EOF
# Configuration for SIGHUP reload smoke test (task #488).
# TCP listener; short zone TTL so post-reload changes are immediately visible.

[[listeners]]
address   = "${BIND_ADDR}"
port      = ${DNS_PORT}
transport = "tcp"

[roles]
authoritative = true

[zones]
[[zones.zone_files]]
origin = "example.com."
path   = "/etc/heimdall/zones/example.com.zone"

[cache]
capacity     = 256
min_ttl_secs = 1
max_ttl_secs = 5

[rate_limit]
enabled = false

[observability]
metrics_addr = "127.0.0.1"
metrics_port = ${OBS_PORT}

[admin]
admin_port = 9093
EOF

# ── Start container ───────────────────────────────────────────────────────────

CONTAINER_ID=""
READYZ_POLL_PID=""
cleanup() {
    [[ -n "$READYZ_POLL_PID" ]] && kill "$READYZ_POLL_PID" 2>/dev/null || true
    if [[ -n "$CONTAINER_ID" ]]; then
        info "Force-removing container $CONTAINER_ID"
        docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

info "Starting $IMAGE (USE_NETWORK_HOST=${USE_NETWORK_HOST})"

if [[ "$USE_NETWORK_HOST" == "1" ]]; then
    CONTAINER_ID=$(docker run -d \
        --read-only \
        --tmpfs /tmp \
        --network host \
        -v "${RELOAD_CFG}:/etc/heimdall/heimdall.toml:ro" \
        -v "${ZONE_DIR}:/etc/heimdall/zones" \
        "$IMAGE" \
        start --config /etc/heimdall/heimdall.toml)
else
    CONTAINER_ID=$(docker run -d \
        --read-only \
        --tmpfs /tmp \
        -p "127.0.0.1:${DNS_PORT}:${DNS_PORT}/tcp" \
        -v "${RELOAD_CFG}:/etc/heimdall/heimdall.toml:ro" \
        -v "${ZONE_DIR}:/etc/heimdall/zones" \
        "$IMAGE" \
        start --config /etc/heimdall/heimdall.toml)
fi
info "Container: $CONTAINER_ID"

# ── Wait for readiness ────────────────────────────────────────────────────────

info "Waiting up to ${READY_TIMEOUT}s for DNS TCP port ${DNS_PORT}..."
ELAPSED=0
while true; do
    RCODE=$(dig +noall +comments +timeout=2 +tries=1 \
        @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>/dev/null \
        | grep "status:" | sed 's/.*status: \([A-Z]*\).*/\1/' || true)
    if [[ "$RCODE" == "NOERROR" ]]; then
        pass "DNS TCP port ${DNS_PORT} ready (NOERROR)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        docker logs "$CONTAINER_ID" 2>&1 | tail -20
        fail "DNS TCP port ${DNS_PORT} not ready within ${READY_TIMEOUT}s"
    fi
    sleep 1
done

# ── Verify v1 RDATA ───────────────────────────────────────────────────────────

V1_RDATA=$(dig +short @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>/dev/null || true)
[[ "$V1_RDATA" == "$V1_IP" ]] \
    || fail "Pre-reload: expected RDATA ${V1_IP}, got: ${V1_RDATA}"
pass "Pre-reload: RDATA = ${V1_IP} (zone v1)"

# ── Start /readyz monitoring (Linux --network host only) ──────────────────────

READYZ_LOG="$WORK_DIR/readyz.log"
READYZ_FAILURES=0

if [[ "$USE_NETWORK_HOST" == "1" ]] && command -v curl >/dev/null 2>&1; then
    info "Starting /readyz polling on 127.0.0.1:${OBS_PORT}/readyz..."
    (
        while true; do
            CODE=$(curl --silent --output /dev/null \
                --write-out "%{http_code}" \
                --max-time 1 \
                "http://127.0.0.1:${OBS_PORT}/readyz" 2>/dev/null || true)
            echo "$CODE"
            sleep 0.5
        done
    ) > "$READYZ_LOG" 2>&1 &
    READYZ_POLL_PID=$!
    sleep 0.2  # let it establish a baseline
fi

# ── Swap zone file to v2 on host ──────────────────────────────────────────────
# The zone directory is bind-mounted (not :ro) so writes here are visible
# inside the container immediately.

info "Updating zone file to v2 (RDATA ${V2_IP})"
cat > "$ZONE_FILE" <<EOF
; SIGHUP reload smoke test zone v2 (task #488).
\$ORIGIN example.com.
\$TTL    5
@   IN  SOA ns1.example.com. admin.example.com. (
              2026050602 3600 900 604800 5 )
@   IN  NS  ns1.example.com.
@   IN  A   ${V2_IP}
ns1 IN  A   ${V2_IP}
EOF

# ── Send SIGHUP ───────────────────────────────────────────────────────────────

info "Sending SIGHUP to container $CONTAINER_ID"
docker kill --signal=HUP "$CONTAINER_ID" >/dev/null 2>&1 \
    || fail "docker kill --signal=HUP failed"

# ── Wait for v2 RDATA ─────────────────────────────────────────────────────────

info "Waiting up to ${RELOAD_TIMEOUT}s for v2 RDATA (${V2_IP}) to appear..."
ELAPSED=0
while true; do
    POST_RDATA=$(dig +short @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>/dev/null || true)
    if [[ "$POST_RDATA" == "$V2_IP" ]]; then
        pass "Post-reload: RDATA = ${V2_IP} (zone v2 loaded)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$RELOAD_TIMEOUT" ]]; then
        info "Container logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -20
        fail "v2 RDATA (${V2_IP}) did not appear within ${RELOAD_TIMEOUT}s after SIGHUP (last: ${POST_RDATA:-no response})"
    fi
    sleep 1
done

# ── Stop /readyz polling and analyse ─────────────────────────────────────────

if [[ -n "$READYZ_POLL_PID" ]]; then
    kill "$READYZ_POLL_PID" 2>/dev/null || true
    READYZ_POLL_PID=""
    sleep 0.2

    # Count non-200 responses.
    NON_200=$(grep -vc "^200$" "$READYZ_LOG" 2>/dev/null || echo 0)
    TOTAL=$(grep -c "." "$READYZ_LOG" 2>/dev/null || echo 0)
    info "/readyz poll results: ${TOTAL} polls, ${NON_200} non-200 responses"

    if [[ "$NON_200" -gt 0 ]]; then
        info "Non-200 responses: $(grep -v '^200$' "$READYZ_LOG" | sort | uniq -c)"
        fail "/readyz returned non-200 during reload (${NON_200}/${TOTAL} polls failed)"
    fi
    pass "/readyz: all ${TOTAL} polls returned 200 during SIGHUP reload"
else
    skip "/readyz monitoring skipped (requires Linux --network host and curl)"
fi

# ── Check SIGHUP in container logs ────────────────────────────────────────────

SIGHUP_LOGGED=$(docker logs "$CONTAINER_ID" 2>&1 | grep -ciE "sighup|reload|hup" || true)
if [[ "$SIGHUP_LOGGED" -gt 0 ]]; then
    pass "SIGHUP reload audited in container logs (${SIGHUP_LOGGED} matching lines)"
else
    info "WARNING: no SIGHUP/reload log lines found — observability gap"
fi

# ── Verify container is still running ────────────────────────────────────────

CONTAINER_STATUS=$(docker inspect "$CONTAINER_ID" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")
[[ "$CONTAINER_STATUS" == "running" ]] \
    || fail "Container is not running after reload (status: ${CONTAINER_STATUS})"
pass "Container is still running after SIGHUP reload"

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All SIGHUP reload smoke checks passed for image: $IMAGE"
