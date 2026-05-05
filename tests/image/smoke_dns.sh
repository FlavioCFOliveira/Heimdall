#!/usr/bin/env bash
# DNS query/response smoke test — verifies that the heimdall container serves
# authoritative answers over UDP and TCP from outside the container.
# Sprint 48 task #483.
#
# Usage:
#   tests/image/smoke_dns.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for DNS to respond (default: 15)
#   DNS_PORT        Host port mapped to the container DNS listener (default: 5300)
#   SKIP_UDP        Set to "1" to skip UDP check (macOS/colima limitation)
#
# On Linux (CI): both UDP and TCP are tested via explicit port mapping.
# On macOS/colima: UDP port mapping is unreliable at the Docker level;
#   SKIP_UDP is auto-set unless running on Linux.

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
DNS_PORT="${DNS_PORT:-5300}"
SMOKE_CONFIG="tests/image/heimdall-auth-smoke.toml"
ZONE_FILE="tests/image/example.com.zone"
EXPECTED_IP="192.0.2.1"
EXPECTED_ZONE="example.com."

# Auto-detect macOS: colima does not forward UDP ports reliably.
if [[ "$(uname -s)" == "Darwin" && -z "${SKIP_UDP:-}" ]]; then
    SKIP_UDP=1
fi
SKIP_UDP="${SKIP_UDP:-0}"

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker >/dev/null || fail "docker not found in PATH"
command -v dig    >/dev/null || fail "dig not found in PATH (install bind-tools or dnsutils)"

[[ -f "$SMOKE_CONFIG" ]] || fail "smoke config not found: $SMOKE_CONFIG (run from repository root)"
[[ -f "$ZONE_FILE"    ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# ── Start container ───────────────────────────────────────────────────────────

CONTAINER_ID=""
cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        info "Stopping container $CONTAINER_ID"
        docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
        docker rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

info "Starting $IMAGE (SKIP_UDP=${SKIP_UDP})"
# Publish both UDP and TCP; on macOS only TCP forwarding is reliable.
CONTAINER_ID=$(docker run -d \
    --read-only \
    --tmpfs /tmp \
    -p "127.0.0.1:${DNS_PORT}:5300/udp" \
    -p "127.0.0.1:${DNS_PORT}:5300/tcp" \
    -v "$(pwd)/${SMOKE_CONFIG}:/etc/heimdall/heimdall.toml:ro" \
    -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
    "$IMAGE" \
    start --config /etc/heimdall/heimdall.toml)
info "Container: $CONTAINER_ID"

# ── Wait for readiness via TCP (reliable on all platforms) ────────────────────

info "Waiting up to ${READY_TIMEOUT}s for DNS to respond over TCP..."
ELAPSED=0
while true; do
    FULL_RCODE=$(dig +noall +comments +timeout=2 +tries=1 \
        @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>/dev/null \
        | grep "status:" | sed 's/.*status: \([A-Z]*\).*/\1/' || true)

    if [[ "$FULL_RCODE" == "NOERROR" ]]; then
        pass "TCP DNS port ${DNS_PORT} is accepting queries (NOERROR)"
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        info "Container logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -30
        fail "DNS port ${DNS_PORT}/TCP did not respond with NOERROR within ${READY_TIMEOUT}s (last: ${FULL_RCODE:-no response})"
    fi
    sleep 1
done

# ── UDP query: example.com A ──────────────────────────────────────────────────

if [[ "$SKIP_UDP" == "1" ]]; then
    skip "UDP check skipped (macOS/colima: UDP port mapping unreliable; CI on Linux covers this)"
else
    info "UDP: dig @127.0.0.1 -p ${DNS_PORT} ${EXPECTED_ZONE} A"
    UDP_FLAGS=$(dig +noall +comments @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A 2>&1)
    UDP_RDATA=$(dig +short @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A 2>&1)
    info "UDP status: $(echo "$UDP_FLAGS" | grep 'status:' || echo 'none')"

    echo "$UDP_FLAGS" | grep -q "NOERROR"  || fail "UDP: expected NOERROR\n$UDP_FLAGS"
    echo "$UDP_FLAGS" | grep -qi "\baa\b"  || fail "UDP: expected AA flag\n$UDP_FLAGS"
    echo "$UDP_RDATA" | grep -q "${EXPECTED_IP}" \
        || fail "UDP: expected RDATA ${EXPECTED_IP}, got: ${UDP_RDATA}"
    pass "UDP: NOERROR + AA + RDATA ${EXPECTED_IP}"
fi

# ── TCP query: example.com A ──────────────────────────────────────────────────

info "TCP: dig @127.0.0.1 -p ${DNS_PORT} ${EXPECTED_ZONE} A +tcp"
TCP_FLAGS=$(dig +noall +comments @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>&1)
TCP_RDATA=$(dig +short @127.0.0.1 -p "${DNS_PORT}" "${EXPECTED_ZONE}" A +tcp 2>&1)
info "TCP status: $(echo "$TCP_FLAGS" | grep 'status:' || echo 'none')"

echo "$TCP_FLAGS" | grep -q "NOERROR"  || fail "TCP: expected NOERROR\n$TCP_FLAGS"
echo "$TCP_FLAGS" | grep -qi "\baa\b"  || fail "TCP: expected AA flag\n$TCP_FLAGS"
echo "$TCP_RDATA" | grep -q "${EXPECTED_IP}" \
    || fail "TCP: expected RDATA ${EXPECTED_IP}, got: ${TCP_RDATA}"
pass "TCP: NOERROR + AA + RDATA ${EXPECTED_IP}"

# ── RR-count / RDATA drift check ─────────────────────────────────────────────

WWW_RDATA=$(dig +short @127.0.0.1 -p "${DNS_PORT}" "www.${EXPECTED_ZONE}" A +tcp 2>&1)
[[ "$WWW_RDATA" == "${EXPECTED_IP}" ]] \
    || fail "Drift check: www.${EXPECTED_ZONE} A expected ${EXPECTED_IP}, got ${WWW_RDATA}"
pass "Drift check: www.${EXPECTED_ZONE} A = ${EXPECTED_IP}"

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All DNS smoke checks passed for image: $IMAGE"
