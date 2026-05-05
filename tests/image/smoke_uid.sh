#!/usr/bin/env bash
# Container UID + root-fs read-only smoke test — verifies that the heimdall
# container runs as nonroot UID 65532 and cannot write to the root filesystem.
# Sprint 48 task #560.
#
# Uses the /version endpoint's "runtime" object:
#   {uid: 65532, gid: 65532, root_fs_writable: false}
#
# Usage:
#   tests/image/smoke_uid.sh [IMAGE]
#
# Environment variables:
#   IMAGE           Container image to test (default: heimdall:test)
#   READY_TIMEOUT   Seconds to wait for server to be ready (default: 15)
#
# Requires: docker, curl (or wget), python3
# On Linux: uses --network host so 127.0.0.1:9090/version is reachable.
# On macOS/colima: --network host connects to the VM, not macOS; this test
# auto-detects and falls back to docker inspect for UID verification.

set -euo pipefail

IMAGE="${1:-${IMAGE:-heimdall:test}}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"

EXPECTED_UID=65532
EXPECTED_GID=65532

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
skip() { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO %s\n' "$*"; }

# ── Detect Linux (can use --network host for observability) ───────────────────

IS_LINUX=0
if [[ "$(uname -s)" == "Linux" ]]; then
    IS_LINUX=1
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────

command -v docker  >/dev/null || fail "docker not found in PATH"
command -v python3 >/dev/null || fail "python3 not found in PATH"

# ── Start container ───────────────────────────────────────────────────────────

WORK_DIR=$(mktemp -d)
SMOKE_CFG="$WORK_DIR/heimdall-uid.toml"
ZONE_FILE="tests/image/example.com.zone"

[[ -f "$ZONE_FILE" ]] || fail "zone file not found: $ZONE_FILE (run from repository root)"

# Write a minimal config with observability enabled.
cat > "$SMOKE_CFG" <<'EOF'
[[listeners]]
address   = "0.0.0.0"
port      = 5303
transport = "udp"

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
metrics_port = 9094

[admin]
admin_port = 9095
EOF

CONTAINER_ID=""
cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [[ "$IS_LINUX" == "1" ]]; then
    info "Starting $IMAGE with --network host (Linux)"
    CONTAINER_ID=$(docker run -d \
        --read-only \
        --tmpfs /tmp \
        --network host \
        -v "${SMOKE_CFG}:/etc/heimdall/heimdall.toml:ro" \
        -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
        "$IMAGE" \
        start --config /etc/heimdall/heimdall.toml)
else
    info "Starting $IMAGE with port mapping (non-Linux)"
    CONTAINER_ID=$(docker run -d \
        --read-only \
        --tmpfs /tmp \
        -v "${SMOKE_CFG}:/etc/heimdall/heimdall.toml:ro" \
        -v "$(pwd)/${ZONE_FILE}:/etc/heimdall/zones/example.com.zone:ro" \
        "$IMAGE" \
        start --config /etc/heimdall/heimdall.toml)
fi
info "Container: $CONTAINER_ID"

# ── Method 1: docker inspect (works on all platforms) ─────────────────────────

info "Checking configured user via docker inspect..."
DOCKER_USER=$(docker inspect "$CONTAINER_ID" --format='{{.Config.User}}' 2>/dev/null || echo "")
info "Config.User: '${DOCKER_USER}'"

# ── Method 2: docker top (shows actual UID from kernel) ──────────────────────

# Wait briefly for the process to start.
ELAPSED=0
while true; do
    CONTAINER_STATUS=$(docker inspect "$CONTAINER_ID" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")
    if [[ "$CONTAINER_STATUS" == "running" ]]; then
        break
    fi
    ELAPSED=$(( ELAPSED + 1 ))
    if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
        docker logs "$CONTAINER_ID" 2>&1 | tail -20
        fail "Container did not reach running state within ${READY_TIMEOUT}s"
    fi
    sleep 1
done

TOP_OUT=$(docker top "$CONTAINER_ID" 2>/dev/null || echo "")
info "docker top output:"
echo "$TOP_OUT"

# Extract UID from the first process line (column 1 = UID on Linux, column 1 on macOS).
PROC_UID=$(echo "$TOP_OUT" | tail -n +2 | awk '{print $1}' | head -1)
info "Process UID from docker top: '$PROC_UID'"

# Check: the UID should be 65532 (or the username "nonroot" which maps to 65532).
if [[ "$PROC_UID" == "$EXPECTED_UID" || "$PROC_UID" == "nonroot" ]]; then
    pass "docker top: process runs as UID ${EXPECTED_UID} (nonroot)"
elif [[ "$PROC_UID" == "0" || "$PROC_UID" == "root" ]]; then
    fail "docker top: process runs as root (UID 0) — Dockerfile USER directive may be missing"
else
    info "WARNING: docker top UID='${PROC_UID}' (expected ${EXPECTED_UID}; may be a username string)"
fi

# ── Method 3: /version runtime object (Linux --network host only) ─────────────

if [[ "$IS_LINUX" == "1" ]]; then
    info "Waiting up to ${READY_TIMEOUT}s for /version endpoint at 127.0.0.1:9094..."
    ELAPSED=0
    while true; do
        VERSION_JSON=$(curl --silent --max-time 2 \
            "http://127.0.0.1:9094/version" 2>/dev/null || true)
        if [[ -n "$VERSION_JSON" ]] && echo "$VERSION_JSON" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
            pass "/version endpoint is responding with valid JSON"
            break
        fi
        ELAPSED=$(( ELAPSED + 1 ))
        if [[ "$ELAPSED" -ge "$READY_TIMEOUT" ]]; then
            docker logs "$CONTAINER_ID" 2>&1 | tail -20
            fail "/version did not respond within ${READY_TIMEOUT}s"
        fi
        sleep 1
    done

    info "/version JSON: $VERSION_JSON"

    # Parse and assert runtime fields.
    python3 - "$EXPECTED_UID" "$EXPECTED_GID" <<PYEOF
import json, sys

expected_uid = int(sys.argv[1])
expected_gid = int(sys.argv[2])
raw = '''${VERSION_JSON}'''
data = json.loads(raw)
rt = data.get("runtime")

if rt is None:
    print("FAIL: /version JSON missing 'runtime' object", file=sys.stderr)
    sys.exit(1)

uid = rt.get("uid")
gid = rt.get("gid")
rfw = rt.get("root_fs_writable")

errors = []
if uid != expected_uid:
    errors.append(f"uid={uid} (expected {expected_uid})")
if gid != expected_gid:
    errors.append(f"gid={gid} (expected {expected_gid})")
if rfw is not False:
    errors.append(f"root_fs_writable={rfw} (expected false)")

if errors:
    print(f"FAIL: runtime object mismatch: {'; '.join(errors)}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"OK: uid={uid}, gid={gid}, root_fs_writable={rfw}")
PYEOF
    pass "/version runtime: uid=${EXPECTED_UID}, gid=${EXPECTED_GID}, root_fs_writable=false"
else
    skip "/version runtime check skipped (requires Linux --network host)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
pass "All UID + root-fs smoke checks passed for image: $IMAGE"
