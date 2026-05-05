#!/usr/bin/env bash
# Flamegraph profiling for each Heimdall role (Sprint 50 task #506).
# Captures CPU flame graphs using cargo-flamegraph (perf on Linux, dtrace on macOS).
#
# Usage:
#   scripts/bench/profile-flamegraph.sh --role <role> [--duration <s>] [--output-dir <dir>]
#
# Options:
#   --role        authoritative | recursive | forwarder  (required)
#   --duration    profiling window in seconds  (default: 30)
#   --output-dir  where to write SVG files  (default: docs/bench/profiling/<role>)
#
# Prerequisites:
#   - cargo-flamegraph (cargo install flamegraph)
#   - On Linux: perf must be available and perf_event_paranoid ≤ 1
#   - On macOS: dtrace (system default; may need SIP disabled on Apple Silicon)
#   - dnsperf for load generation
#
# Outputs:
#   <output-dir>/<role>-<transport>-<git-sha>.svg

set -euo pipefail

ROLE=""
DURATION=30
OUTPUT_DIR=""
QUERY_FILE="${DNSPERF_QUERY_FILE:-tests/bench/queries.txt}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)       ROLE="$2";       shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ROLE" ]; then
  echo "Error: --role is required" >&2; exit 1
fi

GIT_SHA="$(git rev-parse --short HEAD)"
OUTPUT_DIR="${OUTPUT_DIR:-docs/bench/profiling/${ROLE}}"
mkdir -p "${OUTPUT_DIR}"

# ── Determine addresses ───────────────────────────────────────────────────────

case "$ROLE" in
  authoritative) ADDR="${HEIMDALL_AUTH_ADDR:-127.0.0.1:5353}" ;;
  recursive)     ADDR="${HEIMDALL_RECURSIVE_ADDR:-127.0.0.1:5354}" ;;
  forwarder)     ADDR="${HEIMDALL_FORWARDER_ADDR:-127.0.0.1:5355}" ;;
  *) echo "Error: unknown role '$ROLE'" >&2; exit 1 ;;
esac

HOST="${ADDR%:*}"
PORT="${ADDR##*:}"

# ── Verify prerequisites ──────────────────────────────────────────────────────

if ! command -v cargo-flamegraph &>/dev/null && ! cargo flamegraph --version &>/dev/null 2>&1; then
  echo "Error: cargo-flamegraph not found.  Install with: cargo install flamegraph" >&2
  exit 1
fi

if ! command -v dnsperf &>/dev/null; then
  echo "Error: dnsperf not found in PATH." >&2
  exit 1
fi

# ── Start load generator in background ───────────────────────────────────────

echo "Starting dnsperf load against ${ADDR} for ${DURATION}s..."
dnsperf -s "$HOST" -p "$PORT" -d "$QUERY_FILE" -l "$DURATION" \
  -Q 100000 &> /tmp/dnsperf-profile.txt &
DNSPERF_PID=$!

# ── Start flamegraph profiling ────────────────────────────────────────────────

OUTPUT_SVG="${OUTPUT_DIR}/${ROLE}-udp53-${GIT_SHA}.svg"
echo "Profiling for ${DURATION}s → ${OUTPUT_SVG}"

# Find the Heimdall process
HEIMDALL_PID=$(pgrep -f "heimdall.*${ROLE}" 2>/dev/null | head -1 || true)
if [ -z "$HEIMDALL_PID" ]; then
  echo "Warning: Heimdall process not found for role '${ROLE}'." \
       "Start Heimdall before profiling." >&2
  kill "$DNSPERF_PID" 2>/dev/null || true
  exit 1
fi

echo "Attaching to Heimdall PID ${HEIMDALL_PID}..."

if [[ "$(uname)" == "Linux" ]]; then
  # Linux: use perf via cargo-flamegraph
  timeout "$DURATION" cargo flamegraph --pid "$HEIMDALL_PID" --output "${OUTPUT_SVG}" \
    2>/dev/null || true
elif [[ "$(uname)" == "Darwin" ]]; then
  # macOS: use dtrace
  timeout "$DURATION" cargo flamegraph --pid "$HEIMDALL_PID" --output "${OUTPUT_SVG}" \
    2>/dev/null || true
fi

wait "$DNSPERF_PID" 2>/dev/null || true

if [ -f "${OUTPUT_SVG}" ]; then
  echo "Flamegraph written: ${OUTPUT_SVG}"
  echo ""
  echo "View with a browser.  Top functions by self-time can be extracted with:"
  echo "  python3 scripts/bench/top-self-time.py ${OUTPUT_SVG}"
else
  echo "Warning: flamegraph output not produced.  Check perf_event_paranoid or dtrace permissions." >&2
fi
