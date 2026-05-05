#!/usr/bin/env bash
# UDP listener saturation + SO_REUSEPORT scaling test (Sprint 50 tasks #507, #549).
#
# Saturates the Heimdall UDP listener with high-rate queries to:
#   1. Measure sustainable QPS (saturation point) per architecture (task #507).
#   2. Measure SO_REUSEPORT N-listener scaling factor (task #549): the ratio of
#      throughput at N listeners versus a single listener.
#
# Usage:
#   scripts/bench/stress-udp.sh --role <role> [--addr <addr>] [--max-n <n>]
#                               [--duration <s>] [--query-file <path>]
#
# Options:
#   --role       authoritative | recursive | forwarder  (required)
#   --addr       target address:port  (default: see below per role)
#   --max-n      maximum number of SO_REUSEPORT listener instances to test (default: 8)
#   --duration   seconds per dnsperf run  (default: 30)
#   --query-file dnsperf query file  (default: tests/bench/queries.txt)
#
# Outputs:
#   docs/bench/saturation/<arch>/<git-sha>/<role>-scaling.json
#
# Requires:
#   - dnsperf in PATH (PERF-014)
#   - Heimdall must be pre-started; set HEIMDALL_LISTENERS=<n> env var to
#     configure SO_REUSEPORT listener count before each test point.

set -euo pipefail

ROLE=""
ADDR=""
MAX_N=8
DURATION=30
QUERY_FILE="${DNSPERF_QUERY_FILE:-tests/bench/queries.txt}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)       ROLE="$2";       shift 2 ;;
    --addr)       ADDR="$2";       shift 2 ;;
    --max-n)      MAX_N="$2";      shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --query-file) QUERY_FILE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ROLE" ]; then
  echo "Error: --role is required" >&2; exit 1
fi

if ! command -v dnsperf &>/dev/null; then
  echo "Error: dnsperf not found in PATH." >&2; exit 1
fi

if [ ! -f "$QUERY_FILE" ]; then
  echo "Error: query file not found: $QUERY_FILE" >&2; exit 1
fi

# ── Address resolution ────────────────────────────────────────────────────────

if [ -z "$ADDR" ]; then
  case "$ROLE" in
    authoritative) ADDR="${HEIMDALL_AUTH_ADDR:-127.0.0.1:5353}" ;;
    recursive)     ADDR="${HEIMDALL_RECURSIVE_ADDR:-127.0.0.1:5354}" ;;
    forwarder)     ADDR="${HEIMDALL_FORWARDER_ADDR:-127.0.0.1:5355}" ;;
  esac
fi

HOST="${ADDR%:*}"
PORT="${ADDR##*:}"
ARCH="$(uname -m)"
GIT_SHA="$(git rev-parse HEAD)"
OUTPUT_DIR="docs/bench/saturation/${ARCH}/${GIT_SHA}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/${ROLE}-scaling.json"

# ── Saturation measurement ────────────────────────────────────────────────────

echo "=== Heimdall UDP saturation + SO_REUSEPORT scaling: ${ROLE} at ${ADDR} ==="
echo "Architecture: ${ARCH}  git: ${GIT_SHA:0:12}"
echo ""

RESULTS="["
FIRST=1
BASELINE_QPS=0

for n in $(seq 1 "$MAX_N"); do
  echo "Testing N=${n} listener(s) (HEIMDALL_LISTENERS=${n})..."
  echo "  Restart Heimdall with HEIMDALL_LISTENERS=${n} before continuing."
  echo "  Press ENTER when ready, or Ctrl-C to stop."
  read -r

  TMPFILE="$(mktemp /tmp/dnsperf-stress-XXXX.txt)"
  dnsperf -s "$HOST" -p "$PORT" \
    -d "$QUERY_FILE" -l "$DURATION" \
    -Q 5000000 2>&1 | tee "$TMPFILE" || true

  qps=$(grep "Queries per second:" "$TMPFILE" | awk '{print $4}' | tr -d ',')
  p99=$(grep "99th" "$TMPFILE" | awk '{print $NF}' | tr -d 's' | awk '{printf "%.3f", $1 * 1000}')
  lost=$(grep "Queries lost" "$TMPFILE" | awk '{print $3}' || echo "0")
  rm -f "$TMPFILE"

  qps="${qps:-0}"
  p99="${p99:-0}"
  lost="${lost:-0}"

  if [ "$n" = "1" ]; then
    BASELINE_QPS="$qps"
  fi

  # Compute scaling factor relative to N=1
  if [ "$BASELINE_QPS" != "0" ]; then
    scaling=$(python3 -c "print(f'{float(\"${qps}\") / float(\"${BASELINE_QPS}\"):.3f}')")
  else
    scaling="1.000"
  fi

  echo "  N=${n}: QPS=${qps}  p99=${p99}ms  lost=${lost}  scaling=${scaling}x"

  if [ "$FIRST" = "1" ]; then FIRST=0; else RESULTS+=","; fi
  RESULTS+="{\"listeners\": ${n}, \"qps\": ${qps}, \"p99_ms\": ${p99}, \"queries_lost\": ${lost}, \"scaling_factor\": ${scaling}}"
done

RESULTS+="]"

# ── Scaling factor evaluation (task #549 AC: ≥5.6x at N=8) ──────────────────

SCALING_AT_MAX=$(echo "$RESULTS" | python3 -c "
import json, sys
data = json.load(sys.stdin)
last = next((d for d in data if d['listeners'] == ${MAX_N}), None)
if last:
    print(last['scaling_factor'])
else:
    print('0')
")

echo ""
echo "=== Scaling summary ==="
echo "  N=1 baseline QPS: ${BASELINE_QPS}"
echo "  N=${MAX_N} scaling factor: ${SCALING_AT_MAX}x"
if python3 -c "exit(0 if float('${SCALING_AT_MAX}') >= 5.6 else 1)" 2>/dev/null; then
  echo "  PASS: scaling at N=8 ≥ 5.6x (task #549 target)"
else
  echo "  WARN: scaling at N=8 < 5.6x — document as ADR if intentional"
fi

# ── Write output JSON ─────────────────────────────────────────────────────────

cat > "${OUTPUT_FILE}" <<JSON
{
  "schema_version": 1,
  "role": "${ROLE}",
  "transport": "udp53",
  "architecture": "${ARCH}",
  "git_sha": "${GIT_SHA}",
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "baseline_qps_n1": ${BASELINE_QPS},
  "scaling_at_n${MAX_N}": ${SCALING_AT_MAX},
  "target_scaling_at_n8": 5.6,
  "measurements": ${RESULTS}
}
JSON

echo "Results written: ${OUTPUT_FILE}"
