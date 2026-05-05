#!/usr/bin/env bash
# Comparative performance benchmark: Heimdall vs reference implementations.
# Implements PERF-019..028 (specification/008-performance-targets.md).
#
# Runs dnsperf against Heimdall and the reference implementations listed in
# PERF-020 for the requested role, then prints a comparison table and exits
# non-zero if Heimdall fails to meet the parity/exceed thresholds.
#
# Usage:
#   scripts/bench/compare-reference.sh --role <role> [--transport <transport>]
#                                       [--duration <s>] [--query-file <path>]
#
# Options:
#   --role        authoritative | recursive | forwarder  (required)
#   --transport   udp53 | tcp53 | dot | doh-h2 | doh-h3 | doq  (default: udp53)
#   --duration    seconds per dnsperf run  (default: 60)
#   --query-file  dnsperf query file path  (default: tests/bench/queries.txt)
#
# Reference implementations (PERF-020):
#   Authoritative: nsd, knot (knot-auth), bind
#   Recursive:     unbound, knot-resolver, pdns-recursor
#   Forwarder:     dnsdist, unbound (forward mode), coredns
#
# Thresholds (PERF-022/024):
#   Plain-DNS cells (udp53, tcp53): parity = within 5% QPS, <120% reference p99
#   Encrypted cells (dot, doh-h2, doh-h3, doq): exceed = >+20% QPS or <80% p99
#
# Prerequisites:
#   - dnsperf  (must be in PATH)
#   - Heimdall and all reference implementations must be running.
#   - Addresses via env vars (see below).
#
# Environment variables:
#   HEIMDALL_AUTH_ADDR        address:port for Heimdall authoritative
#   HEIMDALL_RECURSIVE_ADDR   address:port for Heimdall recursive
#   HEIMDALL_FORWARDER_ADDR   address:port for Heimdall forwarder
#   NSD_ADDR                  address:port for NSD
#   KNOT_AUTH_ADDR            address:port for Knot DNS (authoritative)
#   BIND_ADDR                 address:port for BIND
#   UNBOUND_ADDR              address:port for Unbound
#   KNOT_RESOLVER_ADDR        address:port for Knot Resolver
#   PDNS_RECURSOR_ADDR        address:port for PowerDNS Recursor
#   DNSDIST_ADDR              address:port for dnsdist
#   COREDNS_ADDR              address:port for CoreDNS

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

ROLE=""
TRANSPORT="udp53"
DURATION="${DNSPERF_DURATION:-60}"
QUERY_FILE="${DNSPERF_QUERY_FILE:-tests/bench/queries.txt}"

# ── Argument parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)       ROLE="$2";       shift 2 ;;
    --transport)  TRANSPORT="$2";  shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --query-file) QUERY_FILE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ROLE" ]; then
  echo "Error: --role is required (authoritative | recursive | forwarder)" >&2
  exit 1
fi

if [ ! -f "$QUERY_FILE" ]; then
  echo "Error: query file not found: $QUERY_FILE" >&2
  exit 1
fi

if ! command -v dnsperf &>/dev/null; then
  echo "Error: dnsperf not found in PATH. Install from https://github.com/DNS-OARC/dnsperf" >&2
  exit 1
fi

# ── Transport flags ───────────────────────────────────────────────────────────

extra_flags=()
case "$TRANSPORT" in
  tcp53)  extra_flags+=("-T") ;;
  dot)    extra_flags+=("-S" "dot") ;;
  doh-h2) extra_flags+=("-S" "doh") ;;
  doh-h3) extra_flags+=("-S" "doh") ;;
  doq)    extra_flags+=("-S" "doq") ;;
esac

# Classify plain vs encrypted for threshold selection (PERF-022 vs PERF-024)
case "$TRANSPORT" in
  udp53|tcp53) CELL_CLASS="plain" ;;
  *)           CELL_CLASS="encrypted" ;;
esac

# ── Reference implementation set per role (PERF-020) ─────────────────────────

declare -A REFERENCE_ADDRS
case "$ROLE" in
  authoritative)
    HEIMDALL_ADDR="${HEIMDALL_AUTH_ADDR:-}"
    REFERENCE_ADDRS["nsd"]="${NSD_ADDR:-}"
    REFERENCE_ADDRS["knot-auth"]="${KNOT_AUTH_ADDR:-}"
    REFERENCE_ADDRS["bind"]="${BIND_ADDR:-}"
    ;;
  recursive)
    HEIMDALL_ADDR="${HEIMDALL_RECURSIVE_ADDR:-}"
    REFERENCE_ADDRS["unbound"]="${UNBOUND_ADDR:-}"
    REFERENCE_ADDRS["knot-resolver"]="${KNOT_RESOLVER_ADDR:-}"
    REFERENCE_ADDRS["pdns-recursor"]="${PDNS_RECURSOR_ADDR:-}"
    ;;
  forwarder)
    HEIMDALL_ADDR="${HEIMDALL_FORWARDER_ADDR:-}"
    REFERENCE_ADDRS["dnsdist"]="${DNSDIST_ADDR:-}"
    REFERENCE_ADDRS["unbound-fwd"]="${UNBOUND_ADDR:-}"
    REFERENCE_ADDRS["coredns"]="${COREDNS_ADDR:-}"
    ;;
  *)
    echo "Error: unknown role '$ROLE'. Use: authoritative | recursive | forwarder" >&2
    exit 1
    ;;
esac

if [ -z "${HEIMDALL_ADDR:-}" ]; then
  echo "Error: Heimdall address not set for role '$ROLE'." >&2
  echo "Set HEIMDALL_AUTH_ADDR / HEIMDALL_RECURSIVE_ADDR / HEIMDALL_FORWARDER_ADDR." >&2
  exit 1
fi

# ── dnsperf runner ────────────────────────────────────────────────────────────

run_dnsperf() {
  local label="$1"
  local addr="$2"
  local host="${addr%:*}"
  local port="${addr##*:}"
  local tmpfile
  tmpfile="$(mktemp /tmp/dnsperf-XXXX.txt)"

  echo "  Running dnsperf against ${label} (${addr}) for ${DURATION}s..."
  dnsperf -s "$host" -p "$port" -d "$QUERY_FILE" -l "$DURATION" \
    "${extra_flags[@]}" > "$tmpfile" 2>&1 || true

  local qps p99
  qps=$(grep "Queries per second:" "$tmpfile" | awk '{print $4}' | tr -d ',')
  p99=$(grep "99th" "$tmpfile" | awk '{print $NF}' | tr -d 's')

  # Convert to ms if in seconds
  if echo "$p99" | grep -qE '^0\.[0-9]+$'; then
    p99=$(echo "$p99" | awk '{printf "%.3f", $1 * 1000}')
  fi

  rm -f "$tmpfile"
  echo "${qps:-0} ${p99:-0}"
}

# ── Measure Heimdall ──────────────────────────────────────────────────────────

echo ""
echo "=== Heimdall vs reference implementations: ${ROLE}/${TRANSPORT} ==="
echo ""

read -r HD_QPS HD_P99 <<< "$(run_dnsperf "heimdall" "$HEIMDALL_ADDR")"
echo "  heimdall: QPS=${HD_QPS}  p99=${HD_P99}ms"
echo ""

# ── Measure reference implementations ────────────────────────────────────────

declare -A REF_QPS
declare -A REF_P99
BEST_QPS=0
BEST_P99=999999

for impl in "${!REFERENCE_ADDRS[@]}"; do
  addr="${REFERENCE_ADDRS[$impl]}"
  if [ -z "$addr" ]; then
    echo "  ${impl}: SKIP (address not set)"
    continue
  fi

  read -r qps p99 <<< "$(run_dnsperf "$impl" "$addr")"
  REF_QPS[$impl]="$qps"
  REF_P99[$impl]="$p99"
  echo "  ${impl}: QPS=${qps}  p99=${p99}ms"

  if (( $(echo "$qps > $BEST_QPS" | bc -l) )); then BEST_QPS="$qps"; fi
  if (( $(echo "$p99 < $BEST_P99" | bc -l) )); then BEST_P99="$p99"; fi
done

echo ""
echo "=== Comparison summary ==="
echo "  Heimdall:          QPS=${HD_QPS}  p99=${HD_P99}ms"
echo "  Best reference:    QPS=${BEST_QPS}  p99=${BEST_P99}ms"

# ── Threshold evaluation (PERF-022/024) ──────────────────────────────────────

FAIL=0

if [ "$BEST_QPS" = "0" ]; then
  echo "  WARNING: No reference implementations measured — cannot evaluate thresholds."
  exit 0
fi

if [ "$CELL_CLASS" = "plain" ]; then
  # PERF-022: parity — within 5% QPS, p99 <= 120% of reference
  qps_ratio=$(echo "scale=4; $HD_QPS / $BEST_QPS" | bc -l)
  p99_ratio=$(echo "scale=4; $HD_P99 / $BEST_P99" | bc -l)
  echo "  QPS ratio (Heimdall/best): ${qps_ratio}  (threshold: >=0.95)"
  echo "  p99 ratio (Heimdall/best): ${p99_ratio}  (threshold: <=1.20)"
  if (( $(echo "$qps_ratio < 0.95" | bc -l) )); then
    echo "  FAIL: QPS parity not met (PERF-022)" >&2
    FAIL=1
  fi
  if (( $(echo "$p99_ratio > 1.20" | bc -l) )); then
    echo "  FAIL: p99 parity not met (PERF-022)" >&2
    FAIL=1
  fi
else
  # PERF-024: exceed — >120% QPS or <80% p99
  qps_ratio=$(echo "scale=4; $HD_QPS / $BEST_QPS" | bc -l)
  p99_ratio=$(echo "scale=4; $HD_P99 / $BEST_P99" | bc -l)
  echo "  QPS ratio (Heimdall/best): ${qps_ratio}  (target: >=1.20)"
  echo "  p99 ratio (Heimdall/best): ${p99_ratio}  (target: <=0.80)"
  if (( $(echo "$qps_ratio < 1.20" | bc -l) )) && (( $(echo "$p99_ratio > 0.80" | bc -l) )); then
    echo "  FAIL: encrypted-transport exceed target not met (PERF-024)" >&2
    FAIL=1
  fi
fi

if [ "$FAIL" = "0" ]; then
  echo "  PASS"
fi

exit "$FAIL"
