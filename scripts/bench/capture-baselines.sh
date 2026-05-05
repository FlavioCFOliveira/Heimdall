#!/usr/bin/env bash
# Capture per-cell performance baselines for Heimdall.
# Implements PERF-033/034 (specification/008-performance-targets.md).
#
# This script must be run on hardware matching the reference baseline for the
# target architecture (PERF-011/012/029).  Results from non-reference hardware
# are stored with is_reference_hardware=false and MUST NOT be used as official
# targets.
#
# Usage:
#   scripts/bench/capture-baselines.sh [--quick]
#
#   --quick   Skip end-to-end dnsperf runs; capture micro-benchmarks only.
#             Useful for development machines that lack dnsperf/flamethrower.
#
# Output:
#   docs/bench/baselines/<arch>/<git-sha>/<role>-<transport>.json
#
# Prerequisites:
#   - cargo, Rust toolchain (MSRV as per rust-toolchain.toml)
#   - dnsperf (unless --quick)
#   - A running Heimdall instance for each role+transport under test (unless --quick)
#
# Environment variables (required for end-to-end runs):
#   HEIMDALL_AUTH_ADDR      - authoritative listener, e.g. 127.0.0.1:5353
#   HEIMDALL_RECURSIVE_ADDR - recursive listener,     e.g. 127.0.0.1:5354
#   HEIMDALL_FORWARDER_ADDR - forwarder listener,     e.g. 127.0.0.1:5355
#   DNSPERF_QUERY_FILE      - path to dnsperf query file (default: tests/bench/queries.txt)
#   DNSPERF_DURATION        - seconds per run (default: 60)

set -euo pipefail

# ── Argument parsing ───────────────────────────────────────────────────────────

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT="$(git rev-parse --show-toplevel)"
GIT_SHA="$(git rev-parse HEAD)"
ARCH="$(uname -m)"
CAPTURED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BASELINE_DIR="${REPO_ROOT}/docs/bench/baselines/${ARCH}/${GIT_SHA}"

mkdir -p "${BASELINE_DIR}"

# ── Hardware info ──────────────────────────────────────────────────────────────

CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
  || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs \
  || echo unknown)"
PHYSICAL_CORES="$(sysctl -n hw.physicalcpu 2>/dev/null \
  || nproc 2>/dev/null \
  || echo 0)"
MEMORY_GB="$(python3 -c "import os; print(round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 1073741824, 1))" 2>/dev/null \
  || sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.1f", $1/1073741824}' \
  || echo 0)"
OS_KERNEL="$(uname -sr)"

# Determine is_reference_hardware.  A machine is NOT reference hardware unless
# HEIMDALL_REFERENCE_HARDWARE=1 is explicitly set.
IS_REF="${HEIMDALL_REFERENCE_HARDWARE:-0}"
if [ "$IS_REF" = "1" ]; then
  IS_REFERENCE="true"
else
  IS_REFERENCE="false"
fi

# ── Step 1: criterion micro-benchmarks ────────────────────────────────────────

echo "=== Running criterion benchmarks ==="
cargo bench -p heimdall-bench --locked 2>&1 | tee /tmp/criterion-output.txt

# Extract micro-benchmark results from criterion's JSON artefacts.
# criterion stores results in target/criterion/<group>/<bench>/new/estimates.json
CRITERION_DIR="${REPO_ROOT}/target/criterion"
MICRO_JSON="{"

first=1
while IFS= read -r est_file; do
  # Derive benchmark name from path: target/criterion/<g>/<b>/new/estimates.json
  rel="${est_file#${CRITERION_DIR}/}"
  # Strip trailing /new/estimates.json
  bench_name="${rel%/new/estimates.json}"
  # Replace / with . for JSON key
  bench_key="${bench_name//\//.}"

  mean_ns=$(python3 -c "
import json, sys
with open('${est_file}') as f:
    d = json.load(f)
print(d['mean']['point_estimate'])
" 2>/dev/null || echo "null")

  p50_ns=$(python3 -c "
import json, sys
with open('${est_file}') as f:
    d = json.load(f)
print(d['median']['point_estimate'])
" 2>/dev/null || echo "null")

  std_dev_ns=$(python3 -c "
import json, sys
with open('${est_file}') as f:
    d = json.load(f)
print(d['std_dev']['point_estimate'])
" 2>/dev/null || echo "null")

  lower_ns=$(python3 -c "
import json, sys
with open('${est_file}') as f:
    d = json.load(f)
print(d['mean']['confidence_interval']['lower_bound'])
" 2>/dev/null || echo "null")

  upper_ns=$(python3 -c "
import json, sys
with open('${est_file}') as f:
    d = json.load(f)
print(d['mean']['confidence_interval']['upper_bound'])
" 2>/dev/null || echo "null")

  if [ "$first" = "1" ]; then first=0; else MICRO_JSON+=","; fi
  MICRO_JSON+="\"${bench_key}\":{\"mean_ns\":${mean_ns},\"p50_ns\":${p50_ns},\"std_dev_ns\":${std_dev_ns},\"lower_bound_ns\":${lower_ns},\"upper_bound_ns\":${upper_ns}}"

done < <(find "${CRITERION_DIR}" -name "estimates.json" -path "*/new/*" 2>/dev/null | sort)

MICRO_JSON+="}"

# ── Step 2: write per-cell JSON (micro-benchmarks only for now) ───────────────
# The cell dimension for micro-benchmarks is role-agnostic (they measure core
# primitives such as parsing and cache lookup, not per-role code paths).  Each
# architecture gets a single micro-benchmark record; per-role end-to-end records
# are written in Step 3 (skipped in --quick mode).

MICRO_FILE="${BASELINE_DIR}/micro-benchmarks.json"
cat > "${MICRO_FILE}" <<JSON
{
  "schema_version": 1,
  "cell": {
    "role": "all",
    "transport": "all",
    "architecture": "${ARCH}"
  },
  "hardware": {
    "cpu_model": "${CPU_MODEL}",
    "physical_cores": ${PHYSICAL_CORES},
    "memory_gb": ${MEMORY_GB},
    "os_kernel": "${OS_KERNEL}",
    "tuning_flags": [],
    "is_reference_hardware": ${IS_REFERENCE}
  },
  "git_sha": "${GIT_SHA}",
  "captured_at": "${CAPTURED_AT}",
  "micro_benchmarks": ${MICRO_JSON},
  "regression_thresholds": {
    "qps_pct": 5,
    "p99_latency_pct": 10,
    "p999_latency_pct": 15,
    "rss_pct": 10,
    "concurrent_connections_pct": 15
  }
}
JSON

echo "Micro-benchmark baseline written to: ${MICRO_FILE}"

# ── Step 3: end-to-end dnsperf runs (skipped in --quick mode) ─────────────────

if [ "$QUICK" = "1" ]; then
  echo "Skipping end-to-end dnsperf runs (--quick mode)."
  echo "Done.  Results in ${BASELINE_DIR}/"
  exit 0
fi

if ! command -v dnsperf &>/dev/null; then
  echo "WARNING: dnsperf not found — skipping end-to-end measurements." >&2
  echo "Install dnsperf (nominum/dnsperf) and re-run without --quick for full baselines." >&2
  exit 0
fi

QUERY_FILE="${DNSPERF_QUERY_FILE:-${REPO_ROOT}/tests/bench/queries.txt}"
DURATION="${DNSPERF_DURATION:-60}"

if [ ! -f "${QUERY_FILE}" ]; then
  echo "WARNING: Query file not found: ${QUERY_FILE}" >&2
  echo "Create tests/bench/queries.txt with dnsperf query format (name type, one per line)." >&2
  exit 1
fi

run_dnsperf() {
  local addr="$1"
  local output_file="$2"
  local transport="$3"

  local extra_flags=()
  case "$transport" in
    tcp53)  extra_flags+=("-T") ;;
    dot)    extra_flags+=("-S" "dot") ;;
    doh-h2) extra_flags+=("-S" "doh") ;;
    doh-h3) extra_flags+=("-S" "doh") ;;
    doq)    extra_flags+=("-S" "doq") ;;
  esac

  local host="${addr%:*}"
  local port="${addr##*:}"

  dnsperf -s "$host" -p "$port" -d "$QUERY_FILE" -l "$DURATION" \
    "${extra_flags[@]}" 2>&1 | tee /tmp/dnsperf-output.txt

  # Parse dnsperf output
  local qps p50 p99 p999
  qps=$(grep "Queries per second:" /tmp/dnsperf-output.txt | awk '{print $4}')
  p50=$(grep "Average Latency" /tmp/dnsperf-output.txt | awk '{print $3}' | tr -d 's' | awk '{print $1 * 1000}')
  p99=$(grep "99th" /tmp/dnsperf-output.txt | awk '{print $NF}' | tr -d 's' | awk '{print $1 * 1000}')

  cat > "$output_file" <<JSON
{
  "schema_version": 1,
  "cell": {
    "role": "$(dirname "${output_file}" | xargs basename | cut -d- -f1)",
    "transport": "${transport}",
    "architecture": "${ARCH}"
  },
  "hardware": {
    "cpu_model": "${CPU_MODEL}",
    "physical_cores": ${PHYSICAL_CORES},
    "memory_gb": ${MEMORY_GB},
    "os_kernel": "${OS_KERNEL}",
    "tuning_flags": [],
    "is_reference_hardware": ${IS_REFERENCE}
  },
  "git_sha": "${GIT_SHA}",
  "captured_at": "${CAPTURED_AT}",
  "micro_benchmarks": {},
  "end_to_end": {
    "tool": "dnsperf",
    "duration_s": ${DURATION},
    "query_file": "${QUERY_FILE}",
    "sustainable_qps": ${qps:-0},
    "p50_latency_ms": ${p50:-0},
    "p99_latency_ms": ${p99:-0},
    "p999_latency_ms": 0,
    "rss_mb": 0,
    "max_concurrent_connections": 0
  },
  "regression_thresholds": {
    "qps_pct": 5,
    "p99_latency_pct": 10,
    "p999_latency_pct": 15,
    "rss_pct": 10,
    "concurrent_connections_pct": 15
  }
}
JSON
}

# Authoritative role
if [ -n "${HEIMDALL_AUTH_ADDR:-}" ]; then
  echo "=== Authoritative baseline: UDP/53 ==="
  mkdir -p "${BASELINE_DIR}/authoritative"
  run_dnsperf "$HEIMDALL_AUTH_ADDR" "${BASELINE_DIR}/authoritative/authoritative-udp53.json" "udp53"
  echo "=== Authoritative baseline: TCP/53 ==="
  run_dnsperf "$HEIMDALL_AUTH_ADDR" "${BASELINE_DIR}/authoritative/authoritative-tcp53.json" "tcp53"
fi

# Recursive role
if [ -n "${HEIMDALL_RECURSIVE_ADDR:-}" ]; then
  echo "=== Recursive baseline: UDP/53 ==="
  mkdir -p "${BASELINE_DIR}/recursive"
  run_dnsperf "$HEIMDALL_RECURSIVE_ADDR" "${BASELINE_DIR}/recursive/recursive-udp53.json" "udp53"
fi

# Forwarder role
if [ -n "${HEIMDALL_FORWARDER_ADDR:-}" ]; then
  echo "=== Forwarder baseline: UDP/53 ==="
  mkdir -p "${BASELINE_DIR}/forwarder"
  run_dnsperf "$HEIMDALL_FORWARDER_ADDR" "${BASELINE_DIR}/forwarder/forwarder-udp53.json" "udp53"
fi

echo "Done.  All baselines written to: ${BASELINE_DIR}/"
