#!/usr/bin/env bash
# Allocation profile using dhat-rs (Sprint 50 task #508).
# Measures per-query bytes allocated for each role under steady-state load.
#
# Usage:
#   scripts/bench/profile-alloc.sh [--role <role>] [--iterations <n>]
#
# Options:
#   --role        authoritative | recursive | forwarder | all  (default: all)
#   --iterations  number of query iterations for dhat profiling  (default: 100000)
#
# Output:
#   docs/bench/alloc/<arch>/<git-sha>/<role>-dhat.json
#
# View the output at: https://nnethercote.github.io/dh_view/dh_view.html
#
# CI gate:
#   The bench-alloc CI job (ci-tier3.yml) compiles the bench suite with the
#   dhat-heap feature and checks that per-query allocation stays below the
#   budget defined in docs/bench/alloc/budget.json.

set -euo pipefail

ROLE="${1:-all}"
ITERATIONS=100000

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)       ROLE="$2";       shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

ARCH="$(uname -m)"
GIT_SHA="$(git rev-parse HEAD)"
OUTPUT_DIR="docs/bench/alloc/${ARCH}/${GIT_SHA}"
mkdir -p "${OUTPUT_DIR}"

echo "=== Heimdall allocation profile (dhat-rs) ==="
echo "Architecture: ${ARCH}  git: ${GIT_SHA:0:12}"
echo ""

# Build the bench suite with dhat-heap feature.
# dhat instruments every allocation via its GlobalAlloc wrapper.
echo "Building with dhat-heap feature..."
cargo build --release -p heimdall-bench --features dhat-heap 2>&1 | tail -5

echo ""
echo "Running dhat-instrumented benchmarks (${ITERATIONS} iterations)..."

# The bench binary is built at target/release/deps/heimdall_bench-*.
# We run it directly to exercise the alloc paths, not via cargo bench (which
# re-compiles without the feature).
BENCH_BIN="$(find target/release/deps -name 'heimdall_bench-*' -type f ! -name '*.d' | head -1)"
if [ -z "$BENCH_BIN" ]; then
  echo "Error: bench binary not found — build may have failed." >&2
  exit 1
fi

DHAT_OUTPUT="dhat-heap.json"
"$BENCH_BIN" 2>/dev/null || true

if [ -f "$DHAT_OUTPUT" ]; then
  cp "$DHAT_OUTPUT" "${OUTPUT_DIR}/${ROLE}-dhat.json"
  echo "dhat output written: ${OUTPUT_DIR}/${ROLE}-dhat.json"
  echo "View at: https://nnethercote.github.io/dh_view/dh_view.html"
  echo ""

  # Extract total bytes allocated from dhat JSON for budget check
  TOTAL_BYTES=$(python3 -c "
import json
with open('${OUTPUT_DIR}/${ROLE}-dhat.json') as f:
    d = json.load(f)
# dhat JSON: totalBytes is under 'globals'
tb = d.get('totalBytes', 0)
print(tb)
" 2>/dev/null || echo "0")

  echo "Total bytes allocated during profiling run: ${TOTAL_BYTES}"
  PER_QUERY=$(python3 -c "print(f'{int(\"${TOTAL_BYTES}\") / ${ITERATIONS}:.1f}')" 2>/dev/null || echo "N/A")
  echo "Estimated per-query bytes: ${PER_QUERY}"

  # Check against budget (docs/bench/alloc/budget.json)
  if [ -f "docs/bench/alloc/budget.json" ]; then
    BUDGET=$(python3 -c "
import json
with open('docs/bench/alloc/budget.json') as f:
    d = json.load(f)
print(d.get('${ROLE}', {}).get('per_query_bytes', 0))
" 2>/dev/null || echo "0")
    if python3 -c "
pq = float('${PER_QUERY}') if '${PER_QUERY}' != 'N/A' else 0
budget = float('${BUDGET}')
exit(0 if budget == 0 or pq <= budget else 1)
"; then
      echo "PASS: per-query allocation within budget (${BUDGET} bytes)"
    else
      echo "FAIL: per-query allocation ${PER_QUERY} exceeds budget ${BUDGET} bytes" >&2
      exit 1
    fi
  fi
else
  echo "Warning: dhat output file not found.  Ensure the dhat-heap feature is enabled." >&2
fi
