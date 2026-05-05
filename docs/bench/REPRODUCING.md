# Reproducing Heimdall performance benchmarks

Sprint 50 task #503 — PERF-014..018, PERF-019..028.

## Overview

This document describes how to reproduce the Heimdall performance baselines and
comparative measurements against reference implementations.  Measurements that
do not follow this procedure MUST NOT be treated as evidence for or against
the per-cell targets defined in `specification/008-performance-targets.md`
(PERF-013, PERF-025).

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| `dnsperf` | ≥ 2.14.0 | QPS and latency measurement (PERF-014) |
| `flamethrower` | ≥ 0.12.0 | Alternative load generator |
| Docker | ≥ 24 | Reference implementation containers |
| `flamegraph` (cargo-flamegraph) | latest | CPU profiling (task #506) |
| `dhat-rs` | via Cargo | Allocation profiling (task #508) |

Install `dnsperf`:
```bash
# Ubuntu / Debian
sudo apt-get install -y dnsperf

# macOS (homebrew tap)
brew install dnsperf
```

## Capturing micro-benchmark baselines (task #502)

Micro-benchmarks use [criterion](https://github.com/bheisler/criterion.rs) and
measure core primitives (parsing, cache lookup, CIDR trie) independent of
network I/O.

```bash
# Development machine (results marked is_reference_hardware=false):
scripts/bench/capture-baselines.sh --quick

# Reference hardware (results marked is_reference_hardware=true):
HEIMDALL_REFERENCE_HARDWARE=1 scripts/bench/capture-baselines.sh --quick
```

Results are written to `docs/bench/baselines/<arch>/<git-sha>/micro-benchmarks.json`.
Commit the JSON alongside the code change that sets the new baseline.

## Capturing end-to-end QPS baselines (task #502, PERF-014)

End-to-end baselines require a running Heimdall instance and `dnsperf`:

```bash
# Start Heimdall (authoritative role, port 5353)
cargo run --release -p heimdall -- --config contrib/heimdall-auth.toml &

# Capture baseline (60-second run, udp/53)
HEIMDALL_AUTH_ADDR=127.0.0.1:5353 \
DNSPERF_QUERY_FILE=tests/bench/queries.txt \
DNSPERF_DURATION=60 \
HEIMDALL_REFERENCE_HARDWARE=1 \
scripts/bench/capture-baselines.sh
```

Repeat for recursive (`HEIMDALL_RECURSIVE_ADDR`) and forwarder
(`HEIMDALL_FORWARDER_ADDR`) roles.

## Comparative measurement vs reference implementations (task #503)

The comparison script starts reference implementations via Docker, runs
`dnsperf` against both Heimdall and each reference, and prints a comparison
table.

```bash
# Start reference implementations (NSD, Unbound, Knot)
# The conformance harness can start them:
HEIMDALL_INTEROP_TESTS=1 cargo test -p heimdall-integration-tests -- golden_nsd &

# Measure authoritative role vs NSD and Knot
NSD_ADDR=127.0.0.1:5300 \
KNOT_AUTH_ADDR=127.0.0.1:5301 \
HEIMDALL_AUTH_ADDR=127.0.0.1:5353 \
DNSPERF_QUERY_FILE=tests/bench/queries.txt \
scripts/bench/compare-reference.sh --role authoritative --transport udp53
```

The script prints a table of QPS and p99 latency for Heimdall and each reference
implementation, evaluates the PERF-022 (parity) or PERF-024 (exceed) threshold,
and exits non-zero on failure.

### Parity and exceed thresholds (PERF-022/024)

| Cell class | Dimension | Threshold |
|---|---|---|
| Plain DNS (udp53/tcp53) | QPS | Within 5 % of best reference |
| Plain DNS (udp53/tcp53) | p99 | ≤ 120 % of best reference |
| Encrypted (DoT/DoH/DoQ) | QPS | ≥ 120 % of best reference |
| Encrypted (DoT/DoH/DoQ) | p99 | ≤ 80 % of best reference |

## Reference implementation Docker images

Images are pinned in `tests/conformance/digests.lock`.  Pull them before
running comparisons:

```bash
docker pull nsd:pinned-sha     # see digests.lock for exact tag
docker pull cznic/knot:pinned
docker pull mvance/unbound:pinned
docker pull powerdns/pdns-auth-49:pinned
docker pull powerdns/pdns-recursor-50:pinned
docker pull coredns/coredns:pinned
```

## Cross-architecture validation (task #504)

Cross-architecture validation runs under QEMU via the `cross` tool.  Results
are informational only — they are not official baselines (PERF-013, PERF-030).

```bash
# aarch64
cross bench -p heimdall-bench --target aarch64-unknown-linux-gnu

# riscv64
cross bench -p heimdall-bench --target riscv64gc-unknown-linux-gnu
```

Official aarch64 and riscv64 baselines require native reference hardware
matching the definitions in PERF-012 and PERF-029.

## CI regression gate (task #505, PERF-016/017)

The `bench.yml` workflow runs on every PR targeting `main`.  It compares each
criterion benchmark against the stored baseline in
`docs/bench/baselines/<arch>/latest/micro-benchmarks.json`.  A regression
greater than 5 % on any benchmark fails the check.

To update the baseline after a deliberate performance improvement:

1. Run `scripts/bench/capture-baselines.sh --quick` on the reference machine.
2. Commit the new JSON file in `docs/bench/baselines/<arch>/<new-sha>/`.
3. Update `docs/bench/baselines/<arch>/latest` to point to the new SHA.
4. PR the baseline update alongside or after the performance change.

## Annual comparative revisit (PERF-026)

Each calendar year, re-identify the best-in-class reference implementation per
cell and re-run `scripts/bench/compare-reference.sh` for all cells.  Commit the
results to `docs/bench/baselines/<arch>/<sha>/` with an updated
`docs/bench/comparisons/YYYY-MM-DD/` directory containing the full comparison
table.  Update `tests/conformance/digests.lock` with the latest image digests.
