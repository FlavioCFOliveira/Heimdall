# Heimdall v1.1 — Performance baselines

**Specification.** Closes PERF-004 in
[`specification/008-performance-targets.md`](../../specification/008-performance-targets.md):
"The numerical values of the per-cell targets are deferred to the first
implementation baseline." This document records the v1.1 baseline status,
the methodology used to capture it, and the per-cell targets derived from
it.

**Audience.** Operators who need to verify whether a deployment meets the
v1.1 targets, and contributors who need to understand how to refresh the
baselines on new hardware or after a substantive change.

---

## 1. Cell matrix

The 18 cells defined by PERF-001..003 are:

| | UDP/53 | TCP/53 | DoT/853 | DoH/H2 | DoH/H3 | DoQ |
|---|---|---|---|---|---|---|
| **Authoritative** | A·UDP | A·TCP | A·DoT | A·DoH2 | A·DoH3 | A·DoQ |
| **Recursive**     | R·UDP | R·TCP | R·DoT | R·DoH2 | R·DoH3 | R·DoQ |
| **Forwarder**     | F·UDP | F·TCP | F·DoT | F·DoH2 | F·DoH3 | F·DoQ |

Each cell has independent numerical targets (PERF-001) on the dimensions
defined by PERF-005:

- Sustainable QPS (PERF-006).
- Latency p50, p99, p99.9 (PERF-007).
- Memory footprint per cache + per process (PERF-008).
- Concurrent connection count (PERF-009).

---

## 2. Methodology (PERF-014..018)

All baselines are produced by `scripts/bench/capture-baselines.sh`, which
implements the requirements of PERF-014..018:

1. **Tooling** (PERF-014): `dnsperf` for QPS and latency on every transport;
   purpose-built micro-benchmarks (criterion) for memory-footprint dimensions.
   Additional tools (`kdig`, `queryperf`, `resperf`) MAY be used for
   triangulation but are not the primary signal.

2. **CI integration** (PERF-015): the script is invoked from
   `.github/workflows/perf-baseline.yml` and stores results in
   `docs/bench/baselines/<arch>/<git-sha>/<role>-<transport>.json`. Each
   capture is keyed by git SHA so runs are traceable.

3. **Regression detection** (PERF-016): captured JSONs include
   `regression_thresholds` — when CI compares a new run against the
   `latest` symlink, any dimension exceeding its threshold fails the build
   for the affected cell. Default thresholds: 5 % QPS, 10 % p99, 15 %
   p99.9, 10 % RSS, 15 % connection count.

4. **Per-PR delta reporting** (PERF-017): every PR runs the baseline
   capture against its head SHA and posts a delta vs `main` to the PR.
   Implementation lives in `.github/workflows/perf-pr-delta.yml`.

5. **Version control** (PERF-018): the harness, scripts and stored
   baselines are checked into the repository and evolve together with the
   code under measurement.

---

## 3. Reference hardware (PERF-010..012, PERF-029)

| Architecture | Reference baseline | Required for official targets |
|---|---|---|
| `x86_64`  | AMD Epyc 9004/9005 or Intel Xeon Sapphire/Emerald Rapids; 32 phys cores; 128 GB DDR5; 25 Gb/s NIC; Linux 6.x | Yes — `is_reference_hardware: true` |
| `aarch64` | Ampere Altra/AmpereOne or AWS Graviton3/4; comparable spec to `x86_64`; Linux 6.x | Yes |
| `riscv64` | `riscv64gc` Linux 6.x; minimum core count and RVV TBD | More modest absolute numbers acceptable (PERF-030) |

A capture run on hardware that does not match the reference baseline is
stored with `is_reference_hardware: false` and MUST NOT be treated as the
official target (PERF-013).

---

## 4. Capture status

**Scaffolding (this repository).**

- `scripts/bench/capture-baselines.sh` is implemented and exercised by
  CI in `--quick` mode (criterion micro-benchmarks; no `dnsperf` required).
- `docs/bench/baselines/<arch>/schema.json` defines the JSON record shape
  (validated in CI).
- `crates/heimdall-bench/benches/*` provides the criterion micro-benchmarks
  for the dimensions that do not need a network harness.
- `docs/bench/baselines/<arch>/latest` is a symlink to the most recent
  reference run; if absent, no official target has been captured for the
  architecture.

**Production measurement (operator action).**

The 18 official cells are captured by running, on reference hardware:

```bash
HEIMDALL_REFERENCE_HARDWARE=1 scripts/bench/capture-baselines.sh
```

This requires:

- `dnsperf` on PATH.
- Heimdall running locally with each `(role, transport)` cell exposed on
  a known port (the script reads `HEIMDALL_AUTH_ADDR`,
  `HEIMDALL_RECURSIVE_ADDR`, `HEIMDALL_FORWARDER_ADDR`).
- A representative query file (`tests/bench/queries.txt` or operator-supplied).

The script produces 18 JSON files under
`docs/bench/baselines/<arch>/<git-sha>/`. Once verified, the operator
updates the `latest` symlink and commits the results — that commit
establishes the v1.1 baseline.

---

## 5. Per-cell targets (post-capture)

The numerical targets below are populated from the official reference
capture. Until that capture is committed, the column reads "PENDING".

| Cell | QPS sustainable | p99 (ms) | p99.9 (ms) | RSS (MB) | Concurrent conns |
|---|---|---|---|---|---|
| A·UDP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·TCP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoT   | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoH2  | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoH3  | PENDING | PENDING | PENDING | PENDING | PENDING |
| A·DoQ   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·UDP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·TCP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoT   | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoH2  | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoH3  | PENDING | PENDING | PENDING | PENDING | PENDING |
| R·DoQ   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·UDP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·TCP   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoT   | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoH2  | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoH3  | PENDING | PENDING | PENDING | PENDING | PENDING |
| F·DoQ   | PENDING | PENDING | PENDING | PENDING | PENDING |

The table is updated by the same commit that introduces the official JSONs
under `docs/bench/baselines/<arch>/<git-sha>/`. The CI regression gate
(see `.github/workflows/perf-baseline.yml`) compares every subsequent run
against this row using the per-cell `regression_thresholds`.

---

## 6. Cross-architecture status

| Architecture | Reference run committed | Notes |
|---|---|---|
| x86_64  | PENDING | Run on hardware matching PERF-011 |
| aarch64 | PENDING | Run on hardware matching PERF-012; absent → document the absence in the next refresh |
| riscv64 | PENDING | Per PERF-029, more modest absolute targets are acceptable; document hardware specifics in the JSON |

PERF-031 requires per-architecture comparison against reference
implementations (NSD, Knot, Unbound, etc.) — see
[`comparative-v1.1.md`](comparative-v1.1.md) (Sprint 59 task #645).

---

## 7. Refresh cadence

A baseline refresh is triggered by:

- Any change that touches the hot path (parser, serialiser, transport,
  cache, admission pipeline).
- Substantial dependency upgrades (rustls, quinn, hyper, tokio).
- A new architecture being added to the supported set.

The CI regression gate on every PR catches accidental degradation between
refreshes; an explicit refresh PR records the new baseline as the
authoritative target.

---

## 8. Open questions

The numerical targets in §5 are themselves the open question that
PERF-004 deferred. They are answered by the reference capture, not by
this document. Until the capture lands, every cell is in PENDING state
and PERF-021/022 parity with reference implementations cannot be
quantitatively evaluated for v1.1.
