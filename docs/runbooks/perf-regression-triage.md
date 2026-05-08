# Runbook — Performance regression triage

**When to use.** The CI "Performance regression gate" job (`bench.yml`)
fails on a pull request because one or more criterion micro-benchmarks
regressed beyond the PERF-037 5 % threshold (PERF-016).

**Goal.** Decide one of: (a) the regression is real and the change must
be fixed; (b) the regression is real but acceptable and the baseline
must be updated alongside an ADR; (c) the regression is a flake or
runner artefact and the job should be re-run.

---

## 1. Read the failure output

The job output prints a comparison table:

```
Benchmark                                              Baseline (ns)   Current (ns)      Delta
-----------------------------------------------------------------------------------------------
parser.message.parse_minimal                                    815.2          820.1     +0.6%
parser.message.parse_with_compression                          1240.5         1310.7   REGR +5.7%
```

The `REGR` rows are the regression candidates. Each one is also emitted
as a GitHub `::error::` annotation, so they appear on the PR file diff
view too.

---

## 2. Reproduce locally

On a workstation with `cargo bench` available:

```bash
git fetch origin main
git checkout origin/main
cargo bench -p heimdall-bench --locked > /tmp/bench-baseline.txt

git checkout <PR-branch>
cargo bench -p heimdall-bench --locked > /tmp/bench-pr.txt
```

`criterion` will print "Time: -2.34%" (or "+5.7%") on each benchmark.
This is the same delta CI computes; if you cannot reproduce locally
the runner is the cause and you can re-run the CI job (option c).

---

## 3. Decision tree

### (a) Real and unintended

Read the diff for the benchmark's hot path. Common culprits:

- A new `Vec::clone()` on every iteration.
- A `Mutex` held across `await` (introduces contention on
  benchmarks that previously ran lock-free).
- A `String::from(...)` in place of a `&str`.
- An additional allocation in a parser/serialiser path.

Fix the underlying cause. Do not "fix" by raising the threshold.

### (b) Real but acceptable

Sometimes a regression is the expected cost of a security fix or a
correctness improvement (e.g., a bounds check now runs on every
iteration). In that case:

1. Open a short ADR under `docs/adr/` justifying the trade-off.
2. Refresh the baseline: run `scripts/bench/capture-baselines.sh`
   on reference hardware (PERF-011) and commit the new JSON +
   updated `latest` symlink.
3. The PR description must reference the ADR. Reviewers verify the
   trade-off was conscious.

There is no automatic threshold-bypass label. The baseline-update
commit is the explicit gate.

### (c) Flake / runner artefact

Re-run the CI job. If the regression vanishes, the runner was
contended (noisy neighbour on the GH-hosted runner). If the
regression persists across re-runs, treat as (a) or (b).

---

## 4. Cross-cell regressions (PERF-016, multi-cell)

The current `bench.yml` job covers the criterion micro-benchmarks
only. The 18 per-cell baselines (PERF-001..003 matrix; UDP/TCP/DoT/
DoH-H2/DoH-H3/DoQ × auth/recursive/forwarder) are tracked in
`docs/bench/baseline-v1.1.md`. Per-cell regression detection
becomes operational when the v1.1 reference capture lands and the
operator wires the comparison into a follow-up `bench-cells.yml`
workflow. Until that lands, per-cell regressions are caught only by
the comparative cycle (`scripts/bench/compare-reference.sh`).

---

## 5. Related artefacts

- `.github/workflows/bench.yml` — the regression gate itself.
- `scripts/bench/capture-baselines.sh` — refresh the stored baseline
  on reference hardware.
- `docs/bench/baseline-v1.1.md` — per-cell target document.
- `docs/bench/comparative-v1.1.md` — comparative cycle methodology.
- PERF-015..018, PERF-037 in `specification/008-performance-targets.md`.
