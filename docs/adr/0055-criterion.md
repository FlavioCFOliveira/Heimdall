---
title: "ADR-0055: criterion as the micro-benchmark harness"
status: accepted
date: 2026-04-27
deciders: [FlavioCFOliveira]
---

# ADR-0055: criterion as the micro-benchmark harness

## Context

Sprint 35 introduces a standalone benchmark crate (`crates/heimdall-bench`) that
must provide statistically rigorous micro-benchmarks of the DNS wire-format hot
path, the query-response cache, the admission pipeline, and RPZ matching.

The benchmark harness must:

- Produce stable, reproducible timing results with statistical rigour (mean,
  standard deviation, confidence interval).
- Prevent the optimiser from eliding benchmark subjects (`black_box`).
- Support parametrised input sizes (`BenchmarkId`, `benchmark_group`).
- Generate HTML reports for human review (optional, via the `html_reports`
  feature).
- Have no `unsafe` code in its public surface.
- Carry a permissive licence compatible with the project's whitelist (MIT /
  Apache-2.0 / ISC).

## Considered options

| Option | Notes |
|---|---|
| `criterion` v0.5 | Stable, widely used, statistical rigour, HTML reports, no unsafe, dual MIT/Apache-2.0. |
| `divan` v0.1 | Newer, lighter, proc-macro-based; less established; HTML output deferred; compatible licence. |
| Custom harness | Would require implementing black-box, statistical analysis, and output from scratch. Unjustifiable effort. |

## Decision

Use `criterion = { version = "0.5", features = ["html_reports"] }` as the
benchmark harness in `crates/heimdall-bench`.

`criterion` is the de-facto standard Rust micro-benchmark harness.  It has
been in widespread use since 2018, is well-maintained by the Rust community,
and has accumulated extensive audit coverage through its reverse-dependency
graph (thousands of Rust projects depend on it).

`gnuplot` is an optional `criterion` dependency for chart generation; its
absence does not prevent benchmarks from running or collecting data — only
HTML charts are affected.  No gnuplot dependency is added to the workspace.

## Consequences

- `criterion 0.5` (and its transitive dependencies: `rayon`, `plotters`,
  `serde`, `itertools`) are added to `Cargo.lock`.
- The `html_reports` feature requires `plotters` which brings in additional
  dependencies; these are all MIT- or Apache-2.0-licensed and pass
  `cargo deny check`.
- Bench binaries are excluded from `cargo test` by using `harness = false` in
  `Cargo.toml`; only the separate `tests/harness_tests.rs` integration suite
  runs in CI.
- If `divan` is adopted in a future sprint for compile-time-heavy workloads
  (e.g., embedded targets), it can coexist alongside `criterion` without
  conflict — they target different `[[bench]]` entries.
