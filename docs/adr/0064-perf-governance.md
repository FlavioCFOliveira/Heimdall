# ADR-0064 — Performance governance: annual revisit, threshold authority, and baseline policy

**Status**: Accepted
**Date**: 2026-05-05
**Deciders**: Core maintainers
**Sprint**: 50 (task #509)

## Context

`specification/008-performance-targets.md` PERF-026 requires annual revisiting
of the external comparison, but does not specify who may update thresholds,
how baselines are promoted to official status, or what happens when a cell fails
its target.  Without explicit governance, the performance framework would be
aspirational rather than enforceable.

## Decision

### Annual revisit schedule

The external performance comparison (PERF-019..028) is revisited in the first
sprint of each calendar year.  The next scheduled date is 2027-01-01.

### Threshold update authority

Regression thresholds (PERF-037) may only be relaxed by a PR that:
1. Documents the rationale in a new or updated ADR.
2. Is approved by at least two core maintainers.
3. Includes a measurement showing that the relaxation is bounded and reversible.

Thresholds may be tightened unilaterally by any maintainer without an ADR, as
this never weakens a quality gate.

### Baseline promotion policy

A micro-benchmark baseline (`docs/bench/baselines/<arch>/<sha>/micro-benchmarks.json`)
is promoted to "official" (`is_reference_hardware: true`) only when:
1. It was captured by `scripts/bench/capture-baselines.sh` with
   `HEIMDALL_REFERENCE_HARDWARE=1`.
2. The hardware matches the definition in PERF-011, PERF-012, or PERF-029.
3. The PR includes the hardware specification (CPU model, core count, memory,
   kernel, tuning flags) in the JSON `hardware` block.

Baselines captured on developer machines or CI runners are acceptable for
regression detection but MUST carry `is_reference_hardware: false` and MUST NOT
be cited as evidence of meeting absolute per-cell targets.

### Cell failure handling

When the annual revisit reveals that Heimdall fails to meet a parity or exceed
target on any cell:
- If fixable within one sprint: open a high-priority task and schedule it in
  the next sprint.
- If blocked by external factors (hardware availability, upstream regression):
  document with a time-bounded waiver ADR.
- If the target itself is miscalibrated: open an ADR to revise it.

### Blocking vs advisory gates

The CI bench regression gate (`bench.yml`) is blocking by default once official
reference-hardware baselines are captured.  Until then it runs with
`continue-on-error: true` (advisory).  The Tier 3 `bench-regression` job remains
advisory permanently (it is informational, not a release gate).

## Alternatives considered

**No explicit governance**: Leaves threshold updates and baseline promotions to
convention.  Rejected because convention degrades silently under time pressure.

**External tool (Bencher.dev)**: Considered for trend tracking and alerting.
Deferred because it adds an external dependency and the criterion + JSON baseline
approach already provides the required enforcement without external services.

## Consequences

- A calendar entry must be created for 2027-01-01 in the maintainer calendar.
- The `bench.yml` workflow gate will become blocking when the first
  `is_reference_hardware: true` baseline is committed.
- The `scripts/bench/capture-baselines.sh` script is the canonical tool for
  producing baselines; other methods are not authoritative.
