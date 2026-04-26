---
title: "ADR-0034: proptest for property-based testing"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0034: proptest for property-based testing

## Context

ENG-029 and ENG-030 in [`specification/010-engineering-policies.md`](../../specification/010-engineering-policies.md)
mandate property-based testing across the Heimdall codebase, with particular emphasis on
every parser and serialiser. ENG-054 requires proptest-based roundtrip tests in Tier 2 CI
with bounded case counts (256 cases per PR), and ENG-068 requires large-budget runs
(10^6 cases) in Tier 3.

A property-based testing framework that integrates with the standard `cargo test` harness
is required. The framework must support: generating arbitrary structured values,
composing strategies from simpler ones, automatic case shrinking on failure, a
`PROPTEST_CASES` environment variable to vary the case budget, and `proptest_state` or
equivalent for deterministic reproduction from saved seeds.

## Decision

Use **`proptest` v1.11.0** (or the latest stable version at the time of each dependency
bump) as the sole property-based testing framework for all `proptest`-based tests in the
Heimdall workspace.

`proptest` is added as a `[dev-dependencies]` entry in every crate that carries property
tests. It is never a runtime dependency.

## Considered options

### Option A — `proptest` (selected)

Hypothesis-inspired framework with composable `Strategy` trait, automatic shrinking,
`PROPTEST_CASES` environment variable, and built-in persistence of failure seeds.

- Pros: industry-standard for Rust PBT; composable strategies; good shrinking; documented
  integration with `cargo test`; active maintenance; no `unsafe` code in the crate itself
  (confirmed by `cargo geiger`); MIT or Apache-2.0 dual licence.
- Cons: generates values from unstructured randomness (not from raw byte buffers — that
  role is filled by `arbitrary` in ADR-0035); slightly larger binary size in test builds.

### Option B — `quickcheck`

Older Haskell-style framework.

- Cons: weaker shrinking than proptest; less ergonomic strategy composition; smaller
  ecosystem for Rust; does not support `PROPTEST_CASES` (different configuration API).
  Rejected in favour of proptest.

### Option C — Manual exhaustive tests only

No external dependency.

- Cons: cannot cover the combinatorial space required by ENG-030 without unsustainable
  test-code size. Rejected.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `proptest` |
| Version adopted           | 1.11.0 |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ (MIT and Apache-2.0 both listed) |
| Licence blocklist (ENG-095) | ✗ (not on blocklist) |
| `unsafe` blocks           | 0 (confirmed via `cargo geiger`) |
| Known CVEs                | None in the NVD at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; regular releases; multiple contributors |
| Transitive dependencies   | `bit-vec`, `bitflags`, `byteorder`, `lazy_static`, `num-traits`, `quick-error`, `rand`, `rand_chacha`, `rand_xorshift`, `regex-syntax`, `rusty-fork`, `tempfile`, `unarray` — all permissively licenced |
| Author identity           | AJ Jordan and contributors; altsysrq (primary) |
| Registry ownership        | Published on crates.io under the `proptest` package |
| Signing / provenance      | Standard crates.io publication; no additional signing at time of adoption |

## Classification

**Convenience** (dev-dependency only). `proptest` is a test-time dependency exclusively.
Its loss would require replacing all property tests with equivalent manual tests —
significant work but not a blocker on production functionality.

## Consequences

- `proptest` is added under `[dev-dependencies]` in every crate that carries property
  tests (initially `heimdall-core`).
- The `PROPTEST_CASES` environment variable controls the case budget in Tier 2
  (set to 256) and Tier 3 (set to 10^6), consistent with ENG-054 and ENG-068.
- Failed test seeds are written to `proptest-regressions/` directories adjacent to each
  test file. These directories **MUST NOT** be added to `.gitignore`; the regression files
  MUST be committed so that CI can reproduce past failures deterministically.
- The `rand`, `rand_chacha`, and `rand_xorshift` transitive dependencies from proptest
  do not require separate ADRs because they are not direct workspace dependencies.

## Links

- Introduced with Sprint 13, task #441.
- Implemented in: `crates/heimdall-core/Cargo.toml` (`[dev-dependencies]`).
- Implements: ENG-008 through ENG-016 (dependency ADR gate), ENG-029, ENG-030 (property-based testing mandate).
