---
title: "ADR-0035: arbitrary for structure-aware fuzzing"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0035: arbitrary for structure-aware fuzzing

## Context

ENG-031, ENG-032, and ENG-055 in [`specification/010-engineering-policies.md`](../../specification/010-engineering-policies.md)
mandate `cargo-fuzz` integration for every parser surface. `cargo-fuzz` uses
libFuzzer under the hood, which provides raw byte buffers. Without structure-aware
fuzzing, the raw byte approach would rarely produce syntactically valid DNS messages
and would spend most of its budget on trivial length-field rejections rather than
exploring the parser's semantic state space.

The `arbitrary` crate provides the `Arbitrary` trait, which converts an unstructured
byte buffer (provided by libFuzzer) into a structured value (for example, a valid
`Message` with realistic field combinations). This makes fuzzing semantically richer:
the fuzzer explores field interactions within valid-looking inputs rather than spending
budget on early length checks.

`cargo-fuzz` itself is an external tool (not a library dep); it requires `arbitrary`
as a dep only in fuzz targets, declared in the fuzz workspace's `Cargo.toml`.

## Decision

Use **`arbitrary` v1.4.2** (or the latest stable version at the time of each dependency
bump) as the sole `Arbitrary`-trait provider for structure-aware `cargo-fuzz` targets
in the Heimdall workspace.

`arbitrary` is added as a `[dev-dependencies]` entry in crates that implement
`Arbitrary` for their types, and as a `[dependencies]` entry in the `fuzz` cargo
workspace (which is always a dev/tooling workspace, never shipped in production
artefacts).

## Considered options

### Option A — `arbitrary` (selected)

Provides the `Arbitrary` trait + `Unstructured` adapter; integrates directly with
`cargo-fuzz`; derive macro available via `derive` feature flag.

- Pros: the de facto standard for structured fuzzing in the Rust ecosystem;
  used by `cargo-fuzz`'s structured-fuzzing tutorial; no `unsafe` blocks (confirmed via
  `cargo geiger`); MIT OR Apache-2.0 dual licence; minimal transitive tree.
- Cons: adds a trait bound on types exposed to fuzzing (minor ergonomic cost).

### Option B — Raw byte fuzzing only (`cargo-fuzz` without `arbitrary`)

Pass raw `&[u8]` directly to parser entry points.

- Cons: libFuzzer spends the majority of its budget producing inputs that fail at the
  first length-field check (the first 2 bytes of the DNS message are the ID, the next
  two the flags, then the four 16-bit counts). Structure-aware fuzzing consistently
  finds deeper bugs faster. Rejected for DNS parser fuzzing.

### Option C — `bolero`

Alternative fuzzing framework that wraps both libFuzzer and AFL.

- Cons: `cargo-fuzz` is already mandated by ENG-055 and ENG-066; introducing a second
  fuzzing framework adds toolchain complexity without proportionate gain. Rejected.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `arbitrary` |
| Version adopted           | 1.4.2 |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ (both MIT and Apache-2.0 listed) |
| Licence blocklist (ENG-095) | ✗ (not on blocklist) |
| `unsafe` blocks           | 0 (confirmed via `cargo geiger`) |
| Known CVEs                | None in the NVD at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by the Rust Fuzzing Authority (github.com/rust-fuzz) |
| Transitive dependencies   | None at runtime; derive macro only in `arbitrary_derive` (proc-macro crate) |
| Author identity           | Rust Fuzzing Authority; fitzgen and contributors |
| Registry ownership        | Published on crates.io under the `arbitrary` package |
| Signing / provenance      | Standard crates.io publication |

## Classification

**Convenience** (dev/fuzz-tooling only). `arbitrary` is never a runtime dependency of
any shipped artefact. Its loss would require implementing `Unstructured`-to-type
conversion manually in every fuzz target — tedious but not architecturally blocking.

## Consequences

- `arbitrary` (with `features = ["derive"]`) is added under `[dev-dependencies]` in
  crates that expose `Arbitrary` implementations for their types (initially
  `heimdall-core`), so that the derive macro is available in test code.
- The `fuzz/` workspace `Cargo.toml` declares `arbitrary` under `[dependencies]`
  (as required by `cargo-fuzz`'s structured-fuzzing mode).
- Every `Arbitrary` implementation MUST be placed in test-only or fuzz-only code paths
  (`#[cfg(test)]` or within the fuzz workspace) so that the `arbitrary` crate is never
  linked into production binaries.
- The `derive` feature flag activates `arbitrary_derive`, a proc-macro crate; this is
  within the transitive tree but not a separately audited dependency for this ADR.

## Links

- Introduced with Sprint 13, task #442.
- Implemented in: `crates/heimdall-core/Cargo.toml` (`[dev-dependencies]`), `fuzz/Cargo.toml`.
- Implements: ENG-008 through ENG-016 (dependency ADR gate), ENG-031 (cargo-fuzz mandate), ENG-055 (Tier 2 fuzz smoke).
