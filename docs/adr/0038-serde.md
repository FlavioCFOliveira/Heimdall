---
title: "ADR-0038: serde + serde_derive for serialisation"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0038: serde + serde_derive for serialisation

## Context

Sprint 17 introduces TOML-based configuration loading (ENG-225). Config structs must be
deserialised from TOML at start-up and during hot-reload. Future sprints will extend
serialisation to:

- Structured log events (JSON, for SIEM pipelines, THREAT-147..149).
- Metrics exposition (Prometheus text format; structured JSON for OTLP).
- Admin-RPC payloads (JSON over mTLS, PROTO-0xx).
- Potential binary formats for inter-process communication.

A serialisation framework must be chosen that:

- Is zero-cost for the common case (derive macros, no runtime reflection).
- Integrates with all target formats (TOML, JSON, binary) through a single set of
  `#[derive]` annotations.
- Is widely audited and trusted.

## Decision

Use **`serde` v1.0** with `features = ["derive"]` as the serialisation framework for
all `heimdall-runtime` config types, and for future serialisation needs across the
workspace.

`serde_derive` is activated via the `derive` feature flag and is a proc-macro crate;
it participates in `cargo-geiger` counts separately.

## Considered options

### Option A — `serde` v1.0 with `derive` feature (selected)

- Pros: de-facto standard; widely audited by the Rust community; zero `unsafe` in `serde`
  core; `serde_derive` is a proc-macro (no runtime `unsafe`); integrates with every major
  Rust serialisation format (TOML, JSON, MessagePack, bincode, CBOR, Protobuf via
  `prost`, etc.); stable API with a long track record; MIT/Apache-2.0.
- Cons: proc-macro adds to compile time; large crate, but essentially universally present
  in the Rust ecosystem.

### Option B — manual serialisation

- Pros: zero dependencies; full control.
- Cons: significant implementation burden; error-prone; no benefit for config types.
  Rejected.

### Option C — `speedy`

- Pros: very fast binary serialisation.
- Cons: not a general-purpose framework; no TOML or JSON support; smaller ecosystem.
  Rejected.

### Option D — `rkyv`

- Pros: zero-copy deserialisation; very fast.
- Cons: overkill for config files; requires `unsafe` in calling code for direct access to
  archived values; complex API. Rejected for config; may be reconsidered for binary
  inter-process payloads in later sprints.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `serde` |
| Version adopted           | 1.0.228 |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Zero in `serde` core. `serde_derive` is a proc-macro: no runtime `unsafe`. |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by dtolnay and David Tolnay; the most downloaded crate on crates.io |
| Transitive dependencies   | `serde_derive` (proc-macro only); no other transitive deps |
| Author identity           | David Tolnay; well-established trust in the Rust community |

## Classification

**Core-critical once used in protocol paths** (currently convenience for config). Adding
`serde` to the workspace means all format-specific crates (`toml`, future `serde_json`,
etc.) share the same trait interface without additional framework overhead.

## Unsafe code posture

`serde` core contains zero `unsafe` blocks. `serde_derive` is a proc-macro crate that
generates safe Rust code at compile time; it runs during compilation and has no runtime
presence. No `unsafe` is introduced in Heimdall source.

## Consequences

- `serde` with `features = ["derive"]` is added under `[dependencies]` in
  `crates/heimdall-runtime/Cargo.toml`.
- All config structs in `config.rs` derive `serde::Deserialize`.
- Future crates in the workspace may declare `serde` as a dependency independently when
  needed (workspace-level version unification applies).

## Links

- Introduced with Sprint 17, task #229.
- Implements: ENG-225 (TOML config loading).
- Implemented in: `crates/heimdall-runtime/src/config.rs`.
