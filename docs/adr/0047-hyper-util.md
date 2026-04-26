---
title: "ADR-0047: hyper-util for higher-level hyper helpers"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0047: hyper-util for higher-level hyper helpers

## Context

hyper 1.x deliberately provides a minimal, low-level API that omits higher-level
service utilities. `hyper-util` is the canonical companion crate maintained by the
`hyperium` organisation that provides `TokioExecutor` (required to drive hyper's
HTTP/2 `Builder` from within a tokio runtime) and other service helpers. Every DoH
over HTTP/2 and HTTP/3 listener in Heimdall requires `TokioExecutor` to satisfy
hyper's `Executor` bound.

`hyper-util` is already a transitive dependency via `hyper` itself in many
configurations; this ADR promotes it to a direct dependency in `heimdall-runtime`.

## Decision

Use **`hyper-util` 0.1** with the `tokio` feature as a direct dependency in
`heimdall-runtime`.

## Considered Options

### Option A — `hyper-util` 0.1 (selected)

Canonical companion crate to hyper 1.x. Provides `TokioExecutor` and service
helpers.

- Pros: canonical, maintained by the `hyperium` organisation (same team as hyper);
  zero `unsafe` in its own code; no additional transitive dependencies beyond tokio
  (already present via ADR-0026) and hyper (ADR-0029); minimal API surface.
- Cons: 0.x version — API may change on minor bumps. Mitigated by `ENG-012`
  update-ADR obligation.

### Option B — Implement `Executor` manually

Write a one-line wrapper `struct TokioExecutor; impl<F> Executor<F> for TokioExecutor
{ fn execute(&self, f: F) { tokio::spawn(f); } }` directly in `heimdall-runtime`.

- Pros: no external dependency.
- Cons: rejected because `hyper-util`'s `TokioExecutor` is exactly this wrapper,
  with identical semantics. Duplicating it provides no benefit and diverges from
  ecosystem convention, making the code less legible for anyone familiar with hyper.

## Audit Trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `hyper-util` |
| Version adopted           | 0.1 |
| Licence                   | MIT |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | 0 in hyper-util itself |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by the `hyperium` organisation |
| Transitive dependencies   | `hyper`, `tokio`, `pin-project-lite` — all covered by other ADRs |
| Author identity           | `hyperium` organisation |
| Registry ownership        | Published on crates.io under the `hyperium` organisation |

## Classification

**Core-critical** (runtime dependency). Every DoH/H2 and DoH/H3 listener requires
`TokioExecutor`; removing hyper-util would require reimplementing it inline.

## Consequences

- `hyper-util = { version = "0.1", features = ["tokio"] }` added under
  `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.
- `TokioExecutor` is imported as `hyper_util::rt::TokioExecutor`.

## Links

- Introduced with Sprint 23, DoH/H2 listener (task #275).
- Companion to ADR-0029 (hyper).
- Implements: NET-005, NET-006, SEC-036..046.
