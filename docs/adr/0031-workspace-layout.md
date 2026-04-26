---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0031: Cargo workspace layout — moderate multi-crate (four crates)

## Context and Problem Statement

Heimdall's source must be organised as a Cargo workspace. The layout choice determines how architectural boundaries are enforced at build time, how the dependency graph between subsystems is expressed, and how the project scales as features are added. `ENG-098` through `ENG-111` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md) fix the policy; this ADR documents the rationale for the four-crate layout it mandates.

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- Architectural boundaries must be enforced at compile time (not by convention), so that `heimdall-core` cannot accidentally import transport-layer state.
- The workspace layout must support the crate-scope policy of `ENG-099..102`: `heimdall-core` (wire format, DNSSEC, EDNS), `heimdall-runtime` (transports, caches, ACL, RL), `heimdall-roles` (auth, recursive, forwarder), `heimdall` (thin binary).
- Layout must not crystallise module boundaries prematurely before the design is validated.
- A single workspace-level `Cargo.lock` must be maintained; per-crate lockfiles are prohibited.

## Considered Options

- **Monolithic single crate** — all code in one `heimdall` crate. Loses compile-time boundary enforcement; makes selective testing and doc generation difficult.
- **Moderate multi-crate (four crates)** — `heimdall`, `heimdall-core`, `heimdall-runtime`, `heimdall-roles`. Matches natural architectural seams without premature fragmentation.
- **Fine-grained multi-crate (10+ crates)** — separate crates for each transport, each role, each data model. Crystallises boundaries before the design is stable; makes refactoring structurally expensive.
- **Two crates (core + binary)** — `heimdall-core` and `heimdall`. Insufficient boundary enforcement: transports and roles would live in the same crate, making the ACL/transport/role interaction unauditable at the crate boundary.

## Decision Outcome

Chosen option: **Moderate multi-crate (four crates)**, because:

- Four crates match the four natural architectural domains of the system: protocol primitives, I/O runtime, DNS-role logic, and process entry point.
- Compile-time boundary enforcement prevents accidental cross-domain coupling (e.g. role logic directly accessing transport sockets without going through `heimdall-runtime`'s public API).
- The four-crate envelope leaves room to introduce `heimdall-config` and `heimdall-observability` at threshold crossings per `ENG-103` and `ENG-104`, without invalidating the initial layout.
- A four-crate workspace is small enough to navigate and understand at project inception.

## Consequences

**Positive:**

- Cross-domain coupling is a compiler error, not a code-review catch.
- Per-crate documentation (`cargo doc`), per-crate benchmarks, and per-crate fuzz harnesses are straightforward.
- The binary crate is thin by construction, reducing the risk of business logic drifting into `main`.

**Negative:**

- Four crates mean four `Cargo.toml` files to maintain and four sets of compiler invocations. This is acceptable overhead.
- Future restructuring (adding `heimdall-config` or `heimdall-observability`) requires moving code between crates, which is a refactor rather than a simple rename.

## Cross-References

- `ENG-098..111` — Workspace layout normative requirements.
- `ENG-103..104` — Conditional expansion to `heimdall-config` / `heimdall-observability`.
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
