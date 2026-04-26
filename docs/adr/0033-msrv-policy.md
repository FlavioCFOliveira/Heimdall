---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0033: MSRV policy — track latest stable rustc

## Context and Problem Statement

Heimdall must declare a Minimum Supported Rust Version (MSRV). The MSRV determines which Rust features the codebase may use, what toolchain source-build audiences must install, and how quickly security fixes in the Rust standard library and compiler are available to the project. `ENG-001` through `ENG-007` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md) fix the policy as "track latest stable"; this ADR documents the rationale.

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- Heimdall is a security-critical server; access to the latest compiler security fixes (sanitiser improvements, soundness fixes, safer standard-library APIs) is valuable.
- Performance is the primary guiding principle; access to the latest stable optimisation improvements (LLVM updates, codegen improvements, new intrinsics) should not be artificially delayed.
- The target environment (`ENV-015..020`) consists of controlled server deployments where administrators manage toolchain versions; end users receive pre-built binaries and are unaffected by MSRV.
- Heimdall is pre-1.0.0 and actively developed; no downstream consumers depend on a stable ABI or a pinned toolchain.

## Considered Options

- **Track latest stable rustc** — MSRV = current stable at release time; updated on every stable rustc release.
- **Pin stable-minus-1** — MSRV lags one stable behind current; provides one release window for Cargo ecosystem to catch up.
- **Pin stable-minus-3** — MSRV lags three stable releases; the most conservative choice, used by some library crates targeting broad ecosystem compatibility.
- **Pin to a specific LTS toolchain (e.g. 1.85)** — no official Rust LTS; using an unofficial stable as a pseudo-LTS is fragile and delays security fixes.
- **Unstable Rust (nightly features)** — rejected; nightly features are not stable and would prevent any MSRV commitment.

## Decision Outcome

Chosen option: **Track latest stable rustc**, because:

- Heimdall is a server application, not a library; it does not need to support downstream crates with conservative MSRV constraints.
- The pre-built binary distribution model means end users never interact with the Rust toolchain; source-build audiences are contributors and packagers who are expected to keep their toolchains current.
- Tracking latest stable maximises access to compiler security improvements, language ergonomics (edition 2024 features), and LLVM codegen advances.
- The automated MSRV-bump PR workflow (`ENG-186`, `ENG-187`) minimises the operational cost of advancing the MSRV on every stable release.

**Classification:** structural decision (applies to the project, not a crate).

## Consequences

**Positive:**

- Source-build contributors always use the current stable toolchain, eliminating "works on my machine" toolchain divergence.
- Access to the full surface of the latest stable edition; no workarounds for missing stable features.
- Compiler security fixes (e.g. improved sanitiser, new lint denials on unsound patterns) are immediately available.

**Negative:**

- A new stable rustc may occasionally introduce a regression that fails the Heimdall build. Mitigation: Tier 1 CI gates detect this immediately on the automated MSRV-bump PR; the bump can be blocked until the regression is upstream-fixed or Heimdall-adjusted.
- Package maintainers who maintain Heimdall in distributions (Debian, Fedora) must ensure the packager's build environment tracks current stable. Pre-built binaries remove this concern for end users.

## Cross-References

- `ENG-001..007` — MSRV normative requirements.
- `ENG-186..188` — MSRV tooling and bump cadence (Sprint 9 additions).
- `ENV-024..028` — Pre-built binary distribution channels.
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
