---
status: accepted
date: 2026-05-03
deciders: [FlavioCFOliveira]
---

# ADR-0061: Adopt tracing-subscriber for log initialisation in the heimdall binary

## Context and Problem Statement

The `heimdall` binary uses the `tracing` facade (already a transitive dependency via `heimdall-runtime`) for structured diagnostics. The binary crate needs to install a concrete subscriber that routes `tracing` events to stderr in two formats per `BIN-002` and `ENG-202`: JSON for non-TTY outputs (production log shippers) and a human-readable pretty format for interactive terminals. The subscriber must respect `RUST_LOG` per `BIN-013` and the `--log-level` option per `BIN-002`.

## Decision Drivers

- Must be the standard companion to the `tracing` crate, already chosen by the workspace.
- Must support `EnvFilter` for `RUST_LOG` integration.
- Must support JSON output (for production) and human-readable output (for terminals).
- Binary-only dependency: only the `heimdall` binary crate needs it.

## Considered Options

- **tracing-subscriber** — the official companion to `tracing`; provides `fmt`, `EnvFilter`, and JSON layer support via `tracing-subscriber/json` feature.
- **tracing-journald** — sends events to `systemd-journald` directly; useful as a complement but not as the primary subscriber.
- **Custom subscriber** — reimplementing formatting and filtering logic is unnecessary given the quality of `tracing-subscriber`.

## Decision Outcome

Chosen option: **tracing-subscriber 0.3** with features `env-filter` and `json`, because:

- It is the canonical subscriber for the `tracing` ecosystem.
- `EnvFilter` provides the `RUST_LOG` integration required by `BIN-013` at zero additional cost.
- The `json` feature enables a `tracing_subscriber::fmt::format::Json` layer for production log shippers.
- The `fmt` feature enables the human-readable pretty layer for TTY sessions.
- License: MIT; on the permitted whitelist per `ENG-018`.

**Classification:** convenience; binary-only dependency.

## Consequences

**Positive:**

- Zero-cost filtering at disabled log levels (no allocation on the hot path per `ENG-202`).
- `RUST_LOG` fallback and `--log-level` integration in a few lines of code.
- TTY detection is automatic via `std::io::IsTerminal`.

**Negative:**

- Adds several utility crates to the binary's dependency graph (sharded-slab, thread_local, etc.). Acceptable because this is a binary-only dependency.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** No exemptions required; `tracing-subscriber` is certified by Mozilla and Bytecode Alliance import sources.
- **CVE/RustSec history:** No advisories as of 2026-05-03.
- **Maintenance:** Active; maintained by the Tokio project team alongside `tracing`.
- **License:** MIT — permitted per `ENG-018`.
- **unsafe footprint:** Minimal; confined to sharded-slab internals already present transitively.
