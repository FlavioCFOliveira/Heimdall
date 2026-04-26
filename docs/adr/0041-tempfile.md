---
title: "ADR-0041: tempfile for test fixture management"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0041: tempfile for test fixture management

## Context

Integration tests for the config loader (Sprint 17, task #229) must write TOML content
to a temporary file on disk and then load it via `ConfigLoader::load()`. This verifies the
full I/O + parse + validate round-trip. The test requires creating a temporary directory
that is automatically cleaned up when the test completes, regardless of whether it passes
or fails.

The standard library's `std::env::temp_dir()` + manual `std::fs::remove_dir_all()` is
error-prone: cleanup is skipped on panic, leaving debris in the system temp directory.

## Decision

Use **`tempfile` v3** as a `[dev-dependencies]` entry in `crates/heimdall-runtime`.

`tempfile::tempdir()` returns a `TempDir` handle whose `Drop` implementation removes the
directory tree automatically, including on test failure/panic.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `tempfile` |
| Version adopted           | 3 (3.19.1 at time of adoption) |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Zero |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by Steven Allen |
| Transitive dependencies   | `cfg-if`, `fastrand`, `rustix` (Linux/BSD) or `windows-sys` (Windows) — all permissively licensed |
| Author identity           | Steven Allen; well-established crate with broad adoption |

## Classification

**Convenience dev-dependency** (test infrastructure only). Has no effect on the compiled
runtime binary.

## Unsafe code posture

Zero `unsafe` in `tempfile` itself. Transitive deps (`rustix`) contain `unsafe` for
syscall wrappers, but this is isolated to the dev-build and has no runtime presence.

## Consequences

- `tempfile = "3"` is added under `[dev-dependencies]` in
  `crates/heimdall-runtime/Cargo.toml`.
- Used in `crates/heimdall-runtime/tests/integration_tests.rs` for the `config_roundtrip`
  test.

## Links

- Introduced with Sprint 17, task #229 (config integration tests).
- Implements: ENG-014 (all dev-dependencies require an ADR).
- Implemented in: `crates/heimdall-runtime/tests/integration_tests.rs`.
