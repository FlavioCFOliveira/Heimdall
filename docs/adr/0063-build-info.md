# ADR-0063 — Build-time version embedding: custom `build.rs` instead of `vergen`

| Field       | Value                   |
|-------------|-------------------------|
| Status      | Accepted                |
| Date        | 2026-05-03              |
| Sprint      | 46 (task #555)          |
| Supersedes  | —                       |

## Context

The `/version` observability endpoint (OPS-026, OPS-029..031) must expose:

- Semantic version (`CARGO_PKG_VERSION`)
- Short git commit SHA at build time
- RFC 3339 UTC build timestamp (reproducible via `SOURCE_DATE_EPOCH`)
- `rustc` version, target triple, build profile, and enabled Cargo features

The industry-standard way to embed such metadata is the `vergen` crate, which
generates `cargo:rustc-env` instructions from a `build.rs`.

## Decision

We implement a **self-contained `build.rs`** in `crates/heimdall` with no
external build-time dependencies. The script uses:

- `std::env::var` for Cargo-provided variables
- `std::process::Command` for `git rev-parse --short HEAD` and `rustc --version`
- Arithmetic-only date formatting to convert `SOURCE_DATE_EPOCH` to RFC 3339

The seven constants produced (`HEIMDALL_VERSION`, `HEIMDALL_GIT_COMMIT`,
`HEIMDALL_BUILD_DATE`, `HEIMDALL_RUSTC`, `HEIMDALL_TARGET`, `HEIMDALL_PROFILE`,
`HEIMDALL_FEATURES`) are exposed as `&'static str` via
`crates/heimdall/src/build_info.rs`.

A `BuildInfo` struct is defined in `heimdall-runtime::ops::observability` and
populated by the binary crate at startup.  This keeps build-script logic in the
binary crate (not the library) and avoids adding a `build.rs` to every crate
that needs version metadata.

## Rationale

**`vergen 9.x` is the stable series; `vergen 10.x` was in beta at decision time.**
Adding a beta dependency violates the supply-chain minimisation principle
(CLAUDE.md §SECURITY) and would be subject to breaking API changes.

**Self-contained implementation is auditable.** The full `build.rs` is under 130
lines with no transitive dependencies.  Every line is reviewable in seconds.

**Supply-chain surface stays zero for the library crate.** `heimdall-runtime` has
no build dependencies.  Only the binary (`crates/heimdall`) runs the script, so
the restriction in the task's technical requirements ("NOT on workspace libs") is
met by construction.

## Consequences

- `git` must be in `PATH` at build time; if it is not, `HEIMDALL_GIT_COMMIT`
  falls back to `"unknown"` (non-fatal).
- For reproducible builds, callers must set `SOURCE_DATE_EPOCH` before invoking
  `cargo build`.  CI pinning this variable is the standard practice.
- If `vergen` reaches a stable 10.x GA with a proven API, we can revisit this
  decision and migrate with a single `build.rs` replacement.

## Rejected alternatives

| Option | Reason rejected |
|--------|-----------------|
| `vergen 10.0.0-beta.8` | Beta software; API may change; supply-chain risk |
| `built 0.7` | Adds a dependency for trivial functionality covered by `env!` |
| Embed in `heimdall-runtime/build.rs` | Violates TR "NOT on workspace libs" |
