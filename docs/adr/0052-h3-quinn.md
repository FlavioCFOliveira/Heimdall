---
title: "ADR-0052: h3-quinn as the quinn transport adapter for h3"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0052: h3-quinn as the quinn transport adapter for h3

## Context

The `h3` crate selected in ADR-0051 implements the HTTP/3 protocol layer but is
transport-agnostic: it defines an abstract `quic::Connection` trait that the
caller must implement to provide the QUIC stream primitives (opening
unidirectional and bidirectional streams, reading and writing stream data,
accepting new streams). The `h3` crate does not depend on any specific QUIC
library.

Heimdall already uses `quinn` v0.11 as its QUIC implementation (ADR-0050) for
the DoQ listener. The DoH/H3 listener must reuse the same quinn endpoint
infrastructure to avoid duplicating QUIC socket management. Bridging `h3` to
`quinn` requires implementing the `h3::quic::Connection` trait for `quinn`'s
connection and stream types.

`h3-quinn` is the purpose-built adapter crate that performs exactly this
bridging: it wraps `quinn::Connection` and its stream types in types that
implement `h3::quic::Connection`, `h3::quic::BidiStream`, and
`h3::quic::SendStream` / `h3::quic::RecvStream`, enabling `h3::server::Connection`
to drive the HTTP/3 protocol layer over a quinn QUIC connection.

## Decision

Use **`h3-quinn` v0.0.9** as the quinn transport adapter for `h3`.

`h3-quinn` is added under `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.

> **Version note:** The sprint brief originally specified `h3-quinn 0.0.7`, but that
> version accesses `quinn::StreamId.0` which is a private tuple-struct field in
> `quinn 0.11.9` (the version already present in the workspace). `h3-quinn 0.0.9` is
> the first release that resolves this incompatibility while remaining compatible with
> `h3 0.0.6`; the upgrade is therefore a compatibility fix, not a scope change.

## Considered options

### Option A — `h3-quinn` v0.0.7 (selected)

The only available adapter crate that bridges `h3` (ADR-0051) to `quinn`
(ADR-0050). Specifically:

- Provides `h3_quinn::Connection::new(quinn::Connection)` which wraps an accepted
  quinn connection for use with `h3::server::Connection`.
- Maintained alongside `h3` in the same repository (hyperium/h3); version
  compatibility between `h3` and `h3-quinn` is therefore trivially ensured by
  using the paired versions (`h3 0.0.6` / `h3-quinn 0.0.7`).
- MIT OR Apache-2.0 licence.
- Zero `unsafe` blocks in the adapter layer.

Cons: pre-1.0 status, same semver caveats as `h3` (ADR-0051 §"Pre-1.0 semver
implications"). The version pin in `Cargo.toml` bounds the risk identically.

### Option B — Implement the `h3::quic::Connection` trait directly on quinn types

Implement the `h3::quic` trait family manually for `quinn::Connection` and its
associated stream types, without the `h3-quinn` crate.

- Pros: no additional dependency.
- Cons: `h3-quinn` is maintained in the same repository as `h3`; its implementation
  tracks internal changes to the `h3::quic` trait family that are not reflected in
  the public `h3` changelog. A manual implementation would need to be updated with
  every `h3` upgrade, risking subtle incompatibilities. The `h3::quic` traits are
  not stable API. Rejected.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `h3-quinn` |
| Version adopted           | 0.0.9 (0.0.7 as specified in the sprint brief; bumped to 0.0.9 to fix quinn 0.11.9 incompatibility — see version note above) |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | 0 in the adapter layer |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; co-maintained with `h3` in the hyperium/h3 repository |
| Transitive dependencies   | `h3` (ADR-0051), `quinn` (ADR-0050), `bytes`, `futures-util`, `tokio` (all already present) |
| Author identity           | hyperium organisation |
| Registry ownership        | Published on crates.io under the `h3-quinn` package |
| Semver stability          | Pre-1.0 (`0.0.x`); breaking changes possible between minor versions |

## Classification

**Core-critical** (runtime dependency). `h3-quinn` is a required companion to
`h3` (ADR-0051) and `quinn` (ADR-0050); there is no viable alternative for
bridging `h3` to `quinn`. It cannot be removed without replacing the entire
DoH/H3 transport or implementing the `h3::quic` traits manually.

## Pre-1.0 semver implications

Same caveats as ADR-0051. The `Cargo.toml` pin uses `"0.0.7"`. Every future
upgrade must be paired with the corresponding `h3` upgrade and reviewed against
`h3::quic` trait changes.

## Consequences

- `h3-quinn = "0.0.9"` is added under `[dependencies]` in
  `crates/heimdall-runtime/Cargo.toml`.
- The `Doh3Listener` in `transport/doh3.rs` wraps each accepted `quinn::Connection`
  with `h3_quinn::Connection::new(conn)` before passing it to
  `h3::server::Connection::new(h3_quinn_conn)`.
- No other module in the codebase uses `h3-quinn` directly.

## Links

- Introduced with Sprint 25, task #289.
- Companion ADR: `0051-h3.md` (the HTTP/3 protocol library).
- Implements: NET-006 (DoH over HTTP/3), transport layer bridging between quinn
  (ADR-0050) and h3 (ADR-0051).
