---
title: "ADR-0049: bytes for zero-copy byte buffers"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0049: bytes for zero-copy byte buffers

## Context

`bytes` is the canonical zero-copy byte buffer crate in the Rust async ecosystem.
It provides `Bytes` (an immutable, reference-counted slice) and `BytesMut` (a
growable, unique buffer). hyper 1.x, the `h2` HTTP/2 implementation, and quinn
(QUIC) all depend on `bytes` and pass `Bytes` across their public APIs. The DoH/H2
handler in `transport/doh2.rs` uses `bytes::Bytes` as the body type in
`http_body_util::Full<Bytes>` for response construction.

`bytes` is already a transitive dependency via hyper; this ADR promotes it to a
direct dependency in `heimdall-runtime` to make the dependency explicit and
version-pinned at the project level.

## Decision

Use **`bytes` 1.x** as a direct dependency in `heimdall-runtime`.

## Considered Options

### Option A — `bytes` 1.x (selected)

Zero-copy byte buffer maintained by the Tokio team.

- Pros: already a transitive dependency (zero supply-chain growth); maintained by
  the Tokio team with a long track record; `unsafe` is intentional and restricted to
  the buffer management internals (reference-counting, pointer arithmetic); MIT
  licence; used throughout the async Rust ecosystem.
- Cons: significant `unsafe` in the implementation. This is intentional and has been
  reviewed by the Tokio team; the `unsafe` enables the zero-copy semantics that make
  `bytes` valuable. Heimdall does not add new `unsafe` when calling the `bytes` API.

### Option B — `Vec<u8>`

Use `Vec<u8>` for all byte buffers and convert to `Bytes` at hyper API boundaries.

- Pros: zero `unsafe` in Heimdall's own code; no additional dependency.
- Cons: rejected because every conversion from `Vec<u8>` to `Bytes` at a hyper
  boundary is a copy. On the response path (DNS response body → HTTP response body),
  this introduces an avoidable allocation. Under high load (primary design constraint
  from CLAUDE.md), the allocator pressure from per-response copies is measurable.
  Using `Bytes::from(vec)` avoids this copy.

## Audit Trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `bytes` |
| Version adopted           | 1.x |
| Licence                   | MIT |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Significant (intentional: zero-copy buffer management via reference counting and pointer arithmetic). Maintained by the Tokio team; audited as part of the tokio project. |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by the Tokio team as part of the tokio organisation |
| Transitive dependencies   | None beyond `std` |
| Author identity           | Tokio team (`tokio-rs` organisation) |
| Registry ownership        | Published on crates.io under the `tokio-rs` organisation |

## Classification

**Core-critical** (runtime dependency). hyper, h2, and quinn require `bytes` on
their public APIs; promoting it to a direct dependency makes the version constraint
explicit and avoids implicit version resolution from transitive paths.

## Unsafe code posture

`bytes`'s `unsafe` is intentional and security-motivated: the `Bytes` type achieves
zero-copy slicing through reference-counted pointer arithmetic that cannot be
expressed in safe Rust. The Tokio team treats this `unsafe` with the same rigour as
the async runtime itself. Heimdall's own code does not introduce new `unsafe` when
calling `bytes` — the public API is entirely safe Rust. The `unsafe` footprint
belongs to `bytes`'s own implementation, which is outside Heimdall's
`#![deny(unsafe_code)]` boundary.

## Consequences

- `bytes = "1"` added under `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.
- `Bytes` is used as the body type in `http_body_util::Full<Bytes>` for DoH/H2
  responses in `transport/doh2.rs`.

## Links

- Introduced with Sprint 23, DoH/H2 listener (task #275).
- Companion to ADR-0029 (hyper).
- Implements: NET-025, NET-026 (zero-copy response body construction).
