---
title: "ADR-0048: http-body-util for hyper 1.x body consumption"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0048: http-body-util for hyper 1.x body consumption

## Context

hyper 1.x separates body types and body utilities into two crates: `http-body`
(the trait definitions, a transitive dep of hyper) and `http-body-util` (concrete
helpers such as `BodyExt` and `Collected`). Consuming a streaming request body from
a `hyper::body::Incoming` requires these helpers to collect all bytes before parsing
the DNS message. Without `http-body-util`, consuming a body requires a manual polling
loop on `Body::poll_frame`, which is error-prone and duplicates what `http-body-util`
provides.

## Decision

Use **`http-body-util` 0.1** as a direct dependency in `heimdall-runtime`.

## Considered Options

### Option A — `http-body-util` 0.1 (selected)

Official companion crate to `http-body` and hyper 1.x. Provides `BodyExt::collect`
for bounded, ergonomic body consumption.

- Pros: zero `unsafe` in its own code; maintained by the `hyperium` organisation;
  no additional transitive dependencies beyond `http-body` and `bytes` (both already
  present via hyper); minimal API surface.
- Cons: 0.x version — API may change on minor bumps. Mitigated by `ENG-012`.

### Option B — Manual body streaming

Poll `hyper::body::Incoming` directly via `HttpBody::poll_frame`, accumulating bytes
into a `Vec<u8>` without using `http-body-util`.

- Pros: no external dependency.
- Cons: rejected because manual polling is error-prone at frame boundaries. The
  resulting code duplicates `http-body-util`'s `collect` implementation without
  improving it. The size-cap enforcement (preventing memory exhaustion from oversized
  bodies) is cleaner to express through `BodyExt::collect` with a preceding length
  check than through a manual accumulation loop.

## Audit Trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `http-body-util` |
| Version adopted           | 0.1 |
| Licence                   | MIT |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | 0 in http-body-util itself |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by the `hyperium` organisation |
| Transitive dependencies   | `http-body`, `bytes` — both covered by other ADRs |
| Author identity           | `hyperium` organisation |
| Registry ownership        | Published on crates.io under the `hyperium` organisation |

## Classification

**Core-critical** (runtime dependency). Every DoH/H2 request handler requires body
consumption; removing http-body-util would require reimplementing `collect` inline.

## Consequences

- `http-body-util = "0.1"` added under `[dependencies]` in
  `crates/heimdall-runtime/Cargo.toml`.
- Used in `transport/doh2.rs` to consume `hyper::body::Incoming` bodies.

## Links

- Introduced with Sprint 23, DoH/H2 listener (task #275).
- Companion to ADR-0029 (hyper).
- Implements: NET-025, NET-026 (body parsing for DoH POST requests).
