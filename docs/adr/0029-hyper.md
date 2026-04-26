---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0029: Adopt hyper as the HTTP implementation

## Context and Problem Statement

Heimdall requires HTTP/2 server support for DoH over HTTP/2 (`NET-005..006`) and HTTP/3 support for DoH over HTTP/3 (`NET-007`). Additionally, the HTTP observability endpoint (`OPS-021..032` in [`012-runtime-operations.md`](../../specification/012-runtime-operations.md)) requires an HTTP server for `/healthz`, `/readyz`, `/metrics`, and `/version` endpoints. The HTTP implementation must support GET and POST methods, the `application/dns-message` content type, and HPACK/QPACK header compression, with the hardening defaults fixed by `SEC-036..046` in [`003-crypto-policy.md`](../../specification/003-crypto-policy.md).

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- HTTP/2 server required for DoH over HTTP/2 (RFC 8484).
- HTTP/3 server required for DoH over HTTP/3 (RFC 9114), to be layered on the quinn QUIC implementation (ADR-0028).
- Must integrate with tokio (ADR-0026) and rustls (ADR-0027).
- HPACK dynamic-table cap, concurrent-stream cap, rapid-reset detection, and CONTINUATION cap must be configurable per `SEC-036..046`.
- HTTP/1.1 support is not required (DoH does not use HTTP/1.1).

## Considered Options

- **hyper 1.x** — low-level, high-performance HTTP/1.1 and HTTP/2 library; HTTP/3 via the `h3` crate on top of quinn.
- **axum** — opinionated web framework built on hyper; brings routing, middleware, and extractor abstractions that are unnecessary overhead for a DNS server.
- **actix-web** — mature web framework; uses its own runtime model (actix) that conflicts with tokio.
- **warp** — functional HTTP framework built on hyper 0.x; no HTTP/3 support.
- **No external HTTP: implement RFC 9113 (HTTP/2) from scratch** — implementing HTTP/2 frame parsing, HPACK, and multiplexing from scratch is months of work; rejected on scope grounds.

## Decision Outcome

Chosen option: **hyper 1.x** (HTTP/2 server), combined with **h3 0.x** (HTTP/3 over quinn), because:

- hyper 1.x provides a low-level HTTP/2 server with explicit control over HPACK dynamic table caps, stream concurrency, and flow-control windows, which are required for the hardening posture of `SEC-036..046`.
- It integrates natively with tokio and rustls via `hyper-rustls`.
- HTTP/3 is layered via the `h3` crate, which is built on top of quinn (ADR-0028), reusing the same QUIC infrastructure.
- No unnecessary routing, middleware, or framework abstractions are imposed on Heimdall's DoH endpoint, which has a single well-defined path (`/dns-query`).

**Classification:** core-critical. Replacing hyper would require finding another HTTP/2 server library with equivalent tokio and rustls integration, of which no viable pure-Rust alternative exists as of 2026.

## Consequences

**Positive:**

- Explicit, auditable HTTP/2 configuration surface: HPACK cap, stream limit, CONTINUATION cap, and flow-control windows are directly configurable.
- HTTP/3 reuses the quinn QUIC layer already present (ADR-0028) via `h3`.
- No unnecessary framework overhead; the DNS server controls every part of the HTTP layer.

**Negative:**

- hyper 1.x's API is lower-level than frameworks like axum; more boilerplate is required for the observability endpoint, which is acceptable given the limited endpoint surface.
- `h3` is under active development (0.x); API may change on minor bumps. Mitigation: `ENG-012` update-ADR obligation applies.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** Mozilla and Bytecode Alliance certifications available; hyper is the foundation of much of the Rust HTTP ecosystem.
- **CVE/RustSec history:** No critical CVEs as of 2026-04-26.
- **Maintenance:** hyper 1.x is actively maintained by the Hyper team; h3 is maintained by the `hyperium` organisation.
- **Transitive footprint:** http, http-body, bytes, tokio, rustls — all covered by other ADRs or well-audited.

## License

MIT — permitted by `ENG-094`.

## Unsafe Footprint (per ENG-009 item 4)

hyper contains minimal `unsafe`, primarily in connection I/O and buffer management. The `unsafe` footprint is smaller than the async runtime it sits on. Heimdall does not call any `unsafe` paths directly through the hyper public API.

## Supply-Chain Trust (per ENG-009 item 5)

Published on crates.io under the `hyperium` organisation. Maintained by a well-established team with documented governance. No registry ownership disputes.

## Cross-References

- `SEC-036..046` — HTTP/2 and HTTP/3 hardening numeric defaults.
- `NET-005..006` — DoH over HTTP/2 listener.
- `NET-007` — DoH over HTTP/3 listener.
- `OPS-021..032` — HTTP observability endpoint.
- `ADR-0026` — tokio integration.
- `ADR-0027` — rustls integration (hyper-rustls).
- `ADR-0028` — quinn integration (h3 over quinn for HTTP/3).
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
