---
title: "ADR-0044: tokio-rustls for async TLS streams"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0044: tokio-rustls for async TLS streams

## Context

Heimdall's DoT listener (port 853) and future DoH over HTTP/2 listener require a way to
wrap a tokio `TcpStream` with a TLS session managed by rustls (ADR-0027). The standard
rustls `ServerConnection` is synchronous and works over an abstract `io::Read`/`io::Write`
pair; bridging it to tokio's async I/O primitives requires explicit integration.

`tokio-rustls` provides exactly this bridge: it wraps a rustls `ServerConnection` inside a
`TlsAcceptor` that performs the handshake asynchronously on a `TcpStream`, yielding a
`TlsStream<TcpStream>` that implements `AsyncRead + AsyncWrite`. This is the canonical
integration pattern in the Rust async ecosystem.

## Decision Drivers

- Must integrate rustls TLS sessions with tokio async I/O (ADR-0026, ADR-0027).
- TLS 1.2 must not be reachable at runtime; the crate must not activate the `tls12` feature
  of rustls (SEC-003).
- The `unsafe` footprint of the crate must be minimal or absent in the Rust layer.
- Must be maintained by the same team or closely tracked with the rustls release cycle.

## Considered Options

- **tokio-rustls 0.26** (selected) — the canonical async integration layer for rustls 0.23.x.
- **hyper-tls** — HTTP-only; does not expose the raw `TlsStream<TcpStream>` needed for DoT.
- **async-tls** — unmaintained; tracked rustls 0.20 and was abandoned when the rustls API
  changed in 0.21.
- **Manual bridging via `tokio::io::ReadBuf` + rustls `ServerConnection`** — feasible but
  reproduces exactly what `tokio-rustls` already does; no benefit.

## Decision Outcome

Chosen option: **tokio-rustls 0.26**, because:

- It is the canonical, actively maintained integration between tokio and rustls.
- Version 0.26 pairs exactly with rustls 0.23.x, which is the version adopted in ADR-0027.
- It contains zero `unsafe` in the Rust layer that Heimdall calls; all unsafe is in the
  underlying rustls and ring crates, which are already audited.
- The `tls12` feature is NOT activated; only TLS 1.3 handshake paths are compiled in,
  satisfying SEC-003.
- It is published on crates.io under the `tokio-rs` organisation and maintained by the
  same team.

**Classification:** core-critical. Every DoT, DoH/H2, and admin-RPC-over-TLS surface
depends on this integration layer.

## Audit Trail (per ENG-009 item 2)

| Field                       | Value |
|-----------------------------|-------|
| crates.io name              | `tokio-rustls` |
| Version adopted             | 0.26.x |
| Licence                     | MIT / Apache-2.0 (dual) — permitted by ENG-094 |
| `unsafe` blocks (Rust layer) | 0 — confirmed via `cargo geiger` |
| Known CVEs                  | None at time of adoption |
| RustSec advisories          | None open at time of adoption |
| Maintenance activity        | Active; co-maintained with the rustls maintainers; releases track rustls minor versions |
| Transitive dependencies     | `rustls`, `tokio`, `rustls-pki-types` — all already in the dependency tree |
| Author identity             | ZHANG Yuchen (quininer) and tokio-rs contributors |

## Consequences

**Positive:**

- `TlsAcceptor::accept(stream)` yields a cancel-safe future; on error the underlying
  `TcpStream` is dropped cleanly without leaking the TLS state machine.
- `TlsStream<TcpStream>` implements `AsyncRead + AsyncWrite`, making it a drop-in
  replacement for `TcpStream` in the per-connection handler.

**Negative:**

- Tightly coupled to rustls version: a major bump in rustls requires a matching bump in
  `tokio-rustls`. This is a tracking obligation, not a safety concern.

## Cross-References

- ADR-0026 — tokio async runtime.
- ADR-0027 — rustls TLS 1.3 library.
- SEC-001..007 — TLS 1.3-only, 0-RTT prohibition.
- NET-004 — DoT listener (TLS on port 853).
