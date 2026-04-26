---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0026: Adopt tokio as the asynchronous runtime

## Context and Problem Statement

Heimdall must handle extremely high concurrency across multiple transports simultaneously — UDP/53, TCP/53, DoT (TLS on port 853), DoH over HTTP/2 and HTTP/3, DoQ on port 853/udp — while serving queries from the authoritative, recursive resolver, and forwarder roles concurrently. This requires a mature, safe asynchronous I/O runtime. The choice is load-bearing: every transport implementation, every cache operation, every admin-RPC handler, and every structured-event emission depends on this choice.

This ADR grandfathers a decision already implicit in the specification (transport decisions in [`002-transports.md`](../../specification/002-transports.md), platform decisions in [`009-target-environment.md`](../../specification/009-target-environment.md)) per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- Must support UDP, TCP, TLS, HTTP/2, HTTP/3, and QUIC sockets concurrently on all supported platforms (Linux, BSD, macOS).
- Must integrate with `rustls` (DoT, DoH, mTLS on admin-RPC), `quinn` (DoQ), and `hyper` (DoH over HTTP/2+3), all of which have first-class tokio integration.
- Must support `io_uring` as a primary backend on Linux per `ENV-037..039` in [`009-target-environment.md`](../../specification/009-target-environment.md) (via `tokio-uring` or equivalent).
- Must enable `SO_REUSEPORT` multi-socket patterns for CPU-parallel listener sharding.
- Supply-chain risk must be minimal relative to its criticality.

## Considered Options

- **tokio 1.x** — the dominant async runtime in the Rust ecosystem (2024–2026).
- **async-std** — an alternative async runtime; unmaintained as of 2024 and no longer actively developed.
- **smol** — a lightweight runtime; lacks first-class support for TLS integrations used by rustls/hyper/quinn.
- **glommio** — an io_uring-only runtime; no kqueue/epoll fallback, incompatible with BSD/macOS targets.
- **No runtime: manual epoll/io_uring wrappers** — rejects the entire transport ecosystem and requires reimplementing futures, wakers, and task scheduling from scratch.

## Decision Outcome

Chosen option: **tokio 1.x**, because:

- It is the only runtime with mature, first-class integrations for `rustls`, `quinn`, and `hyper`, all of which are mandatory dependencies by specification.
- It supports Linux (`io_uring` via `tokio-uring`), BSD, and macOS (`kqueue`) out of the box, matching the full platform matrix.
- It is the de-facto standard for high-performance Rust servers, with the largest ecosystem of compatible crates.
- Its audit trail is strong: the crate is maintained by the Tokio team with active contributors, regular releases, a disclosed CVE history (none critical as of 2026-04-26), and cargo-vet certifications from multiple peers.

**Classification:** core-critical. Replacing tokio would require rewriting every transport, every async boundary, and all tokio-dependent crate integrations.

## Consequences

**Positive:**

- Native integration with rustls (`tokio-rustls`), quinn, hyper, and all ecosystem crates.
- `io_uring` backend available via `tokio-uring` for Linux hot-path per `ENV-037`.
- Mature task scheduling, timer infrastructure, and I/O readiness model.
- Broad adoption reduces supply-chain risk through community scrutiny.

**Negative:**

- Large transitive dependency graph (mio, parking_lot, etc.) increases the total `cargo-geiger` unsafe count; all unsafe is within well-audited sub-crates.
- Tokio's design choices (work-stealing scheduler) may need explicit tuning (worker threads, blocking threads) for optimal NUMA performance.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** No exemptions required; certifications available from Mozilla and Bytecode Alliance import sources.
- **CVE/RustSec history:** No critical CVEs as of 2026-04-26. Minor advisory RUSTSEC-2021-0124 (resolved in tokio 1.8.1+).
- **Maintenance:** Active; Tokio team releases on a regular cadence. Multiple long-term contributors.
- **Transitive footprint:** mio, bytes, parking_lot, pin-project, socket2, signal-hook — all well-audited.

## License

MIT — permitted by `ENG-094` without qualification.

## Unsafe Footprint (per ENG-009 item 4)

tokio contains `unsafe` blocks primarily in the scheduler internals (task wakers, atomic state transitions), I/O polling integration with mio, and the timer wheel. All unsafe is upstream-audited and covered by the Tokio team's documented invariants. Heimdall does not invoke any `unsafe` paths directly through the tokio public API.

## Supply-Chain Trust (per ENG-009 item 5)

Published on crates.io under the `tokio-rs` organisation. Maintained by the Tokio team with a multi-year track record. No registry ownership disputes. Signed releases are not currently standard practice across crates.io, but the crate's identity is established through long-standing ownership and public key continuity.

## Cross-References

- `ENV-037..039` — io_uring primary / epoll fallback per deployment target.
- `SEC-001..016` — TLS 1.3 requirements (fulfilled via tokio-rustls integration).
- `NET-004..010` — Transport listener requirements.
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
