---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0028: Adopt quinn as the QUIC implementation

## Context and Problem Statement

Heimdall requires QUIC v1 and v2 support for DoQ (DNS over QUIC, port 853/udp) per `NET-008` in [`002-transports.md`](../../specification/002-transports.md) and for the HTTP/3 transport layer underlying DoH over HTTP/3. QUIC is the transport for both DoQ and HTTP/3. The choice of QUIC library determines the protocol compliance posture, the TLS-in-QUIC integration, and the 0-RTT/amplification security behaviour (`SEC-017..035` in [`003-crypto-policy.md`](../../specification/003-crypto-policy.md)).

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- QUIC v1 (RFC 9000) and v2 (RFC 9369) required; no other versions (`SEC-020`).
- 0-RTT data must be refused to eliminate replay attack surfaces (`SEC-022..024`).
- Amplification mitigation (Retry tokens, anti-amplification limit) must be implemented (`SEC-025..027`).
- Must integrate with rustls (chosen in ADR-0027) for TLS-in-QUIC (`SEC-019`).
- Must integrate with tokio (chosen in ADR-0026) as the async runtime.
- `NEW_TOKEN` keys must be rotatable at runtime (`SEC-028..030`).

## Considered Options

- **quinn 0.11.x** — pure-Rust QUIC library, built on `rustls` and `tokio`.
- **s2n-quic** — AWS's QUIC implementation; uses its own TLS abstraction (s2n-tls), not rustls; C TLS dependency introduced.
- **neqo** — Mozilla's Firefox QUIC library; not designed as a standalone server library; minimal public API.
- **msquic** — Microsoft's QUIC library; C code via FFI; requires building native libraries outside the Rust ecosystem.
- **No external QUIC: implement from RFC 9000** — implementing a QUIC stack from scratch is a years-long project; rejected on scope grounds.

## Decision Outcome

Chosen option: **quinn 0.11.x**, because:

- It is the only pure-Rust QUIC library with first-class `rustls` and `tokio` integration, consistent with ADR-0026 and ADR-0027.
- It supports QUIC v1 and v2, Retry tokens, and anti-amplification limits out of the box, satisfying `SEC-020` and `SEC-025..027`.
- It refuses 0-RTT by default (or makes 0-RTT acceptance explicit), satisfying `SEC-022..024`.
- `NEW_TOKEN` key rotation is exposed through the `ServerConfig` abstraction, satisfying `SEC-028..030`.
- The HTTP/3 ecosystem (`h3` crate) is built on top of quinn, enabling DoH over HTTP/3 (`NET-007`) without a separate QUIC implementation.

**Classification:** core-critical. Replacing quinn would require finding or building a QUIC implementation that integrates with both rustls and tokio, which has no viable alternative in the current Rust ecosystem.

## Consequences

**Positive:**

- Unified QUIC layer for both DoQ (port 853/udp) and HTTP/3 (DoH).
- `rustls`-backed TLS-in-QUIC with the same session-ticket and mTLS semantics as DoT/DoH.
- `h3` crate (HTTP/3 over quinn) enables DoH-over-HTTP/3 without code duplication.

**Negative:**

- quinn's API evolves rapidly (0.x versioning); breaking changes on minor bumps are expected pre-1.0. Mitigation: dependency ADR update required on each major API change per `ENG-012`.
- QUIC congestion control tuning (CUBIC, BBR) may require additional configuration for high-load performance.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** Certifications available; quinn is widely used (cloudflare/quiche ecosystem provides adjacent audits).
- **CVE/RustSec history:** No critical CVEs as of 2026-04-26.
- **Maintenance:** Active; maintained by the quinn-rs project team with regular releases.
- **Transitive footprint:** rustls, tokio, ring/aws-lc-rs, bytes — all covered by other ADRs or well-audited.

## License

MIT / Apache-2.0 dual-licensed — permitted by `ENG-094`.

## Unsafe Footprint (per ENG-009 item 4)

quinn itself contains minimal `unsafe`; the unsafe footprint comes primarily from its dependencies (`rustls`, `ring`/`aws-lc-rs`, `tokio`). All are covered by upstream audits documented in their respective ADRs. Heimdall does not call any `unsafe` paths directly through the quinn public API.

## Supply-Chain Trust (per ENG-009 item 5)

Published on crates.io under the `quinn-rs` organisation. Maintained by a small but active team. No registry ownership disputes. Identity continuity established through long-standing ownership.

## Cross-References

- `SEC-017..035` — QUIC hardening requirements (version, 0-RTT, amplification, NEW_TOKEN).
- `NET-008` — DoQ listener (QUIC on port 853/udp).
- `NET-007` — DoH over HTTP/3 (QUIC transport layer).
- `ADR-0026` — tokio integration.
- `ADR-0027` — rustls integration (TLS-in-QUIC).
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
