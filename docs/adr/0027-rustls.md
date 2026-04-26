---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0027: Adopt rustls as the TLS implementation

## Context and Problem Statement

Heimdall requires TLS 1.3 across multiple surfaces: DoT listeners (port 853), DoH listeners (HTTP/2+3), mTLS on the admin-RPC TCP binding, mTLS on the HTTP observability endpoint when non-loopback, and outbound connections to upstream resolvers and Redis. The choice of TLS library determines the cryptographic trust boundary, the cipher suite negotiation, and the session-ticket security posture (`SEC-001` through `SEC-016` in [`003-crypto-policy.md`](../../specification/003-crypto-policy.md)).

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- TLS 1.3 exclusively; TLS 1.2 must not be supported (`SEC-003`).
- Pure Rust implementation required for supply-chain safety and memory safety guarantees.
- Must integrate with tokio (chosen in ADR-0026) via `tokio-rustls`.
- Must support stateless session tickets with configurable rotation cadence (`SEC-008..011`).
- Must support mutual TLS with custom certificate validation logic (`SEC-012..016`).
- Must refuse 0-RTT data to eliminate replay attack surfaces (`SEC-005..007`).

## Considered Options

- **rustls 0.23.x** — pure-Rust TLS 1.3-only library.
- **openssl / openssl-sys** — bindings to libssl; C code, not memory-safe, historically the source of numerous critical CVEs (Heartbleed, POODLE, etc.).
- **boring** — Google's BoringSSL Rust bindings; C code, no community support outside Google's internal use.
- **mbedtls** — ARM's C TLS library; C code, limited Rust ecosystem integration.
- **native-tls** — platform-native TLS (SChannel/SecureTransport/OpenSSL); divergent behaviour across platforms, cannot guarantee TLS 1.3-only posture on all targets.
- **No TLS: TLS offloaded to a sidecar** — rejected by the threat model; would expose plaintext between Heimdall and the sidecar.

## Decision Outcome

Chosen option: **rustls 0.23.x**, because:

- It is the only pure-Rust TLS 1.3 implementation with a complete, stable public API as of 2026.
- It enforces TLS 1.3 as the minimum version and refuses all downgrade-negotiation by design, satisfying `SEC-003`.
- It refuses 0-RTT data by default, satisfying `SEC-005..007`.
- It integrates natively with tokio via `tokio-rustls` (chosen runtime, ADR-0026).
- Its cryptographic backend (`aws-lc-rs` or `ring`) is independently audited.
- It is the reference TLS library for the Rust ecosystem and has the widest cargo-vet coverage.

**Classification:** core-critical. Replacing rustls would require rewriting every TLS surface across all transports and connections.

## Consequences

**Positive:**

- Memory safety by construction: all TLS state lives in Rust with no C heap.
- Explicit TLS 1.3-only posture enforced at compile time, not configuration.
- Session tickets managed programmatically through the `ServerConfig` builder, enabling the TEK rotation pattern required by `SEC-010`.
- Strong `cargo-vet` coverage from Mozilla, Bytecode Alliance, and crates.io community.

**Negative:**

- Does not support reading system trust stores natively; a helper crate (`rustls-native-certs`) is required for outbound TLS to systems using system CAs.
- Certificate pinning beyond what the standard `rustls` verifier provides requires a custom `ServerCertVerifier` implementation.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** Certifications from Mozilla and Bytecode Alliance.
- **CVE/RustSec history:** No critical CVEs. Minor advisories resolved upstream within days of disclosure.
- **Maintenance:** Maintained by the Rustls maintainers (independent of any single company) with regular releases.
- **Transitive footprint:** `aws-lc-rs` or `ring`, `webpki`, `rustls-pemfile` — all audited.

## License

Apache-2.0 / MIT dual-licensed — permitted by `ENG-094`. Attribution obligations acknowledged.

## Unsafe Footprint (per ENG-009 item 4)

rustls itself contains minimal `unsafe`; its cryptographic backend (`aws-lc-rs` or `ring`) contains `unsafe` for SIMD acceleration and FFI to the underlying C crypto library. This unsafe is upstream-audited by the respective maintainers. Heimdall does not invoke any `unsafe` paths directly through the rustls public API.

## Supply-Chain Trust (per ENG-009 item 5)

Published on crates.io under the `rustls-family` organisation. Maintained by a governance committee with documented decision-making. No registry ownership disputes.

## Cross-References

- `SEC-001..016` — TLS 1.3, session tickets, 0-RTT refusal, mTLS requirements.
- `NET-004` — DoT listener (TLS on port 853).
- `NET-005..007` — DoH listeners (TLS on HTTP/2+3).
- `OPS-009` — Admin-RPC TCP binding with mTLS.
- `ADR-0026` — tokio integration (tokio-rustls).
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
