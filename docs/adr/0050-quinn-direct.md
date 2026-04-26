---
title: "ADR-0050: Promote quinn 0.11 to direct dependency in heimdall-runtime"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0050: Promote quinn 0.11 to direct dependency in heimdall-runtime

## Context

ADR-0028 selected `quinn` as Heimdall's QUIC implementation, recording the
crate-selection rationale (QUIC v1 + v2, rustls integration, tokio runtime,
Retry token generation, 0-RTT refusal). That ADR covers the library decision.
This ADR records the promotion of `quinn` to a **direct dependency** of the
`heimdall-runtime` crate and the specific version, feature flags, and security
posture applied during Sprint 24.

## Decision

Promote `quinn 0.11` to a direct `[dependencies]` entry in
`crates/heimdall-runtime/Cargo.toml` with the following declaration:

```toml
quinn = { version = "0.11", features = ["runtime-tokio"] }
```

### Feature selection

| Feature | Reason |
|---------|--------|
| `runtime-tokio` | Integrates quinn's async I/O with the tokio executor chosen in ADR-0026. Required for `quinn::Endpoint::accept()` and all async stream operations. Without this feature, quinn falls back to its own blocking I/O which is incompatible with tokio's cooperative scheduler. |

No other features are enabled. In particular:

- `rustls-ring`: **not** directly selected on `quinn`. Quinn's `ring` feature
  is satisfied transitively through `rustls` (ADR-0027) which already pulls in
  `ring` (ADR-0036). Enabling it redundantly on `quinn` would duplicate the
  feature-resolution constraint without adding clarity.
- `aws-lc-rs`: **not** enabled. Heimdall uses `ring` as its cryptographic
  primitive library throughout (ADR-0036); mixing `aws-lc-rs` into the QUIC
  path would introduce a second cryptographic backend with a C/C++ build
  dependency, violating the supply-chain minimisation principle.
- `qlog`, `rustls-platform-verifier`: **not** enabled. Qlog is an observability
  format not used in the current sprint; platform verifier is irrelevant for a
  server with operator-supplied certificates.

### Version pinning

`"0.11"` selects the latest patch release within the `0.11.x` series (currently
`0.11.9`). Quinn uses 0.x versioning, meaning minor bumps may introduce breaking
API changes. Each quinn minor-version bump requires a dependency ADR update per
`ENG-012`.

### 0-RTT refusal

`SEC-022..024` prohibit QUIC 0-RTT on all Heimdall QUIC listeners. The
enforcement mechanism is:

1. The `rustls::ServerConfig` produced by `build_tls_server_config` has
   `max_early_data_size = 0` (set explicitly in Sprint 22, enforced by
   `tls.rs`).
2. `quinn_proto::crypto::rustls::QuicServerConfig::try_from(Arc<ServerConfig>)`
   — the conversion used in `build_quinn_endpoint` — rejects `ServerConfig`
   values with `max_early_data_size` other than `0` or `u32::MAX`. A value of
   `0` instructs quinn to refuse all early-data packets without processing them.
3. No API surface in the `heimdall-runtime` public API enables 0-RTT (`SEC-024`).

### QUIC version restriction

`EndpointConfig::supported_versions` is set to `[0x00000001, 0x6b3343cf]`
(QUIC v1 and v2 only) per `SEC-017..019`. Clients presenting only unsupported
versions receive a Version Negotiation packet (RFC 8999, RFC 9000 §6).

### Amplification mitigation

quinn enforces the RFC 9000 §8.1 anti-amplification limit (3× unvalidated
bytes received) internally. No Heimdall-level configuration is required.
Unconditional Retry (`SEC-026`) is implemented in the `DoqListener` accept
loop via `Incoming::retry()`.

### `quinn_proto` access

`quinn 0.11` re-exports the types from `quinn_proto` under `quinn::` — notably
`quinn::TransportConfig`, `quinn::IdleTimeout`, `quinn::VarInt`,
`quinn::EndpointConfig`, `quinn::ServerConfig`, and
`quinn::crypto::rustls::QuicServerConfig`. Heimdall accesses all types through
the `quinn::` namespace without taking a direct dependency on `quinn_proto`.

## Considered Options

### Upgrade to quinn 0.12 (when available)

Quinn `0.12` was not yet stable at the time of Sprint 24. This ADR will be
superseded by an update ADR when a `0.12` upgrade is warranted.

### Take a direct `quinn_proto` dependency

Rejected. `quinn_proto` is an internal implementation detail of `quinn`; its
public API surface is not stable across minor versions. All necessary types are
accessible through `quinn::`.

## Audit Trail (per ENG-009)

| Field | Value |
|-------|-------|
| crates.io name | `quinn` |
| Version adopted | 0.11.9 (semver range `"0.11"`) |
| Licence | MIT OR Apache-2.0 (permitted by ENG-094) |
| `unsafe` blocks | Minimal in `quinn` itself; the unsafe footprint is in transitive dependencies (`rustls`, `ring`, `tokio`, `quinn-udp`) all covered by upstream audits in their respective ADRs |
| Known CVEs | None in `quinn` at 2026-04-26 |
| RustSec advisories | None open at 2026-04-26 |
| Maintenance | Active; `quinn-rs` organisation; regular releases |
| Transitive additions | `quinn-proto`, `quinn-udp` (both `quinn-rs`), `rustc-hash`, `lru-slab`, `tinyvec`, `rand`, `ring` (already present), `tokio` (already present) |
| Registry ownership | Published on crates.io under the `quinn-rs` organisation |

## Classification

**Core-critical** — QUIC transport is a first-class Heimdall feature (`NET-008`,
`NET-007`). Replacing `quinn` requires replacing the entire QUIC layer and its
TLS-in-QUIC integration.

## Consequences

- `quinn = { version = "0.11", features = ["runtime-tokio"] }` is added to
  `crates/heimdall-runtime/Cargo.toml` under `[dependencies]`.
- `transport::quic` module is added to `heimdall-runtime`, implementing
  `DoqListener`, `QuicHardeningConfig`, `StrikeRegister`, `NewTokenTekManager`,
  `QuicTelemetry`, and `build_quinn_endpoint`.
- Future quinn minor-version bumps require a dependency-ADR update per `ENG-012`
  before the bump is merged.
- QUIC congestion control tuning (CUBIC vs. BBR, initial window) is deferred
  to a post-1.0 performance sprint.

## Links

- Introduced with Sprint 24.
- Supersedes part of ADR-0028 (promotes from transitive to direct dep and
  records the specific feature selection).
- Implements: `SEC-017..035`, `SEC-071..075`, `NET-008`.
- Related ADRs: ADR-0026 (tokio), ADR-0027 (rustls), ADR-0028 (quinn
  crate selection), ADR-0036 (ring), ADR-0044 (tokio-rustls).
