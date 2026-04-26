---
title: "ADR-0045: rustls-pemfile for PEM certificate and key parsing"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0045: rustls-pemfile for PEM certificate and key parsing

## Context

Operator-supplied TLS certificates and private keys are delivered as PEM files, the
universal interchange format used by OpenSSL, Let's Encrypt (Certbot), ACME clients, and
all major CA issuance pipelines. The server configuration factory in
`crates/heimdall-runtime/src/transport/tls.rs` must parse these files at startup and
on configuration reload.

PEM files contain Base64-encoded DER blocks framed by `-----BEGIN ...-----` / `-----END
...-----` markers. Parsing them involves boundary detection, Base64 decoding, and mapping
block type labels to the appropriate `rustls-pki-types` structures
(`CertificateDer`, `PrivateKeyDer`). This is non-trivial to get right under adversarial
input, and manual implementation is error-prone.

`rustls-pemfile` is the canonical PEM-parsing crate maintained alongside rustls. It
produces `rustls-pki-types` types directly, which are the exact types expected by the
rustls `ServerConfig` builder.

## Decision Drivers

- Must parse PEM certificate chains and private key files into types accepted by rustls 0.23.x.
- Zero `unsafe` in Heimdall's own code; crate must not introduce new `unsafe` on the parse path.
- Must be maintained by the same team as rustls to stay in sync with type definitions.
- Used only on the configuration / startup path, never on the hot query path.

## Considered Options

- **rustls-pemfile 2.x** (selected) — canonical rustls PEM parser, tracks rustls-pki-types 1.x.
- **pem** crate — generic PEM block reader; does not produce `rustls-pki-types` types
  directly; requires additional DER parsing.
- **openssl** / **openssl-sys** — C FFI, introduces OpenSSL as a build dependency; rejected
  on supply-chain grounds.
- **Manual Base64 + DER parsing** — error-prone; violates the security principle that
  parsing untrusted input must use well-audited libraries; rejected.

## Decision Outcome

Chosen option: **rustls-pemfile 2.x**, because:

- It is maintained by the rustls maintainers and tracks `rustls-pki-types` 1.x precisely.
- It contains zero `unsafe` in its Rust implementation.
- It handles the full set of PEM block types Heimdall needs: `CERTIFICATE`,
  `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `PRIVATE KEY` (PKCS#8).
- It is already a transitive dependency via rustls; promoting it to a direct dependency
  adds no new supply-chain surface.
- Its API (`certs`, `private_key`, `pkcs8_private_keys`) maps directly to the structs
  required by `ServerConfig::builder().with_single_cert(...)`.

**Classification:** convenience (configuration / startup path only, never on the hot query
path). Replacing it would require implementing PEM parsing manually or pulling in an
alternative parser — both higher-risk options.

## Audit Trail (per ENG-009 item 2)

| Field                       | Value |
|-----------------------------|-------|
| crates.io name              | `rustls-pemfile` |
| Version adopted             | 2.x |
| Licence                     | MIT / Apache-2.0 (dual) — permitted by ENG-094 |
| `unsafe` blocks             | 0 — confirmed via `cargo geiger` |
| Known CVEs                  | None at time of adoption |
| RustSec advisories          | None open at time of adoption |
| Maintenance activity        | Active; maintained by the rustls maintainers; releases track rustls-pki-types versions |
| Transitive dependencies     | `base64`, `rustls-pki-types` — already in the tree |
| Author identity             | ctz, djc, and the rustls maintainer group |

## Consequences

**Positive:**

- Structured API returns typed errors (`Error::NoItemsFound`, etc.) rather than raw
  bytes; malformed PEM files produce clean diagnostics at startup rather than panics or
  misinterpretations.
- The `certs()` reader is an iterator; it does not require holding the entire file in
  memory simultaneously.

**Negative:**

- Minor version coupling: a breaking change in `rustls-pki-types` requires a matching
  bump in `rustls-pemfile`. This is a tracking obligation managed alongside the rustls
  dependency.

## Cross-References

- ADR-0027 — rustls TLS 1.3 library.
- ADR-0044 — tokio-rustls async integration.
- ADR-0046 — rcgen test certificate generation (dev-dependency).
- SEC-063 — mTLS trust anchor PEM file loading.
