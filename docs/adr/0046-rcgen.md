---
title: "ADR-0046: rcgen for test certificate generation"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0046: rcgen for test certificate generation

## Context

Integration tests for the DoT listener (Sprint 22) require valid TLS certificates for
the server and, for mTLS tests, for test clients. There are two strategies for providing
test certificates:

1. **Pre-baked certificates committed to the repository.** Certificates expire; rotating
   them is a manual, coordination-intensive operation prone to breakage. Self-signed certs
   committed as binary blobs also require manual review of the blob whenever the build
   toolchain or test policy changes.

2. **Programmatic generation at test time.** Each test run generates a fresh certificate
   with a generous validity window (e.g., 100 years). No manual rotation, no committed
   blobs, no drift between the certificate and the test expectations.

`rcgen` is a pure-Rust X.509 certificate generation library that supports RSA, ECDSA
(P-256, P-384), and Ed25519, produces both DER and PEM output, and integrates natively
with `rustls-pki-types`.

## Decision Drivers

- Must produce self-signed certificates accepted by rustls 0.23.x at test time.
- Must be a dev-dependency only; it must not appear in the production binary.
- Zero `unsafe` required; `cargo-geiger` must report clean for Heimdall's own code.
- Certificates must be generated programmatically so that tests never rely on committed
  credential material.

## Considered Options

- **rcgen** (selected) — pure-Rust X.509 generation; produces `rustls-pki-types` natively.
- **Pre-baked DER constants embedded in test modules** — rejected: manual rotation burden;
  certificates expire; DER blobs require binary review.
- **openssl CLI invoked in a build script** — rejected: introduces an OS dependency on
  OpenSSL being installed; non-reproducible across platforms; rejected by CI portability
  requirement.
- **x509-certificate** crate — supports parsing but not generation in the version available
  at the time of adoption.

## Decision Outcome

Chosen option: **rcgen** as a `[dev-dependencies]` entry, because:

- It is pure Rust with zero `unsafe` in the generation layer.
- It produces self-signed certificates directly compatible with rustls 0.23.x through
  `rustls-pki-types` (`CertificateDer`, `PrivateKeyDer`).
- It is a dev-dependency only and therefore does not affect the production binary or the
  SBOM of a release artefact.
- It removes the need for committed credential material in the test suite.

**Classification:** convenience (test-time only, never in production binary).

## Audit Trail (per ENG-009 item 2)

| Field                       | Value |
|-----------------------------|-------|
| crates.io name              | `rcgen` |
| Version adopted             | 0.13.x |
| Licence                     | MIT / Apache-2.0 (dual) — permitted by ENG-094 |
| `unsafe` blocks             | 0 — confirmed via `cargo geiger` |
| Known CVEs                  | None at time of adoption |
| RustSec advisories          | None open at time of adoption |
| Maintenance activity        | Active; maintained by estk and contributors |
| Transitive dependencies     | `ring`, `pem`, `yasna` — all permissively licenced |
| Author identity             | est31 (estk) |

## Consequences

**Positive:**

- Tests are hermetic: no filesystem certificate files required; no `TEST_CERT_PATH`
  environment variable needed; CI runs without external provisioning.
- Fresh certificates are generated on every test run; expiry is never a test-failure
  vector.

**Negative:**

- `rcgen` generates certificates during test compilation linkage, adding a small latency
  to the first test run build. This is acceptable in a test context.
- `rcgen` is not in the production dependency tree, so supply-chain obligations for it are
  lighter (dev-dep policy under ENG-009 item 6 applies rather than the full ENG-009
  audit).

## Cross-References

- ADR-0027 — rustls (the consumer of generated certificates in tests).
- ADR-0044 — tokio-rustls (the TLS acceptor exercised by the DoT round-trip tests).
- ADR-0045 — rustls-pemfile (used in the server-side PEM loading path under test).
