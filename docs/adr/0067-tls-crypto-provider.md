# ADR-0067: `rustls` cryptographic provider — `ring` as default, `aws-lc-rs` deferred

Status: accepted (2026-05-10, Sprint 65 task #669).

Supersedes the relevant clause of ADR-0036 (rustls + provider) and amends
THREAT-150 in `specification/007-threat-model.md`.

## Context

`rustls` 0.23+ supports two cryptographic providers via Cargo features:
`ring` and `aws-lc-rs`. The original threat-model wording (THREAT-150)
declared `aws-lc-rs` the default with `ring` as an alternative. The actual
code shipping at v1.1.1 wires `ring` exclusively in every Cargo.toml
(`crates/heimdall*/Cargo.toml`). No feature flag, no build matrix, no
test exercises the `aws-lc-rs` path. The drift between spec and code
created an inability to claim FIPS posture publicly and a soundness gap
in the threat model.

Task #669 forced a decision: either bring the code up to the spec
(introduce a feature flag + build matrix, expand the audit surface) or
bring the spec down to the code (declare `ring` the default and document
the deferral). Both providers are constant-time for the algorithms used
at the TLS layer; the choice is a supply-chain / FIPS / build-cost
decision, not a security-vs-insecurity decision.

## Decision

`ring` is the default and currently sole cryptographic provider for
`rustls` (and `quinn` over rustls, transitively). `aws-lc-rs` is
deferred. When the project introduces FIPS-alignment requirements, a
follow-up ADR will add `aws-lc-rs` behind a Cargo feature and a CI build
matrix that exercises both providers; the spec will be re-amended at
that point.

## Rationale

### Supply chain

`ring` is a pure-Rust crate with a small audited C component (BoringSSL
fork). `aws-lc-rs` is a Rust binding over `aws-lc-sys`, a substantial
AWS-LibCrypto fork of BoringSSL that requires a C++ toolchain to build
from source and ships C++ object files when used pre-built. Adding
`aws-lc-rs` would expand the `cargo-vet` exemption list materially
(several supporting crates) and increase the toolchain surface.

### Build cost

`aws-lc-rs` adds 30-60 seconds to a clean build on every CI runner —
material for the per-PR Tier-1 budget. A dual-provider matrix doubles
the cost on every PR that touches `crates/heimdall-runtime` or
`crates/heimdall`.

### FIPS posture

The project does not currently have a FIPS-validated downstream
requirement. Declaring `ring` the default does not block a future FIPS
deployment: the project remains free to introduce `aws-lc-rs` later via
a Cargo feature without breaking changes for the default builders.

### Constant-time properties

Both `ring` and `aws-lc-rs` provide constant-time AEAD constructions
and constant-time signature verification for the algorithms used at the
TLS layer. Side-channel resistance is not the decision axis for
choosing between them.

## Consequences

### Positive

- THREAT-150 and the code agree. No outstanding drift.
- Single CI build path for crypto; faster PRs.
- Lower audit surface for `cargo-vet` and `cargo-deny`.
- No false claim of FIPS alignment in public-facing material.

### Negative

- A future FIPS deployment will need a follow-up ADR + feature wiring
  before it can validate the deployment.
- Until that follow-up lands, `aws-lc-rs` is not available even as an
  opt-in. Operators who need FIPS-aligned providers today must hold off
  or maintain a private fork.

## Implementation notes

- THREAT-150 in `specification/007-threat-model.md` updated to declare
  `ring` the default and reference this ADR.
- `docs/security-posture.md` §2.1 updated correspondingly.
- THREAT-151 residual-risk text adjusted: "ring bindings today;
  aws-lc-rs when introduced per ADR-0067".
- Every `crates/*/Cargo.toml` already pins
  `rustls = { version = "0.23", default-features = false, features = ["std", "ring"] }`;
  no code change required by this ADR.

## When to revisit

- A downstream customer requires FIPS 140-3 / 140-2 validation.
- The Rust crypto ecosystem gains a pure-Rust FIPS-validated provider.
- `aws-lc-rs` matures to the point its supply chain weight is
  comparable to `ring`.
