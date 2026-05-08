# ADR-0066: DNSSEC signing — RSA, SIG(0), Ed448

**Status.** Proposed (Sprint 62, tasks #654, #655, #656).

**Date.** 2026-05-08.

**Specification.** DNSSEC-031..040 in
`specification/005-dnssec-policy.md` enumerate the algorithms Heimdall
accepts for validation and signing. The 2026-05-08 audit identified a
gap: validation works for the full set, but signing on the
authoritative path is implemented for none of the asymmetric
algorithms — only TSIG (HMAC-SHA256) is signed.

This ADR records the design and staging plan for filling the
authoritative signing surface across the three algorithm families
identified in the audit.

---

## 1. Algorithm scope

| Algorithm | Number | Validation | Signing — current | Signing — staging |
|---|---|---|---|---|
| RSA-SHA1   |  5 | MAY | MUST NOT (RFC 8624) | MUST NOT (deprecated) |
| RSA-SHA256 |  8 | MUST | not implemented | **#654** Sprint 63 |
| RSA-SHA512 | 10 | MUST | not implemented | **#654** Sprint 63 |
| ECDSA P-256 | 13 | MUST | not implemented | Sprint 64 (parallel ECDSA work) |
| ECDSA P-384 | 14 | MUST | not implemented | Sprint 64 |
| Ed25519    | 15 | MUST | not implemented | Sprint 64 |
| Ed448      | 16 | MAY  | not implemented | **#656** blocked on `ring` upstream |

SIG(0) (RFC 2931, **#655**) is a separate use of the same algorithm
families on the inbound UPDATE path; its signing surface is shared
with the DNSSEC signers.

## 2. Decision (Sprint 62 — this ADR)

The signing implementation is deferred to Sprint 63 / 64 because:

- The signer interface must integrate cleanly with the existing
  validation surface (`crates/heimdall-core/src/dnssec/`) so a future
  signing-then-validating round-trip remains coherent.
- Key material handling (KSK / ZSK lifecycle, on-disk format,
  rotation) is a separate ADR-class decision (Sprint 63 ADR-0067
  scope).
- Backend choice (`aws-lc-rs` vs `ring` for RSA-SHA256/SHA512) is a
  policy decision that interacts with the existing TLS backend
  selection in `Cargo.toml`.

This ADR documents the staged plan; it does not introduce any signing
code. The 2026-05-08 audit findings are resolved against this ADR
rather than against an in-flight implementation that would add risk
without measurable benefit before Sprint 63.

## 3. Staging plan

### 3.1 Sprint 63 — RSA-SHA256 / RSA-SHA512 signing (#654)

- ADR-0067: key material lifecycle (KSK / ZSK on-disk format,
  rotation, secure deletion). Mirror the BIND9 / Knot conventions for
  operator familiarity.
- Public trait `DnssecSigner` in `heimdall-core::dnssec::sign`:
  ```rust
  pub trait DnssecSigner {
      fn algorithm(&self) -> Algorithm;
      fn key_tag(&self) -> u16;
      fn sign(&self, signed_data: &[u8]) -> Result<Vec<u8>, SignError>;
  }
  ```
- `RsaSha256Signer`, `RsaSha512Signer` backed by `aws-lc-rs`
  (preferred) or `ring`.
- Round-trip tests against NIST FIPS-186 vectors; round-trip via the
  existing validator (signer → validator must always validate to
  Secure).
- Auth-server integration: zone-load path picks the signer per the
  zone's KSK/ZSK record set; RRSIG records are produced for every
  signed RRSet on initial load and on every dynamic update.

### 3.2 Sprint 63 — SIG(0) signing (#655)

- The SIG(0) signer is the same `DnssecSigner` trait applied to the
  inbound UPDATE path: when Heimdall is configured as a DDNS client
  it signs UPDATE messages with SIG(0).
- Algorithms: 13 (ECDSA P-256), 15 (Ed25519). RSA variants permitted
  but not the default. Algorithm 5 (RSA-SHA1) refused at config load.
- Round-trip test against a known SIG(0)-validating server (BIND9 or
  NSD with TSIG/SIG(0) configured).
- Operator-manual section: key generation + rotation + UPDATE-client
  configuration.

### 3.3 Sprint 64+ — ECDSA / Ed25519 signing

The same trait extended with ECDSA P-256, P-384 and Ed25519
implementations. These are the modern recommended algorithms per
RFC 8624 and are required for parity with NSD/Knot Auth on a
greenfield zone deployment.

### 3.4 Blocked — Ed448 (#656)

Ed448 (algorithm 16) is rare in the wild and `ring` does not support
it. Two paths to unblock:

1. `aws-lc-rs` adds Ed448 support — adopt directly.
2. A pure-Rust Ed448 crate becomes audit-acceptable per ENG-008..016.

Until then, #656 is tracked as blocked-on-upstream. The audit-
follow-up ADR (post-2027) will record the decision: implement on
the first available backend, or document Ed448 as
permanently-not-implemented if no production zone is found to use
it.

## 4. Operational impact

- Until Sprint 63 lands, Heimdall continues to operate as a
  validation-only DNSSEC participant. Operators who need
  authoritative signing must use the existing pre-signed-zone
  workflow (operator signs zones with an external tool;
  Heimdall serves the signed zone file as-is).
- The trait surface introduced in §3 is additive; the operator-
  facing CLI gains `--sign` flags with sensible defaults at that
  point.

## 5. Why not implement now (Sprint 62)

The audit findings #654, #655, #656 are real gaps but their
acceptable-risk-window is long: pre-signed zones cover every
production deployment scenario today (Heimdall-as-secondary, manually-
signed primaries). The cost of implementing signing without the key-
lifecycle ADR is a foot-gun: an operator might rely on un-rotatable
keys or insecure on-disk storage. The staged plan in §3 ships the
right surface in Sprint 63 with the key-lifecycle decision made
first.

## 6. Open questions

- Backend choice for RSA: `aws-lc-rs` is the preferred TLS backend per
  ENG-008..016. Confirm RSA-SHA256/512 signing performance vs `ring`
  on the auth hot path.
- Online vs offline KSK: an offline KSK (signed RRSIGs cached for the
  full validity window) is the simplest model and matches NSD/Knot
  defaults. An online KSK enables auto-rotation but requires a HSM-
  class key store. Sprint 63 ADR-0067 resolves.
