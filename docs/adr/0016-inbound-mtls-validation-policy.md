---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Inbound mTLS validation policy (cross-transport, cross-listener-purpose)

## Context and Problem Statement

[`SEC-012`](../../specification/003-crypto-policy.md) through [`SEC-016`](../../specification/003-crypto-policy.md) fix the structural posture of TLS-over-TCP mTLS on DoT and DoH over HTTP/2: optional, per-listener, default OFF, structurally gated. [`SEC-031`](../../specification/003-crypto-policy.md) through [`SEC-035`](../../specification/003-crypto-policy.md) extend the same posture to TLS-inside-QUIC on DoQ and DoH over HTTP/3. [`OPS-009`](../../specification/012-runtime-operations.md) and [`OPS-028`](../../specification/012-runtime-operations.md) extend mTLS to the admin-RPC surface and the HTTP observability endpoint when those listeners are bound beyond loopback.

The validation policy applied to client certificates received during such mTLS handshakes — trust-anchor scope, chain-validation rules, optional pinning, revocation, certificate-to-identity mapping — was tracked as the open question "mTLS validation policy (cross-transport)" in [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). The present decision closes that open question. The policy is fixed as a single cross-transport, cross-listener-purpose policy with operator-tunable per-listener parameters.

The decision had to settle five sub-questions jointly:

1. **Trust anchor scope** — vendored bundle, OS bundle, or operator-supplied per-listener.
2. **Chain validation rules** — alignment with the outbound validation pipeline of [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md), or independent.
3. **Optional pinning** — per-listener SPKI pinning parallel to outbound, or absent.
4. **Revocation** — OCSP stapling, OCSP fetch, CRL, must-staple, or some combination.
5. **Certificate-to-identity mapping** — Subject DN, Subject CN, SAN URI / DNS / email, or operator-controlled per-listener.

The decisions had to compose with [`SEC-012`](../../specification/003-crypto-policy.md) through [`SEC-016`](../../specification/003-crypto-policy.md) and [`SEC-031`](../../specification/003-crypto-policy.md) through [`SEC-035`](../../specification/003-crypto-policy.md), with the outbound validation policy fixed by [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) (recorded in [`0007-outbound-server-certificate-validation-policy.md`](0007-outbound-server-certificate-validation-policy.md)) for cross-direction alignment, with the ACL matcher under [`THREAT-036`](../../specification/007-threat-model.md), with the rate-limiting keying axis under [`THREAT-052`](../../specification/007-threat-model.md), and with the runtime-reload mechanism of [`012-runtime-operations.md`](../../specification/012-runtime-operations.md).

## Decision Drivers

- **Audience-specific PKI**. Client certificates are typically signed by an operator-internal or audience-specific CA, not by a public root in the Mozilla bundle. The trust anchor must reflect this.
- **Cross-direction alignment** (cf. [`SEC-047`](../../specification/003-crypto-policy.md)–[`SEC-059`](../../specification/003-crypto-policy.md)). Algorithm restrictions and the no-active-OCSP-fetch posture should be the same in both directions; divergence would be a latent source of incidents.
- **Identity expressivity**. Modern deployment models (SPIFFE / SPIRE, audience-specific tokens, X.509-encoded service identities) carry the identity in different cert fields. The mapping must accommodate the dominant patterns.
- **Bounded operational complexity**. The policy must be expressible per-listener with a small set of well-defined sub-keys; arbitrary identity-extraction logic (regex over fields, custom DSL) would expand the configuration surface beyond utility.
- **Cross-listener-purpose uniformity**. DoT, DoH/H2, DoQ, DoH/H3, admin-RPC TCP, and HTTP observability all run mTLS validation at the same TLS layer; one policy, one matrix, one test surface.

## Considered Options

### A. Trust anchor scope

- **Per-listener `mtls.trust_anchor` (PEM file path), no default vendored bundle (chosen).** Operator declares the trust anchor per listener; no implicit fallback. Each listener can serve a different audience.
- **Vendored Mozilla bundle as default.** Wrong default for inbound: client certs are typically not from public roots.
- **Operator-explicit (no implicit default; mTLS-disabled means no trust anchor needed).** Already the case under the chosen design — mTLS off = no trust anchor required, mTLS on = trust anchor required.

### B. Chain validation rules

- **Same as outbound (`SEC-048`, `SEC-049`), with EKU `id-kp-clientAuth` (chosen).** Strict RFC 5280 PKIX, SHA-1/MD5 reject, RSA ≥ 2048, ECC P-256/P-384/Ed25519, defensive cap of 10 intermediates.
- **Independent inbound rules.** No reason for divergence; would create two policies to maintain.
- **Library-default validation.** Same defect as in [`0007-outbound-server-certificate-validation-policy.md`](0007-outbound-server-certificate-validation-policy.md) — couples the spec to library defaults that may move silently.

### C. Optional pinning

- **Per-listener `mtls.spki_pins` array, semantically parallel to outbound `SEC-053` (chosen).** Defence-in-depth for narrow-trust scenarios (admin-RPC with a small known set of operator client certs).
- **Mandatory pinning.** Operationally heavy; pin staleness breaks the connection class.
- **No pinning.** Leaves CA-only trust as the sole input; same residual exposure to CA compromise as outbound without pinning.

### D. Revocation

- **OCSP stapling (when client offers it) + operator-supplied CRL + must-staple honoured; no active OCSP fetch (chosen).** Mirrors the outbound posture of `SEC-055`–`SEC-057` with the inbound-direction adjustment of accepting an operator-supplied CRL as the primary inbound revocation mechanism (since clients rarely staple).
- **CRL only.** Misses the rare-but-supported case of stapling clients (some SPIFFE / SPIRE-based deployments do staple their workload identities).
- **Active OCSP fetch.** Privacy leak to the OCSP responder operator; same DNS dependency concern as outbound.
- **No revocation.** Leaves revoked client certs in circulation until expiry.

### E. Certificate-to-identity mapping

- **Per-listener `identity_source` enum: `subject_dn` | `subject_cn` | `san_uri` | `san_dns` | `san_email`, default `subject_dn` (chosen).** Five canonical mappings cover the dominant deployment patterns.
- **Fixed `subject_dn` only.** Excludes SPIFFE-style URI-SAN-based identities, which are increasingly common.
- **Operator-controlled regex over Subject and SAN fields.** Maximum flexibility, maximum complexity, maximum room for misconfiguration. No identified use case beyond the five canonical mappings.

## Decision Outcome

**A. Trust anchor.** Per-listener `mtls.trust_anchor` PEM file, mandatory when mTLS is enabled, per [`SEC-063`](../../specification/003-crypto-policy.md).

**B. Chain validation.** Same rules as outbound (`SEC-048` PKIX, `SEC-049` algorithm restrictions), with EKU `id-kp-clientAuth` for the leaf, per [`SEC-064`](../../specification/003-crypto-policy.md).

**C. Optional pinning.** Per-listener `mtls.spki_pins` array, parallel to `SEC-053` outbound, per [`SEC-065`](../../specification/003-crypto-policy.md).

**D. Revocation.** OCSP stapling honoured + operator-supplied CRL with SIGHUP reload + must-staple honoured; no active OCSP fetch, per [`SEC-066`](../../specification/003-crypto-policy.md).

**E. Identity mapping.** Per-listener `mtls.identity_source` enum (`subject_dn` default; `subject_cn` / `san_uri` / `san_dns` / `san_email` alternatives), case-sensitive byte-exact comparison, per [`SEC-067`](../../specification/003-crypto-policy.md).

**F. Cross-listener-purpose uniformity.** Same policy applies to DoT, DoH/H2, DoQ, DoH/H3, admin-RPC TCP, and HTTP observability, per [`SEC-068`](../../specification/003-crypto-policy.md).

**G. Failure handling.** Handshake aborted before any application data; structured event under [`THREAT-080`](../../specification/007-threat-model.md) with categorised failure reason, per [`SEC-069`](../../specification/003-crypto-policy.md).

**H. Conformance test matrix.** `(listener-purpose × failure category)` cross-product plus per-purpose success-case rows, per [`SEC-070`](../../specification/003-crypto-policy.md).

### Rejection rationale

The **vendored Mozilla bundle as default** was rejected because client certificates are not typically signed by public CAs; the bundle would almost always be the wrong trust anchor for inbound mTLS, and the default would mask configuration errors (operator forgets `mtls.trust_anchor`, instance accepts certs from public CAs nobody intended to trust).

The **independent inbound chain-validation rules** option was rejected because no use case for divergence has been identified, and divergence would create two policies that could drift independently. The chosen alignment with outbound preserves a single PKIX validation pipeline with one EKU difference.

The **mandatory pinning** option was rejected on operational grounds (pin-staleness breaks resumption); the **no-pinning** option was rejected because it leaves CA compromise as a residual exposure for narrow-trust scenarios where pinning would close it.

The **CRL-only revocation** option was rejected because it misses the stapling case (rare but supported in modern workload-identity deployments). The **active-OCSP-fetch** option was rejected for the same reasons given in [`0007-outbound-server-certificate-validation-policy.md`](0007-outbound-server-certificate-validation-policy.md): privacy leak to the OCSP responder, DNS dependency, latency.

The **fixed `subject_dn` only** mapping was rejected because it excludes SPIFFE-style URI-SAN identities, which are common in zero-trust workload deployments. The **operator-controlled regex** option was rejected because the cost of misconfiguration is high (incorrect identity extraction silently degrades ACL accuracy and rate-limiting fairness).

## Consequences

### Operator-visible configuration shape

```toml
# DoT listener with mTLS, corporate PKI, Subject DN identity:
[[recursive.listener]]
transport = "dot"
address = "0.0.0.0"
port = 853

[recursive.listener.mtls]
trust_anchor = "/etc/heimdall/corporate-client-ca.pem"
identity_source = "subject_dn"

# DoQ listener with mTLS, SPIFFE workload identity:
[[recursive.listener]]
transport = "doq"
address = "0.0.0.0"
port = 853

[recursive.listener.mtls]
trust_anchor = "/etc/heimdall/spiffe-bundle.pem"
identity_source = "san_uri"
crl_file = "/etc/heimdall/spiffe-revocations.pem"

# Admin-RPC TCP with narrow trust + SPKI pinning:
[runtime.admin_rpc.tcp]
address = "127.0.0.1"
port = 6443

[runtime.admin_rpc.tcp.mtls]
trust_anchor = "/etc/heimdall/admin-ca.pem"
identity_source = "subject_cn"
spki_pins = [
  "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
]
```

(The exact path of admin-RPC and HTTP-observability mTLS sub-tables is governed by the runtime-operations spec; the `mtls.*` shape itself is uniform across listener purposes.)

### Conformance test matrix (representative scenarios)

The matrix has six listener purposes × thirteen failure categories = 78 (purpose, category) failure cells, plus seven success cells per purpose (valid + 5 identity_source values + valid-with-stapled-OCSP-good + valid-with-pin-match) = 42 success cells. The total normative test surface is 78 + 42 = 120 cells. Implementations are not required to author 120 distinct test fixtures, but MUST cover, at minimum, one cell per (purpose, category) pair plus one success cell per purpose. The remaining cells MAY be exercised by parameterised test inputs over a single shared test scaffold.

A representative subset (spanning every category and every purpose):

| # | Purpose | Scenario | Expected outcome |
|---|---------|----------|------------------|
| 1 | DoT | Valid cert, identity_source = subject_dn | Handshake succeeds; identity = "CN=alice,O=Acme,C=US" |
| 2 | DoT | Cert chain doesn't lead to mtls.trust_anchor | Aborted: trust-anchor-mismatch |
| 3 | DoT | Leaf signed with SHA-1 | Aborted: signature-algorithm-rejected |
| 4 | DoT | Leaf RSA-1024 | Aborted: weak-key-rejected |
| 5 | DoT | Leaf cert expired | Aborted: chain-validity-expired |
| 6 | DoH/H2 | Leaf EKU lacks id-kp-clientAuth | Aborted: extended-key-usage-mismatch |
| 7 | DoH/H2 | spki_pins set, leaf SPKI not in pins | Aborted: spki-pin-mismatch |
| 8 | DoQ | Valid cert with stapled OCSP `revoked` | Aborted: ocsp-revoked |
| 9 | DoQ | Valid cert with stapled OCSP signature invalid | Aborted: ocsp-staple-invalid |
| 10 | DoQ | Cert declares must-staple, no staple offered | Aborted: must-staple-violation |
| 11 | DoH/H3 | Cert serial in mtls.crl_file revoked list | Aborted: crl-revoked |
| 12 | DoH/H3 | identity_source = san_uri, no URI SAN | Aborted: identity-source-unavailable |
| 13 | admin-RPC TCP | identity_source = subject_cn, multiple CN attrs | Identity = rightmost CN |
| 14 | admin-RPC TCP | identity_source = san_dns, valid | Identity = first dNSName SAN |
| 15 | HTTP observability | identity_source = san_email, valid | Identity = first rfc822Name SAN |
| 16 | HTTP observability | Cert chain valid, all checks pass | Handshake succeeds; identity used by downstream ACL/RL |

(Cells 17–120 follow the same pattern across the cross-product.)

### Closure

The "mTLS validation policy (cross-transport)" open question is removed from [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md). No new operational-default open question is added; the policy's operator-tunable parameters are per-listener and do not have global numeric defaults.

### Non-consequences (deliberate scope limits)

- **Active OCSP fetch.** Rejected entirely; mirror of the outbound prohibition.
- **CRL fetch over the network.** The CRL is operator-supplied as a file; periodic network fetch is not part of this decision (would reintroduce DNS dependency and additional traffic surface).
- **Identity extraction via regex or DSL.** Rejected; the five canonical `identity_source` values cover the dominant patterns.
- **Multiple identities per cert (e.g., "all SAN URIs").** Heimdall extracts one identity per cert per the chosen `identity_source`. Multi-identity extraction is out of scope.
- **OCSP must-staple TLS Feature on inbound** is honoured under [`SEC-066`](../../specification/003-crypto-policy.md) (c) but rare in practice; clients that staple are typically SPIRE workloads.

### Numbering

This ADR takes the sequence number `0016`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). With Sprint 1 having occupied `0002`–`0014` and Sprint 2 task #19 having occupied `0015`, the grandfather batch (sprint 11 work) will start at `0017` or later; the descriptive text of [`ENG-123`](../../specification/010-engineering-policies.md) ("expected to start at `0002`") will be updated during sprint 11.
