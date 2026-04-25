---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Outbound server-certificate validation policy (forwarder upstream and recursive ADoT)

## Context and Problem Statement

[`NET-018`](../../specification/002-transports.md) and [`NET-024`](../../specification/002-transports.md) in [`002-transports.md`](../../specification/002-transports.md) fix the MUST-validate obligation on every outbound TLS-protected or QUIC-based connection that Heimdall initiates as a client: forwarder upstream connections under [`NET-018`](../../specification/002-transports.md), and recursive-resolver-to-authoritative ADoT connections under [`NET-024`](../../specification/002-transports.md). The two requirements explicitly defer the validation policy itself — trust store scope, chain validation rules, hostname or SNI verification, optional SPKI pinning, and revocation checking — to a single cross-role, cross-transport policy to be specified jointly. The present decision specifies that policy.

The decision had to settle five interlocking sub-questions:

1. **Trust store scope and override mechanism**.
2. **Chain validation rules** — strictness level, deprecated-algorithm rejection, key-strength minimums.
3. **Hostname / IP identity verification and SNI semantics**.
4. **Optional SPKI pinning** on a per-upstream basis.
5. **Revocation checking strategy** — OCSP stapling, OCSP fetch, CRL.

The decisions had to compose with the TLS 1.3-only posture fixed by [`SEC-001`](../../specification/003-crypto-policy.md) through [`SEC-007`](../../specification/003-crypto-policy.md), with the QUIC v1/v2-only posture fixed by [`SEC-017`](../../specification/003-crypto-policy.md) through [`SEC-024`](../../specification/003-crypto-policy.md), with the supply-chain obligations (SBOM, signing) fixed by [`THREAT-013`](../../specification/007-threat-model.md) and [`THREAT-014`](../../specification/007-threat-model.md), with the structured-event observability obligation fixed by [`THREAT-080`](../../specification/007-threat-model.md), and with the hardened minimal-base OCI image deployment shape fixed by [`ENV-026`](../../specification/009-target-environment.md). The policy is the same on every outbound encrypted-DNS path, so the chosen requirements are cross-role and cross-transport without divergence.

## Decision Drivers

- **Security non-negotiable** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). Outbound TLS validation is the linchpin between Heimdall and its upstreams; a relaxed policy compromises every upstream connection, every cached answer derived from one, and the trust an operator places in the resolver.
- **Predictability and reproducibility**. The trust anchor set, the algorithm acceptance set, and the validation rules must be stable across deployments of the same Heimdall release; configuration drift across hosts is a class of incident the policy must structurally exclude.
- **Container-friendly deployment** (cf. [`ENV-026`](../../specification/009-target-environment.md)). The validation policy must work without depending on the operating-system filesystem layout (a hardened minimal-base OCI image has no `/etc/ssl/certs/` to read from).
- **Privacy preservation**. Active OCSP queries leak which certificates Heimdall is validating to a third party (the OCSP responder operator); a privacy-aware design excludes that leak.
- **No circular DNS dependency**. A DNS resolver cannot rely on DNS resolution to validate its own outbound TLS without exposing a bootstrap dependency that breaks under partial failure.
- **Operator parity with established practice**. Operators deploying Heimdall against public encrypted-DNS upstreams (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9, NextDNS, AdGuard) already configure these upstreams in stubby, dnscrypt-proxy, dnsdist, Unbound, and similar products. The validation surface must accommodate the dominant operational pattern: an IP literal address with a known hostname identity.
- **Defence in depth**. CA-based validation alone leaves residual exposure to CA compromise; an opt-in pinning mechanism closes that residual without imposing operational cost on deployments that do not need it.

## Considered Options

### A. Trust store scope and override

- **Vendored Mozilla CA bundle (`webpki-roots`) as default; per-upstream `trust_anchor` PEM override (chosen).** Predictable, reproducible, container-friendly, SBOM-visible.
- **Operating-system trust store as default; per-upstream override.** Operating-system bundle changes silently with package updates; absent in minimal-base OCI images; fragments validation across deployment hosts.
- **Operator-explicit (no implicit default; every upstream MUST declare `trust_anchor` or `trust = "system" | "mozilla"`).** Maximally explicit; verbose for the dominant case (public upstream with public CA).
- **System-bundle-only with no override.** Excludes private-PKI deployments; inadequate for enterprise scenarios.

### B. Chain validation rules

- **Strict RFC 5280 PKIX with explicit additional algorithm restrictions (chosen).** Library-default RFC 5280 path validation, plus explicit MUST-reject on SHA-1 / MD5 in any certificate of the chain, plus explicit RSA-2048 minimum, plus explicit ECC curve restriction to P-256 / P-384 / Ed25519. Auditable at the spec level; resilient against silent library-default drift.
- **Library-default RFC 5280, no additional explicit constraints.** Concise but couples the spec to library choices that may move silently.
- **Operator-tunable strictness.** No identified use case for relaxing strictness; runtime tunable would be a denial-of-security attack vector.

### C. Hostname / SNI verification

- **Mandatory hostname verification (DNS-ID for hostnames, IP-ID for IP literals); SNI sent for hostnames per RFC 6066 §3; per-upstream `server_name` override (chosen).** Aligns with [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) §3; covers the IP-with-known-hostname pattern (Cloudflare, Google, Quad9 idiom).
- **Mandatory hostname verification with `server_name` always required.** Verbose for the hostname-`address` case; no security gain.
- **Operator-skippable hostname verification.** Silent downgrade vector; unacceptable under the security-first posture.
- **SNI always sent (including for IP literals).** Non-conformant with RFC 6066 §3; some servers reject ClientHello with an IP-literal SNI value.

### D. SPKI pinning

- **Optional per-upstream `spki_pins` array of `sha256/<base64>` values (chosen).** Defence in depth against CA compromise; multiple-pin support enables zero-downtime key rotation on the upstream side.
- **Mandatory pinning on every upstream.** Imposes operational cost on every deployment; pin-staleness is a resolution-breaking failure mode.
- **No pinning support.** Leaves CA compromise as a residual exposure with no operator-side mitigation.
- **Tagged-trust-mode field (`trust = "ca" | "spki" | "ca+spki"`).** Adds expressive surface without justified use case; the `trust = "spki"` mode (no CA validation) loses revocation handling and chain-of-trust without compensating gain.

### E. Revocation checking

- **OCSP stapling soft-fail with [RFC 7633](https://www.rfc-editor.org/rfc/rfc7633) `must-staple` honoured; no OCSP fetch; no CRL (chosen).** Privacy-preserving (no OCSP leak), no circular DNS dependency, ecosystem-compatible (does not break upstreams that do not staple), with hard-fail enforcement available where the upstream itself opts in via must-staple.
- **Hard-fail OCSP stapling (handshake aborted on absent staple).** Maximum security; breaks upstreams that do not staple, which still includes a non-negligible fraction of public encrypted-DNS upstreams in 2026.
- **OCSP fetch + stapling + CRL (full revocation checking).** Privacy leak (the OCSP responder learns which certificates Heimdall is validating), circular DNS dependency (OCSP responder hostnames must be resolved by DNS), latency on every handshake.
- **No revocation checking at all.** Leaves revoked-certificate exposure with no Heimdall-side mitigation; vulnerable to revoked certificates that the CA has revoked but that remain in circulation until expiry.

## Decision Outcome

**A. Trust store scope.** Vendored Mozilla CA bundle (`webpki-roots`) as default, per-upstream `trust_anchor` PEM override, per [`SEC-047`](../../specification/003-crypto-policy.md).

**B. Chain validation rules.** Strict RFC 5280 PKIX path validation with explicit SHA-1 / MD5 rejection, RSA-2048 minimum, ECC restricted to P-256 / P-384 / Ed25519, per [`SEC-048`](../../specification/003-crypto-policy.md) and [`SEC-049`](../../specification/003-crypto-policy.md).

**C. Hostname / SNI verification.** Mandatory hostname verification per RFC 6125 / RFC 9525 (DNS-ID for hostnames, IP-ID for IP literals), SNI sent for hostnames per RFC 6066 §3 only, per-upstream `server_name` override, per [`SEC-050`](../../specification/003-crypto-policy.md), [`SEC-051`](../../specification/003-crypto-policy.md), and [`SEC-052`](../../specification/003-crypto-policy.md).

**D. SPKI pinning.** Optional per-upstream `spki_pins` array of `sha256/<base64>` values, multiple-pin rotation supported, per [`SEC-053`](../../specification/003-crypto-policy.md) and [`SEC-054`](../../specification/003-crypto-policy.md).

**E. Revocation checking.** OCSP stapling soft-fail with [RFC 7633](https://www.rfc-editor.org/rfc/rfc7633) must-staple honoured, no OCSP fetch, no CRL, per [`SEC-055`](../../specification/003-crypto-policy.md), [`SEC-056`](../../specification/003-crypto-policy.md), and [`SEC-057`](../../specification/003-crypto-policy.md).

**F. Cross-role and cross-transport uniformity.** The policy applies uniformly to forwarder upstream connections under [`NET-018`](../../specification/002-transports.md) and to recursive-resolver ADoT connections under [`NET-024`](../../specification/002-transports.md), and uniformly to TLS-over-TCP and TLS-inside-QUIC outbound paths, per [`SEC-058`](../../specification/003-crypto-policy.md).

**G. Failure handling.** Every validation failure aborts the handshake before any DNS query or response is carried; the failure emits a structured event under [`THREAT-080`](../../specification/007-threat-model.md) with a categorised failure reason, per [`SEC-059`](../../specification/003-crypto-policy.md).

### Rejection rationale — trust store

The **operating-system trust store as default** was rejected on three grounds. First, predictability: the OS bundle changes silently with operating-system package updates, which means the same Heimdall release running on two hosts may trust different sets of CAs depending on each host's patch cadence. Second, container-friendliness: the hardened minimal-base OCI image required by [`ENV-026`](../../specification/009-target-environment.md) has no `/etc/ssl/certs/` to read from; the OS-bundle default would require either bind-mounting from the host or basing the image on a less-hardened parent that includes a CA bundle. Third, SBOM visibility: a vendored bundle appears in the Software Bill of Materials produced under [`THREAT-014`](../../specification/007-threat-model.md), where it is auditable and its version is recorded; an OS bundle does not.

The **operator-explicit (no implicit default)** option was rejected on ergonomics. The dominant operational case is a public encrypted-DNS upstream presenting a certificate signed by a public CA in the Mozilla bundle; requiring every operator to redundantly declare `trust = "mozilla"` on every upstream adds verbosity without information gain. The chosen design preserves the explicit-override mechanism for private PKIs (where it is necessary) without imposing the verbosity tax on the dominant case.

The **system-bundle-only without override** option was rejected because it excludes private-PKI deployments outright. Enterprise and corporate scenarios in which Heimdall forwards to internal upstreams whose certificates are signed by a corporate CA are a legitimate use case; an override mechanism is required to support them.

### Rejection rationale — chain validation

The **library-default RFC 5280 without explicit additional constraints** option was rejected because library defaults can move silently between releases. webpki-rs and rustls have evolved their algorithm acceptance sets across releases (TLS 1.2 acceptance, deprecated curves, signature algorithm policies), and the spec's auditability is improved by explicit MUST-reject statements. The cost is a longer requirements section; the benefit is that a future library default that happens to relax (or the use of a forked library that does so) does not silently lower the security floor of Heimdall.

The **operator-tunable strictness** option was rejected because no use case for relaxing the strictness has been identified. TLS 1.3 already constrains the cipher-suite envelope; the algorithm restrictions in [`SEC-049`](../../specification/003-crypto-policy.md) match the [NIST SP 800-131A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) Rev 2 baseline; and a runtime knob to relax PKIX would be a denial-of-security attack vector that an operator could enable inadvertently.

### Rejection rationale — hostname verification

The **always-required `server_name`** option was rejected because the dominant case (an `address` that is itself a hostname) is correctly handled by verifying the cert against the `address`. Requiring the operator to repeat the hostname in `server_name` adds verbosity without information.

The **operator-skippable hostname verification** option was rejected as a security regression. Skipping hostname verification reduces TLS validation to "this cert chains to a CA we trust", which fails the basic test of confirming that the server we are talking to is the server we intended to reach. No use case has been identified that needs this in 2026; private-PKI deployments can address custom hostname schemes via the `server_name` override.

The **SNI-always-sent (including for IP literals)** option was rejected because it does not conform to [RFC 6066 §3](https://www.rfc-editor.org/rfc/rfc6066#section-3): the `HostName` value MUST NOT contain an IP literal. Some TLS servers reject ClientHello with an invalid SNI value; sending SNI for IP literals would create a class of upstreams Heimdall could not connect to.

### Rejection rationale — SPKI pinning

The **mandatory pinning** option was rejected on operational cost. Pin-staleness (the upstream rotates its key, the pin remains the old value) is a resolution-breaking failure mode that would impose a non-trivial maintenance burden on every deployment; for the dominant case (public CA-signed upstream), CA validation already provides adequate trust, and pinning's marginal benefit is reserved for high-value upstreams where an operator has explicitly chosen to take on the maintenance cost.

The **no-pinning** option was rejected because it leaves CA compromise as a residual exposure with no Heimdall-side mitigation. CA compromise is not a hypothetical concern; the historical record (DigiNotar, Symantec / WoSign, Trustico, multiple Mozilla distrust events) shows that publicly trusted CAs are sometimes compromised or distrusted. Optional pinning is the lowest-cost defence for operators who choose to harden specific high-value upstreams.

The **tagged-trust-mode** option was rejected because the `trust = "spki"` (no CA validation) sub-mode loses the chain-of-trust and revocation-stapling story without compensating gain; the `trust = "ca+spki"` sub-mode is structurally identical to the chosen design (CA-based path validation followed by SPKI pin matching) but with extra surface in the configuration shape.

### Rejection rationale — revocation checking

The **hard-fail OCSP stapling** option was rejected because a non-negligible fraction of public encrypted-DNS upstreams in 2026 do not staple consistently; a hard-fail policy on absent staple would break legitimate connections without a corresponding security gain (the same upstream's certificates are validated by the CA chain regardless of whether a staple is present). The chosen soft-fail-with-must-staple-honoured design captures hard-fail enforcement where the upstream itself has committed to it via the [RFC 7633](https://www.rfc-editor.org/rfc/rfc7633) cert extension, without imposing the failure mode on upstreams that have not.

The **OCSP fetch + stapling + CRL** option was rejected on three grounds. First, privacy: the [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) status_request extension was specifically designed to remove the privacy leak that OCSP fetch creates (the responder learns which certificates Heimdall is validating); a Heimdall that issues OCSP fetches reintroduces that leak against its own upstreams' end users. Second, circular dependency: an OCSP fetch requires DNS resolution of the OCSP responder hostname, which a DNS resolver cannot rely on at startup or during partial failure of the resolver itself. Third, latency: OCSP fetch adds a round-trip and a TLS handshake of its own to every TLS handshake; CRL fetch adds a bulk download that can be megabytes for large CAs.

The **no revocation checking at all** option was rejected because it leaves revoked-certificate exposure with no Heimdall-side mitigation. The chosen design captures the privacy-preserving subset of revocation handling (stapled OCSP, must-staple-respecting hard-fail) and pairs it with the optional SPKI pinning under [`SEC-053`](../../specification/003-crypto-policy.md) for high-value upstreams that need stronger guarantees.

## Consequences

### Operator-visible upstream descriptor shape

```toml
# Public upstream by hostname (most common case):
[[forwarder.forward_zone]]
zone = "."
match = "suffix"

[[forwarder.forward_zone.upstream]]
address = "dns.google."
port = 853
transport = "dot"

# Public upstream by IP, hostname identity verification (alternative rule):
[[forwarder.forward_zone]]
zone = "."
match = "suffix"

[[forwarder.forward_zone.upstream]]
address = "1.1.1.1"
port = 853
transport = "dot"
server_name = "cloudflare-dns.com"

# Public upstream by IP, hostname identity, SPKI pinning with rotation backup:
[[forwarder.forward_zone]]
zone = "."
match = "suffix"

[[forwarder.forward_zone.upstream]]
address = "1.1.1.1"
port = 853
transport = "dot"
server_name = "cloudflare-dns.com"
spki_pins = [
  "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
]

# Private upstream, corporate PKI:
[[forwarder.forward_zone]]
zone = "internal-resolver.corp.example."
match = "suffix"

[[forwarder.forward_zone.upstream]]
address = "internal-resolver.corp.example."
port = 853
transport = "dot"
trust_anchor = "/etc/heimdall/internal-ca.pem"
```

### Validation pipeline (per outbound handshake)

For every outbound TLS or QUIC handshake, the pipeline runs in this order:

1. ClientHello with SNI (if hostname identity), `status_request` extension, ALPN as required by the transport.
2. Receive ServerHello, Certificate, optional CertificateStatus, etc.
3. Path validation: signature, validity, basic constraints, key usage, extended key usage, name constraints — strict RFC 5280 PKIX, against vendored Mozilla bundle (or per-upstream `trust_anchor`).
4. Algorithm restrictions: SHA-1 / MD5 reject, RSA < 2048 reject, ECC outside {P-256, P-384, Ed25519} reject.
5. Identity verification: DNS-ID against `server_name` or hostname `address`; IP-ID against IP-literal `address` (with no `server_name`).
6. SPKI pin matching (if `spki_pins` is set).
7. OCSP staple validation (if staple is present): signature, status, temporal window, serial.
8. Must-staple enforcement: if leaf cert declares must-staple and no staple was received → abort.
9. Handshake completes; outbound DNS queries may now flow.

Failure at any step → handshake abort → structured event under [`THREAT-080`](../../specification/007-threat-model.md) → no DNS query or response carried on the connection.

### Conformance test scenarios

The "conformance tests for every validation mode" requirement of the task acceptance criteria translates to the following matrix of normative test scenarios. Each scenario describes an upstream certificate situation and the expected outcome.

| # | Scenario | Expected outcome |
|---|----------|------------------|
| 1 | Cert chain valid, signed by public CA in vendored Mozilla bundle, `address` hostname matches DNS-ID | Handshake succeeds |
| 2 | Cert chain valid, `address` IP literal, `server_name` matches DNS-ID | Handshake succeeds |
| 3 | Cert chain valid, `address` IP literal, IP-ID matches | Handshake succeeds |
| 4 | Cert signed by CA in `trust_anchor` PEM (private PKI), DNS-ID matches | Handshake succeeds |
| 5 | Cert chain valid, identity does not match (`address` `dns.google.`, cert is for `dns.example.`) | Handshake aborted, `identity-mismatch` |
| 6 | Cert chain valid, leaf signed with SHA-1 | Handshake aborted, `signature-algorithm-rejected` |
| 7 | Cert chain valid, leaf RSA-1024 | Handshake aborted, `weak-key-rejected` |
| 8 | Cert chain valid, identity match, but cert expired | Handshake aborted, `chain-validity-expired` |
| 9 | Cert chain that does not lead to any trusted root (rogue intermediate) | Handshake aborted, `trust-anchor-mismatch` |
| 10 | Cert chain valid, identity match, `spki_pins` set, leaf SPKI matches one pin | Handshake succeeds |
| 11 | Cert chain valid, identity match, `spki_pins` set, leaf SPKI matches no pin | Handshake aborted, `spki-pin-mismatch` |
| 12 | Cert chain valid, identity match, OCSP staple present and `good` | Handshake succeeds |
| 13 | Cert chain valid, identity match, OCSP staple present and `revoked` | Handshake aborted, `ocsp-revoked` |
| 14 | Cert chain valid, identity match, OCSP staple present but signature invalid | Handshake aborted, `ocsp-staple-invalid` |
| 15 | Cert chain valid, identity match, OCSP staple absent, leaf does NOT declare must-staple | Handshake succeeds (soft-fail) |
| 16 | Cert chain valid, identity match, OCSP staple absent, leaf DOES declare must-staple | Handshake aborted, `must-staple-violation` |
| 17 | Cert chain valid, IP-literal `address`, no `server_name`, IP-ID present in cert | Handshake succeeds, no SNI sent |
| 18 | Cert chain valid, IP-literal `address`, no `server_name`, IP-ID absent (only DNS-ID) | Handshake aborted, `identity-mismatch` |

### Cross-references updated

- [`NET-018`](../../specification/002-transports.md) and [`NET-024`](../../specification/002-transports.md) now identify [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md) as the validation policy.
- The "Upstream certificate validation policy (forwarder)" open question is removed from [`002-transports.md §5`](../../specification/002-transports.md).
- The "mTLS validation policy (cross-transport)" open question in [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md) is updated to clarify the inbound / outbound boundary: the inbound mTLS validation policy remains open, the outbound server-certificate validation policy is fixed by [`SEC-047`](../../specification/003-crypto-policy.md) through [`SEC-059`](../../specification/003-crypto-policy.md).
- A new open question is added to [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md): the per-upstream `ocsp_required` opt-in to harden the soft-fail OCSP posture for high-value upstreams.

### Non-consequences (deliberate scope limits)

- **Inbound mTLS validation policy.** The corresponding inbound policy ([`SEC-012`](../../specification/003-crypto-policy.md) through [`SEC-016`](../../specification/003-crypto-policy.md), [`SEC-031`](../../specification/003-crypto-policy.md) through [`SEC-035`](../../specification/003-crypto-policy.md)) remains open. Alignment with the present outbound policy is expected for shared concerns when the inbound policy is resolved.
- **`ocsp_required` per-upstream opt-in.** A future per-upstream override for hard-fail OCSP enforcement remains open, tracked in the new [`003-crypto-policy.md §10`](../../specification/003-crypto-policy.md) open question.
- **Trust-anchor distribution and rotation.** The `webpki-roots` crate version pinning policy (how often to bump, under which conditions) is an operational concern of the release process and is not specified here.
- **Certificate Transparency (CT) verification.** Active CT log monitoring or SCT validation on the leaf certificate is not part of this policy and is not required at this stage.
- **DANE / TLSA record validation.** DNSSEC-anchored DANE for outbound TLS is out of scope at this stage; the open question on ADoT capability discovery in [`002-transports.md §5`](../../specification/002-transports.md) may revisit DANE alongside SVCB/HTTPS-based discovery.

### Numbering

This ADR takes the sequence number `0007`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). The descriptive guidance in [`ENG-123`](../../specification/010-engineering-policies.md) ("the grandfather batch is expected to occupy the low sequence numbers starting at `0002`") will be updated when the grandfather batch is authored (roadmap sprint 11).
