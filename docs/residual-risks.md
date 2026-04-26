# Heimdall — Residual risks accepted

This document catalogues the residual risks that the Heimdall project accepts
under its threat model. It is the artefact mandated by `THREAT-151` in
`specification/007-threat-model.md` and is reviewed annually alongside the
macOS sandbox-profile cadence of `THREAT-106`.

A "residual risk" is a risk that:

1. is acknowledged in the threat model,
2. is not structurally mitigated by the Heimdall process, and
3. is accepted because the mitigation lies outside Heimdall's scope (depends
   on the deployment environment, on upstream libraries, on operator
   configuration, or on hardware) or because the cost of structural
   mitigation outweighs the residual exposure.

The categories below are ranked by exposure profile, not by severity. Severity
depends on the deployment.

---

## (a) C-library crypto code paths reachable via dependencies

**Exposure**: Heimdall's TLS and QUIC stack (rustls + aws-lc-rs by default,
ring as alternative) ultimately calls C-implemented cryptographic primitives.
Side-channel attacks against C implementations are mitigated by upstream
constant-time discipline, which Heimdall depends on but does not enforce.

**Residual risk**: a side-channel attack that breaks the upstream constant-time
guarantees would compromise the corresponding cryptographic operation in
Heimdall. A vulnerability discovered in aws-lc-rs or ring would propagate to
every Heimdall deployment running with that backend until the dependency is
updated and the update is rolled out.

**Acceptance rationale**: Heimdall is not in a position to re-implement TLS or
to audit AEAD ciphers from first principles. The chosen libraries are the most
actively maintained, audited, and community-reviewed cryptographic backends
available in the Rust ecosystem in 2026. The dependency-acceptance gate of
`ENG-008` through `ENG-016` in `specification/010-engineering-policies.md`
ensures that backend choices are reviewed via ADR; the supply-chain
obligations of `THREAT-010` through `THREAT-014` ensure that updates are
verifiable.

**Mitigation outside Heimdall**: keep aws-lc-rs / ring updated; monitor
[GHSA](https://github.com/advisories) and [RustSec](https://rustsec.org/) for
relevant advisories; adopt the security-release coordination of `ENG-* §`
once 1.0 ships.

---

## (b) Side-channel residuals beyond constant-time

**Exposure**: cache-timing attacks, branch-prediction attacks, and
speculative-execution attacks (Spectre, Meltdown, and the family of
microarchitectural side-channels published since 2018) are not structurally
mitigated by Heimdall.

**Residual risk**: a co-located adversary on the same physical machine could
extract cryptographic secret material via microarchitectural channels even
when the cryptographic implementation is algorithmically constant-time.

**Acceptance rationale**: Heimdall is a single-process daemon; it does not
control its co-tenants, the hypervisor, or the CPU microcode. Mitigations
require hardware microcode updates, operating-system configuration (kernel
mitigations enabled at boot), and sometimes deployment-architecture choices
(dedicated host, no co-tenant workload). These are operator concerns.

**Mitigation outside Heimdall**: run Heimdall on hardware with up-to-date
microcode; enable the operating-system's Spectre/Meltdown/L1TF mitigations;
avoid co-locating Heimdall with untrusted workloads on the same physical CPU.

---

## (c) 32-bit address-space attacks

**Exposure**: classes of memory-related vulnerabilities specific to 32-bit
address spaces (limited ASLR entropy, predictable mapping locations, brute-
forceable address ranges).

**Residual risk**: not applicable. `ENV-006` through `ENV-008` in
`specification/009-target-environment.md` restrict supported architectures to
`x86_64`, `aarch64`, and `riscv64` — all 64-bit. 32-bit architectures are
explicitly out of scope.

**Acceptance rationale**: out of scope by design.

---

## (d) Local insider or operator compromise

**Exposure**: an attacker with root or operator privileges on the host
running Heimdall.

**Residual risk**: complete; an attacker who already controls the host can
read, modify, or replace Heimdall's process state, configuration, and runtime
data without going through the threat-model surface.

**Acceptance rationale**: classified out of scope by `THREAT-007` in
`specification/007-threat-model.md`. The operational hardening profile of
`THREAT-022` through `THREAT-107` limits the blast radius of partial in-scope
exploits, but it does not defend against an attacker who already holds root.
Defending against local-root attackers is beyond the structural reach of any
DNS server process.

**Mitigation outside Heimdall**: standard host-hardening practices (least-
privilege operator accounts, MFA on operator access, audit logging of
privileged commands, separation of duties).

---

## (e) Physical attacks against the host

**Exposure**: an attacker with physical access to the Heimdall server
(side-channel measurements via power analysis or electromagnetic emanations,
cold-boot attacks against memory, hardware tampering).

**Residual risk**: complete; physical access bypasses every software-layer
mitigation.

**Acceptance rationale**: classified out of scope by `THREAT-008` in
`specification/007-threat-model.md`. Physical security is a deployment-
environment concern.

**Mitigation outside Heimdall**: physical access controls (datacenter-grade
hosting, locked racks, surveillance, intrusion detection on the chassis).

---

## (f) Cryptographic algorithm break

**Exposure**: a cryptographic break of an algorithm Heimdall accepts (RSA
factoring at scale, ECDSA curve compromise, SHA-2 collision break, future
quantum attacks against current asymmetric crypto).

**Residual risk**: a successful attack against an accepted algorithm
compromises the associated cryptographic property (signature unforgeability,
hash collision resistance, etc.).

**Acceptance rationale**: Heimdall accepts the same algorithm set as the
broader DNSSEC ecosystem (per `DNSSEC-031` through `DNSSEC-040` in
`specification/005-dnssec-policy.md`) and the same TLS 1.3 cipher set (per
`SEC-001` in `specification/003-crypto-policy.md`). A break would affect the
entire ecosystem, not Heimdall in particular; mitigation requires an industry-
wide migration to post-break algorithms.

**Mitigation outside Heimdall**: track [NIST](https://csrc.nist.gov/) and
[IETF CFRG](https://datatracker.ietf.org/rg/cfrg/about/) recommendations;
update the algorithm-acceptance policy via specification revision when
post-quantum or other migrations are warranted; adopt new algorithms
upstream and propagate via library updates.

---

## (g) DNS protocol weaknesses without DNSSEC

**Exposure**: 16-bit DNS Header ID is a known weakness (birthday attacks,
Kaminsky-style cache poisoning) when the response is not DNSSEC-signed.

**Residual risk**: a queried zone that is not DNSSEC-signed accepts a
poisoning attack on the recursive resolver path. Heimdall validates DNSSEC by
default per `DNSSEC-009`, but unsigned zones (still numerous in 2026) cannot
be validated.

**Acceptance rationale**: Heimdall cannot retroactively sign zones it does
not control. The structural mitigations (0x20 randomisation per `PROTO-025`
through `PROTO-031`, DNS Cookies per `PROTO-010`, segregated caches per
`CACHE-*`) reduce but do not eliminate the residual exposure on unsigned
zones.

**Mitigation outside Heimdall**: encourage zone operators to deploy DNSSEC;
maintain the DNSSEC validation default; monitor `bogus` outcomes for
indications of attack patterns on the unsigned-zone path.

---

## (h) Supply-chain compromise of pinned dependencies

**Exposure**: a compromise of an upstream maintainer of a Heimdall
dependency (Tokio, rustls, quinn, hyper, rustix, aws-lc-rs, ed25519-dalek,
etc.) could result in a malicious release that Heimdall pulls in via routine
dependency updates.

**Residual risk**: a compromised release in the dependency chain could
introduce arbitrary behaviour into the Heimdall binary. The structural
mitigations are reproducible builds (`THREAT-012`), `cargo-audit` and
`cargo-vet` as CI gates (`THREAT-010` and `THREAT-011`), the SBOM published
per release (`THREAT-014`), and the dependency-acceptance ADR gate
(`ENG-008` through `ENG-016`).

**Acceptance rationale**: the mitigations narrow but do not eliminate the
window during which a compromised release could go undetected. Discovery is
typically community-driven (e.g., the [crev](https://github.com/crev-dev/crev)
chain-of-trust ecosystem, or post-incident community review).

**Mitigation outside Heimdall**: maintain `cargo-vet` audit peers
(`ENG-052`); subscribe to RustSec advisories; review SBOM deltas at every
release for unexpected dependency changes; adopt `cargo-crev` / `cargo-vet`
peer reviews where available.

---

## Review cadence

This document is reviewed annually, alongside:

- macOS sandbox-profile cadence per `THREAT-106` (typically September, at
  every macOS major release).
- OpenBSD `pledge` / `unveil` boundary review per `THREAT-100` through
  `THREAT-103`.

The annual review MUST produce a written outcome (no change required, list
updated, new categories added, accepted-rationale revised). The
review-outcome record is retained alongside this file as historical record.
