# Heimdall Security Audit — Scope Document

**Version:** 1.0  
**Date:** 2026-04-27  
**Status:** Pre-engagement review  
**Classification:** Confidential (share under NDA)

---

## 1. Purpose

This document defines the scope, objectives, and constraints for an external security
audit of the Heimdall DNS server.  It is intended to be shared with candidate audit
firms during the RFP process and ratified by the selected firm before the engagement
begins.

Heimdall is a high-performance, security-focused DNS server written in Rust targeting
environments of extremely high load and concurrency.  It implements the authoritative,
recursive, and forwarder roles; DNS-over-TLS (DoT), DNS-over-HTTPS (DoH/H2, DoH/H3),
and DNS-over-QUIC (DoQ) transports; DNSSEC validation; and a hardened runtime (seccomp-
bpf, privilege drop, W^X, OpenBSD pledge/unveil, macOS sandbox).

---

## 2. Audit Objectives

1. Identify vulnerabilities in the cryptographic and transport layers that could allow
   an attacker to decrypt, forge, or intercept DNS messages.
2. Assess the correctness and robustness of the DNSSEC validation path, including
   resistance to known attacks (KeyTrap, algorithm downgrade, NSEC3 denial-of-service).
3. Identify parsing vulnerabilities in the DNS wire-format and zone-file parsers that
   could lead to memory corruption, denial-of-service, or incorrect resolution.
4. Validate the hardening profile: seccomp-bpf allow-list, privilege drop, W^X, and
   OS-level sandboxing.
5. Identify supply-chain risks in the dependency tree.
6. Assess the ACL, rate-limiting, and admission-control components for bypass or
   amplification vulnerabilities.

---

## 3. In-Scope Components

### 3.1 Cryptographic / Transport Layer

| Component | File(s) | Reference |
|---|---|---|
| TLS 1.3 configuration (rustls) | `crates/heimdall-runtime/src/transport/tls.rs` | ADR-0027, SEC-003 |
| DoT listener + client | `crates/heimdall-runtime/src/transport/dot.rs` | RFC 7858 |
| DoH/H2 listener | `crates/heimdall-runtime/src/transport/doh2.rs` | RFC 8484 |
| DoH/H3 listener | `crates/heimdall-runtime/src/transport/doh3.rs` | RFC 9250 |
| DoQ listener | `crates/heimdall-runtime/src/transport/quic.rs` | RFC 9250 |
| QUIC 0-RTT refusal | `crates/heimdall-runtime/src/transport/quic.rs` | SEC-022 |
| TLS session ticket key rotation | `crates/heimdall-runtime/src/transport/tls.rs` | ADR-0015 |
| mTLS identity fingerprinting | `crates/heimdall-runtime/src/transport/tls.rs` | ADR-0016 |
| DNS cookie implementation | `crates/heimdall-runtime/src/transport/cookie.rs` | RFC 7873 |

**Key questions for the auditor:**
- Are there TLS configuration issues that permit downgrade to TLS 1.2?
- Is the 0-RTT refusal correctly enforced across all code paths?
- Could a client manipulate HPACK/QPACK to cause memory exhaustion or information leakage?
- Are DNS cookies generated with sufficient entropy and validated correctly?

### 3.2 DNSSEC Validator

| Component | File(s) | Reference |
|---|---|---|
| Validator core | `crates/heimdall-roles/src/recursive/validate.rs` | RFC 4033–4035 |
| Trust anchor store | `crates/heimdall-roles/src/dnssec_roles/trust_anchor.rs` | RFC 5011 |
| NTA (Negative Trust Anchors) | `crates/heimdall-roles/src/dnssec_roles/nta.rs` | RFC 7646 |
| Aggressive NSEC/NSEC3 | `crates/heimdall-roles/src/recursive/validate.rs` | RFC 8198 |
| NSEC3 iteration cap | `crates/heimdall-core/src/dnssec/nsec.rs` | RFC 9276 |
| KeyTrap mitigations | `crates/heimdall-roles/src/recursive/validate.rs` | RFC 9364 |
| DS algorithm selection | `crates/heimdall-core/src/dnssec/` | RFC 8624 |
| Algorithm rollover | `crates/heimdall-roles/src/dnssec_roles/trust_anchor.rs` | RFC 8901 |

**Key questions for the auditor:**
- Is the NSEC3 iteration cap (150 per RFC 9276) enforced at all parser entry points?
- Are KeyTrap mitigations (limiting signature validation work per response) correct?
- Can a crafted zone operator cause the validator to enter an infinite loop or exhaust CPU?
- Is the trust anchor update path (RFC 5011) resistant to rollover poisoning?
- Are algorithm downgrade attacks possible against the DS selection logic?

### 3.3 Parsers

| Component | File(s) | Reference |
|---|---|---|
| DNS wire-format parser | `crates/heimdall-core/src/parser.rs` | RFC 1035 |
| Zone-file parser | `crates/heimdall-core/src/zone.rs` | RFC 1035 |
| EDNS option parser | `crates/heimdall-core/src/edns.rs` | RFC 6891 |
| SVCB/HTTPS record parser | `crates/heimdall-core/src/` | RFC 9460 |
| HPACK decoder (HTTP/2) | `crates/heimdall-runtime/src/transport/doh2.rs` | RFC 7541 |
| QPACK decoder (HTTP/3) | `crates/heimdall-runtime/src/transport/doh3.rs` | RFC 9204 |

**Key questions for the auditor:**
- Can the wire-format parser be driven into a panic, integer overflow, or infinite loop?
- Are name compression pointer loops (RFC 1035 §4.1.4) correctly detected and rejected?
- Can an oversized or malformed EDNS option cause heap exhaustion?
- Are HPACK and QPACK decoders protected against decompression bombs (dynamic table overflows)?

### 3.4 Hardening Profile

| Component | File(s) | Reference |
|---|---|---|
| seccomp-bpf filter | `crates/heimdall-runtime/src/security/seccomp.rs` | THREAT-024 |
| Privilege drop | `crates/heimdall-runtime/src/security/privdrop.rs` | THREAT-022/023 |
| OpenBSD pledge/unveil | `crates/heimdall-runtime/src/security/pledge.rs` | THREAT-029 |
| systemd unit hardening | `contrib/systemd/heimdall.service` | THREAT-025 |
| W^X enforcement | `.cargo/config.toml` (linker flags) | THREAT-027 |

**Key questions for the auditor:**
- Does the seccomp-bpf allow-list contain syscalls that could enable a container escape?
- Is the privilege drop correctly ordered relative to socket binding?
- Could the pledge promise set be reduced further without breaking functionality?

### 3.5 ACL / Rate Limiting / Admission Control

| Component | File(s) | Reference |
|---|---|---|
| ACL evaluation | `crates/heimdall-runtime/src/admission/acl.rs` | THREAT-041..043 |
| Response Rate Limiting | `crates/heimdall-runtime/src/admission/rrl.rs` | THREAT-064..067 |
| Admission pipeline | `crates/heimdall-runtime/src/admission/pipeline.rs` | THREAT-068..070 |
| Load signal | `crates/heimdall-runtime/src/admission/load_signal.rs` | THREAT-071..074 |
| RPZ (Response Policy Zones) | `crates/heimdall-roles/src/recursive/` | THREAT-055..063 |

**Key questions for the auditor:**
- Can ACL rules be bypassed via source IP spoofing, IPv4-mapped IPv6 addresses, or EDNS client subnet?
- Can RRL thresholds be exploited to cause self-denial-of-service (under-throttling)?
- Is the RPZ first-match-wins logic resistant to poisoning via a crafted zone operator?
- Can the admission pipeline be saturated to deny service to legitimate clients?

### 3.6 Supply Chain

| Component | Reference |
|---|---|
| Direct dependency tree | `Cargo.lock` |
| cargo-vet audit records | `supply-chain/audits.toml` |
| cargo-deny configuration | `deny.toml` |
| SBOM (CycloneDX) | Generated at Tier 3 nightly |
| Release signing | `docs/runbooks/signing.md` |

**Key questions for the auditor:**
- Are there transitive dependencies with known vulnerabilities not covered by waivers?
- Are there dependencies with unexpectedly broad syscall/network access in build scripts?
- Could a supply-chain compromise of ring, rustls, or quinn affect release artefacts?

---

## 4. Out of Scope

- Heimdall configuration files provided by the operator (the audit covers the server's
  default security posture; operator misconfigurations are out of scope).
- Network infrastructure surrounding the deployment (firewalls, load balancers).
- Side-channel attacks requiring physical co-location.
- The Sigstore/Rekor transparency log infrastructure (external service, not Heimdall code).

---

## 5. Deliverables Expected from the Auditor

1. **Audit report**: Executive summary, methodology, findings (one section per finding
   with reproduction steps, severity per CVSS v3.1, CWE classification, and
   recommended fix).
2. **Threat model review**: Commentary on `specification/007-threat-model.md` and the
   coverage of the mitigation matrix.
3. **Re-review report**: After Heimdall fixes are applied, a short follow-up report
   confirming closure of each finding.
4. **Sign-off document**: Signed by the audit firm, confirming no open Critical or High
   findings remain.

---

## 6. Constraints

- The audit must be conducted against a tagged commit (the Sprint 41 RC tag).
- All findings must be reported under responsible disclosure; public disclosure is
  embargoed for 90 days or until a fix is released, whichever is sooner.
- The audit report is shared under NDA; the sign-off document may be published.
- Fix PRs for Critical and High findings must be merged before the Sprint 41 GA tag.

---

## 7. Contact

**Project maintainer:** Flavio Oliveira <flavio.c.oliveira@meo.pt>  
**Repository:** https://github.com/FlavioCFOliveira/Heimdall  
**Security policy:** SECURITY.md

---

## Appendix A: Threat Model Coverage Matrix

The following THREAT-* identifiers are referenced in `specification/007-threat-model.md`.
Each should be reviewed by the auditor against the corresponding implementation.

| ID | Category | Sprint | Status |
|---|---|---|---|
| THREAT-012 | Reproducible build | 38 | Mitigated |
| THREAT-013 | Release signing | 38 | Mitigated |
| THREAT-014 | SBOM | 38 | Mitigated |
| THREAT-022 | Privilege drop | 37 | Mitigated |
| THREAT-023 | CAP_NET_BIND_SERVICE only | 37 | Mitigated |
| THREAT-024 | seccomp-bpf allow-list | 37 | Mitigated |
| THREAT-025 | systemd hardening directives | 37 | Mitigated |
| THREAT-026 | Filesystem isolation | 37 | Mitigated |
| THREAT-027 | W^X enforcement | 39 | Mitigated |
| THREAT-029 | OpenBSD pledge + unveil | 37 | Mitigated |
| THREAT-030 | macOS sandbox profile | 37 | Mitigated |
| THREAT-031 | CI drift gate | 37 | Mitigated |
| THREAT-041 | ACL — source IP spoofing | 26 | Mitigated |
| THREAT-055 | RPZ cache poisoning | 34 | Mitigated |
| THREAT-064 | Amplification via RRL | 26 | Mitigated |
| THREAT-079 | DNSSEC algorithm downgrade | 30 | Mitigated |
| THREAT-089 | seccomp allow-list categories | 37 | Mitigated |
| THREAT-094 | SECCOMP_RET_KILL_PROCESS | 37 | Mitigated |
| THREAT-100 | pledge promise set | 37 | Mitigated |
