# Security Audit — Request for Proposal

**Project:** Heimdall DNS Server  
**Date:** 2026-04-27  
**Response deadline:** 2026-06-15  
**Audit window target:** 2026-07 through 2026-08  

---

## 1. Introduction

Heimdall is an open-source, high-performance DNS server written in Rust targeting
environments of extremely high load and concurrency.  The project is approaching its
first production release (v1.0) and requires an independent external security audit
before the GA tag.

---

## 2. Scope

The full audit scope is defined in `docs/audit/scope.md`.  In summary:

- **Cryptographic / transport layer**: TLS 1.3 (rustls), QUIC (quinn), DoT/DoH/DoQ
  listeners and clients, 0-RTT refusal, TLS session ticket rotation, DNS cookies.
- **DNSSEC validator**: RFC 4033–4035 correctness, KeyTrap mitigations (RFC 9364),
  NSEC3 iteration cap (RFC 9276), trust anchor store (RFC 5011), NTA handling.
- **Parsers**: DNS wire-format, zone-file, EDNS options, HPACK/QPACK decoders.
- **Hardening profile**: seccomp-bpf allow-list, privilege drop, W^X, OpenBSD
  pledge/unveil, macOS sandbox profile.
- **ACL / rate limiting / admission control**: RRL, RPZ, load signal, admission pipeline.
- **Supply chain**: Cargo.lock dependency tree, cargo-vet audit records, cargo-deny
  configuration.

---

## 3. Desired Expertise

Candidate firms should demonstrate:

- Experience auditing Rust security-critical software (Rust-specific memory safety,
  unsafe reasoning, lifetime/ownership invariants).
- Experience auditing DNS implementations (protocol-level attacks: amplification,
  cache poisoning, DNSSEC implementation flaws).
- Experience with cryptographic protocol audits (TLS 1.3, QUIC).
- Experience with seccomp-bpf / Linux kernel security mechanisms.
- Prior published audit reports for open-source projects (references required).

**Shortlisted firms** (non-exhaustive; other qualified firms welcome to respond):
NCC Group, Trail of Bits, Cure53, Include Security, Quarkslab.

---

## 4. Deliverables

1. Audit report with: executive summary, methodology, per-finding entries (severity per
   CVSS v3.1, CWE class, reproduction steps, recommended fix).
2. Threat model review commentary on `specification/007-threat-model.md`.
3. Re-review report confirming closure of all Critical and High findings.
4. Signed audit sign-off document (publishable).

---

## 5. Timeline

| Milestone | Target date |
|---|---|
| RFP response deadline | 2026-06-15 |
| Firm selected + contract signed | 2026-06-30 |
| Audit kick-off | 2026-07-07 |
| Draft report received | 2026-08-07 |
| Fix period | 2026-08-08 — 2026-08-21 |
| Re-review | 2026-08-22 — 2026-08-28 |
| Final sign-off | 2026-09-04 |
| Sprint 41 GA release | 2026-09-11 |

---

## 6. Responsible Disclosure

All findings are subject to a 90-day embargo from the date of the draft report.
Public disclosure is permitted after a fix is released or the embargo expires,
whichever is sooner.

---

## 7. Contact

**Project maintainer:** Flavio Oliveira <flavio.c.oliveira@meo.pt>  
**Repository:** https://github.com/FlavioCFOliveira/Heimdall
