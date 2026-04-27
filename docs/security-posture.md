# Heimdall Security Posture

This document describes Heimdall's security posture: its threat model coverage,
cryptographic policy, process hardening profile, and supply-chain controls.

**Normative specification references**: `specification/007-threat-model.md`
(THREAT-*), `specification/003-crypto-policy.md` (SEC-*),
`specification/005-dnssec-policy.md` (DNSSEC-*),
`specification/010-engineering-policies.md` (ENG-*).

**See also**

- [Residual Risks](residual-risks.md) — accepted residual exposures.
- [Operator Manual](operator-manual.md) — deployment and lifecycle.
- [Troubleshooting Guide](troubleshooting.md) — diagnosis workflows.

---

## 1. Threat model coverage matrix

Heimdall's threat model is defined in `specification/007-threat-model.md`. The
table below maps each in-scope threat class to the primary mitigation
requirements and the task/sprint in which they were implemented.

| Threat | Class | Primary mitigation requirements | Implemented in |
|--------|-------|---------------------------------|---------------|
| THREAT-001 | Off-path attacker | 0x20 (PROTO-025..031), DNS Cookies (PROTO-010), DNSSEC (DNSSEC-009..030), QUIC amplification (SEC-025..030), segregated caches (CACHE-001) | Sprints 13–16, 17–19 |
| THREAT-002 | On-path attacker | TLS 1.3-only (SEC-001..004), no 0-RTT (SEC-005..007, SEC-022..024), QUIC v1/v2 (SEC-017..021), TEK rotation (SEC-008..011), mTLS (SEC-012..016, SEC-031..035) | Sprints 22–25 |
| THREAT-003 | Upstream peer compromise | DNSSEC on every upstream response (DNSSEC-009), segregated forwarder cache (CACHE-001), encrypted outbound (NET-015..017, NET-022..023) | Sprints 16, 32 |
| THREAT-004 | Adversarial zone operator | KeyTrap cap (DNSSEC-028), NSEC3 iteration cap 150/RFC 9276 (DNSSEC-030), algorithm acceptance policy (DNSSEC-031..040) | Sprints 16–17 |
| THREAT-005 | Volumetric DoS/DDoS | QUIC amplification limit (SEC-025..030), HTTP/2+3 hardening (SEC-036..046), aggressive NSEC/NSEC3 (DNSSEC-), QUIC no-0-RTT (SEC-022..024), ACL (THREAT-033..047), RRL (THREAT-048..060), admission control (THREAT-061..078) | Sprints 18–21 |
| THREAT-006 | Supply-chain attacker | Dependency minimisation (THREAT-010), cargo-audit+vet CI gate (THREAT-011), reproducible builds (THREAT-012), signed artefacts (THREAT-013), SBOM (THREAT-014) | Sprints 1, 35 |
| THREAT-013 | Signed artefacts | cosign/sigstore signing | Sprint 35 |
| THREAT-014 | SBOM | CycloneDX/SPDX per release (ADR-0056) | Sprint 35 |
| THREAT-015 | Off-path mitigations (detail) | (see THREAT-001) | — |
| THREAT-016 | On-path mitigations (detail) | (see THREAT-002) | — |
| THREAT-017 | Upstream compromise mitigations | (see THREAT-003) | — |
| THREAT-018 | Adversarial zone mitigations | (see THREAT-004) | — |
| THREAT-019 | DoS mitigations (detail) | (see THREAT-005) | — |
| THREAT-020 | Supply-chain mitigations | (see THREAT-006) | — |
| THREAT-022 | Privilege drop (Linux) | `useradd -r heimdall`, drop after socket bind | Sprint 37 |
| THREAT-023 | Minimum capabilities (Linux) | `CAP_NET_BIND_SERVICE` only | Sprint 37 |
| THREAT-024 | seccomp-bpf (Linux) | Allow-list filter, `ENOSYS` on violation | Sprint 37 |
| THREAT-025 | systemd hardening | Reference unit `contrib/systemd/heimdall.service` | Sprint 33 |
| THREAT-026 | Filesystem isolation (Linux) | `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices` | Sprint 33 |
| THREAT-027 | W^X | `MemoryDenyWriteExecute=yes`, no RWX mappings | Sprint 37 |
| THREAT-029 | pledge + unveil (OpenBSD) | Self-applied at startup | Sprint 37 |
| THREAT-030 | macOS sandbox | `contrib/macos/heimdall.sb` | Sprint 33 |
| THREAT-031 | Reference artefacts | `contrib/systemd/`, `contrib/openbsd/`, `contrib/macos/` | Sprint 33 |

Threats classified **out of scope** (THREAT-007, THREAT-008, THREAT-009,
THREAT-032) are not listed because Heimdall provides no structural mitigation
for them by design. See [Residual Risks](residual-risks.md).

---

## 2. Cryptographic policy

### 2.1 TLS

| Policy | Specification | ADR |
|--------|---------------|-----|
| TLS 1.3 only; TLS 1.2 disabled at build time | SEC-001 through SEC-004 | ADR-0027 |
| No TLS 1.3 early data (0-RTT) on DoT and DoH/H2 | SEC-005 through SEC-007 | ADR-0027 |
| Stateless session tickets via TEK; no server-side session cache | SEC-008 through SEC-011 | ADR-0015 |
| mTLS optional per listener; validated before ACL | SEC-012 through SEC-016 | ADR-0016 |

**Library**: `rustls` (ADR-0027) + `aws-lc-rs` (primary) / `ring` (alternative,
ADR-0036). No `openssl` dependency.

### 2.2 QUIC

| Policy | Specification | ADR |
|--------|---------------|-----|
| QUIC v1 (RFC 9000) and v2 (RFC 9369) accepted; no earlier drafts | SEC-017 through SEC-021 | ADR-0028, ADR-0050 |
| No 0-RTT application data on DoQ and DoH/H3 | SEC-022 through SEC-024 | ADR-0017 |
| Unconditional QUIC Retry for address validation | SEC-025 through SEC-027 | ADR-0028 |
| Single-use `NEW_TOKEN` anti-replay | SEC-028 through SEC-030 | ADR-0017 |
| mTLS on QUIC optional per listener | SEC-031 through SEC-035 | ADR-0016 |

**Library**: `quinn` (ADR-0028, ADR-0050).

### 2.3 DNSSEC

| Policy | Specification |
|--------|---------------|
| DNSSEC validation enabled by default | DNSSEC-009 |
| BOGUS → SERVFAIL; INSECURE treated as unsigned | DNSSEC-010 |
| Aggressive NSEC/NSEC3 negative caching | DNSSEC-014 |
| KeyTrap cap on DNSKEY × RRSIG combinations | DNSSEC-028 |
| NSEC3 iteration cap at 150 (RFC 9276) | DNSSEC-030 |
| Algorithm policy: SHA-256/384, ECDSA P-256/P-384, Ed25519; MD5/SHA-1 rejected | DNSSEC-031..040 |

### 2.4 HTTP/2 and HTTP/3 hardening

SEC-036 through SEC-046 apply to every DoH listener (H2 and H3):

| Hardening control | Specification |
|-------------------|---------------|
| Header-block size limit | SEC-036 |
| Concurrent-stream cap | SEC-037 |
| HPACK/QPACK dynamic-table cap | SEC-038 |
| Rapid-reset (CVE-2023-44487) detection | SEC-039 |
| CONTINUATION-flood cap | SEC-040 |
| Control-frame rate limit | SEC-041 |
| Header-completion timeout | SEC-042 |
| Flow-control window bounds | SEC-043 through SEC-046 |

---

## 3. Hardening profile

### 3.1 Linux (systemd)

The reference unit (`contrib/systemd/heimdall.service`) applies all mandatory
hardening directives mandated by THREAT-025:

| Directive | Purpose |
|-----------|---------|
| `User=heimdall`, `Group=heimdall` | Dedicated unprivileged user (THREAT-022) |
| `AmbientCapabilities=CAP_NET_BIND_SERVICE` | Minimum capability set (THREAT-023) |
| `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` | Drop all other capabilities (THREAT-023) |
| `NoNewPrivileges=yes` | Prevent privilege escalation (THREAT-025) |
| `ProtectSystem=strict` | Filesystem isolation (THREAT-026) |
| `ProtectHome=yes` | Prevent home directory access |
| `PrivateTmp=yes` | Private /tmp |
| `PrivateDevices=yes` | No raw device access |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | Limit socket families |
| `RestrictNamespaces=yes` | Prevent namespace manipulation |
| `RestrictSUIDSGID=yes` | Prevent SUID/SGID execution |
| `MemoryDenyWriteExecute=yes` | W^X enforcement (THREAT-027) |
| `LockPersonality=yes` | Prevent personality change |
| `SystemCallArchitectures=native` | No compat syscalls |
| `SystemCallFilter=@system-service ~@privileged ~@resources` | Syscall allow-list |

The seccomp-bpf filter (THREAT-024, ADR-0019) is installed by the Heimdall
binary itself at runtime, after socket binding and before serving traffic.
The rejection action for blocked syscalls is `ENOSYS` (THREAT-094, ADR-0020).

### 3.2 OpenBSD (pledge + unveil)

Applied by the Heimdall binary at startup (THREAT-029, THREAT-100..102):

- **`pledge(2)`** restricts the system-call surface to the minimum required
  by the active role set (network I/O, file reads, process signals).
- **`unveil(2)`** restricts filesystem visibility:
  - `/etc/heimdall` (read-only, all roles)
  - Zone directory (read-only, authoritative role)
  - `/var/run/heimdall` (read-write, admin-RPC socket)
  - `/var/heimdall` (read-write, trust anchor — recursive role only)

The unveil set is fixed at startup and is not extended by SIGHUP reloads
(THREAT-103). A full restart is required to add new paths.

### 3.3 macOS (sandbox-exec)

The sandbox profile at `contrib/macos/heimdall.sb` applies (THREAT-030,
THREAT-031, ADR-0023):

- `(deny default)` — deny-all baseline.
- Explicit deny of `process-exec` and `process-fork`.
- Read access limited to system libraries, `/etc/heimdall`, and zone files.
- Write access limited to `/var/run/heimdall`.
- Network restricted to DNS ports (53, 853, 443).

This is a **SHOULD-level** control; macOS is development-only (ENV-009).

### 3.4 W^X (all platforms)

No mapped memory region is simultaneously writable and executable (THREAT-027).
Enforced via `MemoryDenyWriteExecute=yes` on Linux and by the absence of
JIT-compiled code in the Heimdall binary.

---

## 4. Supply chain

### 4.1 Dependency policy

Every external dependency addition requires an explicit Architecture Decision
Record (ADR) and is subject to the dependency-acceptance gate (THREAT-010,
ENG-008 through ENG-016). Dependencies are kept to the strict minimum required.

### 4.2 Audit tooling

| Tool | CI gate | Purpose |
|------|---------|---------|
| `cargo-audit` | ENG-051 | CVE / RustSec advisory scan |
| `cargo-vet` | ENG-052 | Third-party trust audits |
| `cargo-deny` | ENG-050 | Licence, ban, and duplicate checks |

All three are mandatory CI gates; a build whose dependencies fail any gate is
not promotable to release (THREAT-011).

### 4.3 Reproducible builds

Release builds are reproducible (THREAT-012, ADR-0057). The `SOURCE_DATE_EPOCH`
environment variable is set from the git history at build time. The build
configuration and steps are documented in the `Dockerfile` and verified by an
independent party using the published inputs.

### 4.4 Artefact signing

Official release artefacts are signed with `cosign` / sigstore (THREAT-013).
Verification procedure:

```sh
cosign verify-blob \
    --certificate heimdall-<version>-x86_64.tar.gz.pem \
    --signature  heimdall-<version>-x86_64.tar.gz.sig \
    heimdall-<version>-x86_64.tar.gz
```

### 4.5 SBOM

A Software Bill of Materials (SBOM) in CycloneDX format is produced for every
official release and published alongside the signed artefacts (THREAT-014,
ADR-0056).

### 4.6 SLSA target

Heimdall targets SLSA Level 3 for official releases (ADR-0058): hermetic builds
in an isolated environment, provenance attestation, and two-party review for
dependency changes.

---

## 5. Residual risks

Accepted residual risks are catalogued in [docs/residual-risks.md](residual-risks.md).
They include:

- **C-library crypto code paths** (ring / aws-lc-rs side-channel residuals).
- **Microarchitectural side-channels** (Spectre, Meltdown, L1TF).
- **Local insider / operator compromise** (out of scope by THREAT-007).
- **Physical attacks** (out of scope by THREAT-008).
- **Cryptographic algorithm break** (ecosystem-wide exposure).
- **DNS protocol weaknesses without DNSSEC** (unsigned zones).
- **Supply-chain compromise of pinned dependencies**.

None of these residual risks invalidate the structural mitigations described in
this document. Each is accepted on the grounds documented in
[residual-risks.md](residual-risks.md).
