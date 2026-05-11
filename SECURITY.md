# Security Policy

## Supported Versions

| Version | Supported | End-of-life |
|---|---|---|
| 1.0.x (LTS) | Yes — security + critical bug fixes | 12 months from 2026-04-27 (2027-04-27) |
| 1.0.0-rc.* | No | Superseded by 1.0.0 |
| 0.9.0-beta.* | No | Superseded by 1.0.0 |
| 0.9.0-alpha.* | No | Superseded by 1.0.0 |

Security fixes are backported to the current LTS branch (`v1.0`).  End-of-life
versions receive no security fixes — upgrade to a supported version.

## Reporting a vulnerability

**Do not open a public GitHub Issue for security-sensitive reports.**

Security vulnerabilities in Heimdall must be reported through the
[GitHub Security Advisories private reporting flow](https://github.com/FlavioCFOliveira/Heimdall/security/advisories/new).
Private reporting ensures the report is handled confidentially and reaches the maintainers directly.

If you are unsure whether an issue is a security vulnerability, err on the side of caution and use the private reporting path.

## What to include

A useful report contains:

- A description of the vulnerability and the affected component.
- Steps to reproduce or a proof-of-concept, if available.
- The version or commit at which the issue was observed.
- Any relevant configuration or environment details.
- Your assessment of the potential impact.

## Response timeline

The maintainers will acknowledge receipt within **72 hours** of a submitted report.
After acknowledgement, the expected timeline is:

| Milestone                        | Target         |
|----------------------------------|----------------|
| Initial triage and severity assessment | Within 7 days  |
| Patch development and internal review  | Depends on severity |
| Coordinated public disclosure          | See policy below |

## Coordinated disclosure policy

Heimdall follows a coordinated disclosure model.

- The default embargo window between report acceptance and public disclosure is **90 days**.
- The embargo may be shortened with the agreement of both the reporter and the maintainers, for example when a fix is ready sooner.
- The embargo may be extended in exceptional circumstances, with the reporter informed of the reason and the revised timeline.
- If a vulnerability is being actively exploited in the wild, the embargo may be shortened or waived in the public interest.

Once a fix is ready and the embargo has elapsed:

1. A fixed version is tagged and released, passing all Tier 4 CI gates.
2. A GitHub Security Advisory (GHSA) is published on the primary repository.
3. A CVE identifier is assigned via the GHSA CVE Numbering Authority integration or MITRE.
4. The GHSA advisory is linked to the assigned CVE and to the fixed release tag.

## Scope

This policy covers the Heimdall binary and all library crates in this repository.
It does not cover third-party dependencies; vulnerabilities in dependencies should be reported
to the dependency's maintainers and tracked through their own advisory process.

## Admin-RPC trust boundary

The administrative RPC surface (`heimdall-runtime::ops::admin_rpc`) accepts
zone-add, RPZ-entry-add, TEK-rotate, drain, and reload commands over a
**local Unix domain socket** with filesystem permissions `0600` owned by
the Heimdall process UID. **This is a host-trust boundary, not a
network-trust boundary.**

- Any process running as the Heimdall UID — including a debugger, an
  unrelated daemon misconfigured to share the UID, or a malicious binary
  that has gained UID-level execution — has **full administrative
  control** of the Heimdall daemon. Commands include `ZoneAdd { file }`
  with an arbitrary path readable to the UID, which is sufficient for
  RCE-equivalent impact: an attacker who can write a malicious zone
  file and call `ZoneAdd` can pivot through any zone-import logic.
- The UDS authentication today is the kernel-enforced filesystem ACL
  on `0600`. There is no additional in-process authentication layer
  (cryptographic, token-based, or otherwise). The
  `crates/heimdall-runtime/src/ops/admin_rpc.rs` source explicitly
  states this with the comment "No additional authentication layer is
  applied in this sprint".
- For non-loopback access — even on a private management network — the
  current UDS surface is **not** appropriate. ADR-0053 and ADR-0054
  describe the gRPC + mTLS migration that will accept TCP carriers
  with the same SEC-012..016 mTLS policy used by DoT/DoH/DoQ. Until
  that migration completes, the only supported access path is the
  loopback UDS or a forwarded UDS over `ssh -L`. The Sprint 67 rmp
  task #690 tracks the gRPC + mTLS implementation.

### Audit log

Every admin-RPC command invocation emits a structured event including
the caller's UID, GID and PID, the command name, the affected zone /
RPZ entry / target, the wall-clock timestamp, the outcome
(success/error), and an event identifier. The audit log is part of
the THREAT-080 control set; operators MUST forward it to their SIEM
tier per the retention defaults in THREAT-145.

### Operator obligation

A correct deployment:

1. Restricts host-UID access to the Heimdall UID. The unit file ships
   `User=heimdall, Group=heimdall, NoNewPrivileges=true, ProtectSystem=strict,
   ProtectHome=true, PrivateTmp=true`. **Do not run Heimdall as root or
   share its UID with another service.**
2. Restricts filesystem access to the directory containing the UDS so
   that no other UID can chmod or chown the socket.
3. Forwards the admin-RPC audit log to a separate-host SIEM tier; a
   compromised Heimdall host must not be able to scrub its own audit
   trail.

Failure to honour these obligations breaks the trust model and
warrants treating the admin-RPC surface as fully exposed.

---

*Concrete embargo-window parameters and their flexibility are tracked as open questions in
[`specification/010-engineering-policies.md`](specification/010-engineering-policies.md) (ENG-133).*
