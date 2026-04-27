# Post-GA Release Cadence and Community Channels

**ENG reference:** ENG-174  
**Effective from:** v1.0.0 GA (2026-04-27)

---

## Release Cadence

### Patch releases (v1.0.x)

- **LTS branch (`v1.0`)**: security and critical bug fix backports.
- **Frequency**: as needed; no fixed schedule.
- **Process**: cherry-pick from main → Tier 1/2 CI → tag → Tier 4 release pipeline.
- **Announcement**: SECURITY.md advisory (for security patches) or GH Release notes.

### Minor releases (v1.x.0)

- **Main branch**: new features, non-breaking improvements.
- **Target cadence**: every 3–6 months.
- **v1.1.0 milestone**: https://github.com/FlavioCFOliveira/Heimdall/milestone/1
- **Gate**: Tier 1 + Tier 2 + Tier 3 all green; no open P0/P1 issues in the milestone.

### Major releases (v2.0.0+)

- **When**: breaking API/config/wire changes are required.
- **Migration guide**: published with the release, at least 6 months after the
  breaking-change deprecation notice.

---

## Post-GA Triage Cadence

| Cadence | Activity |
|---|---|
| Weekly (Monday) | Triage new issues: apply labels, assign severity |
| Monthly | Review open `rc-blocker` / `beta-blocker` residuals; update LTS status |
| Quarterly | Minor release planning; review v1.0 EOL timeline |
| Annually (Apr) | LTS EOL review; announce migration guidance if EOL < 90 days away |

---

## Community Channels

| Channel | Purpose |
|---|---|
| GitHub Issues | Bug reports, feature requests |
| GitHub Discussions | Q&A, usage help, RFCs |
| GitHub Security Advisories | Private security reports (SECURITY.md) |
| GitHub Releases | Release announcements with artefact links |

---

## v1.0.0 GA Announcement Template

```
Subject: Heimdall 1.0.0 — General Availability

Heimdall 1.0.0, a production-ready DNS server written in Rust, is now
generally available.

Download: https://github.com/FlavioCFOliveira/Heimdall/releases/tag/v1.0.0
Operator manual: https://github.com/FlavioCFOliveira/Heimdall/blob/main/docs/operator-manual.md
SECURITY.md: https://github.com/FlavioCFOliveira/Heimdall/blob/main/SECURITY.md

Key capabilities:
- Recursive resolver with full DNSSEC validation (RFC 4033–4035)
- Authoritative server with AXFR/IXFR zone transfer support
- Forwarder with DoT upstream and DNSSEC re-validation
- DNS-over-TLS, DNS-over-HTTPS/2, DNS-over-HTTPS/3, DNS-over-QUIC transports
- Response Policy Zones (RPZ) for threat intelligence integration
- Runtime hardening: seccomp-bpf, privilege drop, W^X, pledge/unveil
- SLSA Level 3 build provenance; CycloneDX SBOM; cosign signatures

The v1.0.x branch is supported for 12 months (until 2027-04-27) with
security and critical bug fix backports.

Feedback: GitHub Issues at the link above.
Security reports: SECURITY.md (private disclosure path).
```

---

## LTS Monitoring Checklist

Run monthly:

- [ ] Check for new CVEs in direct dependencies (`cargo audit`).
- [ ] Review open issues labelled `affects-1.0.x`.
- [ ] Check for Tier 3 nightly regressions on the `v1.0` branch.
- [ ] Confirm GHSA advisory page is up to date.
