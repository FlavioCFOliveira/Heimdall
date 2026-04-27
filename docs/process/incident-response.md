# Incident Response Playbook — Security Vulnerabilities

**ENG reference:** ENG-179/180  
**Applies to:** All releases in the supported version table (SECURITY.md)

---

## Overview

This playbook covers the end-to-end process from receiving a security report
to publishing a fixed release and a public advisory.

---

## Phase 1 — Triage (within 48 hours of report)

1. **Acknowledge** the report to the reporter.  Do not disclose any details
   publicly.

2. **Open a draft GitHub Security Advisory (GHSA)**:
   - Go to: https://github.com/FlavioCFOliveira/Heimdall/security/advisories/new
   - Set severity (CVSS v3.1 base score).
   - Add the reporter as a collaborator (optional, with their consent).

3. **Assess exploitability**:
   - Is it remotely exploitable?
   - Does it require authentication or specific configuration?
   - Is there a known exploit in the wild?

4. **Assign severity** per CVSS v3.1:

   | Severity | CVSS | Fix target |
   |---|---|---|
   | Critical | 9.0–10.0 | 14 days from report |
   | High | 7.0–8.9 | 30 days from report |
   | Medium | 4.0–6.9 | 90 days from report |
   | Low | 0.1–3.9 | Next minor release |

5. **Decide scope**: which versions are affected?  Which require backporting?

---

## Phase 2 — Fix Development (private)

1. Create a **private fork** or use the GHSA private repository feature.

2. Develop the fix:
   - Write a minimal, targeted patch.
   - Add a regression test that reproduces the vulnerability.
   - Do not reference the vulnerability in the commit message on the private
     branch (the GHSA ID is sufficient once published).

3. Run the full CI suite (Tier 1 + 2 + 3) on the private branch.

4. For **LTS backports** (v1.0.x): cherry-pick the fix to the `v1.0` branch
   in the private repository.

5. **Request a CVE** via the GHSA CNA integration:
   - In the draft GHSA, click "Request CVE".
   - GitHub's CNA assigns within 72 hours.
   - Fallback: request from MITRE at https://cveform.mitre.org

---

## Phase 3 — Coordinated Release

Default embargo window: **90 days** from report acceptance.  The window may
be shortened (with reporter agreement) or extended in exceptional circumstances.

1. **Coordinate disclosure date** with the reporter.

2. On the disclosure date:
   a. Merge the fix PR(s) to `main` (and `v1.0` for LTS backports).
   b. Bump version and tag the fixed release(s) per the normal release pipeline.
   c. Push the tag — Tier 4 pipeline runs and produces signed artefacts.
   d. Confirm all artefacts are published (GH Release, crates.io, OCI).

3. **Publish the GHSA**:
   - Attach the CVE number.
   - Reference the fixed version tag(s).
   - Include a clear description, impact, and upgrade instructions.

4. **Announcement** (same day as GHSA publication):
   - Post on the project website.
   - Send to relevant security mailing lists (oss-security@openwall.com if
     a CVE was assigned).
   - Update the GitHub repository Security Advisories page.

---

## Phase 4 — Post-Incident Review

Within 7 days of the public disclosure:

1. Document the root cause and contributing factors.
2. Identify process improvements (were there gaps in the threat model?).
3. Update `docs/audit/findings-triage.md` with the finding and its resolution.
4. Update the audit scope (`docs/audit/scope.md`) if the finding revealed an
   uncovered attack surface.

---

## GHSA Dry-Run Procedure

To verify the GHSA → CVE pipeline before a real incident:

1. Open a **draft** advisory on a test repository:
   - Title: `[TEST] CVE pipeline dry-run — do not publish`
   - Severity: Low
   - CWE: CWE-1 (placeholder)
2. Invite a collaborator and confirm access control works.
3. Click "Request CVE" — confirm the CNA integration is active.
4. **Delete the draft** (do not publish).

This dry-run confirms the tooling is functional without creating a public
advisory or consuming a real CVE number.

---

## Contacts

| Role | Contact |
|---|---|
| Security lead | flavio.c.oliveira@meo.pt |
| GitHub GHSA | https://github.com/FlavioCFOliveira/Heimdall/security/advisories |
| CVE fallback | https://cveform.mitre.org |
| OSS disclosure list | oss-security@openwall.com |
