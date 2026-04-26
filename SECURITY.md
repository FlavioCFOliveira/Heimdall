# Security Policy

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

---

*Concrete embargo-window parameters and their flexibility are tracked as open questions in
[`specification/010-engineering-policies.md`](specification/010-engineering-policies.md) (ENG-133).*
