# Governance

This document records Heimdall's governance model, as required by ENG-219 in
[`specification/010-engineering-policies.md`](specification/010-engineering-policies.md).

## Maintainers

| GitHub handle       | Role          |
|---------------------|---------------|
| @FlavioCFOliveira   | Maintainer    |

## Maintainer responsibilities

Maintainers are expected to:

- Review and approve pull requests in a timely manner.
- Triage and respond to issues and GitHub Security Advisories.
- Uphold the security, performance, and code-quality standards fixed by the specification.
- Participate in release decisions.
- Be reachable on the project's primary communication channels.

## Nomination and onboarding

A new maintainer may be nominated by any active existing maintainer. The nomination process is:

1. The nominating maintainer opens a GitHub Issue (or a pull request updating this file)
   describing the nominee's contributions and why maintainership is appropriate.
2. Existing active maintainers review the nomination. Approval follows the
   **lazy-consensus** model: if no active maintainer objects within **14 calendar days**,
   the nomination is accepted.
3. Upon acceptance, the nominee is granted the repository permissions appropriate to their
   role and this file is updated to list them.

## Inactive-maintainer removal

A maintainer is considered inactive after **18 consecutive months** of no substantive
contribution (code review, commits, issue triage, or specification work). Substantive
contribution is defined at the discretion of the remaining active maintainers.

An inactive maintainer may be removed by a simple majority vote of the active maintainers.
The removal is recorded by updating this file and adjusting repository permissions.

## Decision-making model

- **Minor decisions** (bug fixes, routine dependency updates, documentation corrections,
  operational configuration): settled by **lazy consensus** — if no active maintainer
  objects within a reasonable window (typically 48 hours for non-urgent items), the
  change proceeds.
- **Major decisions** (architectural changes, new dependencies, changes to the
  specification, MSRV policy changes, governance changes, release cadence changes):
  require a **supermajority of ≥ two-thirds of active maintainers** to approve.

What constitutes a "major" decision is assessed by the maintainers. When in doubt,
treat it as major.

## Conflict resolution

If lazy consensus fails on a decision — that is, an objection is raised and cannot be
resolved by discussion in the pull request or issue thread — the active maintainers
convene a synchronous call (video or voice) to deliberate. The outcome of the call is
recorded in the relevant pull request or issue thread.

If a synchronous call fails to produce a resolution, a supermajority vote is held
among active maintainers. Abstentions are not counted.

## Changes to this document

Any change to this file must follow the standard pull-request flow and must be reviewed
under the two-code-owner regime fixed by `ENG-079` and `ENG-083` in the specification.
A change to the maintainer list also requires a supermajority decision per the
major-decisions rule above.
