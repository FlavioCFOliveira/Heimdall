# Alpha Feedback Triage Process

**Applies to:** v0.9.0-alpha.* series  
**ENG reference:** ENG-130  
**Triage window:** 2026-04-27 — 2026-06-30 (approximately)  
**Triage cadence:** Weekly, every Monday

---

## Labels

| Label | Meaning |
|---|---|
| `alpha-2026` | Auto-applied by issue template; marks alpha-series issues |
| `beta-blocker` | Must be resolved before promoting to beta |
| `triage-needed` | Default on open; removed after first triage pass |
| `triage-accepted` | Accepted for this release cycle |
| `triage-declined` | Deferred or closed without fix in alpha |
| `severity-critical/high/medium/low` | Applied during triage |
| `affects-<role/transport>` | Applied during triage |

---

## Triage Procedure

### Step 1 — First response (within 48 hours of filing)

- Apply `triage-needed` if not already present.
- Apply `affects-<role/transport>` labels.
- For **Critical or High** bugs: apply `severity-critical` or `severity-high`
  immediately; assess whether `beta-blocker` applies.
- Acknowledge the issue with a comment confirming it has been seen.

### Step 2 — Weekly triage meeting (every Monday)

Review all issues labelled `triage-needed` and `alpha-2026`:

1. Confirm or adjust severity label.
2. Apply `triage-accepted` or `triage-declined` and remove `triage-needed`.
3. For `beta-blocker` issues: assign a fixer and a target sprint.
4. Update the **Alpha Beta-blocker Milestone** in GitHub with the current
   open issue count.

### Step 3 — Beta-blocker burndown gate

Before the beta promotion decision:

- **All** `beta-blocker` issues must be in state: Fixed (PR merged) or
  Accepted-risk (explicitly documented in `docs/audit/findings-triage.md`).
- Milestone open-issue count must be zero.
- The next pre-release changelog entry must include a "Beta-blocker burndown"
  section listing all resolved blockers.

---

## Severity Classification

| Severity | Definition | SLA |
|---|---|---|
| Critical | Server crash, data corruption, security regression | Fix in current sprint |
| High | Incorrect DNS answers under realistic load | Fix before beta |
| Medium | Degraded performance, intermittent failure | Fix before beta (tracked issue) |
| Low | Cosmetic or rare edge case | Fix in beta or defer |

---

## Security Reports

Security bugs must **not** be filed as public GitHub Issues. Report them to
`security@flaviocfoliveira.dev` with subject `[SECURITY] Heimdall alpha`.

The maintainer will triage privately, open a draft security advisory, and
coordinate a fix + CVE assignment before public disclosure.

---

## Milestone Setup

Create the following milestones in GitHub:

| Milestone | Description |
|---|---|
| `alpha-blockers` | All `beta-blocker` issues from the alpha phase |
| `v0.9.0-beta.1` | Target milestone for all accepted fixes |

---

## Reporting

At each weekly triage:

- Post a comment on the pinned triage tracking issue (or the GitHub Discussion
  if one is opened) with:
  - New issues filed this week
  - Severity breakdown
  - Beta-blocker open count
  - Beta-blocker resolved count
