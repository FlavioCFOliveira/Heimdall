# Beta Feedback Triage Process

**Applies to:** v0.9.0-beta.* series  
**ENG reference:** ENG-130  
**Triage window:** 2026-05-01 — 2026-07-31 (approximately)  
**Triage cadence:** Weekly, every Monday

---

## Labels

| Label | Meaning |
|---|---|
| `beta-2026` | Auto-applied by issue template; marks beta-series issues |
| `rc-blocker` | Must be resolved before promoting to RC (v1.0.0-rc.1) |
| `triage-needed` | Default on open; removed after first triage pass |
| `triage-accepted` | Accepted for this release cycle |
| `triage-declined` | Deferred or closed without fix in beta |
| `severity-critical/high/medium/low` | Applied during triage |
| `affects-<role/transport>` | Applied during triage |

---

## RC-Blocker Gate

Before promoting to v1.0.0-rc.1:

- **All** `rc-blocker` issues must be in state: Fixed (PR merged) or
  Accepted-risk (documented in `docs/audit/findings-triage.md`).
- The `rc-blocker-burndown` milestone open-issue count must be zero.
- The Sprint 41 external audit sign-off must be attached to the release.
- The next pre-release changelog entry must include an "RC-blocker burndown"
  section listing all resolved blockers.

---

## Patch-Tag Process

If an RC-blocker is fixed during the beta window, issue a patch tag rather
than waiting for the full RC sprint:

1. Apply the fix on main (PR + Tier 1/2 CI green).
2. Tag as `v0.9.0-beta.N+1` (e.g. `v0.9.0-beta.2`).
3. Bump workspace version in `Cargo.toml` + update `Cargo.lock`.
4. Create `docs/release-notes/v0.9.0-beta.N+1.md` with the delta section.
5. Add CHANGELOG.md entry.
6. Push tag — Tier 4 runs automatically.

---

## Severity Classification

| Severity | Definition | SLA |
|---|---|---|
| Critical | Server crash, data corruption, security regression | Fix in current sprint |
| High | Incorrect DNS answers under realistic load | Fix before RC |
| Medium | Degraded performance, intermittent failure | Fix before RC (tracked issue) |
| Low | Cosmetic or rare edge case | Fix in RC or defer |

---

## Security Reports

Security bugs must **not** be filed as public GitHub Issues. Report them to
`security@flaviocfoliveira.dev` with subject `[SECURITY] Heimdall beta`.

---

## Milestone Setup

| Milestone | Description |
|---|---|
| `rc-blocker-burndown` | All `rc-blocker` issues from the beta phase |
| `v1.0.0-rc.1` | Target milestone for all accepted fixes |
