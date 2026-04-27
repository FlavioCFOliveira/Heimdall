# ADR-0059: Long-Term Support Model

**Status:** Accepted  
**Date:** 2026-04-27  
**ENG reference:** ENG-181  
**Deciders:** @flaviocfo

---

## Context

Heimdall 1.0.0 is the first stable release.  Operators deploying Heimdall in
production need a clear support commitment: which versions receive security
fixes, for how long, and what the upgrade path looks like when a version reaches
end-of-life.

---

## Decision

### LTS branch

The `v1.0` branch is created at the v1.0.0 GA commit.  It is the **sole LTS
branch** for the v1.0 major version.

### Support window

| Version line | Type | Support duration | EOL date |
|---|---|---|---|
| v1.0.x | LTS | 12 months from GA | 2027-04-27 |
| v1.1.x (future) | Standard | 6 months from release | TBD |
| v2.0.x (future) | TBD | TBD | TBD |

### Backport policy

The LTS branch receives:

- **Security fixes**: backported for all Critical, High, and Medium findings.
  Low findings are backported at maintainer discretion.
- **Critical bug fixes**: crashes, data corruption, wrong DNS answers under
  production load.
- **No new features**: feature additions target the main branch only.

Backport procedure:

1. Fix on `main` (PR + Tier 1/2/3 CI green).
2. Cherry-pick to `v1.0` branch.
3. Bump patch version (v1.0.x).
4. Tag, Tier 4 release pipeline, publish artefacts.

### Maintenance branch workflow

```
main       ──●──●──●── (v1.1.0) ──●──●──
              \
v1.0          ●── (v1.0.0) ──●── (v1.0.1) ── … ── (EOL 2027-04-27)
```

The `v1.0` branch is **protected**: direct pushes are forbidden; all changes
via PR with Tier 1/2 CI required.

### Downstream migration guidance

The Heimdall release notes for v1.0.x will include a notice 3 months before
EOL (i.e. by 2027-01-27) advising operators to upgrade to the then-current
stable version and providing a migration guide.

### Version numbers for LTS patches

Patch releases on the LTS branch follow `v1.0.x` (patch increment only).
Security-only patches are tagged with the release notes field
`[security]` to distinguish them from functional-change patches.

---

## Alternatives Considered

### 6-month LTS window

Too short for operators running Heimdall in environments with quarterly change
windows or slow upgrade cycles.  12 months was chosen to align with a typical
enterprise security-patch cycle.

### Rolling release (no LTS)

Requires operators to always run the latest version, which is impractical in
regulated environments.  Rejected.

### Two LTS branches simultaneously

Increases maintenance burden significantly.  Deferred until adoption warrants
it; can be revisited at v2.0.

---

## Consequences

- The `v1.0` branch must be created at the v1.0.0 GA commit and protected.
- Maintainers must monitor for security reports against v1.0.x throughout the
  support window.
- A calendar reminder must be set for 2027-01-27 (3 months before EOL) to
  publish migration guidance.
- Future ADRs for v1.1 and beyond must specify their own support windows.
