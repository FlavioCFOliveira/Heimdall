# Retrospective: Sprints 46–54 (Binary wiring → v1.1.0 GA)

**Date:** 2026-05-05
**Scope:** Sprints 46–54 (tasks #454–#571, #525–#530, #550–#551)

---

## What went well

- **Library crates were solid.** `heimdall-core`, `heimdall-runtime`, and
  `heimdall-roles` required no significant rework to wire up.  The careful
  specification work in Sprints 1–45 paid off.

- **Sprint 53 soak tests surfaced no regressions.** 30/30 tests green on
  first attempt after API-signature fixes.  The concurrent HMAC-chain bug
  (AuditLogger seq outside mutex) was caught in unit tests before reaching
  integration tests.

- **Cherry-pick backport to v1.0 LTS was conflict-free.** Because the LTS
  branch was branched at the exact commit where Sprint 46 started, all 22
  cherry-picks applied cleanly.

- **OpenMetrics compliance.** Adding `# EOF` and switching the content type
  to `application/openmetrics-text` was a one-line fix; catching it early
  (Sprint 52) prevented a future breaking change.

---

## What went wrong

### v1.0.0 shipped with `fn main() {}`

The v1.0.0 GA tag was pushed when the binary entry-point was still a
placeholder.  This was intentional in the original plan (validate the release
pipeline before wiring the binary), but was not communicated clearly.  External
observers reasonably expected v1.0.0 to be runnable.

**Root cause:** The release plan treated the binary wiring as a Sprint-46 task,
but the Sprint-45 release gate did not verify that the binary was functional.

**Resolution:** Sprint 54 task #571 bumped to v1.1.0 (first functional build).
v1.0.1 backports the wiring to the LTS branch.

### API signature mismatches in Sprint 53 soak tests

`soak_ddos.rs` was written with incorrect `RrlEngine::check` argument order
and `QueryRlConfig` field names.  Caught at compile time but required a
read-back from the implementation before fixing.

**Root cause:** The soak tests were written from memory of the planned API, not
from reading the actual implementation.

**Resolution:** Fixed before merge.  See the CI gate below.

---

## Action items

### CI gate added (Sprint 54)

A new Tier 1 CI step (`ci/smoke-binary.sh`) verifies that the `heimdall`
binary starts, responds to `--version`, and exits cleanly.  This gate
will prevent a repeat of the non-functional binary incident.

See `.github/workflows/ci-tier1.yml` — step `smoke-binary`.

### Sprint 55 tracking

- [ ] External security audit sign-off publication (ENG pending).
- [ ] SLSA provenance hash binding (ENG-080).
- [ ] `cargo install --check-config` (ENG backlog).
- [ ] crates.io actual publication verification post v1.1.0 tag.

---

## Milestones

- **v1.2.0 milestone:** open; targets the next feature sprint (Sprint 55+).
- **v1.0-LTS milestone:** open; tracks LTS patch releases under ADR-0059.
