# ADR-0068: `riscv64` release-artefact tier — Intermediate (non-blocking)

Status: accepted (2026-05-12, Sprint 70 task #695).

Amends `ENV-047` (`specification/009-target-environment.md` §2.13) and
introduces `ENV-071` / `ENV-072` to the same document.

## Context

`ENV-047` (since v1.1.0) requires that the release pipeline produce
native artefacts for three production architectures: `x86_64`,
`aarch64`, and `riscv64`. The five release workflows
(`release.yml`, `release-targz.yml`, `release-deb.yml`,
`release-rpm.yml`, `release-container.yml`) all enumerate `riscv64`
as a matrix entry with `experimental: true` and
`continue-on-error: ${{ matrix.experimental == true }}`. The result
is that a `riscv64` build failure does not block the release; the
`release-container.yml` manifest-coverage check additionally emits a
`::warning::` rather than failing when `linux/riscv64` is absent
(`ENV-021` dated-exception path).

This pragmatic-but-undocumented state cannot remain indefinite.
Either the self-hosted `riscv64` runner has been demonstrably stable
across recent releases and the `continue-on-error` clauses can be
removed (path (a)), or the spec must formally recognise that
`riscv64` is an Intermediate-tier architecture with explicit criteria
for promotion to first-class (path (b)).

The self-hosted `riscv64` runner pool is a single dedicated host of
modest availability; the GitHub-hosted runner ecosystem does not yet
offer `riscv64` runners; rustup `riscv64gc-unknown-linux-musl` is not
yet stable (`ENV-022`). These constraints make path (a) impractical
in the current cycle: a transient outage of the single self-hosted
host would block every release.

Path (b) was therefore selected. Selection was recorded under
Sprint 70 task #695.

## Decision

`riscv64` is recognised as an **Intermediate-tier** architecture in
the Heimdall release-artefact tier hierarchy. Build attempts on
`riscv64` remain mandatory in every release pipeline, but a failure
on `riscv64` alone MUST NOT block the release (the existing
`continue-on-error` and `experimental: true` matrix configuration is
preserved). The spec is amended to introduce the tier hierarchy
explicitly and to define the criteria for future promotion to Tier-1
(blocking).

This is a deliberate trade-off between architecture coverage and
release reliability. `x86_64` and `aarch64` remain Tier-1 (blocking)
because GitHub-hosted runners and the Ampere / Graviton self-hosted
pool, respectively, are robust enough to gate a release on. `riscv64`
is not yet in that position.

## Promotion criteria

Promotion of `riscv64` (or any other Intermediate-tier architecture)
to Tier-1 is governed by `ENV-072`. All of the following must hold:

- (a) The dedicated self-hosted runner has been online and reachable
  for at least 95 % of the immediately prior 30 days.
- (b) The last five releases (across alpha / beta / rc / patch) have
  produced green artefacts on the Intermediate-tier architecture with
  zero unscheduled red status.
- (c) A signed ADR documents the promotion decision, the historical
  record, and the operational fall-back if the runner subsequently
  becomes unavailable.
- (d) The `continue-on-error` clauses governing the architecture's
  matrix entries are removed across every release workflow and the
  architecture is removed from any `experimental: true` matrix branch.
- (e) `ENV-071` is amended in the same commit that lands the workflow
  change, moving the architecture from Intermediate to Tier-1, with
  the commit message and the spec change both citing the promotion
  ADR.

## Consequences

**Positive.**

- Public posture (README, specification, release notes) now matches
  the actual behaviour of the release pipeline.
- A clear, falsifiable bar for promotion is in place.
- Operators reading the README know in advance that the
  `linux/riscv64` artefact is best-effort, not a release blocker, and
  can plan their architecture coverage accordingly.

**Negative.**

- A persistent outage of the self-hosted `riscv64` runner can silently
  reduce the architecture coverage of a release. Mitigation: a
  release-readiness audit at the end of each minor cycle reviews the
  green / red history per `ENV-072(b)`.
- The Intermediate tier creates a permanent risk that an architecture
  remains Intermediate indefinitely. Mitigation: the `ENV-072`
  promotion criteria are checked at every minor release as part of
  the close-out audit.

## Alternatives considered

- **Path (a) — promote `riscv64` to blocking now.** Rejected because
  the self-hosted runner pool is a single host, GitHub-hosted
  `riscv64` runners are not yet available, and a transient outage
  would block every release.
- **Remove `riscv64` from the official architecture set entirely.**
  Rejected because the project's positioning
  (`specification/009-target-environment.md` §2.5) treats `riscv64`
  as a first-class long-term target; downgrading the architecture
  would be a significant scope reduction.
- **Cross-compile `riscv64` artefacts on `x86_64`.** Rejected as
  forbidden by `ENV-047` / `ENV-048` (cross-compilation MUST NOT be
  used for official release artefacts).

## Affected files

- `specification/009-target-environment.md` (§2.13: `ENV-047`
  amendment; new `ENV-071`, `ENV-072`).
- `README.md` ("Production architectures" row of the Status and
  maturity table; clarifies Intermediate tier).
- `.github/workflows/release.yml`,
  `.github/workflows/release-targz.yml`,
  `.github/workflows/release-deb.yml`,
  `.github/workflows/release-rpm.yml`,
  `.github/workflows/release-container.yml` (inline comments
  referencing this ADR and `ENV-071` adjacent to every
  `continue-on-error` and `experimental: true` line targeting
  `riscv64`).
