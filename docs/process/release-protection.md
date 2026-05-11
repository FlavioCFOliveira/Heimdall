# Release branch and tag protection

> Status: required configuration — operator action.
> Anchors: ENG-072, ENG-079..082; Sprint 64 task #666.

The Tier 4 release workflow (`.github/workflows/release.yml`) enforces a
**strict** gate: it queries the GitHub Actions API and fails closed if any
of the three CI tiers (`ci-tier1.yml`, `ci-tier2.yml`, `ci-tier3.yml`) did
not run **and conclude `success`** on the exact commit being tagged, with
every required job (see the `REQUIRED_TIER*_JOBS` env in `release.yml`) also
green. There is no advisory mode.

The in-workflow gate is necessary but not sufficient: it executes only after
the tag has been pushed. Branch-protection and tag-protection rules
prevent the tag from being pushed in the first place when the upstream tier
runs are missing or red.

## Required GitHub repository settings

The following must be configured on `github.com/<owner>/Heimdall`. They
require **admin** rights on the repository.

### 1. Branch protection on `main`

Apply via the GitHub UI (`Settings → Branches → Branch protection rules`) or
the REST API:

```sh
gh api -X PUT \
  /repos/<owner>/Heimdall/branches/main/protection \
  --input docs/process/branch-protection-main.json
```

Required checks (`required_status_checks.contexts`):

- `CI Tier 1 / build`
- `CI Tier 1 / test-linux`
- `CI Tier 1 / test-macos`
- `CI Tier 1 / fmt`
- `CI Tier 1 / clippy`
- `CI Tier 1 / deny`
- `CI Tier 1 / audit`
- `CI Tier 1 / vet`
- `CI Tier 1 / doc`
- `CI Tier 1 / docs-spec-sync`
- `CI Tier 1 / docs-freeze`
- `CI Tier 1 / commit-lint`
- `CI Tier 1 / smoke-binary`
- `CI Tier 2 / proptest-smoke`
- `CI Tier 2 / fuzz-smoke`
- `CI Tier 2 / loom`
- `CI Tier 2 / bench-regression`
- `Performance regression gate / criterion regression check`

Required pull-request reviews: **1** (`required_pull_request_reviews.required_approving_review_count = 1`).

`enforce_admins = true`: even repository admins must satisfy the required
checks before merging — a deliberate guard against an operator panicking
during incident response.

`required_linear_history = true`: prevents merge commits.

`allow_force_pushes = false`, `allow_deletions = false`.

### 2. Tag protection for release tags

Apply via `Settings → Tags → Protected tags` or the REST API:

```sh
gh api -X POST /repos/<owner>/Heimdall/tags/protection \
  -f pattern='v[0-9]+.[0-9]+.[0-9]+'
gh api -X POST /repos/<owner>/Heimdall/tags/protection \
  -f pattern='v[0-9]+.[0-9]+.[0-9]+-alpha.[0-9]+'
gh api -X POST /repos/<owner>/Heimdall/tags/protection \
  -f pattern='v[0-9]+.[0-9]+.[0-9]+-beta.[0-9]+'
gh api -X POST /repos/<owner>/Heimdall/tags/protection \
  -f pattern='v[0-9]+.[0-9]+.[0-9]+-rc.[0-9]+'
```

Tag protection forbids non-admins from creating, updating, or deleting
matching tags — release tags can only be cut by maintainers.

### 3. Tier 3 nightly run on the tagged commit

`ci-tier3.yml` runs on a `schedule` and on `workflow_dispatch`. The
release workflow will reject any Tier 3 run older than 7 days
(`TIER3_RUN_MAX_AGE_SECS`) so the release engineer must trigger a
`workflow_dispatch` run on the tagged commit if no fresh nightly exists:

```sh
gh workflow run ci-tier3.yml --ref <release-branch>
```

Wait for the run to finish green, then push the tag.

## Verification checklist

After applying the settings above, validate with:

```sh
# Branch protection
gh api repos/<owner>/Heimdall/branches/main/protection | jq -r '
  "checks: " + (.required_status_checks.contexts | length | tostring),
  "reviews: " + (.required_pull_request_reviews.required_approving_review_count | tostring),
  "enforce_admins: " + (.enforce_admins.enabled | tostring),
  "linear_history: " + (.required_linear_history.enabled | tostring)
'

# Tag protection
gh api repos/<owner>/Heimdall/tags/protection | jq -r '.[].pattern'
```

A test of the Tier 4 gate itself (without performing a real release) is
to push a tag onto a branch whose Tier 3 run is **deliberately stale or
red**: the `tier-gate` job in `release.yml` must fail with a clear
`::error::` message and the `build` jobs must not run.

## Why fail-closed

Heimdall's threat model treats a signed but ungated artefact as worse than
no artefact: downstream verification (cosign + SLSA) creates the impression
of a fully-vetted binary, but if the upstream gates were skipped the
signature merely attests to the build, not to its quality. The Tier 4 gate
collapses that gap by refusing to produce signatures unless every required
upstream job is success on the exact commit.
