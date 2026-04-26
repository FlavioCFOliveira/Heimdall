# Branch protection configuration

This document specifies the required protected-branch configuration for `main` on GitHub,
implementing ENG-155 through ENG-160, ENG-212, and ENG-213 from
[`specification/010-engineering-policies.md`](../specification/010-engineering-policies.md).

The settings listed here are **normative requirements**, not suggestions. They must be
configured on the repository host so that enforcement is structural rather than social.

## Required GitHub settings (`main` branch)

### General protection settings

| Setting                              | Required value | Spec |
|--------------------------------------|----------------|------|
| Require a pull request before merging | Enabled       | ENG-158 |
| Require approvals                    | Enabled        | ENG-157 |
| Required number of approvals — source code changes | 2 | ENG-077 |
| Required number of approvals — docs/spec only PRs  | 1 | ENG-078 |
| Dismiss stale pull request approvals when new commits are pushed | Enabled | ENG-157 |
| Require review from Code Owners      | Enabled        | ENG-080, ENG-087 |
| Require status checks to pass before merging | Enabled | ENG-156 |
| Require branches to be up to date before merging | Enabled | ENG-156 |
| Require linear history               | Enabled        | ENG-160 |
| Allow force pushes                   | Disabled       | ENG-159 |
| Allow deletions                      | Disabled       | ENG-159 |
| Do not allow bypassing the above settings | Enabled (applies to admins) | ENG-158 |

### Required status checks (ENG-156, ENG-212)

All Tier 1 checks (ENG-046..053) and all Tier 2 checks (ENG-054..057) must be listed
as required status checks. The job names below correspond to those defined in
`.github/workflows/ci-tier1.yml` and `.github/workflows/ci-tier2.yml`.

**Tier 1 — CI Tier 1 workflow:**

| Status check name       | Implements |
|-------------------------|------------|
| `build (ubuntu-latest)` | ENG-046    |
| `build (macos-latest)`  | ENG-046    |
| `test`                  | ENG-047    |
| `fmt`                   | ENG-048    |
| `clippy`                | ENG-049    |
| `deny`                  | ENG-050, ENG-051 |
| `audit`                 | ENG-052    |
| `vet`                   | ENG-052    |
| `doc`                   | ENG-053    |
| `commit-lint`           | ENG-053 (ENG-141) |

**Tier 2 — CI Tier 2 workflow:**

| Status check name    | Implements |
|----------------------|------------|
| `proptest smoke`     | ENG-054    |
| `fuzz smoke`         | ENG-055    |
| `loom`               | ENG-056    |
| `bench regression`   | ENG-057    |

### Merge queue (ENG-213)

| Setting                                       | Required value |
|-----------------------------------------------|----------------|
| Enable merge queue for `main`                 | Enabled        |
| Maximum concurrent speculative merges         | 4              |
| Required status checks on speculative commits | All Tier 1 + Tier 2 checks listed above |
| Block merge-queue entry when CODEOWNERS approval pending | Enforced via "Require review from Code Owners" |

## Applying the configuration

GitHub does not provide a declarative branch-protection file format in the repository
itself; the settings must be applied through the repository's **Settings → Branches** UI
or via the GitHub API / `gh` CLI. The authoritative configuration is the one active on
the hosting platform, not the documentation in this file — this file records the
normative intent so that the configuration can be audited and restored.

To inspect the current configuration via the CLI:

```
gh api repos/FlavioCFOliveira/Heimdall/branches/main/protection
```

To apply these settings programmatically, use the GitHub Branch Protection API endpoint:
`PUT /repos/{owner}/{repo}/branches/{branch}/protection`.
