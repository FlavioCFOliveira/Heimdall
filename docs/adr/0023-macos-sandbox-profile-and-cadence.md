---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# macOS sandbox profile (`sandbox-exec`) — single profile, annual + library-triggered review cadence

## Context and Problem Statement

[`THREAT-030`](../../specification/007-threat-model.md) requires the project to provide a reference macOS sandbox profile (App Sandbox or `sandbox-exec`). [`THREAT-031`](../../specification/007-threat-model.md) requires that the profile be shipped under version control alongside the binary. The concrete profile content and the review cadence were tracked as an open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md). [`ENV-009`](../../specification/009-target-environment.md) fixes macOS as a development-only target, which sets the SHOULD-quality bar for the deliverable.

## Decision Drivers

- **Mandatory deliverable** ([`THREAT-031`](../../specification/007-threat-model.md)). The profile must ship with the project.
- **Development-only target** ([`ENV-009`](../../specification/009-target-environment.md)). SHOULD-quality is appropriate; production deployments use Linux or BSD.
- **`sandbox-exec` deprecation status**. Apple has soft-deprecated `sandbox-exec` but the mechanism continues to function. App Sandbox + Hardened Runtime require an application bundle that is inadequate for a daemon. No production-ready alternative has been announced.
- **Drift detection**. macOS evolves yearly; library upgrades may introduce new system-access patterns. The profile must be reviewed accordingly.

## Considered Options

- **Single sandbox-exec profile + annual + library-triggered review + CI parse + nightly run (chosen).** Single `.sb` file under `contrib/macos/`; annual review at macOS major releases; library-triggered review on Heimdall dependency upgrades; Tier 1 CI parse + Tier 3 nightly run on macOS runner.
- **Per-role profile variants.** macOS lacks the systemd-style drop-in pattern; per-role variants would multiply artefacts on a development-only target without operational benefit.
- **App Sandbox via Hardened Runtime.** Requires application-bundle packaging; inadequate for daemon.
- **Skip macOS sandbox profile entirely.** Contradicts [`THREAT-030`](../../specification/007-threat-model.md) (SHOULD).

## Decision Outcome

**A. Profile delivery.** Single `.sb` file at `contrib/macos/heimdall.sb` per [`THREAT-104`](../../specification/007-threat-model.md). Companion `contrib/macos/README.md` documents invocation, compatibility envelope, deprecation status.

**B. Profile content.** `(deny default)` posture; explicit `(allow ...)` rules for configuration / zone / trust-anchor / runtime paths and ports 53/853/443; no `process-exec`, no `mach-task` to other processes, no ptrace-equivalent.

**C. Single-profile, no per-role variants** ([`THREAT-105`](../../specification/007-threat-model.md)). Operators MAY narrow the profile locally for role-specific deployments.

**D. Review cadence** ([`THREAT-106`](../../specification/007-threat-model.md)):
- **Annual**: at every macOS major release, against new sandbox primitives, deprecated rules, new enforcement behaviour.
- **Library-triggered**: on every Heimdall dependency upgrade introducing new system-access patterns.

**E. CI conformance** ([`THREAT-107`](../../specification/007-threat-model.md)): Tier 1 parse with `sandbox-exec -p` (parse failure fails the gate); Tier 3 nightly run on macOS runner with synthetic workload (sandbox violations during legitimate operation fail the run).

**F. Review-outcome record** in governance document. The governance document is not yet established (scheduled for sprint 11); the [`THREAT-107`](../../specification/007-threat-model.md) requirement defers the record location to that document once established.

### Rejection rationale

The **per-role variants** option was rejected because macOS lacks a drop-in pattern equivalent to systemd; per-role variants on macOS would mean per-role profile files with substantial duplication, on a development-only target where the benefit is small.

The **App Sandbox via Hardened Runtime** option was rejected on packaging grounds. Hardened Runtime requires a macOS application bundle (`.app` directory structure with `Info.plist`, code-signed with a Developer ID, etc.); a long-running daemon is structurally unsuited to that packaging model. App Sandbox is fundamentally an iOS/Mac-App-Store mechanism that does not fit a server-side daemon.

The **skip-the-profile** option was rejected outright because [`THREAT-030`](../../specification/007-threat-model.md) is SHOULD; even on a development-only target, the SHOULD-quality deliverable is part of the threat-model coverage commitment.

## Consequences

### Operator usage

```sh
sandbox-exec -f contrib/macos/heimdall.sb \
    /usr/local/bin/heimdall \
    --config /usr/local/etc/heimdall/heimdall.toml
```

The profile produces deprecation warnings on recent macOS majors. The project tracks the deprecation status under [`THREAT-106`](../../specification/007-threat-model.md) and will respond at the annual review if Apple removes the mechanism.

### Closure

The "Concrete macOS sandbox profile and review cadence" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). With this closure and the closures of sprint 3 tasks #23, #24, #25, and #26, the operational-hardening profile open questions in §5 are fully resolved.

### Non-consequences (deliberate scope limits)

- **App Sandbox / Hardened Runtime migration.** Out of scope; conditional on Apple's deprecation timeline and on a daemon-suitable replacement.
- **Per-role profile variants.** Out of scope for the current release; a future revision MAY revisit if measurement identifies the operational value.
- **Production use on macOS.** Out of scope per [`ENV-009`](../../specification/009-target-environment.md); the profile is for development and integration testing.
- **GOVERNANCE.md entry.** The governance document is scheduled for sprint 11; the review-outcome record will land there at that time.

### Numbering

This ADR takes the sequence number `0023`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1–3 thus far have occupied `0002`–`0023`. Sprint 3 is now complete on the operational-hardening-profile track.
