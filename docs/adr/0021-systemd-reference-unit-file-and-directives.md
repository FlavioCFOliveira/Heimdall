---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Reference systemd unit file — directive values, path mapping, and per-role drop-ins

## Context and Problem Statement

[`THREAT-025`](../../specification/007-threat-model.md) fixes the mandatory hardening directives the reference systemd unit file MUST apply (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, etc.) and requires "an explicit minimal `ReadWritePaths=` and `ReadOnlyPaths=` appropriate to the role set". [`THREAT-031`](../../specification/007-threat-model.md) requires that the project ship the reference unit file alongside the binary. The remaining open question — the concrete directive values where latitude exists, in particular the per-role-combination `ReadWritePaths=` / `ReadOnlyPaths=` — was tracked in [`007-threat-model.md §5`](../../specification/007-threat-model.md). The present decision fixes the unit-file shape, the per-role drop-in pattern, the default path mapping, and the CI validation.

## Decision Drivers

- **Per-role surface reduction**. Different role combinations need different filesystem views; the unit file must accommodate them without duplicating the entire file per combination.
- **systemd drop-in convention**. The standard mechanism for service-unit overrides is the `*.service.d/*.conf` drop-in pattern; operators expect this convention.
- **Hardening drift detection**. CI must fail when a directive is removed or weakened.
- **Operator predictability**. Default paths must be obvious, distribution-conventional, and documented.

## Considered Options

- **Single base unit + per-role drop-ins (chosen).** `heimdall.service` for shared content; `heimdall.service.d/01-authoritative.conf`, `02-recursive.conf`, `03-forwarder.conf` for role-specific paths.
- **Per-role unit files.** `heimdall-authoritative.service`, etc. Multiplies artefacts; hybrid combinations require new files.
- **Single unit file with permissive paths.** Simplifies but contradicts minimum-attack-surface.
- **No reference unit; operator-fully-tunable.** Contradicts `THREAT-025` and `THREAT-031`.

## Decision Outcome

**A. Layout.** `contrib/systemd/heimdall.service` (base) + `contrib/systemd/heimdall.service.d/01-authoritative.conf` / `02-recursive.conf` / `03-forwarder.conf` (drop-ins), per [`THREAT-096`](../../specification/007-threat-model.md).

**B. Operationally-tuned directives** in the base unit, per [`THREAT-097`](../../specification/007-threat-model.md): `User=heimdall`, `Group=heimdall`, `RuntimeDirectory=heimdall` / `RuntimeDirectoryMode=0750`, `StateDirectory=heimdall` / `StateDirectoryMode=0750`, `Restart=on-failure`, `RestartSec=2`, `StartLimitBurst=5`, `StartLimitIntervalSec=30`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `LimitNOFILE=65536`, `LimitNPROC=512`, `OnFailure=` commented placeholder.

**C. Default path mapping**, per [`THREAT-098`](../../specification/007-threat-model.md): `/etc/heimdall/` RO, `/etc/heimdall/tls/` RO, `/var/lib/heimdall/zones/` RO (auth role only), `/run/heimdall/redis.sock` RW, `/run/heimdall/` RW, `/var/lib/heimdall/trust-anchors.xml` RW (recursive role only) / RO elsewhere.

**D. CI validation**, per [`THREAT-099`](../../specification/007-threat-model.md): Tier 1 runs `systemd-analyze verify` (no warnings) + `systemd-analyze security` (exposure score ≤ 1.5 = "highly hardened"). Drift detection by score regression.

### Rejection rationale

The **per-role unit files** option was rejected because hybrid combinations (authoritative + recursive + forwarder all on one instance) are common in enterprise DNS deployments; each combination would require its own unit file. The drop-in pattern stacks role-specific overlays cleanly onto the base unit.

The **single permissive unit** option was rejected because it would contradict the minimum-attack-surface principle that motivates [`THREAT-025`](../../specification/007-threat-model.md) in the first place. A single `ReadWritePaths=` covering all conceivable role combinations would expose write access to the auth-zone files even on a forwarder-only deployment.

The **no-reference-unit** option was rejected because [`THREAT-031`](../../specification/007-threat-model.md) requires the project to ship the reference unit file under version control.

## Consequences

### Operator usage

```bash
# Authoritative-only deployment:
$ sudo cp contrib/systemd/heimdall.service /etc/systemd/system/
$ sudo mkdir -p /etc/systemd/system/heimdall.service.d/
$ sudo cp contrib/systemd/heimdall.service.d/01-authoritative.conf /etc/systemd/system/heimdall.service.d/

# Hybrid (authoritative + recursive):
$ sudo cp contrib/systemd/heimdall.service /etc/systemd/system/
$ sudo mkdir -p /etc/systemd/system/heimdall.service.d/
$ sudo cp contrib/systemd/heimdall.service.d/01-authoritative.conf /etc/systemd/system/heimdall.service.d/
$ sudo cp contrib/systemd/heimdall.service.d/02-recursive.conf /etc/systemd/system/heimdall.service.d/

$ sudo systemctl daemon-reload
$ sudo systemctl enable --now heimdall
```

### Hardening posture verification

After installation, operators can verify the hardening posture with:

```bash
$ systemd-analyze security heimdall.service
```

The expected exposure score is ≤ 1.5 ("highly hardened"). A higher score after operator overrides indicates that one of the hardening directives has been weakened locally, and the operator's customisation should be reviewed.

### Closure

The "Concrete directive values in the reference systemd unit file" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). Remaining open questions in the operational-hardening profile (OpenBSD `pledge` / `unveil`, macOS sandbox profile + cadence) remain for sprint 3 tasks #26 / #27.

### Numbering

This ADR takes the sequence number `0021`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1–3 thus far have occupied `0002`–`0021`.
