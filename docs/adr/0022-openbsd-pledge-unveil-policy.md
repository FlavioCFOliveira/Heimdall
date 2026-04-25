---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# OpenBSD `pledge(2)` and `unveil(2)` policy — staged narrowing per role combination

## Context and Problem Statement

[`THREAT-029`](../../specification/007-threat-model.md) requires Heimdall on OpenBSD to apply [`pledge(2)`](https://man.openbsd.org/pledge.2) to restrict the system-call surface and [`unveil(2)`](https://man.openbsd.org/unveil.2) to restrict filesystem visibility. The concrete promise set and unveil paths per role combination were tracked as an open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md). [`THREAT-031`](../../specification/007-threat-model.md) requires the project to ship a reference rc.d script under version control. The present decision fixes the lifecycle stages, the per-role pledge promise set, the unveil path map, the rc.d delivery, and the CI conformance test.

## Decision Drivers

- **OpenBSD-native idiom**. OpenBSD applications conventionally narrow pledge in stages, dropping promises as the process leaves boot and enters steady state (cf. OpenBSD `nginx`, `smtpd`, `httpd`).
- **Minimum-attack-surface per role**. The pledge promise set should differ between role combinations only where the role-specific functionality requires it; in Heimdall's case, the only such requirement is the recursive role's RFC 5011 trust-anchor rollover, which needs `wpath cpath`.
- **Reload boundary limitation**. `unveil` is one-way; once locked with `unveil(NULL, NULL)`, the unveiled set cannot be extended. Operators must restart the process to add new paths.
- **Cross-platform parallelism**. The OpenBSD policy mirrors the seccomp-bpf policy of [`THREAT-088`](../../specification/007-threat-model.md) through [`THREAT-094`](../../specification/007-threat-model.md) and the systemd reference unit of [`THREAT-096`](../../specification/007-threat-model.md) through [`THREAT-099`](../../specification/007-threat-model.md), with platform-specific mechanisms.

## Considered Options

- **Lifecycle-staged pledge + per-role unveil + rc.d delivery + CI VM test (chosen).** Three pledge stages (boot / pre-bind / steady-state); two steady-state promise sets distinguished by recursive-role activation; per-role unveil paths.
- **Single uniform pledge set across roles.** Simpler but violates minimum-attack-surface (auth-only and forwarder-only deployments do not need `wpath cpath`).
- **Pledge only, no unveil.** Leaves the filesystem fully visible; contradicts `THREAT-029`.
- **Defer OpenBSD support to a future release.** Contradicts `THREAT-029` (mandatory).

## Decision Outcome

**A. Lifecycle stages**, per [`THREAT-100`](../../specification/007-threat-model.md). Three stages: boot (`stdio rpath wpath cpath inet unix proc id`); pre-bind (`stdio rpath wpath cpath inet unix`); steady state (per [`THREAT-101`](../../specification/007-threat-model.md)).

**B. Steady-state promise sets**, per [`THREAT-101`](../../specification/007-threat-model.md):
- Authoritative-only / forwarder-only / authoritative+forwarder: `stdio inet unix rpath`.
- Any combination including recursive: `stdio inet unix rpath wpath cpath` (RFC 5011 trust-anchor rollover).

**C. Unveil path map**, per [`THREAT-102`](../../specification/007-threat-model.md):
- `/etc/heimdall/`: `r`, all roles.
- `/etc/heimdall/tls/`: `r`, when DoT/DoH/DoQ enabled.
- `/etc/ssl/cert.pem`: `r`, on the forwarder role (system trust bundle fallback for `SEC-047`).
- `/var/heimdall/zones/`: `r`, on the authoritative role.
- `/var/heimdall/trust-anchors.xml`: `rwc` on the recursive role only; `r` elsewhere.
- `/var/run/heimdall/`: `rwc`, all roles.
- Locked with `unveil(NULL, NULL)` after the last call.

**D. Reload boundary**, per [`THREAT-103`](../../specification/007-threat-model.md). `SIGHUP` reloads configuration but does not extend unveil; operators must restart to add new paths.

**E. Reference rc.d script**, per [`THREAT-103`](../../specification/007-threat-model.md). Delivered at `contrib/openbsd/heimdall.rc`. Pledge and unveil are self-applied by the Heimdall binary; rc.d ensures the `_heimdall` user, the runtime directory, and the standard rc framework integration.

**F. CI conformance**, per [`THREAT-103`](../../specification/007-threat-model.md). Tier 3 nightly VM-based test against OpenBSD `current` and OpenBSD stable; all four role combinations exercised; intentional access outside the unveiled set MUST cause SIGABRT.

### Promises explicitly excluded from every stage

- `dns`: Heimdall does not use the OpenBSD system DNS resolver; uses raw `inet` sockets directly.
- `exec`: Heimdall is single-process post-boot; no spawning child processes.
- `prot_exec`: W^X enforcement under [`THREAT-027`](../../specification/007-threat-model.md).
- `id` (post-drop): privilege re-acquisition prevented.
- `proc` (post-boot): no fork/wait once steady state is reached.
- `tty`, `audio`, `pf`, `chown`: outside Heimdall's interaction surface.

### Rejection rationale

The **single uniform promise set** option was rejected because it would force `wpath cpath` onto authoritative-only and forwarder-only deployments that do not need them. The marginal complexity of two promise sets (with vs without recursive) is small; the security benefit of denying `wpath cpath` to non-recursive deployments is concrete (any post-exploitation primitive that wants to write to the filesystem is denied at the kernel layer).

The **pledge-only, no-unveil** option was rejected because it leaves the filesystem visibility unrestricted. `unveil` is the OpenBSD-native counterpart of the systemd `ProtectSystem=strict` directive plus the seccomp path-restricted file I/O of [`THREAT-089`](../../specification/007-threat-model.md); omitting it would leave Heimdall on OpenBSD substantially less hardened than on Linux.

The **deferral** option was rejected because [`THREAT-029`](../../specification/007-threat-model.md) is mandatory.

## Consequences

### Process lifecycle on OpenBSD

```
[boot, root]                                                     pledge: stdio rpath wpath cpath inet unix proc id
        |
        | configuration loaded; sockets bound on privileged ports
        |
        v
[unprivileged user setuid()]                                     pledge: (still wide; pre-bind narrowing applied)
        |
        v
[unveil() called; unveil(NULL, NULL) locks the set]
        |
        v
[steady state]                                                   pledge: per THREAT-101
                                                                  unveil: per THREAT-102 (locked)
        |
        | SIGHUP arrives → configuration reload within unveiled set
        |
        v
[continued steady state]                                         (no pledge change; no unveil extension)
```

### Reload boundary documentation

Operators MUST be informed in the operator manual that adding a new TLS certificate directory, a new zone-files location, or a new trust-anchor path on a running Heimdall instance requires a process restart (not a SIGHUP reload). The standard configuration directories (`/etc/heimdall/`, `/etc/heimdall/tls/`, `/var/heimdall/zones/`, `/var/heimdall/trust-anchors.xml`, `/var/run/heimdall/`) cover the dominant operational case; operators with non-standard layouts must restart Heimdall when adding new paths.

### CI conformance test outline

Tier 3 nightly VM-based test:

1. Boot OpenBSD VM (current and stable, separate runs).
2. Install Heimdall binary + rc.d script.
3. Configure for authoritative-only, recursive-only, forwarder-only, and full-hybrid (all four combinations).
4. Start Heimdall; verify steady-state pledge applied via `kdump(1)` trace.
5. Issue an intentional access outside the unveiled set (a syscall in the test harness that opens `/etc/passwd`).
6. Assert process termination by SIGABRT (the OpenBSD-native equivalent of the seccomp `SECCOMP_RET_KILL_PROCESS` action of [`THREAT-094`](../../specification/007-threat-model.md)).

### Closure

The "Concrete OpenBSD `pledge` promises and `unveil` paths" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). The remaining open question in the operational-hardening profile (macOS sandbox profile + cadence) remains for sprint 3 task #27.

### Numbering

This ADR takes the sequence number `0022`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1–3 thus far have occupied `0002`–`0022`.
