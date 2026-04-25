---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Seccomp-bpf rejection action — `SECCOMP_RET_KILL_PROCESS`

## Context and Problem Statement

[`THREAT-024`](../../specification/007-threat-model.md), refined by [`THREAT-088`](../../specification/007-threat-model.md) through [`THREAT-093`](../../specification/007-threat-model.md) (recorded in [`0019-seccomp-bpf-allow-list-categories.md`](0019-seccomp-bpf-allow-list-categories.md)), fixes the seccomp-bpf allow-list categories and the source-tree filter implementation. The remaining open question — the action the kernel applies when a syscall outside the allow-list is attempted — was tracked in [`007-threat-model.md §5`](../../specification/007-threat-model.md). The Linux seccomp-bpf interface offers several actions (cf. [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)): `SECCOMP_RET_KILL_PROCESS`, `SECCOMP_RET_KILL_THREAD`, `SECCOMP_RET_ERRNO`, `SECCOMP_RET_TRAP`, `SECCOMP_RET_LOG`, `SECCOMP_RET_ALLOW`. The decision had to choose among these, weighing security posture against operational degradation.

## Decision Drivers

- **Fail-safe / fail-closed** (cf. [`../../CLAUDE.md`](../../CLAUDE.md)). A denied syscall is either an unanticipated code path (a defect to be investigated) or an attempted post-exploitation primitive (which must be terminated). Either way, continuing operation is contraindicated.
- **No silent recovery**. The rejection must be unambiguous to operators and to monitoring; a graceful return that the application can swallow would mask the underlying defect.
- **Worker-pool integrity**. Heimdall runs a Tokio multi-threaded worker pool; killing one thread leaves the pool in a partially-degraded state.
- **Composability with systemd**. The systemd unit file delivered under [`THREAT-031`](../../specification/007-threat-model.md) supervises the process and can restart it automatically; process-level termination integrates cleanly with this supervision.

## Considered Options

- **`SECCOMP_RET_KILL_PROCESS` (chosen).** Whole-process termination by SIGSYS. Fail-closed; systemd-restartable; unambiguous to operators.
- **`SECCOMP_RET_KILL_THREAD`.** Thread-level termination. Leaves the worker pool in a partially-degraded state; can lead to deadlocks or partial-state inconsistencies.
- **`SECCOMP_RET_ERRNO(EPERM)`.** Syscall returns `-EPERM`; application continues. Masks the violation; admits adversary probing of the syscall surface.
- **`SECCOMP_RET_TRAP`.** Raises SIGSYS to a userspace handler. Adds complexity in a security-critical path; end-effect equivalent to KILL_PROCESS after handler completes; the handler itself runs in restricted context (no syscalls that themselves would be denied).
- **`SECCOMP_RET_LOG`.** Log-only; no rejection. Reserved for Tier 3 drift-detection workload per [`THREAT-093`](../../specification/007-threat-model.md); not a production rejection action.

## Decision Outcome

`SECCOMP_RET_KILL_PROCESS`, per [`THREAT-094`](../../specification/007-threat-model.md). Observability through systemd journal + kernel audit subsystem + systemd `Restart=on-failure` + `OnFailure=` alerting, per [`THREAT-095`](../../specification/007-threat-model.md).

### Rejection rationale

`KILL_THREAD` was rejected on worker-pool integrity grounds. Heimdall's Tokio runtime relies on a coherent worker pool; losing one worker thread without losing the process leaves the runtime in an undefined state — pending tasks may deadlock waiting on the dead worker, shared synchronisation primitives may carry references the dead thread held, and the failure mode becomes a stuck process that systemd cannot easily detect or recover from. Process-level kill is unambiguous and recoverable; thread-level kill is the worst of both worlds.

`ERRNO(EPERM)` was rejected on masking grounds. A `-EPERM` return propagates through the application as if a routine permission denial had occurred; the application's error handling is unlikely to distinguish "operating system says no" from "seccomp filter says no". An adversary who has gained partial code execution could repeatedly probe the syscall surface looking for what is admitted, with each probe returning `-EPERM` rather than terminating the process. The security property the filter is designed to provide — "the post-exploitation surface is limited" — degrades to "the post-exploitation surface is limited but the adversary has unlimited probing time".

`TRAP` was rejected on complexity grounds. The userspace SIGSYS handler runs in a context where most syscalls are themselves disallowed (the very condition that triggered the trap); the handler must be carefully written to avoid issuing further forbidden syscalls during its diagnostic-emission attempts. End-effect after handler completion is process termination, identical to `KILL_PROCESS`, but with a more error-prone path to get there.

`LOG` was rejected as a production rejection action because it does not reject — it merely logs and continues. It is a valid mode for the Tier 3 drift-detection workload (where the goal is to detect new syscalls without killing the process), but using it in production would defeat the security property entirely.

## Consequences

### Termination signature

A SIGSYS termination produces:

- Process exit code `159` (= `128 + 31`, the conventional encoding for "killed by signal 31" / SIGSYS).
- Systemd journal entry: `process killed by signal SIGSYS (Bad system call)` with the relevant unit context.
- Kernel audit log entry (when `auditd` is configured): the offending syscall number, the offending architecture, the program counter, and the process credentials at time of violation.
- Automatic restart by systemd if the unit file specifies `Restart=on-failure` or `Restart=on-abnormal` (per [`THREAT-095`](../../specification/007-threat-model.md)).
- Optional alert via `OnFailure=` directive (per [`THREAT-095`](../../specification/007-threat-model.md)).

### No structured-event from the SIGSYS path

[`THREAT-080`](../../specification/007-threat-model.md)'s structured-event obligation does not apply on the SIGSYS path because the structured-event emission itself requires syscalls (`write` to a log file or socket) that the filter is in the process of denying. The post-mortem observability is delivered exclusively through the kernel-side mechanisms (journal, audit log) and through systemd's supervision (`OnFailure=`).

### Conformance test

A test scenario MUST exercise a syscall outside the allow-list (for example, `fork()`) and MUST observe that:

1. The Heimdall process terminates immediately with exit code 159.
2. The systemd journal records the SIGSYS termination.
3. (When auditd is enabled) the kernel audit log records the offending syscall.
4. (Under systemd supervision) the unit is restarted per `Restart=on-failure`.

The test MUST run in a controlled environment (test container or VM) because the syscall must be issued from a path that has bypassed Heimdall's normal restrictions; a debug build with a test harness is the typical mechanism.

### Closure

The "Seccomp-bpf rejection action" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). The remaining open questions in the operational-hardening profile (systemd directive values, OpenBSD `pledge` / `unveil`, macOS sandbox profile) remain for sprint 3 tasks #25 / #26 / #27.

### Numbering

This ADR takes the sequence number `0020`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1–3 thus far have occupied `0002`–`0020`.
