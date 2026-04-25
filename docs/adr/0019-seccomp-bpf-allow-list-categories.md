---
status: accepted
date: 2026-04-25
deciders: [FlavioCFOliveira]
---

# Seccomp-bpf allow-list — categorisation, source-tree filter, and CI calibration

## Context and Problem Statement

[`THREAT-024`](../../specification/007-threat-model.md) requires Heimdall on Linux to install a seccomp-bpf filter that allow-lists only the syscalls it actually uses. The precise allow-list was deferred as an open question in [`007-threat-model.md §5`](../../specification/007-threat-model.md). The complete syscall surface of the Heimdall runtime is determined by the dependencies (Tokio, rustls, quinn, hyper, the Redis client, and the `io_uring` or `epoll` I/O backend) and by the per-architecture syscall numbering of Linux on `x86_64`, `aarch64`, and `riscv64`. Producing a definitive enumeration in the specification text would couple the spec to the implementation surface and subject it to drift on every library upgrade.

The decision had to settle four sub-questions:

1. **Granularity of the spec normative content** — exhaustive enumeration vs structural categorisation.
2. **Filter source location** — single source for all architectures or per-architecture.
3. **Per-role variants** — single filter for all role combinations or per-role surface reduction.
4. **CI validation strategy** — how to enforce that the filter does not deny syscalls that legitimate runtime operation issues.

The decisions had to compose with [`THREAT-022`](../../specification/007-threat-model.md) (privilege drop), [`THREAT-023`](../../specification/007-threat-model.md) (`CAP_NET_BIND_SERVICE` retention), [`THREAT-025`](../../specification/007-threat-model.md) (systemd reference unit file), [`THREAT-026`](../../specification/007-threat-model.md) (filesystem isolation), [`THREAT-027`](../../specification/007-threat-model.md) (W^X enforcement), [`ENV-001`](../../specification/009-target-environment.md) and [`ENV-002`](../../specification/009-target-environment.md) (Linux 6.1 minimum, `io_uring`/`epoll`), [`ENV-006`](../../specification/009-target-environment.md) through [`ENV-008`](../../specification/009-target-environment.md) (architectures), [`ENG-125`](../../specification/010-engineering-policies.md) (spec-vs-implementation discipline), and [`ENG-049`](../../specification/010-engineering-policies.md) through [`ENG-079`](../../specification/010-engineering-policies.md) (CI tiers).

## Decision Drivers

- **Spec-vs-implementation discipline** (cf. [`ENG-125`](../../specification/010-engineering-policies.md)). Specification fixes structural content; implementation fixes specific syscall numbers. A definitive list in the spec text would be at the wrong layer and would drift on every library upgrade.
- **Library-upgrade resilience**. Tokio, rustls, quinn, hyper, and the Redis client evolve. A library upgrade may introduce new syscalls; the filter must accommodate that without spec changes.
- **Per-architecture portability**. Syscall numbers differ across `x86_64`, `aarch64`, `riscv64`; the filter cannot be a single binary.
- **Drift detection**. New syscalls introduced silently by a dependency must surface in CI before they reach production, where they would be killed by the filter.
- **Implementation simplicity**. A single allow-list across role combinations is simpler than per-role variants, and the marginal attack-surface reduction of per-role variants is not justified at the current threat-model resolution.

## Considered Options

### A. Granularity of normative content

- **Spec-level structural categories + repo source filter + CI calibration (chosen).** Normative spec describes admitted and denied categories at a level abstract enough to be stable across library upgrades; the concrete syscalls live in the source tree.
- **Spec lists every admitted syscall by name.** Definitive but rigid; couples spec to library surface; drift on every upgrade.
- **No spec-level allow-list (filter is purely an implementation concern).** Misses the threat-model coverage obligation of `THREAT-024`; leaves the security property unverifiable from the spec.

### B. Filter source location

- **Per-architecture source files in `crates/heimdall-runtime/src/security/seccomp/` (chosen).** Three files (`linux_x86_64.rs`, `linux_aarch64.rs`, `linux_riscv64.rs`); each emits the BPF program at process start through `libseccomp` or equivalent.
- **Single source file.** Cannot represent per-architecture syscall numbers cleanly.
- **External configuration file.** Adds a parser surface for the filter language; couples runtime to filesystem configuration; harder to ship updated filters in lock-step with code changes.

### C. Per-role variants

- **Single allow-list across all role combinations (chosen).** Implementation simplicity; one filter to maintain, one CI matrix to exercise.
- **Per-role variants (auth-only, recursive-only, forwarder-only, hybrid).** Maximum surface reduction (auth-only never initiates outbound TLS, etc.). Multiplies the filter set and the CI matrix without measurement-driven justification.

### D. CI validation strategy

- **Three-tier CI gate (chosen).** Tier 1 syntactic; Tier 2 functional under active filter against synthetic workload covering every role × every transport; Tier 3 nightly with `SECCOMP_RET_LOG` for drift detection.
- **Tier 2 only.** Misses drift detection between releases.
- **No CI validation.** Filter ships untested; library upgrade can silently introduce a new syscall that kills production on first hot-path use.

## Decision Outcome

**A. Granularity.** Spec-level categorisation per [`THREAT-089`](../../specification/007-threat-model.md) (admitted) and [`THREAT-090`](../../specification/007-threat-model.md) (denied); concrete enumeration in the source tree per [`THREAT-088`](../../specification/007-threat-model.md).

**B. Source location.** Per-architecture under `crates/heimdall-runtime/src/security/seccomp/`, per [`THREAT-088`](../../specification/007-threat-model.md). Three files: `linux_x86_64.rs`, `linux_aarch64.rs`, `linux_riscv64.rs`.

**C. Variants.** Single allow-list across role combinations, per [`THREAT-091`](../../specification/007-threat-model.md). Per-role reduction deferred.

**D. Kernel handling.** Per-architecture filter aware of running kernel version; falls back from `io_uring` to `epoll` syscalls when kernel features absent, per [`THREAT-092`](../../specification/007-threat-model.md).

**E. CI validation.** Three tiers (syntactic, functional, drift-detection nightly with `SECCOMP_RET_LOG`), per [`THREAT-093`](../../specification/007-threat-model.md).

### Admitted categories (summary)

Network I/O · `io_uring` / `epoll` · path-restricted file I/O · memory management (W^X-respecting) · time / clock (read-only) · synchronisation · signals · threading (Tokio worker pool, `CLONE_THREAD` only) · process info (read-only) · privilege drop and capability management (boot-time only) · random · process lifecycle (terminal only).

### Denied categories (summary)

Process creation (`fork` / `vfork` / `clone(CLONE_FORK)` / `execve` / `execveat`) · kernel module operations · privileged kernel operations (`kexec_*`, `bpf` except `io_uring` subset, `unshare`, `setns`, `pivot_root`, `chroot` post-boot) · privileged network device manipulation (`AF_PACKET`, `AF_NETLINK` except `io_uring` subset, `iopl`, `ioperm`) · anti-debugging (`ptrace`, `process_vm_*`) · memory-execution toggling (`mprotect` to `PROT_EXEC`) · privilege re-acquisition (`setuid` / `setgid` / `setresuid` / `setresgid` / `capset` post-drop).

### Rejection rationale

The **exhaustive-enumeration-in-spec** option was rejected because it would couple the specification to the syscall surface of the chosen libraries. Every Tokio, rustls, quinn, hyper, or Redis-client upgrade could introduce or remove a syscall; the spec would have to be updated in lock-step or fall out of date. The chosen categorisation is stable across upgrades because library evolution typically stays within already-admitted categories.

The **no-spec-level-allow-list** option was rejected because [`THREAT-024`](../../specification/007-threat-model.md) is normative; the spec must offer enough structural content to make the security property verifiable.

The **single-file-source** option was rejected on portability grounds; per-architecture syscall numbering cannot be cleanly handled in a unified file. The **external-configuration-file** option was rejected on parser-surface grounds and on lock-step-with-code-changes grounds.

The **per-role-variants** option was rejected on implementation-simplicity grounds; the surface reduction is marginal under Rust's memory-safety story and is not justified at the current threat-model resolution. A future revision MAY reconsider if measurement identifies a high-value role-specific syscall to deny.

The **Tier-2-only CI** option was rejected because it would not detect a new syscall introduced silently by a library upgrade between Tier 2 runs and the next release. The chosen Tier 3 nightly with `SECCOMP_RET_LOG` provides the drift-detection signal that no other tier can supply.

## Consequences

### Source-tree layout

```
crates/heimdall-runtime/src/security/seccomp/
├── mod.rs                   # public install_filter() entry point
├── linux_x86_64.rs          # admitted syscall numbers + BPF program emission for x86_64
├── linux_aarch64.rs         # ditto for aarch64
├── linux_riscv64.rs         # ditto for riscv64
├── boot_filter.rs           # boot-time filter admitting privilege-drop syscalls
└── steady_state_filter.rs   # post-drop filter denying privilege-drop syscalls
```

### Two-stage filter installation

1. **Boot filter** (loaded before `bind()`): admits the privilege-drop and capability-management syscalls of [`THREAT-089`](../../specification/007-threat-model.md)'s privilege-drop category.
2. **Steady-state filter** (loaded after privilege drop completes): denies the same set, plus all of [`THREAT-090`](../../specification/007-threat-model.md). The post-drop transition uses `prctl(PR_SET_SECCOMP, ...)` to install the more-restrictive filter or appends a deny rule for those syscalls.

### Library-upgrade workflow

When a Tokio / rustls / quinn / hyper / Redis-client upgrade introduces a new syscall:

1. Tier 3 nightly run with `SECCOMP_RET_LOG` logs the new syscall.
2. CI alert raises a maintainer ticket.
3. Maintainer reviews: is the new syscall in an admitted category? If yes, add to the per-architecture source file. If no, the dependency upgrade is rejected or the dependency is replaced.
4. The corresponding spec change (if any) is applied in the same pull request, in line with [`ENG-125`](../../specification/010-engineering-policies.md).

### Closure

The "Seccomp-bpf allow-list" open question is removed from [`007-threat-model.md §5`](../../specification/007-threat-model.md). The "Seccomp-bpf rejection action" open question remains for sprint 3 task #24. The "concrete systemd directive values" open question remains for task #25, "OpenBSD `pledge` promises and `unveil` paths" for task #26, "macOS sandbox profile" for task #27.

### Non-consequences (deliberate scope limits)

- **Per-syscall argument filtering.** The chosen filter applies coarse syscall-number admission; per-argument filtering (e.g., `socket(AF_UNIX, ...)` admitted, `socket(AF_PACKET, ...)` denied) is admitted at category granularity only. Fine-grained argument filtering is implementation discretion within the categories.
- **eBPF LSM hooks.** The chosen mechanism is seccomp-bpf, not the eBPF Linux Security Module. Reconsidering at the LSM layer is out of scope for this decision.
- **Container runtime profiles.** Heimdall runs as a single Linux process; container-engine-level seccomp profiles (Docker / Podman / Kubernetes) are an orthogonal layer and are not specified here.
- **OpenBSD `pledge` mapping.** OpenBSD uses [`pledge(2)`](https://man.openbsd.org/pledge.2), not seccomp-bpf. The OpenBSD analogue is task #26's scope.
- **macOS sandbox.** macOS uses `sandbox-exec`, not seccomp-bpf. The macOS analogue is task #27's scope.

### Numbering

This ADR takes the sequence number `0019`, assigned monotonically under [`ENG-118`](../../specification/010-engineering-policies.md). Sprints 1 and 2 occupied `0002`–`0018`; the grandfather batch (sprint 11 work) will start at `0020` or later.
