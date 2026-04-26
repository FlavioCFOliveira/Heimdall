---
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
---

# ADR-0030: Adopt rustix as the system-call interface

## Context and Problem Statement

Heimdall requires direct system-call access for several purposes: `SO_REUSEPORT` socket configuration for parallel listeners; `io_uring` submission and completion queue access (Linux); privilege-drop operations (capability management, `setuid`/`setgid`); and platform-specific hardening interfaces (`seccomp_load` on Linux, `pledge`/`unveil` on OpenBSD). These operations are not exposed by the Rust standard library and require a syscall interface crate. The choice must be memory-safe, well-audited, and must cover all platform targets (Linux, BSD, macOS) defined in [`009-target-environment.md`](../../specification/009-target-environment.md).

This ADR grandfathers a decision already implicit in the specification per `ENG-013` and `ENG-123` in [`010-engineering-policies.md`](../../specification/010-engineering-policies.md).

## Decision Drivers

- Must support Linux, FreeBSD, OpenBSD, and macOS system-call surfaces.
- Must expose `SO_REUSEPORT`, raw socket options, and pipe2/eventfd for the transport layer.
- Must expose `io_uring` queue operations for the Linux io_uring backend (`ENV-037..039`).
- Must not require linking against glibc wrappers where direct syscall access is more appropriate.
- Must be memory-safe; no raw libc FFI written by Heimdall itself where rustix covers the same surface.

## Considered Options

- **rustix 0.38.x** — high-level, memory-safe syscall bindings using reference types and checked conversions.
- **nix** — similar high-level syscall bindings; older design, more boilerplate for file-descriptor management, overlapping functionality with rustix.
- **libc** — raw C bindings with no type safety guarantees; requires `unsafe` at every call site within Heimdall.
- **std::os::unix** — standard library extensions; covers a subset of the required surface (no `io_uring`, no seccomp, no pledge/unveil).
- **No explicit syscall crate: use inline asm or syscall(2) directly** — bypasses all safety infrastructure; rejected on safety grounds and per `ENG-017..025`.

## Decision Outcome

Chosen option: **rustix 0.38.x**, because:

- It provides the widest platform coverage (Linux, FreeBSD, macOS, and partial OpenBSD support) in a single, consistent API.
- It exposes socket options (`SO_REUSEPORT`, `IP_PKTINFO`, `IPPROTO_UDP`), pipe operations, and eventfd through safe Rust types.
- It is the dependency that `tokio`, `hyper`, and `quinn` themselves depend on transitively, meaning it is already present in the transitive dependency graph; adding it as a direct dependency is zero marginal supply-chain cost.
- Its design avoids libc wrappers for the system-call layer, reducing the risk of glibc-version pinning on musl targets.

**Classification:** core-critical. The platform hardening surface (`seccomp`, `pledge`, `unveil`) and the `io_uring` backend cannot be implemented without a syscall interface crate.

## Consequences

**Positive:**

- Safe Rust API for all required syscall surfaces; `unsafe` is entirely within rustix, not in Heimdall's own code.
- Already present in the transitive dependency tree (tokio depends on it); no new supply-chain surface introduced.
- Consistent API across Linux and BSD reduces conditional compilation complexity.

**Negative:**

- OpenBSD support in rustix is less mature than Linux support; `pledge`/`unveil` may require a thin inline `unsafe` wrapper within `heimdall-runtime` until rustix covers the full pledge promise set. Each such wrapper is a new `unsafe` pattern requiring an ADR per `ENG-021`.
- `io_uring` operations may require `rustix-uring` or a separate crate; this will be addressed when the io_uring backend is implemented.

## Audit Trail (per ENG-009 item 2)

- **cargo-vet:** Certifications from Bytecode Alliance; rustix is a dependency of the Wasmtime project (heavily audited).
- **CVE/RustSec history:** No CVEs as of 2026-04-26.
- **Maintenance:** Actively maintained by Dan Gohman and contributors; regular releases.
- **Transitive footprint:** linux-raw-sys (kernel constants), bitflags — minimal and well-audited.

## License

Apache-2.0 / MIT dual-licensed — permitted by `ENG-094`.

## Unsafe Footprint (per ENG-009 item 4)

rustix contains `unsafe` exclusively in the syscall invocation layer (`syscall!` macro wrappers) and in the `linux-raw-sys` integration. All unsafe is reviewed by the maintainers. Heimdall's own code is `unsafe`-free with respect to syscall calls when using rustix's safe API.

## Supply-Chain Trust (per ENG-009 item 5)

Published on crates.io. Maintained by a small but active team with multi-year track record. Identity continuity confirmed through crates.io ownership history.

## Cross-References

- `ENV-037..039` — io_uring primary backend / epoll fallback.
- `THREAT-022..026` — Privilege drop, filesystem isolation, W^X enforcement.
- `THREAT-024` — seccomp-bpf allow-list (Linux).
- `THREAT-029` — OpenBSD pledge + unveil.
- `THREAT-030` — macOS sandbox profile.
- `ENG-013`, `ENG-123` — Grandfather-ADR obligation.
