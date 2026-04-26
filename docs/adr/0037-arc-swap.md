---
title: "ADR-0037: arc-swap for lock-free atomic Arc swapping"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0037: arc-swap for lock-free atomic Arc swapping

## Context

The hot-reload path (OPS-037) requires that a `RunningState` — the immutable snapshot of
all mutable server state (config, zones, caches, ACLs, RPZ) — can be atomically replaced
while the server is under load. Every query handler reads the current state on the hot
path; the replacement must be:

- **Lock-free on reads**: no mutex acquire on every DNS query.
- **Atomic on writes**: a reload replaces the entire state pointer in one operation; no
  reader can observe a partial transition.
- **Safe under concurrent readers**: readers that started processing a query before the
  swap must be able to complete their work against the old state; the old state must not be
  freed while any such reader is active.

A naive `Arc<RwLock<RunningState>>` satisfies atomicity and safety but requires acquiring
a read lock on every query. Under the target load (hundreds of thousands of QPS per core),
read-lock contention becomes measurable. A naive `Arc<Mutex<Arc<RunningState>>>` has the
same problem.

## Decision

Use **`arc-swap` v1.9.1** (`arc_swap::ArcSwap<T>`) for the `StateContainer` in
`heimdall-runtime`.

`arc-swap` provides an `ArcSwap<T>` type that stores an `Arc<T>` in an atomic pointer and
exposes `load()` (lock-free, returns a guard keeping the `Arc` alive) and `swap()` (atomic
pointer replacement). It uses a variant of epoch-based hazard-pointer reclamation to ensure
the old `Arc` is not dropped while any `load()` guard is live.

## Considered options

### Option A — `arc-swap` v1.9.1 (selected)

- Pros: designed exactly for this use case; lock-free `load()` on the read path; atomic
  `swap()` on the write path; maintains `Arc` lifetime correctness automatically; widely
  used (tokio, actix ecosystem); zero CVEs; zero RustSec advisories at time of adoption;
  MIT/Apache-2.0.
- Cons: non-trivial `unsafe` footprint within the crate (atomic pointer swap via
  `std::sync::atomic::AtomicPtr`); adds a direct dependency.

### Option B — `RwLock<Arc<T>>`

- Pros: no extra dependency; well-understood semantics.
- Cons: every `load()` on the query hot path acquires a read lock; under high QPS, lock
  contention degrades throughput non-linearly. Rejected.

### Option C — `Mutex<Arc<T>>`

- Pros: simpler than RwLock.
- Cons: exclusive lock on every read — worse than RwLock for read-heavy workloads. Rejected.

### Option D — `seqlock`

- Pros: wait-free reads.
- Cons: requires manual `unsafe`; no audited implementation for `Arc` payloads in the
  Rust ecosystem at this time; error-prone. Rejected.

### Option E — custom epoch-based reclamation

- Pros: could be tuned precisely for Heimdall's access pattern.
- Cons: significant implementation complexity; unaudited; duplicates what `arc-swap`
  already provides. Rejected.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `arc-swap` |
| Version adopted           | 1.9.1 |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Significant (atomic pointer swap via `AtomicPtr`; epoch-based guard tracking). Intentional and audited by Michal Vaner (author). |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by Michal Vaner; used across the Rust ecosystem |
| Transitive dependencies   | None (no transitive deps beyond `std`) |
| Author identity           | Michal Vaner; crate has a documented safety rationale in its source |

## Classification

**Core-critical** (runtime dependency). Every query handler acquires an `arc-swap` guard
on the hot path. Removing `arc-swap` would require reintroducing lock-based state access
on every DNS query.

## Unsafe code posture

`arc-swap`'s `unsafe` is internal to the crate: it uses `AtomicPtr` and carefully ordered
atomic operations to implement lock-free pointer swapping and hazard-pointer-style guard
tracking. This unsafe is intentional, documented by the author, and is the sole reason the
crate exists.

Heimdall's own code uses only the safe public API (`ArcSwap::load()`, `ArcSwap::swap()`,
`ArcSwap::new()`). No `unsafe` is introduced in Heimdall source as a result of this
dependency. The `#![deny(unsafe_code)]` attribute in `heimdall-runtime` remains
unconditionally satisfied.

## Consequences

- `arc-swap` is added under `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.
- `StateContainer` in `state.rs` wraps `ArcSwap<RunningState>` and exposes `load()` /
  `swap()` safe wrappers.
- `ConfigLoader` in `config.rs` uses `ArcSwap<Config>` to serve the current config
  lock-free to all callers.
- The `unsafe` footprint of `arc-swap` is excluded from Heimdall-internal counts and
  tracked in the SBOM delta report (ENG-071).

## Links

- Introduced with Sprint 17, task #230.
- Implements: OPS-037 (hot-reload without query interruption).
- Implemented in: `crates/heimdall-runtime/src/state.rs`, `crates/heimdall-runtime/src/config.rs`.
