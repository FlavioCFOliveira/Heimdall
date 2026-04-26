---
title: "ADR-0043: deadpool + deadpool-redis for connection pooling"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0043: deadpool + deadpool-redis for connection pooling

## Context

`STORE-014` requires a connection pool shared across all data domains. `STORE-047`
specifies default pool parameters: min 5, max 64, acquisition timeout 100 ms, max idle
10 min. Task #234 lists "bb8 (or deadpool)" as candidate pooling libraries.

A pool is needed for the **standalone** and **Sentinel** topologies. The Redis Cluster
topology (`STORE-040`) uses `redis::cluster_async::ClusterClient`, which manages its own
connection multiplexing internally and does not use an external pool.

## Decision

Use **`deadpool` v0.12** (feature `managed`) and **`deadpool-redis` v0.18** as the
connection pool for standalone and Sentinel topologies.

`deadpool-redis 0.18` is the first version that aligns with `redis 0.27` (`^0.27`
dependency). `deadpool-redis 0.16` (the version referenced in task #234) depends on
`redis ^0.26` and is incompatible with the `redis 0.27` dependency required by
`STORE-041` (which mandates the `redis-rs` crate's sentinel API). Version 0.18 was
the correct pairing.

Both are added as `[dependencies]` in `crates/heimdall-runtime`.

## Considered options

### Option A — `deadpool` + `deadpool-redis` (selected)

`deadpool` is a generic async object pool; `deadpool-redis` provides a purpose-built
`Manager` and `Pool` that wraps `redis-rs` connections with automatic health-checking
(`PING` on recycle) and configurable acquisition timeouts.

- Pros: purpose-built for redis-rs integration (same community); native tokio async
  integration; clean `Pool::get()` API returning `PooledConnection` with RAII release;
  configurable min/max/idle/timeout matching `STORE-047` defaults exactly; zero `unsafe`
  in `deadpool` itself; MIT OR Apache-2.0 licence; `deadpool-redis` reuses the existing
  `redis` (ADR-0042) transitive dep — no new supply-chain surface beyond `deadpool` core.
- Cons: adds one additional crate (`deadpool`) beyond `redis`; `deadpool-redis` is a thin
  wrapper, meaning bugs in `redis-rs` surface unchanged.

### Option B — `bb8` + `bb8-redis` (rejected)

`bb8` is a general-purpose async connection pool inspired by r2d2.

- Rejected because: `bb8` is generic and requires a `ManageConnection` implementation;
  `bb8-redis` provides this but offers no inherent advantage over `deadpool-redis` for
  this use case; `deadpool-redis` has a simpler API and more Redis-specific recycling
  semantics (PING-on-recycle); task #234 lists both as equivalent options and
  `deadpool-redis` was chosen on API clarity grounds.

### Option C — Manual connection pool (rejected)

Implementing a bespoke async pool using `tokio::sync::Semaphore` + `VecDeque`.

- Rejected because: reimplementation effort; no recycling / health-checking without
  reproducing what `deadpool-redis` already provides; new code = new surface for bugs;
  the backoff reconnection in `backoff.rs` handles reconnection, but pool lifecycle is
  separate and better handled by a maintained library.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io names           | `deadpool`, `deadpool-redis` |
| Versions adopted          | `deadpool` 0.12.x; `deadpool-redis` 0.18.x |
| Licence                   | MIT OR Apache-2.0 |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Zero in `deadpool` itself; `deadpool-redis` inherits the `redis` crate's unsafe (documented in ADR-0042). Heimdall's own code introduces no `unsafe`. |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by Michael P. Jung and contributors |
| Transitive dependencies   | `deadpool-runtime` (internal), plus the already-audited `redis` transitive tree |
| Author identity           | Michael P. Jung; well-established in the Rust async ecosystem |
| Registry ownership        | Published on crates.io under `deadpool` and `deadpool-redis` |

## Classification

**Core-critical** (runtime dependency). The connection pool mediates all Redis I/O for
standalone and Sentinel topologies. Removal would require replacing pool management.

## Unsafe code posture

Zero `unsafe` in `deadpool` itself. `deadpool-redis` delegates connections to `redis-rs`,
whose `unsafe` is documented in ADR-0042. No new `unsafe` is introduced in Heimdall's
code.

## Consequences

- `deadpool = { version = "0.12", features = ["managed"] }` and
  `deadpool-redis = { version = "0.18", features = ["rt_tokio_1", "sentinel", "cluster", "serde"] }`
  are added under `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.
- `StorePool` (standalone/sentinel) uses `deadpool_redis::Pool` with the following
  defaults matching `STORE-047`: max size 64, `create_timeout` 100 ms, `recycle_timeout`
  100 ms, `wait_timeout` 100 ms.
- Minimum pool size (5 per `STORE-047`) is achieved by pre-warming connections at
  startup via `Pool::get()` calls during `RedisStore::connect()`.
- Redis Cluster topology bypasses this pool and uses `redis::cluster_async::ClusterClient`
  directly.
- Pool utilisation (in-use / max) is exposed as a gauge metric (task #241).

## Links

- Introduced with Sprint 18, task #234.
- Implements: ENG-008 (dependency ADR gate), STORE-014, STORE-015, STORE-047.
- Implemented in: `crates/heimdall-runtime/Cargo.toml` (`[dependencies]`),
  `crates/heimdall-runtime/src/store/client.rs`.
