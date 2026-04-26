---
title: "ADR-0042: redis (redis-rs) for Redis client"
status: accepted
date: 2026-04-26
deciders: [FlavioCFOliveira]
consulted: []
informed: []
---

# ADR-0042: redis (redis-rs) for Redis client

## Context

Sprint 18 implements `STORE-001..050` — the Redis persistence layer for Heimdall's three
data domains (authoritative zone data, query-response cache, and RPZ trigger store).

Three capabilities are required simultaneously:

1. **Async commands over Unix domain socket and TCP+TLS** — all Redis operations occur on
   the tokio runtime; blocking I/O on the async runtime is prohibited.
2. **Redis Cluster** (`STORE-040`) — hash-tag routing, MOVED/ASK redirection, and
   multi-master topology.
3. **Redis Sentinel** (`STORE-041`) — leader discovery and <1 s failover detection, using
   the Sentinel API explicitly named in `STORE-041` ("using the Sentinel API provided by
   the `redis-rs` crate").

The specification names `redis-rs` directly in `STORE-041`. This ADR records the
evaluation and formalises the adoption per `ENG-008`.

## Decision

Use **`redis` v0.27** (the `redis-rs` crate) as the sole Redis client library in the
Heimdall workspace.

Features enabled: `["aio", "tokio-comp", "cluster-async", "sentinel"]`.

`redis` is added as a `[dependencies]` entry in `crates/heimdall-runtime`.

## Considered options

### Option A — `redis` v0.27 (`redis-rs`) (selected)

The canonical Rust Redis client, maintained by the redis-rs community under the
`redis-rs` GitHub organisation. Provides async commands, pipelining, Pub/Sub, scripting,
cluster routing, and sentinel discovery in a single crate.

- Pros: explicitly named by `STORE-041`; single crate covers all three required topologies
  (standalone, cluster, sentinel); `aio` + `tokio-comp` features provide native tokio
  async commands; `cluster-async` provides MOVED/ASK redirection; `sentinel` provides the
  leader-discovery API; MIT licence; used in production by major Rust projects; 4000+
  reverse dependents on crates.io; active maintenance cadence.
- Cons: `unsafe` present in C-backed RESP parsing on performance paths (intentional;
  isolated to the crate's implementation); API surface is large, requiring careful feature
  selection.

### Option B — `fred` (rejected)

`fred` is a newer async Redis client with a higher-level API.

- Rejected because: `STORE-041` names `redis-rs` by crate identity; `fred` is a different
  library that would not satisfy the spec wording; it is newer and has a smaller community
  than `redis-rs`; adopting it would require a spec amendment.

### Option C — `redis-async` (rejected)

An older async Redis client.

- Rejected because: unmaintained (last meaningful release in 2019); does not support
  Redis Cluster or Sentinel; no tokio 1.x integration.

## Audit trail

| Field                     | Value |
|---------------------------|-------|
| crates.io name            | `redis` |
| Version adopted           | 0.27.x (0.27.6 at time of adoption) |
| Licence                   | MIT |
| Licence whitelist (ENG-094) | ✓ |
| Licence blocklist (ENG-095) | ✗ |
| `unsafe` blocks           | Present in the C-backed RESP parser performance path (intentional, for throughput). Not in Heimdall's own code — Heimdall's `#![deny(unsafe_code)]` boundary is not crossed. |
| Known CVEs                | None at time of adoption |
| RustSec advisories        | None open at time of adoption |
| Maintenance activity      | Active; maintained by the redis-rs community; frequent releases |
| Transitive dependencies   | `tokio`, `tokio-util`, `bytes`, `futures`, `socket2`, `combine`, `sha1_smol`, `url` — all permissively licensed and already present or well-audited |
| Author identity           | redis-rs community organisation on GitHub |
| Registry ownership        | Published on crates.io under the `redis` package |

## Classification

**Core-critical** (runtime dependency). The Redis client underpins all three persistence
domains. Removal would require replacing the entire persistence layer.

## Unsafe code posture

`redis`'s `unsafe` is confined to its internal RESP parser optimisation path. Heimdall's
own code does not introduce `unsafe` to interact with `redis` — the public API is entirely
safe Rust. The `unsafe` footprint belongs to `redis`'s implementation and is outside
Heimdall's `#![deny(unsafe_code)]` boundary.

## Consequences

- `redis = { version = "0.27", features = ["aio", "tokio-comp", "cluster-async",
  "sentinel"] }` is added under `[dependencies]` in `crates/heimdall-runtime/Cargo.toml`.
- Standalone and Sentinel topologies use a `deadpool-redis` connection pool (ADR-0043).
- Cluster topology uses `redis::cluster_async::ClusterClient` directly (its own
  connection management).
- Unix domain socket connections use the `redis::aio::ConnectionManager` path with a
  `redis://` URL that encodes the UDS path.
- TCP+TLS connections require TLS 1.3 per `STORE-050` and `SEC-001..003`; TLS
  configuration is supplied by the operator and validated at startup.
- The `sentinel` feature enables `redis::sentinel::SentinelClient` for `STORE-041`.

## Links

- Introduced with Sprint 18, tasks #234, #237, #238, #239, #240.
- Implements: ENG-008 (dependency ADR gate), STORE-005..017, STORE-018..025,
  STORE-026..030, STORE-040, STORE-041, STORE-045..046.
- Implemented in: `crates/heimdall-runtime/Cargo.toml` (`[dependencies]`),
  `crates/heimdall-runtime/src/store/`.
