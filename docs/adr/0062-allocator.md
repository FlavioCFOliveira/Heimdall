# ADR-0062 — Global memory allocator: mimalloc as production default

**Status:** Accepted  
**Date:** 2026-05-03  
**Sprint:** 46 (task #540)  
**Spec:** BIN-039, BIN-040

---

## Context

Heimdall's hot path involves a high rate of small–medium allocations and
deallocations: DNS cache cells (~128 B RRset records), message receive buffers
(~512 B UDP datagrams), and HashMap index churn. The global allocator directly
affects per-query latency and throughput on these paths.

Three candidates were benchmarked: the OS default allocator (glibc on Linux,
libmalloc on macOS), `mimalloc` (Microsoft, cross-platform), and `jemalloc`
(Meta/FreeBSD, via `tikv-jemallocator`).

The benchmark suite (`heimdall-bench/benches/allocator.rs`) exercises three
workloads representative of Heimdall cache hot paths:

| Workload | Description |
|----------|-------------|
| `alloc_small_128B` | Tight loop of 128-byte Vec alloc/dealloc (RRset cells) |
| `alloc_medium_512B` | 512-byte Vec alloc/dealloc (message receive buffers) |
| `hashmap_1k` | 1 000 HashMap inserts + 1 000 lookups with 64-byte values |

---

## Benchmark results (macOS 25.4, M-series, debug mode off, release bench profile)

| Workload | System | mimalloc | jemalloc |
|----------|--------|----------|---------|
| small_128B (ns/op) | 10.66 | **6.91** | 10.26 |
| medium_512B (ns/op) | 17.35 | **8.68** | 11.50 |
| hashmap_1k (µs/op) | 24.24 | **14.40** | 25.14 |

**mimalloc vs. system allocator:**

- `alloc_small_128B`: −35.2 % latency (+54 % throughput)
- `alloc_medium_512B`: −50.0 % latency (+100 % throughput)
- `hashmap_1k`: −40.5 % latency (+68 % throughput)

**jemalloc vs. system allocator:**

- `alloc_small_128B`: −3.7 % latency (near-parity)
- `alloc_medium_512B`: −33.7 % latency
- `hashmap_1k`: +3.7 % latency (slightly slower)

All differences are statistically significant (criterion p < 0.05).

---

## Decision

**mimalloc** is selected as the production-default allocator.

Rationale:
1. Margins over the system allocator are 35–50 %, far above the 5 % threshold
   specified in the task requirements.
2. mimalloc outperforms jemalloc on every measured workload on the macOS
   development platform; it is also known to be competitive on Linux.
3. mimalloc is cross-platform (Linux, macOS, Windows, MUSL), which matches
   Heimdall's multi-platform support matrix (ENV-001..ENV-009).
4. The `mimalloc` crate (`v0.1`) has a minimal `unsafe` footprint (delegates to
   the well-audited upstream C library) and no non-trivial transitive
   dependencies.
5. jemalloc requires a C toolchain and a full in-tree jemalloc build; mimalloc
   compiles faster and produces a smaller binary.

---

## Consequences

- `crates/heimdall/Cargo.toml` sets `default = ["mimalloc"]`.
- `crates/heimdall/src/alloc.rs` installs `#[global_allocator]` conditioned on
  feature flags.
- Operators building without the `mimalloc` feature get the system allocator.
- The `jemalloc` feature remains available for explicit opt-in on Linux.
- A mutual-exclusivity compile error prevents enabling both features at once.
- Reproducible builds: allocator selection affects only performance, not
  observable behaviour (BIN-040). The feature is captured in the build
  metadata emitted by `build.rs` (task #555).

---

## Rejected alternatives

| Alternative | Reason for rejection |
|-------------|---------------------|
| System allocator as default | 35–50 % performance penalty with no compensating benefit |
| jemalloc as default | Near-parity with system on macOS; non-trivial build-time overhead; C-toolchain requirement on MUSL targets |
| snmalloc | Not yet evaluated; deferred to a future sprint if mimalloc shows regressions |
