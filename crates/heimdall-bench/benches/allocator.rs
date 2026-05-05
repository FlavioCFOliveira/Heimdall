// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! Allocator benchmark — Sprint 46 task #540, BIN-039, ADR-0062.
//!
//! Measures the throughput of three allocation workloads representative of
//! Heimdall's hot paths:
//!
//! - `small_alloc_dealloc`: a tight loop of 128-byte Vec allocations and
//!   deallocations, modelling DNS `RRset` cache cells.
//! - `medium_alloc_dealloc`: 512-byte allocations, modelling DNS message
//!   buffers on the receive path.
//! - `hashmap_insert_lookup`: inserts 1 000 entries into a `HashMap` and then
//!   does 1 000 point lookups; models the cache index.
//!
//! Run with a specific allocator by enabling the matching feature:
//!
//!   # system allocator (baseline)
//!   cargo bench -p heimdall-bench --bench allocator --no-default-features
//!
//!   # mimalloc
//!   cargo bench -p heimdall-bench --bench allocator --no-default-features --features mimalloc
//!
//!   # jemalloc
//!   cargo bench -p heimdall-bench --bench allocator --no-default-features --features jemalloc

#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!("features `mimalloc` and `jemalloc` are mutually exclusive");

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "jemalloc", not(feature = "mimalloc")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ── Workloads ─────────────────────────────────────────────────────────────────

fn small_alloc_dealloc(iters: u64) {
    for _ in 0..iters {
        let v: Vec<u8> = vec![0u8; 128];
        std::hint::black_box(v);
    }
}

fn medium_alloc_dealloc(iters: u64) {
    for _ in 0..iters {
        let v: Vec<u8> = vec![0u8; 512];
        std::hint::black_box(v);
    }
}

fn hashmap_insert_lookup(iters: u64) {
    const N: usize = 1_000;
    for _ in 0..iters {
        let mut map: HashMap<u64, Vec<u8>> = HashMap::with_capacity(N);
        for i in 0..N {
            map.insert(i as u64, vec![0u8; 64]);
        }
        let mut sum: u8 = 0;
        for i in 0..N {
            if let Some(v) = map.get(&(i as u64)) {
                sum = sum.wrapping_add(v[0]);
            }
        }
        std::hint::black_box(sum);
    }
}

// ── Bench groups ──────────────────────────────────────────────────────────────

fn bench_small(c: &mut Criterion) {
    let mut g = c.benchmark_group("alloc_small_128B");
    g.throughput(Throughput::Elements(1));
    g.bench_function(BenchmarkId::from_parameter("alloc_dealloc"), |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            small_alloc_dealloc(iters);
            start.elapsed()
        });
    });
    g.finish();
}

fn bench_medium(c: &mut Criterion) {
    let mut g = c.benchmark_group("alloc_medium_512B");
    g.throughput(Throughput::Elements(1));
    g.bench_function(BenchmarkId::from_parameter("alloc_dealloc"), |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            medium_alloc_dealloc(iters);
            start.elapsed()
        });
    });
    g.finish();
}

fn bench_hashmap(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashmap_1k");
    g.throughput(Throughput::Elements(1));
    g.bench_function(BenchmarkId::from_parameter("insert_lookup"), |b| {
        b.iter_custom(|iters| {
            let start = std::time::Instant::now();
            hashmap_insert_lookup(iters);
            start.elapsed()
        });
    });
    g.finish();
}

criterion_group!(benches, bench_small, bench_medium, bench_hashmap);
criterion_main!(benches);
