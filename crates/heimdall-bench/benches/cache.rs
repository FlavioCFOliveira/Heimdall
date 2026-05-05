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

//! Criterion benchmarks for the query-response cache:
//! insert, lookup-hit, and lookup-miss paths.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use heimdall_core::dnssec::ValidationOutcome;
use heimdall_runtime::cache::{CacheEntry, CacheKey, RecursiveCache};

// ── Benchmark parameters ──────────────────────────────────────────────────────

/// Cache capacities (entries) used as benchmark parameters.
const PROTECTED_CAP: usize = 1_000;
const PROBATIONARY_CAP: usize = 4_000;

/// Sizes for the parametrised "pre-fill" benchmarks.
const FILL_SIZES: [usize; 3] = [100, 1_000, 4_000];

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn make_key(i: u32) -> CacheKey {
    // Wire-encode a synthetic owner name:  <i>.bench.example.com. (lower-case)
    let label = format!("n{i}");
    // Manual wire encoding: [len][label_bytes][7]bench[7]example[3]com[0]
    let mut qname = Vec::with_capacity(label.len() + 1 + 22);
    qname.push(label.len() as u8);
    qname.extend_from_slice(label.as_bytes());
    qname.extend_from_slice(b"\x05bench\x07example\x03com\x00");
    CacheKey {
        qname,
        qtype: 1,
        qclass: 1,
    }
}

fn make_entry(now: Instant) -> CacheEntry {
    CacheEntry {
        rdata_wire: b"\x5d\xb8\xd8\x22".to_vec(), // 93.184.216.34 in wire bytes
        ttl_deadline: now + Duration::from_hours(24),
        dnssec_outcome: ValidationOutcome::Indeterminate,
        is_negative: false,
        serve_stale_until: None,
        zone_apex: b"\x07example\x03com\x00".to_vec(),
    }
}

fn filled_cache(size: usize) -> RecursiveCache {
    let cache = RecursiveCache::new(PROTECTED_CAP, PROBATIONARY_CAP);
    let now = Instant::now();
    for i in 0..size as u32 {
        cache.insert(make_key(i), make_entry(now));
    }
    cache
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert");
    for &size in &FILL_SIZES {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || {
                    // Build a fresh cache for each batch so capacity does not
                    // saturate across iterations and skew results.
                    (
                        RecursiveCache::new(PROTECTED_CAP, PROBATIONARY_CAP),
                        (0..size as u32).map(make_key).collect::<Vec<_>>(),
                        Instant::now(),
                    )
                },
                |(cache, keys, now)| {
                    for key in black_box(keys) {
                        cache.insert(key, make_entry(now));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_cache_hit(c: &mut Criterion) {
    let cache = filled_cache(PROBATIONARY_CAP);
    // After initial insertion every entry is in probationary; one prior get
    // would promote it, but we measure the cost of the probationary hit path.
    let probe_key = make_key(42);
    let now = Instant::now();

    c.bench_function("cache_lookup_hit", |b| {
        b.iter(|| cache.get(black_box(&probe_key), black_box(now)));
    });
}

fn bench_cache_miss(c: &mut Criterion) {
    let cache = filled_cache(100); // small fill — key 99_999 is definitely absent
    let absent_key = make_key(99_999);
    let now = Instant::now();

    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| cache.get(black_box(&absent_key), black_box(now)));
    });
}

criterion_group!(
    benches,
    bench_cache_insert,
    bench_cache_hit,
    bench_cache_miss
);
criterion_main!(benches);
