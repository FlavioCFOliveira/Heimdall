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

//! Criterion benchmarks for the admission pipeline:
//! CIDR-set lookup at varying prefix counts.

use std::net::{IpAddr, Ipv4Addr};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use heimdall_runtime::admission::CidrSet;

// ── Benchmark parameters ──────────────────────────────────────────────────────

/// Prefix counts used to parameterise the CIDR-lookup benchmark.
const CIDR_SIZES: [u32; 4] = [100, 1_000, 5_000, 10_000];

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Builds a `CidrSet` containing `count` distinct /24 IPv4 prefixes.
///
/// Prefixes are allocated from the 1.0.0.0/8 – 39.0.0.0/8 address space
/// (non-overlapping for typical `count` values ≤ 65536).
fn build_cidr_set(count: u32) -> CidrSet {
    let mut set = CidrSet::default();
    for i in 0..count {
        // Distribute across /24 blocks: different Class-B subnet per entry.
        let octet2 = (i / 256) as u8;
        let octet3 = (i % 256) as u8;
        let ip: IpAddr = Ipv4Addr::new(10, octet2, octet3, 0).into();
        set.insert(ip, 24);
    }
    set
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_cidr_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr_lookup");

    // Probe address: within a block that IS present for all sizes ≥ 1.
    let probe_hit: IpAddr = Ipv4Addr::new(10, 0, 0, 200).into();
    // Probe address: outside all inserted blocks.
    let probe_miss: IpAddr = Ipv4Addr::new(192, 168, 99, 1).into();

    for &count in &CIDR_SIZES {
        let set = build_cidr_set(count);

        group.bench_with_input(BenchmarkId::new("hit", count), &count, |b, _| {
            b.iter(|| set.contains(black_box(probe_hit)));
        });

        group.bench_with_input(BenchmarkId::new("miss", count), &count, |b, _| {
            b.iter(|| set.contains(black_box(probe_miss)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cidr_lookup);
criterion_main!(benches);
