// SPDX-License-Identifier: MIT

//! Criterion benchmarks for RPZ matching:
//! `QnameTrie` lookup at 100, 10 000, and 100 000 entries.

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use heimdall_core::name::Name;
use heimdall_roles::rpz::{
    action::RpzAction,
    trie::{CidrTrie, QnameTrie},
    trigger::CidrRange,
};

// ── Benchmark parameters ──────────────────────────────────────────────────────

/// Trie entry counts used to parameterise the lookup benchmarks.
const TRIE_SIZES: [usize; 3] = [100, 10_000, 100_000];

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Builds a `QnameTrie` with `size` synthetic wildcard entries of the form
/// `*.n<i>.bench.example.com.` and `size` exact-match entries of the form
/// `n<i>.bench.exact.com.`.
///
/// The two-part population exercises both the `wildcard` and `exact` hash maps.
fn build_qname_trie(size: usize) -> QnameTrie {
    let mut trie = QnameTrie::new();
    for i in 0..size {
        // Wildcard suffix entry: suffix = n<i>.bench.example.com.
        let suffix_str = format!("n{i}.bench.example.com.");
        let suffix =
            Name::from_str(&suffix_str).expect("INVARIANT: benchmark fixture name is always valid");
        trie.insert_wildcard(&suffix, RpzAction::Nxdomain);

        // Exact-match entry.
        let exact_str = format!("n{i}.bench.exact.com.");
        let exact =
            Name::from_str(&exact_str).expect("INVARIANT: benchmark fixture name is always valid");
        trie.insert_exact(&exact, RpzAction::Nodata);
    }
    trie
}

/// A probe name that does NOT match any entry (cache-miss benchmark).
fn miss_probe() -> Name {
    Name::from_str("completely.absent.zone.")
        .expect("INVARIANT: benchmark fixture name is always valid")
}

/// A probe name that matches a wildcard entry when the trie has ≥ 1 entry.
fn wildcard_hit_probe() -> Name {
    Name::from_str("sub.n0.bench.example.com.")
        .expect("INVARIANT: benchmark fixture name is always valid")
}

/// Builds a `CidrTrie` with `size` distinct /24 IPv4 entries.
fn build_cidr_trie(size: usize) -> CidrTrie {
    let mut trie = CidrTrie::new();
    for i in 0..size as u32 {
        let octet2 = (i / 256) as u8;
        let octet3 = (i % 256) as u8;
        let addr: IpAddr = Ipv4Addr::new(10, octet2, octet3, 0).into();
        let range = CidrRange {
            addr,
            prefix_len: 24,
        };
        trie.insert(&range, RpzAction::Nxdomain);
    }
    trie
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_qname_trie_lookup(c: &mut Criterion) {
    let miss = miss_probe();
    let hit = wildcard_hit_probe();

    let mut group = c.benchmark_group("qname_trie_lookup");
    for &size in &TRIE_SIZES {
        let trie = build_qname_trie(size);

        group.bench_with_input(BenchmarkId::new("hit_wildcard", size), &size, |b, _| {
            b.iter(|| trie.lookup(black_box(&hit)))
        });

        group.bench_with_input(BenchmarkId::new("miss", size), &size, |b, _| {
            b.iter(|| trie.lookup(black_box(&miss)))
        });
    }
    group.finish();
}

fn bench_cidr_trie_lookup(c: &mut Criterion) {
    // Probe: within an inserted /24 block (hit for all sizes ≥ 1).
    let probe_hit: IpAddr = Ipv4Addr::new(10, 0, 0, 200).into();
    // Probe: outside all inserted blocks.
    let probe_miss: IpAddr = Ipv4Addr::new(172, 16, 0, 1).into();

    let mut group = c.benchmark_group("cidr_trie_lookup");
    for &size in &TRIE_SIZES {
        let trie = build_cidr_trie(size);

        group.bench_with_input(BenchmarkId::new("hit", size), &size, |b, _| {
            b.iter(|| trie.lookup(black_box(probe_hit)))
        });

        group.bench_with_input(BenchmarkId::new("miss", size), &size, |b, _| {
            b.iter(|| trie.lookup(black_box(probe_miss)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_qname_trie_lookup, bench_cidr_trie_lookup);
criterion_main!(benches);
