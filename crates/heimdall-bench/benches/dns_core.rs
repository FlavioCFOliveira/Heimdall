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

//! Criterion benchmarks for the DNS wire-format hot path:
//! message parsing, message serialisation, name parsing, and name comparison.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use heimdall_bench::{example_query_message, example_response_wire};
use heimdall_core::{name::Name, parser::Message, serialiser::Serialiser};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A realistic DNS A-response wire packet built once at benchmark startup.
///
/// We initialise it lazily via a closure inside each bench rather than at
/// module level so that criterion's timing does not include construction cost.
fn wire_response() -> Vec<u8> {
    example_response_wire()
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_message_parse(c: &mut Criterion) {
    let wire = wire_response();
    c.bench_function("message_parse", |b| {
        b.iter(|| {
            Message::parse(black_box(&wire))
                .expect("INVARIANT: fixture wire packet is always valid")
        });
    });
}

fn bench_message_serialise(c: &mut Criterion) {
    let msg = example_query_message();
    c.bench_function("message_serialise", |b| {
        b.iter(|| {
            let mut ser = Serialiser::new(false);
            ser.write_message(black_box(&msg))
                .expect("INVARIANT: fixture message is always serialisable");
            ser.finish()
        });
    });
}

fn bench_message_serialise_compressed(c: &mut Criterion) {
    let msg = example_query_message();
    c.bench_function("message_serialise_compressed", |b| {
        b.iter(|| {
            let mut ser = Serialiser::new(true);
            ser.write_message(black_box(&msg))
                .expect("INVARIANT: fixture message is always serialisable");
            ser.finish()
        });
    });
}

fn bench_name_from_str(c: &mut Criterion) {
    c.bench_function("name_from_str", |b| {
        b.iter(|| {
            Name::from_str(black_box("sub.example.com."))
                .expect("INVARIANT: 'sub.example.com.' is a valid DNS name")
        });
    });
}

fn bench_name_eq(c: &mut Criterion) {
    let a = Name::from_str("sub.example.com.")
        .expect("INVARIANT: 'sub.example.com.' is a valid DNS name");
    let b = Name::from_str("sub.example.com.")
        .expect("INVARIANT: 'sub.example.com.' is a valid DNS name");
    c.bench_function("name_eq", |b_| b_.iter(|| black_box(&a) == black_box(&b)));
}

// ── Import std::str::FromStr for name_from_str bench ─────────────────────────

use std::str::FromStr;

criterion_group!(
    benches,
    bench_message_parse,
    bench_message_serialise,
    bench_message_serialise_compressed,
    bench_name_from_str,
    bench_name_eq,
);
criterion_main!(benches);
