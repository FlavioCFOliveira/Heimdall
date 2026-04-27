// SPDX-License-Identifier: MIT

//! Integration tests for the `heimdall-bench` harness utilities.
//!
//! Verifies that:
//! - Wire fixtures are parseable by `heimdall-core`.
//! - The regression-comparison logic correctly classifies deltas.

use heimdall_bench::{example_query_wire, example_response_wire};
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;

// ── Wire-fixture tests ────────────────────────────────────────────────────────

#[test]
fn example_query_wire_parses() {
    let wire = example_query_wire();
    let msg = Message::parse(&wire).expect("example query wire must parse without error");
    assert_eq!(
        msg.header.qdcount, 1,
        "query must have exactly one question"
    );
    assert!(msg.answers.is_empty(), "query must have no answers");
    let q = &msg.questions[0];
    assert_eq!(
        q.qname.to_string(),
        "example.com.",
        "qname must be example.com."
    );
}

#[test]
fn example_response_wire_parses() {
    let wire = example_response_wire();
    let msg = Message::parse(&wire).expect("example response wire must parse without error");
    assert!(msg.header.qr(), "QR bit must be set on a response");
    assert_eq!(
        msg.header.ancount, 1,
        "response must have exactly one answer"
    );
    assert_eq!(
        msg.questions[0].qname.to_string(),
        "example.com.",
        "qname must be example.com."
    );

    // Verify the answer is an A record for 93.184.216.34.
    let answer = &msg.answers[0];
    match &answer.rdata {
        RData::A(addr) => {
            assert_eq!(
                addr.to_string(),
                "93.184.216.34",
                "answer A record must be the IANA example address"
            );
        }
        other => panic!("expected RData::A, got {other:?}"),
    }
}

// ── Regression-comparison tests ───────────────────────────────────────────────

/// Convenience re-use of the `compare` function from `main.rs`.
///
/// We reach into the binary crate by duplicating the comparison logic here;
/// the canonical implementation lives in `src/main.rs` and is tested there
/// through its own unit tests.  These integration tests exercise the same
/// semantics from the user-facing perspective.
fn compare(
    baseline: &std::collections::HashMap<String, f64>,
    current: &std::collections::HashMap<String, f64>,
    threshold_pct: f64,
) -> Vec<String> {
    let mut regressions = Vec::new();
    for (name, &base_ns) in baseline {
        if let Some(&curr_ns) = current.get(name) {
            if base_ns > 0.0 {
                let delta_pct = (curr_ns - base_ns) / base_ns * 100.0;
                if delta_pct > threshold_pct {
                    regressions.push(name.clone());
                }
            }
        }
    }
    regressions.sort();
    regressions
}

#[test]
fn regression_compare_no_regression() {
    let mut map = std::collections::HashMap::new();
    map.insert("bench_a".to_owned(), 1_000.0);
    map.insert("bench_b".to_owned(), 2_500.0);

    // Identical maps — zero delta on every benchmark.
    let regressions = compare(&map, &map, 5.0);
    assert!(
        regressions.is_empty(),
        "identical baseline and current must produce no regressions, got: {regressions:?}"
    );
}

#[test]
fn regression_compare_detects_regression() {
    let mut baseline = std::collections::HashMap::new();
    baseline.insert("hot_path".to_owned(), 1_000.0);

    let mut current = std::collections::HashMap::new();
    // 10% slower — exceeds the 5% threshold.
    current.insert("hot_path".to_owned(), 1_100.0);

    let regressions = compare(&baseline, &current, 5.0);
    assert_eq!(
        regressions,
        vec!["hot_path".to_owned()],
        "10% regression must be detected"
    );
}

#[test]
fn regression_compare_improvement_not_flagged() {
    let mut baseline = std::collections::HashMap::new();
    baseline.insert("fast_path".to_owned(), 2_000.0);

    let mut current = std::collections::HashMap::new();
    // 50% faster — must NOT be flagged.
    current.insert("fast_path".to_owned(), 1_000.0);

    let regressions = compare(&baseline, &current, 5.0);
    assert!(
        regressions.is_empty(),
        "a 50% improvement must not be flagged as a regression"
    );
}
