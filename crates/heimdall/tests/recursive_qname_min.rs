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

//! E2E: QNAME minimisation — outbound qname progression observed via spy servers
//! (Sprint 47 task #474).
//!
//! ## Delegation chain
//!
//! ```text
//! recursive ──→ 127.0.0.2:<port>   combined root+TLD spy
//!     1st query (root context):     referral → test. NS → 127.0.0.2
//!     2nd query (test. context):    referral → example.test. NS → 127.0.0.3
//! recursive ──→ 127.0.0.3:<port>   example.test. spy
//!                                   referral → nested.example.test. NS → 127.0.0.4
//! recursive ──→ 127.0.0.4:<port>   nested.example.test. spy
//!                                   answer: deeply.nested.example.test. A 192.0.2.99
//! ```
//!
//! ## Spy server design
//!
//! `SpyDnsServer` is an in-process UDP server that records every QNAME/QTYPE it
//! receives (case-normalised to lowercase) and returns pre-configured responses
//! in order: the nth query picks `responses[n]` (or the last element once
//! exhausted).  The combined root+TLD spy on 127.0.0.2 therefore returns the
//! `test.` NS referral on the first query and the `example.test.` NS referral on
//! the second.
//!
//! ## Acceptance criteria (task #474)
//!
//! Relaxed mode (`qname_min_mode = "relaxed"`):
//! - Root+TLD spy receives `test.` first (minimised at root).
//! - Root+TLD spy receives `example.test.` second (minimised at test.).
//! - Root+TLD spy does NOT receive `deeply.nested.example.test.`.
//! - Final answer: RCODE=NOERROR, A=192.0.2.99.
//!
//! Disabled mode (`qname_min_mode = "off"`):
//! - Root+TLD spy receives `deeply.nested.example.test.` as its first query.
//! - Root+TLD spy does NOT receive the minimised `test.`.
//! - Final answer: RCODE=NOERROR, A=192.0.2.99.
//!
//! ## Linux-only
//!
//! Binding to 127.0.0.2/127.0.0.3/127.0.0.4 requires Linux, where the entire
//! 127.0.0.0/8 block routes to `lo` without elevated privileges.

#![cfg(all(unix, target_os = "linux"))]

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use heimdall_e2e_harness::{
    TestServer, config, dns_client, free_port, spy_dns, spy_dns::SpyResponse,
};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const TARGET: &str = "deeply.nested.example.test.";
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

// ── Shared test infrastructure ────────────────────────────────────────────────

struct QminEnv {
    _rec: TestServer,
    rec_addr: SocketAddr,
    root_spy: spy_dns::SpyDnsServer,
    example_spy: spy_dns::SpyDnsServer,
    _nested_spy: spy_dns::SpyDnsServer,
    // Keep the hints tempdir alive until the test ends.
    _hints_dir: tempfile::TempDir,
}

/// Build the delegation chain and a recursive resolver with the given QNAME min mode.
fn setup_qmin_env(qname_min_mode: &str) -> QminEnv {
    let auth_port = free_port();

    // 127.0.0.2 — combined root+TLD spy.
    //
    // This server is queried twice:
    //   1. From the root zone context:
    //      • relaxed: receives `test. NS`          → returns test.  NS / 127.0.0.2
    //      • off:     receives `deeply... A`       → returns test.  NS / 127.0.0.2
    //   2. From the test. zone context:
    //      • relaxed: receives `example.test. NS`  → returns example.test. NS / 127.0.0.3
    //      • off:     receives `deeply... A`       → returns example.test. NS / 127.0.0.3
    //
    // The sequence approach: response[0] = test. referral, response[1] = example.test. referral.
    let root_spy = spy_dns::SpyDnsServer::start(
        format!("127.0.0.2:{auth_port}").parse().unwrap(),
        vec![
            SpyResponse::Referral {
                zone: "test.".to_owned(),
                ns_name: "ns1.test.".to_owned(),
                glue_ip: Ipv4Addr::new(127, 0, 0, 2),
            },
            SpyResponse::Referral {
                zone: "example.test.".to_owned(),
                ns_name: "ns1.example.test.".to_owned(),
                glue_ip: Ipv4Addr::new(127, 0, 0, 3),
            },
        ],
    );

    // 127.0.0.3 — example.test. spy → delegates nested.example.test. to 127.0.0.4.
    let example_spy = spy_dns::SpyDnsServer::start(
        format!("127.0.0.3:{auth_port}").parse().unwrap(),
        vec![SpyResponse::Referral {
            zone: "nested.example.test.".to_owned(),
            ns_name: "ns1.nested.example.test.".to_owned(),
            glue_ip: Ipv4Addr::new(127, 0, 0, 4),
        }],
    );

    // 127.0.0.4 — nested.example.test. spy → authoritative A answer.
    let nested_spy = spy_dns::SpyDnsServer::start(
        format!("127.0.0.4:{auth_port}").parse().unwrap(),
        vec![SpyResponse::Answer { ip: ANSWER_IP }],
    );

    // Root hints: point the recursive resolver at 127.0.0.2.
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, "ns1.root-test. 3600 IN A 127.0.0.2\n").expect("write root hints");

    let rec_dns = free_port();
    let rec_obs = free_port();
    let rec_toml = config::minimal_recursive_custom_with_qname_min(
        rec_dns,
        rec_obs,
        &hints_path,
        auth_port,
        qname_min_mode,
    );
    let _rec = TestServer::start_with_ports(BIN, &rec_toml, rec_dns, rec_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("recursive resolver did not become ready");

    std::thread::sleep(Duration::from_millis(200));
    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_dns}").parse().unwrap();

    QminEnv {
        _rec,
        rec_addr,
        root_spy,
        example_spy,
        _nested_spy: nested_spy,
        _hints_dir: hints_dir,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Relaxed QNAME minimisation: root+TLD spy receives only minimised qnames.
///
/// Acceptance criteria:
/// - RCODE=NOERROR, A=192.0.2.99.
/// - Root spy 1st query = `test.` (minimised from root zone).
/// - Root spy 2nd query = `example.test.` (minimised from test. zone).
/// - Root spy never receives the full `deeply.nested.example.test.`.
#[test]
fn qname_min_relaxed_minimises_outbound_queries() {
    let env = setup_qmin_env("relaxed");

    let addr = dns_client::query_a_addr(env.rec_addr, TARGET);
    assert_eq!(
        addr,
        Some(ANSWER_IP),
        "relaxed QNAME min: resolution must succeed with A={ANSWER_IP}"
    );

    let root_queries = env.root_spy.received();
    let root_qnames: Vec<&str> = root_queries.iter().map(|(q, _)| q.as_str()).collect();

    assert!(
        root_qnames.first().map(|s| s.as_str()) == Some("test."),
        "relaxed QNAME min: 1st query to root spy must be 'test.' (minimised); got: {root_qnames:?}"
    );
    assert!(
        root_qnames.get(1).map(|s| s.as_str()) == Some("example.test."),
        "relaxed QNAME min: 2nd query to root spy must be 'example.test.' (minimised); got: {root_qnames:?}"
    );
    assert!(
        !root_qnames.contains(&"deeply.nested.example.test."),
        "relaxed QNAME min: root spy must NOT receive the full qname; got: {root_qnames:?}"
    );
}

/// QNAME min disabled: every server receives the full QNAME, not minimised labels.
///
/// Acceptance criteria:
/// - RCODE=NOERROR, A=192.0.2.99.
/// - Root spy 1st query = `deeply.nested.example.test.` (full qname, no minimisation).
/// - Root spy does NOT receive the minimised `test.`.
/// - example.test. spy receives `deeply.nested.example.test.`.
#[test]
fn qname_min_off_sends_full_qname_everywhere() {
    let env = setup_qmin_env("off");

    let addr = dns_client::query_a_addr(env.rec_addr, TARGET);
    assert_eq!(
        addr,
        Some(ANSWER_IP),
        "QNAME min=off: resolution must succeed with A={ANSWER_IP}"
    );

    let root_queries = env.root_spy.received();
    let root_qnames: Vec<&str> = root_queries.iter().map(|(q, _)| q.as_str()).collect();

    assert!(
        root_qnames.first().map(|s| s.as_str()) == Some("deeply.nested.example.test."),
        "QNAME min=off: root spy 1st query must be the full qname; got: {root_qnames:?}"
    );
    assert!(
        !root_qnames.contains(&"test."),
        "QNAME min=off: root spy must NOT receive minimised 'test.'; got: {root_qnames:?}"
    );

    let example_queries = env.example_spy.received();
    let example_qnames: Vec<&str> = example_queries.iter().map(|(q, _)| q.as_str()).collect();
    assert!(
        example_qnames.contains(&"deeply.nested.example.test."),
        "QNAME min=off: example.test. spy must receive the full qname; got: {example_qnames:?}"
    );
}
