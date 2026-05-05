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

//! E2E: TC=1 UDP truncation + TCP retry (PROTO-008 / PROTO-115, Sprint 47 task #477).
//!
//! Serves a zone that contains `bigtxt.example.com.` — a TXT record with two
//! 255-byte character-strings (512 bytes of RDATA), which makes the full UDP
//! response ≈ 571 bytes.  When the client advertises EDNS UDP payload = 512, the
//! server MUST:
//!
//! 1. Return a UDP response with TC=1, ANCOUNT=0, containing only the header and
//!    question section (PROTO-115).
//! 2. When the client retries the same query over TCP, return the full answer
//!    (TC=0, ANCOUNT ≥ 1).
//!
//! The boundary assertion confirms that a response that fits within the negotiated
//! limit is never truncated (PROTO-008).

#![cfg(unix)]

use std::path::Path;

use heimdall_e2e_harness::{TestServer, dns_client};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

/// UDP TXT query with EDNS UDP=512 for a large record returns TC=1 with no
/// answer records.
#[test]
fn udp_large_txt_with_edns_512_returns_tc1() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_txt_edns(server.dns_addr(), "bigtxt.example.com.", 512);

    assert!(resp.qr, "QR bit must be set");
    assert!(resp.tc, "TC bit must be set (response truncated)");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert_eq!(
        resp.ancount, 0,
        "truncated UDP response must have no answer records"
    );
}

/// TCP retry for the same large TXT record returns the full answer (TC=0,
/// ANCOUNT ≥ 1).
#[test]
fn tcp_retry_after_tc1_returns_full_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    // Confirm UDP triggers TC=1 first.
    let udp_resp = dns_client::query_txt_edns(server.dns_addr(), "bigtxt.example.com.", 512);
    assert!(udp_resp.tc, "UDP must return TC=1 for large TXT");

    // TCP retry must deliver the full answer.
    let tcp_resp = dns_client::query_txt_tcp(server.dns_addr(), "bigtxt.example.com.");

    assert!(tcp_resp.qr, "QR bit must be set");
    assert!(!tcp_resp.tc, "TC bit must NOT be set on TCP response");
    assert_eq!(tcp_resp.rcode, 0, "RCODE must be NOERROR");
    assert!(
        tcp_resp.ancount >= 1,
        "TCP response must include at least one answer record"
    );
}

/// A small response (SOA query, well under 512 bytes) is never truncated on UDP
/// even when EDNS UDP=512 is advertised (boundary assertion, PROTO-008).
#[test]
fn udp_small_response_within_edns_limit_is_not_truncated() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_txt_edns(server.dns_addr(), "example.com.", 512);

    assert!(resp.qr, "QR bit must be set");
    assert!(!resp.tc, "TC bit must NOT be set for a small response");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(
        resp.ancount >= 1,
        "small TXT response must include an answer"
    );
}
