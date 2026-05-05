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

//! E2E: `DoQ` (DNS-over-QUIC, RFC 9250) inbound transport (Sprint 47 task #578).
//!
//! Starts a real `heimdall` process with a `DoQ` listener backed by the test
//! PKI, sends an A query via a bidirectional QUIC stream with 2-byte framing
//! (RFC 9250 §4.2), and asserts a correct NOERROR response with at least one
//! answer.
//!
//! TLS 1.3 over QUIC v1 is confirmed implicitly: a successful handshake and
//! response proves the full QUIC+TLS stack operates.  The `DoQ` server does not
//! enforce a specific ALPN value per RFC 9250 — the client connects without
//! setting ALPN, which is the correct interoperability posture.

#![cfg(unix)]

use std::path::Path;

use heimdall_e2e_harness::{TestServer, dns_client, pki::TestPki};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

/// `DoQ` query over QUIC returns NOERROR with at least one answer.
#[test]
fn doq_server_basic_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doq(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_doq(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}
