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

//! E2E: DoH/3 (DNS-over-HTTPS over HTTP/3 / QUIC, RFC 8484 + RFC 9114)
//! inbound transport (Sprint 47 task #577).
//!
//! Starts a real `heimdall` process with a DoH/3 listener backed by the test
//! PKI, sends A queries via HTTP/3 GET and POST over QUIC, and asserts correct
//! NOERROR responses.
//!
//! QUIC v1 and TLS 1.3 are confirmed implicitly: the `Doh3Listener` enforces
//! ALPN "h3" and the quinn endpoint restricts to QUIC v1+v2 (SEC-017..019).
//! A successful response proves the full QUIC+TLS+HTTP/3 stack operates.

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

/// DoH/3 GET query over QUIC returns NOERROR with at least one answer.
#[test]
fn doh3_server_get_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh3(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_doh3_get(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

/// DoH/3 POST query over QUIC returns NOERROR with at least one answer.
#[test]
fn doh3_server_post_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh3(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_doh3_post(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}
