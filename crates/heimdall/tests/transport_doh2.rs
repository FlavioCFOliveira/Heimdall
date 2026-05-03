// SPDX-License-Identifier: MIT

//! E2E: DoH/2 (DNS-over-HTTPS over HTTP/2, RFC 8484) inbound transport
//! (Sprint 47 task #576).
//!
//! Starts a real `heimdall` process with a DoH/2 listener backed by the test
//! PKI, sends A queries via both HTTP GET and POST, and asserts correct
//! NOERROR responses with proper Content-Type headers.
//!
//! HTTP/2 framing is confirmed implicitly: the DoH/2 listener enforces ALPN
//! "h2" (NET-006) and rejects any connection that does not negotiate HTTP/2
//! — a successful response proves HTTP/2 was used.

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

/// DoH/2 GET query for an A record returns NOERROR with at least one answer.
///
/// HTTP/2 framing is confirmed by the successful ALPN "h2" negotiation that
/// the Doh2Listener enforces before processing any request (NET-006).
#[test]
fn doh2_server_get_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh2(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_doh2_get(
        server.dns_addr(),
        "example.com.",
        &pki.ca_cert_pem,
    );

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

/// DoH/2 POST query for an A record returns NOERROR with at least one answer.
#[test]
fn doh2_server_post_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh2(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_doh2_post(
        server.dns_addr(),
        "example.com.",
        &pki.ca_cert_pem,
    );

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}
