// SPDX-License-Identifier: MIT

//! E2E: EDNS Padding (RFC 7830 / RFC 8467) over DoT, DoH/2, DoH/3, and DoQ
//! (Sprint 47 task #545).
//!
//! For each encrypted transport the server MUST:
//!
//! 1. Include an OPT RR Padding option (option code 12, RFC 7830) in every
//!    response.
//! 2. Pad the response wire to the next multiple of 468 bytes (RFC 8467 §4.1
//!    recommended block size).
//!
//! Plaintext UDP must NOT include padding — the server applies padding only on
//! encrypted transports.

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

// ── DoT ───────────────────────────────────────────────────────────────────────

/// DoT response includes a Padding option and wire length is a multiple of 468.
#[test]
fn dot_response_is_padded_to_468_block() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_dot(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_dot(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.opt_has_padding, "DoT response must contain a Padding option (RFC 7830)");
    assert_eq!(
        resp.wire.len() % 468,
        0,
        "DoT response wire length {} must be a multiple of 468 (RFC 8467)",
        resp.wire.len()
    );
}

// ── DoH/2 ─────────────────────────────────────────────────────────────────────

/// DoH/2 GET response includes a Padding option and wire length is a multiple of 468.
#[test]
fn doh2_get_response_is_padded_to_468_block() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh2(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp =
        dns_client::query_a_doh2_get(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.opt_has_padding, "DoH/2 GET response must contain a Padding option");
    assert_eq!(
        resp.wire.len() % 468,
        0,
        "DoH/2 GET response wire length {} must be a multiple of 468",
        resp.wire.len()
    );
}

/// DoH/2 POST response includes a Padding option and wire length is a multiple of 468.
#[test]
fn doh2_post_response_is_padded_to_468_block() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh2(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp =
        dns_client::query_a_doh2_post(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.opt_has_padding, "DoH/2 POST response must contain a Padding option");
    assert_eq!(
        resp.wire.len() % 468,
        0,
        "DoH/2 POST response wire length {} must be a multiple of 468",
        resp.wire.len()
    );
}

// ── DoQ ───────────────────────────────────────────────────────────────────────

/// DoQ response includes a Padding option and wire length is a multiple of 468.
#[test]
fn doq_response_is_padded_to_468_block() {
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
    assert!(resp.opt_has_padding, "DoQ response must contain a Padding option (RFC 7830)");
    assert_eq!(
        resp.wire.len() % 468,
        0,
        "DoQ response wire length {} must be a multiple of 468 (RFC 8467)",
        resp.wire.len()
    );
}

// ── DoH/3 ─────────────────────────────────────────────────────────────────────

/// DoH/3 GET response includes a Padding option and wire length is a multiple of 468.
#[test]
fn doh3_get_response_is_padded_to_468_block() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_doh3(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp =
        dns_client::query_a_doh3_get(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.opt_has_padding, "DoH/3 GET response must contain a Padding option");
    assert_eq!(
        resp.wire.len() % 468,
        0,
        "DoH/3 GET response wire length {} must be a multiple of 468",
        resp.wire.len()
    );
}

// ── UDP (no padding) ──────────────────────────────────────────────────────────

/// Plain UDP response must not include a Padding option.
#[test]
fn udp_response_has_no_padding() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_a(server.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(
        !resp.opt_has_padding,
        "UDP response must NOT include a Padding option (padding only applies to encrypted transports)"
    );
}
