// SPDX-License-Identifier: MIT

//! E2E: authoritative server serves the example.com zone.
//!
//! Starts a real `heimdall` process, sends A / AAAA / MX queries over UDP, and
//! asserts that NOERROR answers are returned with the expected answer count.

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

#[test]
fn a_query_returns_noerror_with_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_a(server.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer for A");
}

#[test]
fn aaaa_query_returns_noerror_with_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_aaaa(server.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer for AAAA");
}

#[test]
fn mx_query_returns_noerror_with_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_mx(server.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer for MX");
}

#[test]
fn soa_query_at_apex_returns_noerror() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    let resp = dns_client::query_soa(server.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert_eq!(resp.ancount, 1, "SOA answer count must be 1");
}

#[test]
fn nxdomain_for_nonexistent_name() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    // Use a two-level name so the wildcard *.example.com. does not match.
    let resp = dns_client::query_a(server.dns_addr(), "deep.nowhere.example.com.");

    assert!(resp.qr, "QR bit must be set");
    // NXDOMAIN = 3
    assert_eq!(resp.rcode, 3, "RCODE must be NXDOMAIN for nonexistent name");
}
