// SPDX-License-Identifier: MIT

//! E2E: DNS Cookies (RFC 7873) on UDP (Sprint 47 task #476).
//!
//! Starts a real `heimdall` authoritative server on a UDP port and exercises
//! the three RFC 7873 cookie paths:
//!
//! 1. **First contact** (client-cookie only): server MUST echo a fresh server
//!    cookie in the response OPT RR and return NOERROR.
//!
//! 2. **Valid full cookie** (client + previously issued server cookie): server
//!    MUST return NOERROR and a refreshed server cookie.
//!
//! 3. **Stale / wrong server cookie**: server MUST return BADCOOKIE (extended
//!    RCODE 23, RFC 6891 encoding) and a fresh server cookie so the client can
//!    retry (RFC 7873 §5.2.3).

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

/// Fixed 8-byte client cookie used across all three test paths.
const CLIENT_COOKIE: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01, 0x02];

/// Path 1: query with client-cookie only (first contact) returns NOERROR and a
/// server cookie in the response OPT RR.
#[test]
fn cookie_first_contact_returns_noerror_and_server_cookie() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    // Send client-cookie-only OPT RR (no server cookie yet).
    let resp =
        dns_client::query_a_with_cookie(server.dns_addr(), "example.com.", CLIENT_COOKIE, None);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode_ext, 0, "RCODE must be NOERROR (0)");
    assert!(resp.ancount >= 1, "must have at least one answer record");
    assert!(
        resp.opt_server_cookie.is_some(),
        "server must include a server cookie in the OPT RR"
    );
    let sc = resp.opt_server_cookie.unwrap();
    assert_eq!(sc.len(), 8, "server cookie must be exactly 8 bytes");
}

/// Path 2: query with the server cookie obtained in path 1 returns NOERROR.
#[test]
fn cookie_valid_full_cookie_returns_noerror() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    // Step A: obtain a valid server cookie.
    let first =
        dns_client::query_a_with_cookie(server.dns_addr(), "example.com.", CLIENT_COOKIE, None);
    let server_cookie = first
        .opt_server_cookie
        .expect("step A must return a server cookie");

    // Step B: re-send with the obtained server cookie.
    let resp = dns_client::query_a_with_cookie(
        server.dns_addr(),
        "example.com.",
        CLIENT_COOKIE,
        Some(&server_cookie),
    );

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode_ext, 0, "RCODE must be NOERROR (0)");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

/// Path 3: query with a wrong server cookie returns BADCOOKIE (extended RCODE
/// 23) and a fresh server cookie so the client can retry.
#[test]
fn cookie_bad_server_cookie_returns_badcookie() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());

    // Craft a deliberately wrong server cookie.
    let bad_server_cookie: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let resp = dns_client::query_a_with_cookie(
        server.dns_addr(),
        "example.com.",
        CLIENT_COOKIE,
        Some(&bad_server_cookie),
    );

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode_ext, 23, "RCODE must be BADCOOKIE (23)");
    assert!(
        resp.opt_server_cookie.is_some(),
        "BADCOOKIE response must include a fresh server cookie"
    );
    let sc = resp.opt_server_cookie.unwrap();
    assert_eq!(sc.len(), 8, "fresh server cookie must be exactly 8 bytes");
    assert_ne!(
        sc.as_slice(),
        &bad_server_cookie,
        "fresh server cookie must differ from the rejected one"
    );
}
