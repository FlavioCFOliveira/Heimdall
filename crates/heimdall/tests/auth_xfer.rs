// SPDX-License-Identifier: MIT

//! E2E: AXFR + IXFR over TCP with TSIG authentication (Sprint 47 task #470).
//!
//! AC verified:
//! - AXFR returns full zone with matching SOA serial.
//! - IXFR with the current serial returns only the bounding SOA (no delta).
//! - Every AXFR response frame carries a TSIG record.
//! - AXFR is REFUSED when the query carries no TSIG.
//! - AXFR is REFUSED when the query is signed with the wrong key.

#![cfg(unix)]

use std::path::Path;

use heimdall_e2e_harness::{TestServer, dns_client, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const ZONE_SERIAL: u32 = 2024010101;

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

fn start_tsig_server() -> TestServer {
    TestServer::start_auth_with_tsig(
        BIN,
        "example.com.",
        zone_path(),
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    )
}

#[test]
fn axfr_returns_full_zone_with_soa_serial() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        "example.com.",
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "AXFR must return NOERROR");
    assert_eq!(resp.soa_serial, ZONE_SERIAL, "SOA serial must match zone file");
    assert!(resp.frames >= 1, "must receive at least one frame");
    // Zone has opening SOA + records + closing SOA — at least 2 answers.
    assert!(resp.answer_count >= 2, "must contain at least opening and closing SOA");
}

#[test]
fn ixfr_current_serial_returns_soa_only() {
    let server = start_tsig_server();

    // Client already has the current serial — server returns only a bounding SOA.
    let resp = dns_client::query_ixfr_tcp(
        server.dns_addr(),
        "example.com.",
        ZONE_SERIAL,
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "IXFR must return NOERROR");
    assert_eq!(resp.soa_serial, ZONE_SERIAL, "SOA serial must match zone file");
    // Up-to-date client receives only the SOA (no incremental delta).
    assert_eq!(resp.answer_count, 1, "up-to-date IXFR must return exactly one SOA");
}

#[test]
fn axfr_tsig_signs_each_response_frame() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        "example.com.",
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "AXFR must return NOERROR");
    assert!(resp.frames >= 1, "must receive at least one frame");
    assert_eq!(
        resp.tsig_frames, resp.frames,
        "every AXFR frame must carry a TSIG record"
    );
}

#[test]
fn axfr_rejected_if_no_tsig() {
    let server = start_tsig_server();

    // Send unsigned AXFR — no TSIG key or bytes.
    let resp = dns_client::query_axfr_tcp(server.dns_addr(), "example.com.", None, None);

    assert_eq!(resp.rcode, 5, "unsigned AXFR must be REFUSED (rcode=5)");
}

#[test]
fn axfr_rejected_if_wrong_tsig() {
    let server = start_tsig_server();

    // Sign with a different key that the server does not recognise.
    let wrong_key = b"WrongKeyWrongKeyWrongKeyWrongKey\x00";
    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        "example.com.",
        Some("wrong-key."),
        Some(wrong_key.as_slice()),
    );

    assert_eq!(resp.rcode, 5, "AXFR with wrong TSIG must be REFUSED (rcode=5)");
}
