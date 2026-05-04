// SPDX-License-Identifier: MIT

//! E2E: TSIG algorithm coverage for AXFR/IXFR (Sprint 47 task #589).
//!
//! Four sub-cases verifying the TSIG algorithm policy for zone transfers:
//!
//! (a) AXFR with valid HMAC-SHA256 — full zone transferred; SOA serial and
//!     record count match the source zone file.
//! (b) AXFR with a corrupted MAC — BADSIG scenario; server returns REFUSED.
//! (c) AXFR with an unknown key name — BADKEY scenario; server returns REFUSED.
//! (d) AXFR with HMAC-SHA1 algorithm — unsupported; server returns REFUSED.

#![cfg(unix)]

use std::path::Path;

use heimdall_e2e_harness::{TestServer, dns_client, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const ZONE_SERIAL: u32 = 2024010101;
// Opening SOA (1) + 18 non-SOA records + closing SOA (1) = 20.
const ZONE_ANSWER_COUNT: usize = 20;

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

// ── (a) AXFR with valid HMAC-SHA256 ──────────────────────────────────────────

/// AXFR signed with HMAC-SHA256 succeeds; SOA serial and record count match the
/// source zone file.
#[test]
fn axfr_sha256_succeeds_and_zone_content_matches() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        "example.com.",
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "AXFR with HMAC-SHA256 must return NOERROR");
    assert_eq!(
        resp.soa_serial, ZONE_SERIAL,
        "SOA serial in AXFR response must match zone file serial {ZONE_SERIAL}"
    );
    assert_eq!(
        resp.answer_count, ZONE_ANSWER_COUNT,
        "AXFR answer count must be {ZONE_ANSWER_COUNT} (opening SOA + zone records + closing SOA)"
    );
}

// ── (b) Corrupted MAC — BADSIG scenario ──────────────────────────────────────

/// AXFR with a valid TSIG structure but a corrupted MAC is rejected.  The
/// server returns REFUSED (rcode=5) — the BADSIG scenario.
#[test]
fn axfr_bad_mac_badsig_rejected() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_bad_mac(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
        tsig::KEY_BYTES,
    );

    assert_eq!(
        resp.rcode, 5,
        "AXFR with corrupted MAC (BADSIG) must be REFUSED (rcode=5); got {}",
        resp.rcode
    );
}

// ── (c) Unknown key name — BADKEY scenario ───────────────────────────────────

/// AXFR signed with a key name the server does not recognise is rejected.  The
/// server returns REFUSED (rcode=5) — the BADKEY scenario.
#[test]
fn axfr_unknown_key_badkey_rejected() {
    let server = start_tsig_server();

    let unknown_key_bytes = b"UnknownKey00UnknownKey00UnknownK\x00";
    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        "example.com.",
        Some("unknown-key."),
        Some(unknown_key_bytes.as_slice()),
    );

    assert_eq!(
        resp.rcode, 5,
        "AXFR with unknown key name (BADKEY) must be REFUSED (rcode=5); got {}",
        resp.rcode
    );
}

// ── (d) Unsupported algorithm — MD5/SHA1 absent ──────────────────────────────

/// AXFR carrying a TSIG record with algorithm `hmac-sha1.` is rejected.  Only
/// HMAC-SHA256/384/512 are supported; MD5 and SHA1 are unavailable per policy.
/// The server returns REFUSED (rcode=5).
#[test]
fn axfr_unsupported_algorithm_rejected() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_unsupported_algorithm(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
    );

    assert_eq!(
        resp.rcode, 5,
        "AXFR with hmac-sha1 algorithm must be REFUSED (rcode=5); got {}",
        resp.rcode
    );
}
