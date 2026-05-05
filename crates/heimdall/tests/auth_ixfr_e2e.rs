// SPDX-License-Identifier: MIT

//! E2E: IXFR happy-path (AXFR fallback) + serial gap fallback (Sprint 47 task #591).
//!
//! The server always falls back to AXFR format because the journal is empty
//! (`&[]`) in the current implementation — this is the defined behaviour for
//! PROTO-042.  Two sub-cases are validated:
//!
//! (i) IXFR with client serial behind the primary → server responds with AXFR
//!     format inside the IXFR envelope; secondary zone state matches primary.
//! (ii) IXFR with client serial far older than any journal entry (serial gap)
//!     → same AXFR fallback path; secondary state still correct.
//!
//! RFC 1982 serial wraparound is verified by directly sending IXFR queries at
//! the 32-bit boundary (0xFFFF_FFFE → 2) and checking the server correctly
//! identifies the client as "behind" (not up-to-date).

#![cfg(unix)]

use std::{
    path::Path,
    time::{Duration, Instant},
};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

/// Zone at serial 4 — used as the "advanced" primary zone.
const ZONE_SERIAL_4: &str = r#"; ixfr-test.test. — zone at serial 4
$ORIGIN ixfr-test.test.
$TTL 300

@   IN SOA ns1 hostmaster (
            4      ; serial 4
            60     ; refresh
            30     ; retry
            604800 ; expire
            300 )  ; minimum

@    IN NS   ns1
ns1  IN A    127.0.0.1
host IN A    192.0.2.4
"#;

/// Zone at serial 1 — used as the "old" primary zone.
const ZONE_SERIAL_1: &str = r#"; ixfr-test.test. — zone at serial 1
$ORIGIN ixfr-test.test.
$TTL 300

@   IN SOA ns1 hostmaster (
            1      ; serial 1
            60     ; refresh
            30     ; retry
            604800 ; expire
            300 )  ; minimum

@    IN NS   ns1
ns1  IN A    127.0.0.1
host IN A    192.0.2.1
"#;

fn write_zone(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("ixfr-test.test.zone");
    std::fs::write(&path, text).expect("write zone file");
    (dir, path)
}

fn start_primary_tsig(zone_path: &Path, serial: u32) -> TestServer {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_tsig(
        dns_port,
        obs_port,
        "ixfr-test.test.",
        zone_path,
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    );
    TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(2))
        .unwrap_or_else(|s| {
            panic!(
                "primary serial={serial} did not become ready on dns_port={}",
                s.dns_port
            )
        })
}

/// Poll `server` for the SOA serial of `qname` until it equals `expected` or timeout.
fn poll_serial(server: &TestServer, qname: &str, expected: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(s) = dns_client::query_soa_serial(server.dns_addr(), qname) {
            if s == expected {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

// ── Sub-case (i): IXFR with stale client serial → AXFR fallback ──────────────

/// An IXFR query sent with a client serial that is behind the primary's serial
/// receives a full AXFR-format response (PROTO-042 fallback, because the
/// journal is empty).
///
/// Verifies:
/// - RCODE = NOERROR
/// - SOA serial in response = 4 (primary's current serial)
/// - Answer includes SOA + zone body + closing SOA
/// - Response carries at least 2 records (opening SOA + closing SOA)
#[test]
fn ixfr_stale_client_serial_receives_axfr_fallback() {
    let (_dir, zone_path) = write_zone(ZONE_SERIAL_4);
    let primary = start_primary_tsig(&zone_path, 4);

    // IXFR query with client_serial=1, primary is at serial=4.
    // Journal is empty → AXFR-format fallback.
    let resp = dns_client::query_ixfr_tcp(
        primary.dns_addr(),
        "ixfr-test.test.",
        1,
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(
        resp.rcode, 0,
        "IXFR AXFR-fallback must return NOERROR; got rcode={}",
        resp.rcode
    );
    assert_eq!(
        resp.soa_serial, 4,
        "SOA serial in AXFR-fallback must equal primary serial 4; got {}",
        resp.soa_serial
    );
    assert!(
        resp.answer_count >= 2,
        "AXFR-fallback must return at least opening+closing SOA (answer_count ≥ 2); got {}",
        resp.answer_count
    );
    assert_eq!(
        resp.rtype_first,
        6, // SOA
        "First record in AXFR-fallback must be SOA (TYPE 6); got {}",
        resp.rtype_first
    );
    assert_eq!(
        resp.rtype_last,
        6, // SOA
        "Last record in AXFR-fallback must be SOA (TYPE 6); got {}",
        resp.rtype_last
    );
}

// ── Sub-case (ii): IXFR with serial gap → AXFR fallback, secondary matches ───

/// When a secondary starts with no zone (serial gap = complete gap from 0 to N),
/// the IXFR-first logic in `pull_zone` triggers AXFR.  The secondary zone state
/// after the pull must match the primary's zone (serial 4).
///
/// This exercises the IXFR→AXFR fallback path end-to-end through the Heimdall
/// binary (PROTO-042).
#[test]
fn secondary_zone_state_matches_after_ixfr_axfr_fallback() {
    let (_dir, zone_path) = write_zone(ZONE_SERIAL_4);
    let primary = start_primary_tsig(&zone_path, 4);
    let primary_addr = primary.dns_addr();

    // Start secondary (no existing zone — full AXFR triggered immediately).
    let secondary = TestServer::start_secondary(BIN, "ixfr-test.test.", primary_addr);

    let ok = poll_serial(&secondary, "ixfr-test.test.", 4, Duration::from_secs(5));
    assert!(
        ok,
        "secondary did not reach serial 4 within 5 s after IXFR/AXFR pull"
    );

    // Verify secondary serves the zone correctly after the pull.
    let soa_resp = dns_client::query_soa(secondary.dns_addr(), "ixfr-test.test.");
    assert_eq!(soa_resp.rcode, 0, "secondary SOA query must return NOERROR");

    let a_resp = dns_client::query_a(secondary.dns_addr(), "host.ixfr-test.test.");
    assert_eq!(a_resp.rcode, 0, "secondary A query must return NOERROR");
    assert!(
        a_resp.ancount >= 1,
        "secondary must return A records after AXFR pull"
    );
}

// ── RFC 1982 wraparound: IXFR correctly identifies stale client near boundary ─

/// RFC 1982 serial wraparound: a client at serial 0xFFFF_FFFE is BEHIND
/// a primary at serial 2 (wraps across the 2^32 boundary).
///
/// The primary must respond with a full AXFR-format response (not SOA-only)
/// because the client is behind per RFC 1982 arithmetic.
#[test]
fn ixfr_rfc1982_wraparound_client_treated_as_stale() {
    // Primary at serial 4 (any value where RFC1982 applies to client below).
    let (_dir, zone_path) = write_zone(ZONE_SERIAL_4);
    let primary = start_primary_tsig(&zone_path, 4);

    // Client at 0xFFFF_FFFE — per RFC 1982, when the primary is at 4:
    // 4 - 0xFFFF_FFFE mod 2^32 = 6, which is < 2^31, so primary > client.
    // The server should serve the full zone (AXFR fallback).
    let stale_serial: u32 = 0xFFFF_FFFE;
    let resp = dns_client::query_ixfr_tcp(
        primary.dns_addr(),
        "ixfr-test.test.",
        stale_serial,
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(
        resp.rcode, 0,
        "IXFR wraparound must return NOERROR; got rcode={}",
        resp.rcode
    );
    // The client is behind so the server must return the zone data, not just SOA.
    // answer_count >= 2 means at least opening SOA + closing SOA = AXFR format.
    assert!(
        resp.answer_count >= 2,
        "RFC 1982 wraparound: primary must serve AXFR-fallback to stale client at 0x{:08X}; \
         got answer_count={}",
        stale_serial,
        resp.answer_count,
    );
    assert_eq!(
        resp.soa_serial, 4,
        "SOA serial in wraparound response must be 4 (primary current); got {}",
        resp.soa_serial
    );
}

// ── IXFR up-to-date: SOA-only response at current serial ─────────────────────

/// When the secondary already has the current serial, IXFR returns only the SOA
/// (no zone body).  This is the IXFR up-to-date path (already at serial 4).
#[test]
fn ixfr_current_serial_returns_soa_only() {
    let (_dir, zone_path) = write_zone(ZONE_SERIAL_4);
    let primary = start_primary_tsig(&zone_path, 4);

    let resp = dns_client::query_ixfr_tcp(
        primary.dns_addr(),
        "ixfr-test.test.",
        4, // same as primary serial
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "IXFR up-to-date must return NOERROR");
    assert_eq!(resp.soa_serial, 4, "SOA serial must be 4");
    assert_eq!(
        resp.answer_count, 1,
        "up-to-date IXFR must return exactly one SOA; got answer_count={}",
        resp.answer_count
    );
}
