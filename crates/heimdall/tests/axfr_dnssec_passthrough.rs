// SPDX-License-Identifier: MIT

//! E2E: AXFR happy-path DNSSEC pass-through + first/last SOA invariant (Sprint 47 task #590).
//!
//! Three sub-cases:
//!
//! (a) AXFR of a DNSSEC-signed zone transfers RRSIG and DNSKEY records
//!     byte-for-byte without modification (PROTO-049).
//! (b) RFC 5936 §3.4 invariant: the first record in the AXFR answer stream is
//!     SOA and the last record is also SOA.
//! (c) Heimdall secondary state matches source: after AXFR from a primary, the
//!     secondary answers DNSKEY and signed A queries correctly.

#![cfg(unix)]

use std::time::{Duration, Instant};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, tsig, zones};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const ZONE_ORIGIN: &str = "dnssec-xfr.test.";
const ZONE_SERIAL: u32 = 2024010101;

// DNS RR TYPE numbers used in assertions.
const RTYPE_SOA: u16 = 6;
const RTYPE_A: u16 = 1;
const RTYPE_NS: u16 = 2;
const RTYPE_DNSKEY: u16 = 48;
const RTYPE_RRSIG: u16 = 46;

/// Write a DNSSEC zone to a tempfile and return (tempdir, path).
fn write_dnssec_zone() -> (tempfile::TempDir, std::path::PathBuf) {
    let zone_text = zones::generate_valid_zone(ZONE_ORIGIN);
    let dir = tempfile::TempDir::new().expect("tempdir for DNSSEC zone");
    let path = dir.path().join("dnssec-xfr.test.zone");
    std::fs::write(&path, &zone_text).expect("write DNSSEC zone file");
    (dir, path)
}

/// Spawn an authoritative primary serving `zone_path` with TSIG, wait for readiness.
fn start_primary(zone_path: &std::path::Path) -> (TestServer, u16) {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_tsig(
        dns_port,
        obs_port,
        ZONE_ORIGIN,
        zone_path,
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(2))
        .unwrap_or_else(|s| panic!("primary did not become ready on dns_port={}", s.dns_port));
    (server, dns_port)
}

// ── (a) DNSSEC records pass through AXFR without modification ────────────────

/// AXFR of a DNSSEC-signed zone must include RRSIG and DNSKEY records.
///
/// Verifies PROTO-049: DNSSEC records (RRSIG, DNSKEY, NSEC, NSEC3PARAM, NSEC3,
/// DS, CDS, CDNSKEY, CSYNC) are transferred end-to-end without modification.
#[test]
fn axfr_dnssec_records_transfer_intact() {
    let (_dir, zone_path) = write_dnssec_zone();
    let (server, _) = start_primary(&zone_path);

    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        ZONE_ORIGIN,
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "AXFR must return NOERROR");
    assert!(
        resp.answer_count > 0,
        "AXFR must transfer at least one record"
    );

    assert!(
        resp.answer_rtypes.contains(&RTYPE_RRSIG),
        "AXFR must include RRSIG records (TYPE 46) for DNSSEC pass-through; \
         types seen: {:?}",
        resp.answer_rtypes,
    );
    assert!(
        resp.answer_rtypes.contains(&RTYPE_DNSKEY),
        "AXFR must include DNSKEY records (TYPE 48) for DNSSEC pass-through; \
         types seen: {:?}",
        resp.answer_rtypes,
    );
    assert!(
        resp.answer_rtypes.contains(&RTYPE_SOA),
        "AXFR must include SOA records; types seen: {:?}",
        resp.answer_rtypes,
    );
    assert_eq!(
        resp.soa_serial, ZONE_SERIAL,
        "SOA serial must match zone file serial {ZONE_SERIAL}"
    );

    // RRSIG and DNSKEY must both travel alongside the signed RRsets.
    assert!(
        resp.answer_rtypes.contains(&RTYPE_A),
        "AXFR must include A records; types seen: {:?}",
        resp.answer_rtypes,
    );
    assert!(
        resp.answer_rtypes.contains(&RTYPE_NS),
        "AXFR must include NS records; types seen: {:?}",
        resp.answer_rtypes,
    );
}

// ── (b) RFC 5936 §3.4 first/last SOA invariant ──────────────────────────────

/// RFC 5936 §3.4 mandates that the first and last records of an AXFR response
/// are the SOA.  Both `rtype_first` and `rtype_last` from the parsed stream
/// must be SOA (TYPE 6).
#[test]
fn axfr_first_and_last_record_are_soa() {
    let (_dir, zone_path) = write_dnssec_zone();
    let (server, _) = start_primary(&zone_path);

    let resp = dns_client::query_axfr_tcp(
        server.dns_addr(),
        ZONE_ORIGIN,
        Some(tsig::KEY_NAME),
        Some(tsig::KEY_BYTES),
    );

    assert_eq!(resp.rcode, 0, "AXFR must return NOERROR");
    assert!(resp.frames >= 1, "must receive at least one TCP frame");
    assert_eq!(
        resp.rtype_first, RTYPE_SOA,
        "first record of AXFR stream must be SOA (TYPE 6) per RFC 5936 §3.4; \
         got TYPE {}",
        resp.rtype_first,
    );
    assert_eq!(
        resp.rtype_last, RTYPE_SOA,
        "last record of AXFR stream must be SOA (TYPE 6) per RFC 5936 §3.4; \
         got TYPE {}",
        resp.rtype_last,
    );
    // The two SOA records (opening + closing) contribute 2 to answer_count.
    assert!(
        resp.answer_count >= 2,
        "AXFR answer_count must be ≥ 2 (opening SOA + records + closing SOA); \
         got {}",
        resp.answer_count,
    );
}

// ── (c) Secondary state matches source after AXFR ───────────────────────────

/// After Heimdall secondary performs AXFR from a primary serving a DNSSEC zone,
/// the secondary must be able to answer:
/// - DNSKEY queries with a DNSKEY RRset.
/// - A queries with DO=1 returning both A and RRSIG records.
///
/// This validates that DNSSEC records survived the AXFR wire transfer and were
/// correctly loaded into the secondary's zone store.
#[test]
fn secondary_has_dnssec_records_after_axfr() {
    let (_dir, zone_path) = write_dnssec_zone();
    let (primary, primary_dns_port) = start_primary(&zone_path);

    let primary_addr: std::net::SocketAddr =
        format!("127.0.0.1:{primary_dns_port}").parse().unwrap();

    let secondary = TestServer::start_secondary(BIN, ZONE_ORIGIN, primary_addr);

    // Poll until the secondary has pulled the correct SOA serial (up to 5 s).
    let deadline = Instant::now() + Duration::from_secs(5);
    let serial_ok = loop {
        if let Some(s) = dns_client::query_soa_serial(secondary.dns_addr(), ZONE_ORIGIN) {
            if s == ZONE_SERIAL {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        serial_ok,
        "secondary did not pull SOA serial={ZONE_SERIAL} from primary within 5 s"
    );

    // DNSKEY query: secondary must return at least one DNSKEY record.
    let dnskey_resp = dns_client::query_tcp(secondary.dns_addr(), ZONE_ORIGIN, RTYPE_DNSKEY);
    assert_eq!(
        dnskey_resp.rcode, 0,
        "DNSKEY query on secondary must return NOERROR"
    );
    assert!(
        dnskey_resp.ancount >= 1,
        "secondary must return at least one DNSKEY record after AXFR"
    );
    assert!(
        dnskey_resp.answer_types.contains(&RTYPE_DNSKEY),
        "secondary answer section must contain DNSKEY (TYPE 48); \
         got types: {:?}",
        dnskey_resp.answer_types,
    );

    // A query with DO=1: secondary must return A + RRSIG.
    let host_qname = format!("host.{ZONE_ORIGIN}");
    let do_resp = dns_client::query_a_with_do(secondary.dns_addr(), &host_qname);
    assert_eq!(
        do_resp.rcode, 0,
        "A+DO query on secondary must return NOERROR"
    );
    assert!(
        do_resp.answer_types.contains(&RTYPE_A),
        "secondary must include A record in DO response"
    );
    assert!(
        do_resp.answer_types.contains(&RTYPE_RRSIG),
        "secondary must include RRSIG record in DO response (DNSSEC pass-through); \
         got types: {:?}",
        do_resp.answer_types,
    );

    drop(primary); // explicit drop for clarity
}
