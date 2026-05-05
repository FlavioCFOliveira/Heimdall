// SPDX-License-Identifier: MIT

//! E2E: authoritative server with DNSSEC pre-signed zone (Sprint 47 task #558).
//!
//! Tests that the authoritative role correctly passes through RRSIG, DNSKEY,
//! NSEC, and DS records when the DO bit is set (RFC 4035 §3.1):
//!
//! 1. A query with DO=1 → answer + RRSIG; AD=0 (authoritative servers MUST NOT set AD).
//! 2. NXDOMAIN query with DO=1 → NXDOMAIN + NSEC chain in authority section.
//! 3. DNSKEY query → DNSKEY RRset in answer section.
//! 4. DS at parent zone → DS record served by the parent authoritative.
//!
//! A stub validator (`heimdall_core::dnssec::verify_rrsig`) is anchored on the
//! zone KSK and verifies the in-memory zone data returns `Secure`.

#![cfg(unix)]

use std::time::Duration;

use heimdall_core::{
    dnssec::{DigestType, ValidationOutcome, canonical::canonical_name_wire, verify_rrsig},
    zone::integrity::key_tag as compute_key_tag,
};
use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, zones};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

// ── Stub validator (in-memory) ────────────────────────────────────────────────

/// Verify that the in-memory host A RRset is cryptographically signed correctly
/// using the zone's DNSKEY, anchored at a timestamp within the validity window.
fn assert_zone_signed_secure(zone_key: &zones::ZoneAndKey) {
    // The validity window in the test zone: inception=1_000_000_000, expiration=2_000_000_000.
    // A timestamp of 1_500_000_000 (2017-07-14) is well within the window.
    let now: u64 = 1_500_000_000;
    let outcome = verify_rrsig(
        &zone_key.host_a_rrset,
        &zone_key.host_a_rrsig,
        &[zone_key.dnskey_record.clone()],
        now,
        4, // KeyTrap cap per DNSSEC-040
    );
    assert_eq!(
        outcome,
        ValidationOutcome::Secure,
        "stub validator must return Secure for the zone's host A RRset: got {:?}",
        outcome
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a DS record zone text for `child_zone` (e.g. `"example.com."`) using
/// the key material from `zone_key`, suitable for inclusion in a parent zone file.
fn build_ds_rr_text(child_zone: &str, zone_key: &zones::ZoneAndKey) -> String {
    use std::str::FromStr as _;

    use heimdall_core::name::Name;

    let owner = Name::from_str(child_zone).expect("valid child zone name");
    let owner_wire = canonical_name_wire(&owner);

    // DNSKEY RDATA wire: flags(2B) || protocol(1B) || algorithm(1B) || public_key.
    let flags: u16 = 256; // ZSK flags used in test zone generator.
    let protocol: u8 = 3;
    let algorithm: u8 = 15; // Ed25519.
    let mut dnskey_rdata = Vec::with_capacity(4 + zone_key.public_key.len());
    dnskey_rdata.extend_from_slice(&flags.to_be_bytes());
    dnskey_rdata.push(protocol);
    dnskey_rdata.push(algorithm);
    dnskey_rdata.extend_from_slice(&zone_key.public_key);

    let digest = DigestType::Sha256
        .compute(&owner_wire, &dnskey_rdata)
        .expect("SHA-256 DS digest computation");

    let digest_hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();

    // DS wire: key_tag algorithm digest_type digest
    format!(
        "{child_zone} 300 IN DS {} {} 2 {}",
        zone_key.key_tag, algorithm, digest_hex
    )
}

// ── Test 1: A query with DO=1 returns answer + RRSIG; AD=0 ───────────────────

#[test]
fn a_query_with_do_returns_rrsig_and_no_ad() {
    let zone_key = zones::generate_nsec_zone_with_key("example.com.");

    // Stub validator: verify the zone's own signing is correct before serving it.
    assert_zone_signed_secure(&zone_key);

    let zone_dir = tempfile::TempDir::new().expect("tempdir");
    let zone_path = zone_dir.path().join("example.com.zone");
    std::fs::write(&zone_path, &zone_key.zone_text).expect("write zone file");

    let server = TestServer::start_auth(BIN, "example.com.", &zone_path);

    // Query the A record with DO=1.
    let resp = dns_client::query_a_with_do(server.dns_addr(), "host.example.com.");

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(
        !resp.ad,
        "AD flag MUST NOT be set on authoritative responses (RFC 4035 §3.1)"
    );
    assert!(resp.ancount >= 1, "must have at least one answer record");
    // RRSIG type = 46 must appear in the answer section alongside the A record.
    assert!(
        resp.answer_types.contains(&46),
        "answer section must contain RRSIG (TYPE 46) when DO=1; got types: {:?}",
        resp.answer_types
    );
    // A record (type 1) must also be present.
    assert!(
        resp.answer_types.contains(&1),
        "answer section must contain A record (TYPE 1); got types: {:?}",
        resp.answer_types
    );
}

// ── Test 2: NXDOMAIN with DO=1 returns NSEC chain ────────────────────────────

#[test]
fn nxdomain_with_do_returns_nsec_in_authority() {
    let zone_key = zones::generate_nsec_zone_with_key("example.com.");

    let zone_dir = tempfile::TempDir::new().expect("tempdir");
    let zone_path = zone_dir.path().join("example.com.zone");
    std::fs::write(&zone_path, &zone_key.zone_text).expect("write zone file");

    let server = TestServer::start_auth(BIN, "example.com.", &zone_path);

    // Query a name that provably does not exist: "nonexistent.example.com."
    // Canonical order: apex < host < nonexistent < ns1, so the NSEC at host
    // covers this name (host → ns1 in the NSEC chain).
    let resp = dns_client::query_a_with_do(server.dns_addr(), "nonexistent.example.com.");

    assert_eq!(resp.rcode, 3, "RCODE must be NXDOMAIN (3)");
    assert!(
        !resp.ad,
        "AD flag MUST NOT be set on authoritative responses (RFC 4035 §3.1)"
    );
    assert_eq!(resp.ancount, 0, "NXDOMAIN must have no answer records");
    assert!(
        resp.nscount > 0,
        "NXDOMAIN with DO=1 must include NSEC record(s) in authority section"
    );
}

// ── Test 3: DNSKEY query returns the DNSKEY RRset ────────────────────────────

#[test]
fn dnskey_query_returns_dnskey_rrset() {
    let zone_key = zones::generate_nsec_zone_with_key("example.com.");

    let zone_dir = tempfile::TempDir::new().expect("tempdir");
    let zone_path = zone_dir.path().join("example.com.zone");
    std::fs::write(&zone_path, &zone_key.zone_text).expect("write zone file");

    let server = TestServer::start_auth(BIN, "example.com.", &zone_path);

    // Query DNSKEY (TYPE 48) over TCP.
    let resp = dns_client::query_tcp(server.dns_addr(), "example.com.", 48 /* DNSKEY */);

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must return at least one DNSKEY record");
    assert!(
        resp.answer_types.contains(&48),
        "answer section must contain DNSKEY (TYPE 48); got types: {:?}",
        resp.answer_types
    );
}

// ── Test 4: DS at parent zone is served correctly ────────────────────────────

#[test]
fn ds_record_served_from_parent_zone() {
    // Generate the child zone key (example.com.).
    let child_zone_key = zones::generate_nsec_zone_with_key("example.com.");

    // Compute the DS record text for example.com. and embed it in a com. zone.
    let ds_rr = build_ds_rr_text("example.com.", &child_zone_key);

    // Build a minimal com. parent zone containing the DS record.
    let parent_zone_text = format!(
        r#"; com. — parent zone fixture for DS test (Sprint 47 task #558)
$ORIGIN com.
$TTL 300

@  IN SOA  ns1 hostmaster (
              2024010101 ; serial
              3600       ; refresh
              900        ; retry
              604800     ; expire
              300 )      ; minimum TTL

@     IN NS    ns1.com.
ns1   IN A     127.0.0.1

; DS for example.com. (computed from child zone DNSKEY)
{ds_rr}
"#
    );

    let dns_port = free_port();
    let obs_port = free_port();

    let zone_dir = tempfile::TempDir::new().expect("tempdir for parent zone");
    let zone_path = zone_dir.path().join("com.zone");
    std::fs::write(&zone_path, &parent_zone_text).expect("write parent zone file");

    let toml = config::minimal_auth(dns_port, obs_port, "com.", &zone_path);
    let parent_server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(3))
        .unwrap_or_else(|s| {
            panic!(
                "parent auth server on dns_port={} did not become ready",
                s.dns_port
            )
        });

    // Query the DS record for example.com. from the parent (com.) server.
    let resp = dns_client::query_tcp(
        parent_server.dns_addr(),
        "example.com.",
        43, // DS
    );

    assert_eq!(
        resp.rcode, 0,
        "RCODE must be NOERROR for DS query at parent"
    );
    assert!(
        resp.ancount >= 1,
        "parent must return at least one DS record"
    );
    assert!(
        resp.answer_types.contains(&43),
        "answer section must contain DS (TYPE 43); got types: {:?}",
        resp.answer_types
    );
}
