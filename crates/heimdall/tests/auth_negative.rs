// SPDX-License-Identifier: MIT

//! E2E: authoritative server — negative answers, CNAME, DNAME, wildcards.
//!
//! Tests cover:
//! - NXDOMAIN with SOA in authority (RFC 2308 §5)
//! - NODATA with SOA in authority (RFC 2308 §2.2)
//! - CNAME chain followed inside the zone
//! - DNAME synthesis with synthesized CNAME (RFC 6672 §3.2)
//! - Wildcard match for undefined names (`*.example.com.` — RFC 4592)
//! - Wildcard suppressed when specific name exists (NODATA instead)

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

// ── NXDOMAIN ──────────────────────────────────────────────────────────────────

#[test]
fn nxdomain_has_soa_in_authority() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // Two-label name: wildcard *.example.com. only expands one label, so
    // deep.nobody.example.com. is truly non-existent.
    let resp = dns_client::query_a(server.dns_addr(), "deep.nobody.example.com.");

    assert_eq!(resp.rcode, 3, "RCODE must be NXDOMAIN");
    assert!(resp.aa, "AA must be set on authoritative NXDOMAIN");
    assert_eq!(resp.ancount, 0, "no answers on NXDOMAIN");
    assert!(resp.nscount >= 1, "SOA must be in authority section");
    // RFC 2308 §5: negative-answer TTL <= SOA minimum (300 in this zone).
    if let Some(ttl) = resp.authority_first_ttl {
        assert!(
            ttl <= 300,
            "authority SOA TTL {ttl} must be <= SOA minimum 300"
        );
    }
}

// ── NODATA ────────────────────────────────────────────────────────────────────

#[test]
fn nodata_has_soa_in_authority() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // noaaaa.example.com. has an A record but no AAAA.
    let resp = dns_client::query_aaaa(server.dns_addr(), "noaaaa.example.com.");

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR for NODATA");
    assert!(resp.aa, "AA must be set");
    assert_eq!(resp.ancount, 0, "no answers on NODATA");
    assert!(resp.nscount >= 1, "SOA must be in authority section");
    if let Some(ttl) = resp.authority_first_ttl {
        assert!(
            ttl <= 300,
            "authority SOA TTL {ttl} must be <= SOA minimum 300"
        );
    }
}

// ── CNAME chain ───────────────────────────────────────────────────────────────

#[test]
fn cname_chain_followed_in_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // alias → www → @ (example.com.) A 192.0.2.1
    let resp = dns_client::query_a(server.dns_addr(), "alias.example.com.");

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.aa, "AA must be set");
    assert!(resp.ancount >= 2, "answer must have CNAME(s) + final A");
    assert!(
        resp.answer_types.contains(&5),
        "answer must include CNAME (type 5)"
    );
    assert!(
        resp.answer_types.contains(&1),
        "answer must include A (type 1)"
    );
}

// ── DNAME synthesis ───────────────────────────────────────────────────────────

#[test]
fn dname_synthesis_produces_cname_in_answer() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // sub.example.com. DNAME other.example.
    // foo.sub.example.com. A → DNAME + synthesized CNAME foo.other.example.
    let resp = dns_client::query_a(server.dns_addr(), "foo.sub.example.com.");

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR for DNAME synthesis");
    assert!(resp.aa, "AA must be set");
    assert!(
        resp.ancount >= 2,
        "answer must have DNAME + synthesized CNAME"
    );
    assert!(
        resp.answer_types.contains(&39),
        "answer must include DNAME (type 39)"
    );
    assert!(
        resp.answer_types.contains(&5),
        "answer must include synthesized CNAME (type 5)"
    );
}

// ── Wildcard ──────────────────────────────────────────────────────────────────

#[test]
fn wildcard_matches_undefined_name() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // undefined.example.com. → matches *.example.com. A 192.0.2.254
    let resp = dns_client::query_a(server.dns_addr(), "undefined.example.com.");

    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR for wildcard match");
    assert!(resp.aa, "AA must be set");
    assert!(resp.ancount >= 1, "wildcard A record must be in answer");
    assert!(
        resp.answer_types.contains(&1),
        "answer must include A (type 1)"
    );
}

#[test]
fn wildcard_not_used_when_name_exists() {
    let server = TestServer::start_auth(BIN, "example.com.", zone_path());
    // noaaaa.example.com. exists (has A) — wildcard must NOT supply an AAAA answer.
    let resp = dns_client::query_aaaa(server.dns_addr(), "noaaaa.example.com.");

    assert_eq!(
        resp.rcode, 0,
        "RCODE must be NOERROR (NODATA, not wildcard)"
    );
    assert_eq!(
        resp.ancount, 0,
        "AAAA answer must be empty — specific name exists (NODATA)"
    );
    assert!(
        resp.nscount >= 1,
        "SOA must be in authority section for NODATA"
    );
}
