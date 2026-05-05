// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! E2E: ROLE step-4 — REFUSED + EDE INFO-CODE 20 across all six transports
//! (Sprint 47 task #583).
//!
//! ROLE-024 and ROLE-025 require that when no active role can serve a query
//! (step-4 of the four-step precedence), Heimdall returns RCODE=REFUSED with
//! EDNS(0) Extended DNS Errors INFO-CODE 20 ("Not Authoritative").  The
//! response MUST be identical in RCODE and EDE INFO-CODE across every transport.
//!
//! # Test scenario
//!
//! An authoritative-only server serves `example.com.`.  A query for
//! `refused.example.org.` (outside the zone) triggers step-4 and must receive
//! REFUSED + EDE-20 on every transport:
//!
//! - UDP/53
//! - TCP/53
//! - DNS-over-TLS (`DoT`)
//! - DNS-over-HTTPS/H2 (DoH/H2) — GET and POST methods
//! - DNS-over-HTTPS/H3 (DoH/H3) — GET and POST methods
//! - DNS-over-QUIC (`DoQ`)
//!
//! All 15 pairwise comparisons of (RCODE, EDE INFO-CODE, ANCOUNT) must be
//! equal, proving transport-uniform step-4 semantics.

#![cfg(unix)]

use std::{net::SocketAddr, path::Path, time::Duration};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, pki::TestPki};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

const QNAME: &str = "refused.example.org.";

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── Response tuple for pairwise comparison ────────────────────────────────────

/// Extracted fields used for the 15-pair identity check.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct RefusedShape {
    rcode: u8,
    ede_code: Option<u16>,
    ancount: u16,
}

fn shape(r: &dns_client::DnsResponse) -> RefusedShape {
    RefusedShape {
        rcode: r.rcode,
        ede_code: r.opt_ede_code,
        ancount: r.ancount,
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

/// Verifies that an out-of-zone query returns REFUSED + EDE-20 on all six
/// transports, and that all 15 pairwise comparisons of (RCODE, EDE, ANCOUNT)
/// are equal.
#[test]
fn step4_refused_ede20_all_transports() {
    let pki = TestPki::generate();

    let udp_port = free_port();
    let tcp_port = free_port();
    let dot_port = free_port();
    let doh2_port = free_port();
    let doh3_port = free_port();
    let doq_port = free_port();
    let obs_port = free_port();

    let toml = config::auth_all_transports(
        udp_port,
        tcp_port,
        dot_port,
        doh2_port,
        doh3_port,
        doq_port,
        obs_port,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let _server = TestServer::start_with_ports(BIN, &toml, udp_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("auth server did not become ready");

    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let tcp_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();
    let dot_addr: SocketAddr = format!("127.0.0.1:{dot_port}").parse().unwrap();
    let doh2_addr: SocketAddr = format!("127.0.0.1:{doh2_port}").parse().unwrap();
    let doh3_addr: SocketAddr = format!("127.0.0.1:{doh3_port}").parse().unwrap();
    let doq_addr: SocketAddr = format!("127.0.0.1:{doq_port}").parse().unwrap();

    let ca_pem = pki.ca_cert_pem.clone();

    // ── Issue one query per transport ─────────────────────────────────────────
    let r_udp = dns_client::query_a(udp_addr, QNAME);
    let r_tcp = dns_client::query_tcp(tcp_addr, QNAME, 1 /* A */);
    let r_dot = dns_client::query_a_dot(dot_addr, QNAME, &ca_pem);
    let r_doh2g = dns_client::query_a_doh2_get(doh2_addr, QNAME, &ca_pem);
    let r_doh2p = dns_client::query_a_doh2_post(doh2_addr, QNAME, &ca_pem);
    let r_doh3g = dns_client::query_a_doh3_get(doh3_addr, QNAME, &ca_pem);
    let r_doh3p = dns_client::query_a_doh3_post(doh3_addr, QNAME, &ca_pem);
    let r_doq = dns_client::query_a_doq(doq_addr, QNAME, &ca_pem);

    let labels = [
        ("UDP", shape(&r_udp)),
        ("TCP", shape(&r_tcp)),
        ("DoT", shape(&r_dot)),
        ("DoH2-G", shape(&r_doh2g)),
        ("DoH2-P", shape(&r_doh2p)),
        ("DoH3-G", shape(&r_doh3g)),
        ("DoH3-P", shape(&r_doh3p)),
        ("DoQ", shape(&r_doq)),
    ];

    // ── Assert each transport individually ────────────────────────────────────
    for (name, s) in &labels {
        assert_eq!(
            s.rcode, 5,
            "{name}: RCODE must be REFUSED (5); got {}",
            s.rcode
        );
        assert_eq!(
            s.ede_code,
            Some(20),
            "{name}: OPT EDE INFO-CODE must be 20 (Not Authoritative); got {:?}",
            s.ede_code
        );
        assert_eq!(
            s.ancount, 0,
            "{name}: ANCOUNT must be 0 for REFUSED; got {}",
            s.ancount
        );
    }

    // ── 15 pairwise comparisons (identity of RCODE + EDE + ANCOUNT) ──────────
    for i in 0..labels.len() {
        for j in (i + 1)..labels.len() {
            let (a_name, a_shape) = &labels[i];
            let (b_name, b_shape) = &labels[j];
            assert_eq!(
                a_shape, b_shape,
                "step-4 response must be transport-uniform: {a_name} vs {b_name}\n  \
                 {a_name}: {a_shape:?}\n  {b_name}: {b_shape:?}"
            );
        }
    }
}
