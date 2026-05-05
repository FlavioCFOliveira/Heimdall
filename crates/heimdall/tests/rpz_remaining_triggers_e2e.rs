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

//! E2E: RPZ remaining triggers — Response-IP, NSIP, NSDNAME, tie-break
//! (Sprint 47 task #604, RPZ-012/013/014/027).
//!
//! A recursive resolver is loaded with a single RPZ zone (`rpz-triggers.test.`)
//! containing rules for all three post-resolution trigger types.  A `SpyDNS`
//! server acts as the root/authoritative nameserver, returning either:
//!
//! - `Answer { ip }` for plain Response-IP tests.
//! - `AnswerWithAuthority { ip, ns_name, ns_ip }` for NSIP and NSDNAME tests,
//!   where the authority/additional sections carry NS metadata for post-resolution
//!   RPZ evaluation.
//!
//! ## Trigger cases
//!
//! (i)   **Response-IP** (RPZ-012): upstream answer contains a blocked A record
//!       (198.51.100.1).  The recursive resolver intercepts post-resolution and
//!       returns NXDOMAIN.
//!
//! (ii)  **NSIP** (RPZ-013): upstream answer includes a glue A record for the NS
//!       (203.0.113.1).  The resolver extracts the NS IP and fires NXDOMAIN.
//!
//! (iii) **NSDNAME** (RPZ-014): upstream answer includes an NS record for
//!       `blocked-ns.example.com.`.  The resolver extracts the NS name and fires
//!       NXDOMAIN.
//!
//! (iv)  **Intra-zone tie-break** (RPZ-027): `tie-break.example.com.` matches
//!       both a QNAME NXDOMAIN rule (priority 1) and a Response-IP NODATA rule
//!       (priority 3).  The QNAME rule wins — the response is NXDOMAIN.

#![cfg(unix)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use heimdall_e2e_harness::{
    TestServer, config, dns_client, free_port, spy_dns, spy_dns::SpyResponse,
};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn rpz_triggers_zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/rpz-triggers.test.zone"
    ))
}

/// Starts a recursive resolver with the RPZ triggers zone and a `SpyDNS` root.
///
/// `responses` is the ordered list of responses the `SpyDNS` server returns.
fn start_server(responses: Vec<SpyResponse>) -> (TestServer, spy_dns::SpyDnsServer) {
    let spy_port = free_port();
    let spy_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), spy_port);
    let spy = spy_dns::SpyDnsServer::start(spy_addr, responses);

    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, "ns1.rpz-trigger-test. 3600 IN A 127.0.0.1\n")
        .expect("write root hints");

    let dns_port = free_port();
    let obs_port = free_port();
    let rpz_path = rpz_triggers_zone_path().to_str().expect("valid UTF-8 path");
    let toml = config::minimal_recursive_with_rpz(
        dns_port,
        obs_port,
        &hints_path,
        spy_port,
        "rpz-triggers.test.",
        rpz_path,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(3))
        .expect("RPZ trigger recursive resolver did not become ready");

    std::mem::forget(hints_dir);
    (server, spy)
}

// ── (i) Response-IP ───────────────────────────────────────────────────────────

/// (i) Response-IP trigger: upstream returns A=198.51.100.1 which is blocked.
/// Resolver intercepts post-resolution and returns NXDOMAIN (RPZ-012).
#[test]
fn rpz_response_ip_nxdomain() {
    let (server, _spy) = start_server(vec![SpyResponse::Answer {
        ip: Ipv4Addr::new(198, 51, 100, 1),
    }]);

    let resp = dns_client::query_a(server.dns_addr(), "any.example.com.");

    assert_eq!(
        resp.rcode, 3,
        "(i) Response-IP match must return NXDOMAIN (rcode=3); got {}",
        resp.rcode
    );
    assert_eq!(
        resp.ancount, 0,
        "(i) Response-IP NXDOMAIN must have empty answer section"
    );
}

// ── (ii) NSIP ────────────────────────────────────────────────────────────────

/// (ii) NSIP trigger: upstream answer includes NS glue IP 203.0.113.1 (blocked).
/// Resolver extracts the glue IP and returns NXDOMAIN (RPZ-013).
#[test]
fn rpz_nsip_nxdomain() {
    let (server, _spy) = start_server(vec![SpyResponse::AnswerWithAuthority {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        ns_name: "ns1.example.com.".to_owned(),
        ns_ip: Ipv4Addr::new(203, 0, 113, 1),
    }]);

    let resp = dns_client::query_a(server.dns_addr(), "any.example.com.");

    assert_eq!(
        resp.rcode, 3,
        "(ii) NSIP match must return NXDOMAIN (rcode=3); got {}",
        resp.rcode
    );
    assert_eq!(
        resp.ancount, 0,
        "(ii) NSIP NXDOMAIN must have empty answer section"
    );
}

// ── (iii) NSDNAME ────────────────────────────────────────────────────────────

/// (iii) NSDNAME trigger: upstream answer includes NS `blocked-ns.example.com.`
/// Resolver extracts the NS name and returns NXDOMAIN (RPZ-014).
#[test]
fn rpz_nsdname_nxdomain() {
    let (server, _spy) = start_server(vec![SpyResponse::AnswerWithAuthority {
        ip: Ipv4Addr::new(10, 0, 0, 2),
        ns_name: "blocked-ns.example.com.".to_owned(),
        ns_ip: Ipv4Addr::new(192, 0, 2, 1),
    }]);

    let resp = dns_client::query_a(server.dns_addr(), "any.example.com.");

    assert_eq!(
        resp.rcode, 3,
        "(iii) NSDNAME match must return NXDOMAIN (rcode=3); got {}",
        resp.rcode
    );
    assert_eq!(
        resp.ancount, 0,
        "(iii) NSDNAME NXDOMAIN must have empty answer section"
    );
}

// ── (iv) Intra-zone tie-break ─────────────────────────────────────────────────

/// (iv) Tie-break: QNAME NXDOMAIN (priority 1) beats Response-IP NODATA
/// (priority 3) for `tie-break.example.com.` (RPZ-027).
///
/// The QNAME trigger fires pre-resolution and returns NXDOMAIN immediately —
/// the Response-IP NODATA rule for 10.99.99.99 is never evaluated.
#[test]
fn rpz_tie_break_qname_beats_response_ip() {
    // SpyDNS would return 10.99.99.99 (NODATA trigger) if reached, but
    // the QNAME rule fires first, so SpyDNS is never queried.
    let (server, spy) = start_server(vec![SpyResponse::Answer {
        ip: Ipv4Addr::new(10, 99, 99, 99),
    }]);

    let resp = dns_client::query_a(server.dns_addr(), "tie-break.example.com.");

    // QNAME NXDOMAIN must win.
    assert_eq!(
        resp.rcode, 3,
        "(iv) QNAME NXDOMAIN must win tie-break over Response-IP NODATA; got rcode={}",
        resp.rcode
    );
    // SpyDNS was NOT queried because the QNAME rule fires pre-resolution.
    assert!(
        spy.received().is_empty(),
        "(iv) SpyDNS must not be queried when QNAME RPZ fires pre-resolution; got {:?}",
        spy.received()
    );
}
