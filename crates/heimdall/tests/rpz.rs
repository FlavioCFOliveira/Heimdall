// SPDX-License-Identifier: MIT

//! E2E: RPZ — all seven response policy actions (Sprint 47 task #479).
//!
//! One RPZ zone with seven rules (one per action) is loaded by a recursive
//! resolver.  A SpyDNS server acts as the root nameserver (via custom root
//! hints), answering any query with a fixed A record so that PASSTHRU and
//! TCP-only-TCP tests can receive an upstream answer.
//!
//! Action paths verified:
//!
//! (a) **NXDOMAIN** — rcode=3, empty answer, AD cleared, EDE 15 (Blocked).
//! (b) **NODATA** — rcode=0, empty answer, AD cleared, EDE 15 (Blocked).
//! (c) **PASSTHRU** — query bypasses RPZ, upstream A record returned.
//! (d) **DROP** — UDP query receives no response (client timeout).
//! (e) **TCP-only** — UDP query receives TC=1 (rcode=0); TCP query gets A record.
//! (f) **LocalData** — rcode=0, synthesised A record, AD cleared, EDE 17 (Filtered).
//! (g) **CNAME-redirect** — rcode=0, CNAME answer, AD cleared, EDE 16 (Censored).

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

fn rpz_zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/rpz.test.zone"
    ))
}

fn start_rpz_server() -> (TestServer, spy_dns::SpyDnsServer) {
    let spy_port = free_port();
    let spy_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), spy_port);
    // SpyDNS acts as the root nameserver (via custom root hints). It answers
    // every query with AA=1 and A=1.2.3.4, which satisfies PASSTHRU and
    // TCP-only-TCP resolution paths.
    let spy = spy_dns::SpyDnsServer::start(
        spy_addr,
        vec![SpyResponse::Answer {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        }],
    );

    // Write root hints pointing to SpyDNS.
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, format!("ns1.rpz-test. 3600 IN A 127.0.0.1\n"))
        .expect("write root hints");

    let dns_port = free_port();
    let obs_port = free_port();
    let rpz_path = rpz_zone_path().to_str().expect("valid UTF-8 path");
    let toml = config::minimal_recursive_with_rpz(
        dns_port,
        obs_port,
        &hints_path,
        spy_port,
        "rpz.test.",
        rpz_path,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(3))
        .expect("RPZ recursive resolver did not become ready");

    // Keep the hints tempdir alive for the lifetime of the server.
    std::mem::forget(hints_dir);

    (server, spy)
}

// ── (a) NXDOMAIN ─────────────────────────────────────────────────────────────

/// NXDOMAIN action: rcode=3, empty answer section, AD=0, EDE 15 (Blocked).
#[test]
fn rpz_nxdomain_returns_nxdomain() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "nxdomain.example.com.");

    assert_eq!(
        resp.rcode, 3,
        "NXDOMAIN action must return rcode=3; got {}",
        resp.rcode
    );
    assert_eq!(resp.ancount, 0, "NXDOMAIN must have empty answer section");
    assert!(!resp.ad, "NXDOMAIN must clear the AD bit");
    assert_eq!(
        resp.opt_ede_code,
        Some(15),
        "NXDOMAIN must carry EDE 15 (Blocked); got {:?}",
        resp.opt_ede_code
    );
}

// ── (b) NODATA ────────────────────────────────────────────────────────────────

/// NODATA action: rcode=0 (NoError), empty answer section, AD=0, EDE 15 (Blocked).
#[test]
fn rpz_nodata_returns_noerror_empty_answer() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "nodata.example.com.");

    assert_eq!(
        resp.rcode, 0,
        "NODATA action must return rcode=0; got {}",
        resp.rcode
    );
    assert_eq!(resp.ancount, 0, "NODATA must have empty answer section");
    assert!(!resp.ad, "NODATA must clear the AD bit");
    assert_eq!(
        resp.opt_ede_code,
        Some(15),
        "NODATA must carry EDE 15 (Blocked); got {:?}",
        resp.opt_ede_code
    );
}

// ── (c) PASSTHRU ─────────────────────────────────────────────────────────────

/// PASSTHRU action: RPZ is bypassed and the upstream A record is returned.
#[test]
fn rpz_passthru_returns_upstream_answer() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "passthru.example.com.");

    assert_eq!(
        resp.rcode, 0,
        "PASSTHRU action must return rcode=0; got {}",
        resp.rcode
    );
    assert!(
        resp.ancount >= 1,
        "PASSTHRU must return the upstream A record"
    );
}

// ── (d) DROP ─────────────────────────────────────────────────────────────────

/// DROP action on UDP: no response is sent; the client times out.
#[test]
fn rpz_drop_sends_no_udp_response() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::try_query_a(server.dns_addr(), "drop.example.com.");

    assert!(resp.is_none(), "DROP action must not send any UDP response");
}

// ── (e) TCP-only ──────────────────────────────────────────────────────────────

/// TCP-only action on UDP: TC=1 is returned so the client retries over TCP.
#[test]
fn rpz_tcp_only_returns_tc_on_udp() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "tcponly.example.com.");

    assert!(
        resp.tc,
        "TCP-only action must set TC=1 on UDP; got tc={}",
        resp.tc
    );
    assert_eq!(
        resp.rcode, 0,
        "TCP-only TC response must have rcode=0; got {}",
        resp.rcode
    );
}

/// TCP-only action on TCP: the query is resolved normally and the A record returned.
#[test]
fn rpz_tcp_only_pass_through_on_tcp() {
    let (server, _spy) = start_rpz_server();

    // Send the query over TCP — the dispatcher sees is_udp=false, so TcpOnly
    // passes through and the recursive resolver delivers the upstream answer.
    let resp = dns_client::query_tcp(server.dns_addr(), "tcponly.example.com.", 1 /* A */);

    assert_eq!(
        resp.rcode, 0,
        "TCP-only on TCP must return rcode=0; got {}",
        resp.rcode
    );
    assert!(
        resp.ancount >= 1,
        "TCP-only on TCP must return the upstream A record"
    );
}

// ── (f) LocalData ─────────────────────────────────────────────────────────────

/// LocalData action: synthesised A record returned, AD=0, EDE 17 (Filtered).
#[test]
fn rpz_localdata_returns_synthesised_record() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "localdata.example.com.");

    assert_eq!(
        resp.rcode, 0,
        "LocalData action must return rcode=0; got {}",
        resp.rcode
    );
    assert!(
        resp.ancount >= 1,
        "LocalData must return at least one answer record"
    );
    assert!(!resp.ad, "LocalData must clear the AD bit");
    assert_eq!(
        resp.opt_ede_code,
        Some(17),
        "LocalData must carry EDE 17 (Filtered); got {:?}",
        resp.opt_ede_code
    );
}

// ── (g) CNAME-redirect ────────────────────────────────────────────────────────

/// CNAME-redirect action: CNAME answer to the configured target, AD=0, EDE 16 (Censored).
#[test]
fn rpz_cname_redirect_returns_cname_answer() {
    let (server, _spy) = start_rpz_server();

    let resp = dns_client::query_a(server.dns_addr(), "redirect.example.com.");

    assert_eq!(
        resp.rcode, 0,
        "CnameRedirect must return rcode=0; got {}",
        resp.rcode
    );
    assert!(
        resp.ancount >= 1,
        "CnameRedirect must return at least one answer record"
    );
    // TYPE 5 = CNAME.
    assert!(
        resp.answer_types.contains(&5),
        "CnameRedirect answer section must contain a CNAME record; types={:?}",
        resp.answer_types
    );
    assert!(!resp.ad, "CnameRedirect must clear the AD bit");
    assert_eq!(
        resp.opt_ede_code,
        Some(16),
        "CnameRedirect must carry EDE 16 (Censored); got {:?}",
        resp.opt_ede_code
    );
}
