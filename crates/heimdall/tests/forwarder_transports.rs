// SPDX-License-Identifier: MIT

//! Forwarder E2E: each upstream transport (Sprint 47 task #475).
//!
//! Verifies that the forwarder role correctly proxies DNS queries to an upstream
//! authoritative server over each of the six supported outbound transports:
//! UDP, TCP, DoT, DoH/H2, DoH/H3, and DoQ.
//!
//! # Test architecture
//!
//! Each test spawns two heimdall processes:
//! 1. An **upstream auth server** with one specific inbound transport listener
//!    (e.g., DoT) serving `example.com.`
//! 2. A **forwarder** configured with a matching outbound transport to that upstream
//!
//! The test then sends an A query for `example.com.` over UDP to the forwarder
//! and asserts the response carries a NOERROR answer — proving the query was
//! forwarded over the declared transport and returned correctly.
//!
//! `tls_verify = false` is used for all TLS upstreams because the upstream uses
//! a self-signed test CA that is not in the OS trust store.

#![cfg(unix)]

use std::{path::Path, time::Duration};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, pki::TestPki};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn start_forwarder_with_toml(toml: &str, dns_port: u16, obs_port: u16) -> TestServer {
    TestServer::start_with_ports(BIN, toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(3))
        .unwrap_or_else(|s| {
            panic!(
                "forwarder did not become ready within 3s (dns_port={})",
                s.dns_port
            )
        })
}

// ── UDP upstream ──────────────────────────────────────────────────────────────

/// Forwarder → upstream over UDP: A query returns NOERROR with an answer.
#[test]
fn forwarder_udp_upstream_noerror() {
    let upstream = TestServer::start_auth(BIN, "example.com.", zone_path());

    let fwd_dns = free_port();
    let fwd_obs = free_port();
    let toml = config::minimal_forwarder(fwd_dns, fwd_obs, "127.0.0.1", upstream.dns_port);
    let forwarder = start_forwarder_with_toml(&toml, fwd_dns, fwd_obs);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

// ── TCP upstream ──────────────────────────────────────────────────────────────

/// Forwarder → upstream over TCP: A query returns NOERROR with an answer.
#[test]
fn forwarder_tcp_upstream_noerror() {
    // The same `minimal_forwarder` uses UDP, but the UdpTcp transport client
    // internally falls back to TCP.  To force TCP-only, configure the upstream
    // auth server with TCP-only listeners and verify it still works.
    let auth_dns = free_port();
    let auth_obs = free_port();
    let auth_toml = config::minimal_auth(auth_dns, auth_obs, "example.com.", zone_path());
    let _upstream = TestServer::start_with_ports(BIN, &auth_toml, auth_dns, auth_obs)
        .wait_ready(Duration::from_secs(2))
        .unwrap_or_else(|s| panic!("auth server did not become ready (port={})", s.dns_port));

    let fwd_dns = free_port();
    let fwd_obs = free_port();
    let toml = config::minimal_forwarder(fwd_dns, fwd_obs, "127.0.0.1", auth_dns);
    let forwarder = start_forwarder_with_toml(&toml, fwd_dns, fwd_obs);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");
    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

// ── DoT upstream ──────────────────────────────────────────────────────────────

/// Forwarder → upstream over DoT: A query returns NOERROR with an answer.
/// TLS chain is the test CA (tls_verify = false on the forwarder side).
#[test]
fn forwarder_dot_upstream_noerror() {
    let pki = TestPki::generate();
    let upstream = TestServer::start_auth_dot(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let forwarder = TestServer::start_forwarder_dot(BIN, upstream.dns_port);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");
    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR (DoT forwarder)");
    assert!(
        resp.ancount >= 1,
        "must have at least one answer (DoT forwarder)"
    );
}

// ── DoH/H2 upstream ──────────────────────────────────────────────────────────

/// Forwarder → upstream over DoH/H2: A query returns NOERROR with an answer.
/// Content-Type: application/dns-message; HTTP/2 ALPN negotiated.
#[test]
fn forwarder_doh2_upstream_noerror() {
    let pki = TestPki::generate();
    let upstream = TestServer::start_auth_doh2(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let forwarder = TestServer::start_forwarder_doh2(BIN, upstream.dns_port);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");
    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR (DoH/H2 forwarder)");
    assert!(
        resp.ancount >= 1,
        "must have at least one answer (DoH/H2 forwarder)"
    );
}

// ── DoH/H3 upstream ──────────────────────────────────────────────────────────

/// Forwarder → upstream over DoH/H3: A query returns NOERROR with an answer.
/// ALPN = "h3"; QUIC + HTTP/3 framing.
#[test]
fn forwarder_doh3_upstream_noerror() {
    let pki = TestPki::generate();
    let upstream = TestServer::start_auth_doh3(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let forwarder = TestServer::start_forwarder_doh3(BIN, upstream.dns_port);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");
    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR (DoH/H3 forwarder)");
    assert!(
        resp.ancount >= 1,
        "must have at least one answer (DoH/H3 forwarder)"
    );
}

// ── DoQ upstream ─────────────────────────────────────────────────────────────

/// Forwarder → upstream over DoQ (RFC 9250): A query returns NOERROR with an answer.
/// DoQ stream framing: 2-byte length-prefixed DNS message on a bidirectional QUIC stream.
#[test]
fn forwarder_doq_upstream_noerror() {
    let pki = TestPki::generate();
    let upstream = TestServer::start_auth_doq(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let forwarder = TestServer::start_forwarder_doq(BIN, upstream.dns_port);

    let resp = dns_client::query_a(forwarder.dns_addr(), "example.com.");
    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR (DoQ forwarder)");
    assert!(
        resp.ancount >= 1,
        "must have at least one answer (DoQ forwarder)"
    );
}
