// SPDX-License-Identifier: MIT

//! E2E: Disabled role — zero state, zero network code path (ROLE-005, ROLE-006).
//!
//! Three deployment shapes are verified:
//!
//! 1. **auth-only** — recursive and forwarder roles disabled:
//!    - Out-of-zone queries return REFUSED (step-4), never routed to a
//!      recursive resolver.
//!    - Metrics: `heimdall_queries_total{role="recursive"}` stays at 0.
//!
//! 2. **recursive-only** — authoritative and forwarder roles disabled:
//!    - The auth server is never instantiated; no zones are loaded.
//!    - Metrics: `heimdall_queries_total{role="authoritative"}` stays at 0
//!      even after sending queries.
//!
//! 3. **auth+recursive** — forwarder role disabled:
//!    - No forwarder upstream rules; no ForwarderCache is populated.
//!    - Metrics: `heimdall_cache_hits_total{role="forwarder"}` and
//!      `heimdall_cache_misses_total{role="forwarder"}` both stay at 0.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── Metrics helpers ───────────────────────────────────────────────────────────

fn fetch_metrics(obs_addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect_timeout(&obs_addr, Duration::from_secs(3))
        .expect("TCP connect to observability");
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();

    let mut reader = BufReader::new(stream);
    let mut past_headers = false;
    let mut body = String::new();

    for line in reader.lines() {
        match line {
            Ok(l) => {
                if !past_headers {
                    if l.trim().is_empty() {
                        past_headers = true;
                    }
                    continue;
                }
                body.push_str(&l);
                body.push('\n');
            }
            Err(_) => break,
        }
    }
    body
}

/// Extract the value of a specific metric label combination from the metrics body.
/// Returns 0 if the metric line is not found.
fn metric_value(body: &str, prefix: &str) -> u64 {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(prefix) {
            if let Some(val_str) = line.trim().split_whitespace().last() {
                return val_str.parse().unwrap_or(0);
            }
        }
    }
    0
}

// ── Shape 1: auth-only ────────────────────────────────────────────────────────

/// ROLE-005/006: auth-only — recursive role is absent.
///
/// Verifies:
/// - In-zone query (example.com. A) returns AA=1, rcode=0.
/// - Out-of-zone query (external.test. A) returns REFUSED (rcode=5), not
///   SERVFAIL — proving the recursive engine is NOT running.
/// - `heimdall_queries_total{role="recursive"}` stays at 0 after both queries.
#[test]
fn auth_only_recursive_role_absent() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path());

    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("auth-only server did not become ready within 5 s");

    let dns = server.dns_addr();

    // In-zone query must be answered authoritatively.
    let auth_resp = dns_client::query_a(dns, "example.com.");
    assert_eq!(
        auth_resp.rcode, 0,
        "in-zone query must succeed; got rcode={}",
        auth_resp.rcode
    );
    assert!(
        auth_resp.aa,
        "in-zone query must have AA=1 (authoritative); got aa={}",
        auth_resp.aa
    );

    // Out-of-zone query must return REFUSED (step-4), not SERVFAIL.
    // If the recursive engine were running, it would attempt resolution
    // and return SERVFAIL (rcode=2) on failure.
    let external_resp = dns_client::query_a(dns, "disabled-recursive.external.test.");
    assert_eq!(
        external_resp.rcode, 5,
        "out-of-zone query must be REFUSED (5) when recursive role is absent; \
         got rcode={} — if this is 2 (SERVFAIL), the recursive engine may be running",
        external_resp.rcode
    );

    // Allow telemetry to propagate.
    std::thread::sleep(Duration::from_millis(100));

    let metrics = fetch_metrics(server.obs_addr());
    let recursive_counter =
        metric_value(&metrics, "heimdall_queries_total{role=\"recursive\"}");
    assert_eq!(
        recursive_counter, 0,
        "ROLE-005: queries_total{{role=\"recursive\"}} must be 0 when recursive role \
         is disabled; got {recursive_counter}\nmetrics:\n{metrics}"
    );
}

// ── Shape 2: recursive-only ───────────────────────────────────────────────────

/// ROLE-005/006: recursive-only — authoritative role is absent.
///
/// Verifies:
/// - `heimdall_queries_total{role="authoritative"}` stays at 0, confirming the
///   auth server was never instantiated and no zone state exists.
///
/// We send a fire-and-forget UDP packet and do not block on a response because
/// the recursive resolver requires real root-server connectivity, which is not
/// available in CI environments. The metric check is sufficient: the
/// `queries_auth_total` counter can only increment if an AuthServer is
/// assembled and handles a query; since `config.roles.authoritative = false`,
/// no AuthServer is built and the counter is permanently 0.
#[test]
fn recursive_only_auth_role_absent() {
    use std::net::UdpSocket;

    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_recursive(dns_port, obs_port);

    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("recursive-only server did not become ready within 5 s");

    // Fire-and-forget: send a minimal valid DNS query to the server without
    // waiting for a response. This triggers the recursive pipeline without
    // relying on real root-server connectivity.
    //
    // Wire format: ID=0xAB42, flags=0x0100 (RD), QDCOUNT=1, then the
    // question for "auth-absent.example.com. A IN".
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();
    let wire: Vec<u8> = vec![
        0xAB, 0x42, 0x01, 0x00,  // ID + RD flag
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // QDCOUNT=1
        11, b'a', b'u', b't', b'h', b'-', b'a', b'b', b's', b'e', b'n', b't',
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        3, b'c', b'o', b'm', 0,
        0x00, 0x01, 0x00, 0x01,  // A IN
    ];
    let _ = sock.send_to(&wire, dns_addr); // fire-and-forget; ignore errors

    // Allow the server to process the packet and update telemetry.
    std::thread::sleep(Duration::from_millis(300));

    let metrics = fetch_metrics(server.obs_addr());
    let auth_counter =
        metric_value(&metrics, "heimdall_queries_total{role=\"authoritative\"}");
    assert_eq!(
        auth_counter, 0,
        "ROLE-005: queries_total{{role=\"authoritative\"}} must be 0 when authoritative \
         role is disabled; got {auth_counter}\nmetrics:\n{metrics}"
    );
}

// ── Shape 3: auth+recursive (forwarder disabled) ──────────────────────────────

/// ROLE-005/006: auth+recursive — forwarder role is absent.
///
/// Verifies:
/// - `heimdall_cache_hits_total{role="forwarder"}` stays at 0.
/// - `heimdall_cache_misses_total{role="forwarder"}` stays at 0.
///
/// These two metrics can only be non-zero if a ForwarderCache is active, which
/// requires the forwarder role to be assembled.
#[test]
fn auth_recursive_forwarder_role_absent() {
    let dns_port = free_port();
    let obs_port = free_port();

    // auth+recursive config — no forwarder role.
    let toml = format!(
        "[roles]\nauthoritative = true\nrecursive = true\n\n\
         [[listeners]]\naddress = \"127.0.0.1\"\nport = {dns_port}\ntransport = \"udp\"\n\n\
         [observability]\nmetrics_addr = \"127.0.0.1\"\nmetrics_port = {obs_port}\n\n\
         [[zones.zone_files]]\norigin = \"example.com.\"\npath = \"{path}\"\n",
        path = zone_path().display()
    );

    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("auth+recursive server did not become ready within 5 s");

    let dns = server.dns_addr();

    // Send in-zone query (handled by auth) and an out-of-zone query (handled
    // by recursive).
    let _ = dns_client::query_a(dns, "example.com.");
    let _ = dns_client::query_a(dns, "forwarder-absent.external.test.");

    // Allow telemetry to propagate.
    std::thread::sleep(Duration::from_millis(200));

    let metrics = fetch_metrics(server.obs_addr());

    let fwd_hits =
        metric_value(&metrics, "heimdall_cache_hits_total{role=\"forwarder\"}");
    let fwd_misses =
        metric_value(&metrics, "heimdall_cache_misses_total{role=\"forwarder\"}");

    assert_eq!(
        fwd_hits, 0,
        "ROLE-005: cache_hits_total{{role=\"forwarder\"}} must be 0 when forwarder \
         role is disabled; got {fwd_hits}\nmetrics:\n{metrics}"
    );
    assert_eq!(
        fwd_misses, 0,
        "ROLE-005: cache_misses_total{{role=\"forwarder\"}} must be 0 when forwarder \
         role is disabled; got {fwd_misses}\nmetrics:\n{metrics}"
    );
}
