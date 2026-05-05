// SPDX-License-Identifier: MIT

//! E2E: admission pipeline — ACL deny, RRL truncation, per-client query RL
//! (Sprint 47 task #478).
//!
//! Three scenarios, each verifying a distinct admission gate:
//!
//! (a) **ACL deny** — `deny_sources = ["127.0.0.1/32"]` on an authoritative
//!     server.  A query from 127.0.0.1 is silently dropped on UDP (no response);
//!     `/metrics` shows `heimdall_acl_denied_total` > 0.
//!
//! (b) **RRL exceeded** — `responses_per_second = 1` on an authoritative server.
//!     The first query receives NOERROR; the second query in the same window
//!     receives TC=1 (slip); `/metrics` shows `heimdall_rrl_truncated_total` > 0.
//!
//! (c) **Per-client query RL exceeded** — forwarder with `allow_sources =
//!     ["127.0.0.1/32"]` and `query_rate_per_second = 1`.  The first query
//!     receives NOERROR; the second query receives REFUSED;
//!     `/metrics` shows `heimdall_query_rl_refused_total` > 0.

#![cfg(unix)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

/// Perform a minimal HTTP/1.1 GET against the observability server and return
/// the response body.
fn fetch_metrics(obs_addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect_timeout(&obs_addr, Duration::from_secs(3))
        .expect("TCP connect to observability");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();

    let mut reader = BufReader::new(stream);
    let mut body = String::new();

    // Skip status line and headers.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    for line in reader.lines() {
        match line {
            Ok(l) => {
                body.push_str(&l);
                body.push('\n');
            }
            Err(_) => break,
        }
    }

    body
}

/// Parse the integer value of a counter named `metric_name` from an
/// OpenMetrics text body.  Returns 0 when the metric is absent.
fn parse_counter(body: &str, metric_name: &str) -> u64 {
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with(metric_name) {
            if let Some(val_str) = trimmed.split_whitespace().nth(1) {
                return val_str.parse().unwrap_or(0);
            }
        }
    }
    0
}

// ── (a) ACL deny ─────────────────────────────────────────────────────────────

/// An ACL-denied source receives no UDP response (silent drop on UDP).
#[test]
fn acl_denied_source_receives_no_udp_response() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_acl_deny(
        dns_port,
        obs_port,
        "example.com.",
        zone_path(),
        "127.0.0.1/32",
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    let resp = dns_client::try_query_a(server.dns_addr(), "example.com.");

    assert!(
        resp.is_none(),
        "expected no response for ACL-denied source, got: {resp:?}"
    );
}

/// After an ACL-denied query, `heimdall_acl_denied_total` is > 0.
#[test]
fn acl_denied_source_increments_acl_denied_counter() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_acl_deny(
        dns_port,
        obs_port,
        "example.com.",
        zone_path(),
        "127.0.0.1/32",
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // Send a query (it will be dropped, so use try_query_a).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");

    // Give the server a moment to update the counter.
    std::thread::sleep(Duration::from_millis(100));

    let body = fetch_metrics(server.obs_addr());
    let denied = parse_counter(&body, "heimdall_acl_denied_total");
    assert!(
        denied > 0,
        "heimdall_acl_denied_total must be > 0 after a denied query; metrics:\n{body}"
    );
}

// ── (b) RRL — TC=1 slip ───────────────────────────────────────────────────────

/// With RRL at 1 rps, the first query succeeds (NOERROR).  With the default
/// slip_ratio=2 the first suppressed query is silently dropped and the second
/// suppressed query receives TC=1 — so the 3rd overall query gets TC=1.
#[test]
fn rrl_exceeded_returns_tc1_on_slip_query() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_rrl(dns_port, obs_port, "example.com.", zone_path(), 1);
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // 1st query: within budget → NOERROR.
    let first = dns_client::query_a(server.dns_addr(), "example.com.");
    assert_eq!(first.rcode, 0, "first query must be NOERROR");
    assert!(!first.tc, "first query must not be truncated");

    // 2nd query: budget exhausted, slip_counter=1 → Drop (no response).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");

    // 3rd query: budget exhausted, slip_counter=2 → Slip (TC=1).
    let slip = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        slip.tc,
        "third query must have TC=1 (RRL slip after default slip_ratio=2)"
    );
}

/// After an RRL slip, `heimdall_rrl_truncated_total` is > 0.
#[test]
fn rrl_exceeded_increments_rrl_truncated_counter() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_rrl(dns_port, obs_port, "example.com.", zone_path(), 1);
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // 1st query: within budget → admitted.
    let _ = dns_client::query_a(server.dns_addr(), "example.com.");
    // 2nd query: slip_counter=1 → Drop (no response, use try_query_a).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");
    // 3rd query: slip_counter=2 → Slip (TC=1 sent, increments rrl_slipped).
    let _ = dns_client::query_a(server.dns_addr(), "example.com.");

    std::thread::sleep(Duration::from_millis(100));

    let body = fetch_metrics(server.obs_addr());
    let slipped = parse_counter(&body, "heimdall_rrl_truncated_total");
    assert!(
        slipped > 0,
        "heimdall_rrl_truncated_total must be > 0 after RRL slip; metrics:\n{body}"
    );
}

// ── (c) Per-client query RL — REFUSED ────────────────────────────────────────

/// With query RL at 1 qps, the second query from the same client receives
/// REFUSED (RCODE=5) immediately from the admission pipeline, before the
/// forwarder ever contacts an upstream.
///
/// The first query is admitted and forwarded; the upstream is unreachable so
/// no response arrives within the test timeout — `try_query_a` handles that.
/// The second query is caught by the rate limiter and refused immediately.
#[test]
fn query_rl_exceeded_returns_refused_on_second_query() {
    let dns_port = free_port();
    let obs_port = free_port();
    let upstream_port = free_port();
    let toml = config::minimal_forwarder_with_query_rl(
        dns_port,
        obs_port,
        "127.0.0.1",
        upstream_port,
        "127.0.0.1/32",
        1,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // First query: admitted by rate limiter, forwarded.  Upstream unreachable →
    // response may or may not arrive within the 500 ms window (try_query_a).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");

    // Second query: rate limit exceeded → immediate REFUSED from admission.
    let second = dns_client::query_a(server.dns_addr(), "example.com.");
    assert_eq!(
        second.rcode, 5,
        "second query must be REFUSED when per-client query RL is exceeded"
    );
}

/// After a query RL refusal, `heimdall_query_rl_refused_total` is > 0.
#[test]
fn query_rl_exceeded_increments_query_rl_refused_counter() {
    let dns_port = free_port();
    let obs_port = free_port();
    let upstream_port = free_port();
    let toml = config::minimal_forwarder_with_query_rl(
        dns_port,
        obs_port,
        "127.0.0.1",
        upstream_port,
        "127.0.0.1/32",
        1,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // First query: admitted by rate limiter, forwarded to unreachable upstream.
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");
    // Second query: rate limit exceeded → immediate REFUSED (increments counter).
    let _ = dns_client::query_a(server.dns_addr(), "example.com.");

    std::thread::sleep(Duration::from_millis(100));

    let body = fetch_metrics(server.obs_addr());
    let refused = parse_counter(&body, "heimdall_query_rl_refused_total");
    assert!(
        refused > 0,
        "heimdall_query_rl_refused_total must be > 0 after query RL refusal; metrics:\n{body}"
    );
}
