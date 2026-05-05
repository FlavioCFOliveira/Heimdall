// SPDX-License-Identifier: MIT

//! E2E: Multi-role coexistence — authoritative + recursive in the same process
//! (Sprint 47 task #557).
//!
//! One Heimdall instance runs with `[roles] authoritative = true` (serving the
//! `example.com.` test zone) and `[roles] recursive = true` (root hints pointing
//! to an in-test spy server).  A `MultiRoleDispatcher` routes queries:
//!
//! - Names covered by `example.com.` → authoritative role (AA=1).
//! - All other names → recursive role (AA=0).
//!
//! ## Test matrix
//!
//! (a) **Auth query** — `example.com. A` → AA=1, rcode=0, A=192.0.2.1.
//! (b) **Recursive query** — `external.test. A` → AA=0, rcode=0, A=5.5.5.5.
//! (c) **In-zone NXDOMAIN** — `a.b.example.com. A` → NXDOMAIN from auth (AA=1),
//!     not forwarded to recursive.
//! (d) **Per-role metrics** — `heimdall_queries_total{role="authoritative"}` and
//!     `heimdall_queries_total{role="recursive"}` both increment after their
//!     respective queries.
//!
//! QNAME minimisation is disabled (`qname_min_mode = "off"`) for deterministic
//! spy-server sequencing.

#![cfg(unix)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

use heimdall_e2e_harness::{
    TestServer, config, dns_client, free_port, spy_dns, spy_dns::SpyResponse,
};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");
const AUTH_ZONE: &str = "example.com.";
const EXTERNAL_TARGET: &str = "external.test.";
const REC_ANSWER_IP: Ipv4Addr = Ipv4Addr::new(5, 5, 5, 5);

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── Shared test infrastructure ────────────────────────────────────────────────

struct MultiRoleEnv {
    server: TestServer,
    _spy: spy_dns::SpyDnsServer,
    _hints_dir: tempfile::TempDir,
}

fn setup() -> MultiRoleEnv {
    let spy_port = free_port();
    let spy_addr: SocketAddr = format!("127.0.0.1:{spy_port}").parse().unwrap();

    // Spy server covers the whole fake DNS infrastructure for external.test.:
    //   query 0: root-level — referral for external.test. NS at 127.0.0.1:<spy_port>
    //   query 1: auth-level — authoritative A answer 5.5.5.5
    //
    // With qname_min_mode="off", the recursive resolver sends the full QNAME
    // to every upstream, so the spy always receives `external.test. A`.
    let spy = spy_dns::SpyDnsServer::start(
        spy_addr,
        vec![
            SpyResponse::Referral {
                zone: EXTERNAL_TARGET.to_owned(),
                ns_name: "ns1.external.test.".to_owned(),
                glue_ip: Ipv4Addr::LOCALHOST,
            },
            SpyResponse::Answer { ip: REC_ANSWER_IP },
        ],
    );

    // Root hints: point the recursive resolver at the spy server (127.0.0.1).
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, "ns1.root-test. 3600 IN A 127.0.0.1\n").expect("write root hints");

    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_recursive_with_hints(
        dns_port,
        obs_port,
        AUTH_ZONE,
        zone_path(),
        &hints_path,
        spy_port,
    );
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("multi-role server did not become ready within 5 s");

    MultiRoleEnv {
        server,
        _spy: spy,
        _hints_dir: hints_dir,
    }
}

// ── Metrics helpers ───────────────────────────────────────────────────────────

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

/// Parse a counter from the metrics body, matching lines that start with
/// `prefix` (handles both bare name and name-with-labels like `name{...}`).
fn parse_role_counter(body: &str, role: &str) -> u64 {
    let needle = format!("heimdall_queries_total{{role=\"{role}\"}}");
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.trim_start().starts_with(&needle) {
            if let Some(val_str) = line.trim().split_whitespace().nth(1) {
                return val_str.parse().unwrap_or(0);
            }
        }
    }
    0
}

// ── (a) Auth query ────────────────────────────────────────────────────────────

/// Auth query: example.com. A → AA=1, rcode=0, apex A record returned.
#[test]
fn multi_role_auth_query_returns_aa() {
    let env = setup();

    let resp = dns_client::query_a(env.server.dns_addr(), "example.com.");

    assert_eq!(
        resp.rcode, 0,
        "auth query must return rcode=0 (NoError); got {}",
        resp.rcode
    );
    assert!(
        resp.aa,
        "auth query must have AA=1 (Authoritative Answer); got aa={}",
        resp.aa
    );
    assert!(
        resp.ancount >= 1,
        "auth query must return at least one answer record; got ancount={}",
        resp.ancount
    );
}

// ── (b) Recursive query ───────────────────────────────────────────────────────

/// Recursive query: external.test. A → AA=0, rcode=0, A=5.5.5.5.
#[test]
fn multi_role_recursive_query_returns_non_aa() {
    let env = setup();

    let addr = dns_client::query_a_addr(env.server.dns_addr(), EXTERNAL_TARGET);

    assert_eq!(
        addr,
        Some(REC_ANSWER_IP),
        "recursive query must resolve to {REC_ANSWER_IP}; got {addr:?}"
    );

    // Verify AA=0 on the resolved query.
    let resp = dns_client::query_a(env.server.dns_addr(), EXTERNAL_TARGET);
    assert!(
        !resp.aa,
        "recursive answer must NOT have AA=1; got aa={}",
        resp.aa
    );
    assert_eq!(
        resp.rcode, 0,
        "recursive query must return rcode=0 (NoError); got {}",
        resp.rcode
    );
}

// ── (c) In-zone NXDOMAIN ──────────────────────────────────────────────────────

/// In-zone NXDOMAIN: a.b.example.com. A → auth answers NXDOMAIN (AA=1), not
/// forwarded to the recursive resolver.
///
/// `a.b.example.com.` has a two-label prefix which does not match the
/// one-label wildcard `*.example.com.`, so the authoritative server returns
/// NXDOMAIN with AA=1.
#[test]
fn multi_role_in_zone_nxdomain_answered_by_auth() {
    let env = setup();

    let resp = dns_client::query_a(env.server.dns_addr(), "a.b.example.com.");

    assert_eq!(
        resp.rcode, 3,
        "in-zone non-existent name must return rcode=3 (NXDOMAIN); got {}",
        resp.rcode
    );
    assert!(
        resp.aa,
        "in-zone NXDOMAIN must come from auth (AA=1), not recursive; got aa={}",
        resp.aa
    );
}

// ── (d) Per-role metrics ──────────────────────────────────────────────────────

/// Per-role metrics: both `heimdall_queries_total{role="authoritative"}` and
/// `heimdall_queries_total{role="recursive"}` increment after queries to each
/// role.
#[test]
fn multi_role_per_role_metrics_increment() {
    let env = setup();

    // Send one authoritative query and one recursive query.
    let _ = dns_client::query_a(env.server.dns_addr(), "example.com.");
    let _ = dns_client::query_a_addr(env.server.dns_addr(), EXTERNAL_TARGET);

    // Allow a moment for async dispatch to flush.
    std::thread::sleep(Duration::from_millis(200));

    let body = fetch_metrics(env.server.obs_addr());

    let auth_count = parse_role_counter(&body, "authoritative");
    let rec_count = parse_role_counter(&body, "recursive");

    assert!(
        auth_count >= 1,
        "heimdall_queries_total{{role=\"authoritative\"}} must be ≥ 1 after auth query; metrics:\n{body}"
    );
    assert!(
        rec_count >= 1,
        "heimdall_queries_total{{role=\"recursive\"}} must be ≥ 1 after recursive query; metrics:\n{body}"
    );
}
