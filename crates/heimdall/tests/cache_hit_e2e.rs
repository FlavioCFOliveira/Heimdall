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

//! E2E: cache hit — second query served from cache + metric counters
//! (Sprint 47 task #559).
//!
//! Three scenarios:
//!
//! (a) **Recursive cache hit** — recursive role with a slow in-test root
//!     (200 ms delay).  Q1 takes ≥ 100 ms (upstream miss); Q2 is served
//!     from the in-process cache and takes < 150 ms.  `/metrics` shows
//!     `heimdall_cache_misses_total{role="recursive"} = 1` and
//!     `heimdall_cache_hits_total{role="recursive"} = 1`.
//!
//! (b) **Forwarder cache hit** — forwarder role with a slow in-test upstream
//!     (200 ms delay).  Same timing and metric assertions, but with
//!     `role="forwarder"` labels.
//!
//! (c) **TTL expiry triggers upstream re-fetch** — recursive role with a
//!     fast in-test root and TTL=1 s.  After Q1 (miss) and Q2 (fresh hit),
//!     waiting 2 s causes the TTL to expire.  Q3 returns stale data and
//!     simultaneously triggers a background re-resolution: the upstream
//!     query counter advances.

#![cfg(unix)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, spy_dns::SlowDnsServer};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

// ── Shared helpers ────────────────────────────────────────────────────────────

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

/// Parse an `OpenMetrics` labeled counter such as
/// `heimdall_cache_hits_total{role="recursive"} 3`.
fn parse_labeled_counter(body: &str, metric_name: &str, role: &str) -> u64 {
    let prefix = format!("{metric_name}{{role=\"{role}\"}}");
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with(prefix.as_str())
            && let Some(val_str) = trimmed.split_whitespace().nth(1)
        {
            return val_str.parse().unwrap_or(0);
        }
    }
    0
}

// ── (a) Recursive cache hit ───────────────────────────────────────────────────

/// Q1 is a cache miss — upstream latency ≥ 100 ms (200 ms injected).
/// Q2 is served from the in-process cache — < 150 ms.
/// `/metrics` must show exactly 1 miss and 1 hit for the recursive role.
#[test]
fn recursive_cache_hit_and_metrics() {
    let upstream_port = free_port();
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    let upstream = SlowDnsServer::start(upstream_addr, 200, Ipv4Addr::new(1, 2, 3, 4), 300);

    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, "ns1.cache-root. 3600 IN A 127.0.0.1\n").expect("write root hints");

    let rec_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_recursive_custom_with_qname_min(
        rec_port,
        obs_port,
        &hints_path,
        upstream_port,
        "off",
    );
    let server = TestServer::start_with_ports(BIN, &toml, rec_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("recursive server did not become ready");

    // Give the server time to initialize its root hints.
    std::thread::sleep(Duration::from_millis(200));

    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_port}").parse().unwrap();

    // Q1: cache miss — the upstream adds a 200 ms delay.
    let t1 = Instant::now();
    let r1 = dns_client::query_a(rec_addr, "slow.cache-test.");
    let q1_elapsed = t1.elapsed();

    assert_eq!(r1.rcode, 0, "Q1 must be NOERROR; got rcode={}", r1.rcode);
    assert!(
        q1_elapsed >= Duration::from_millis(100),
        "Q1 must take ≥ 100 ms (upstream miss with 200 ms delay); got {q1_elapsed:?}"
    );

    // Q2: cache hit — served from the in-process cache.
    let t2 = Instant::now();
    let r2 = dns_client::query_a(rec_addr, "slow.cache-test.");
    let q2_elapsed = t2.elapsed();

    assert_eq!(r2.rcode, 0, "Q2 must be NOERROR; got rcode={}", r2.rcode);
    assert!(
        q2_elapsed < Duration::from_millis(150),
        "Q2 must take < 150 ms (cache hit); got {q2_elapsed:?}"
    );

    // Allow the server a moment to update the counters.
    std::thread::sleep(Duration::from_millis(100));

    let body = fetch_metrics(server.obs_addr());
    let misses = parse_labeled_counter(&body, "heimdall_cache_misses_total", "recursive");
    let hits = parse_labeled_counter(&body, "heimdall_cache_hits_total", "recursive");

    assert_eq!(
        misses, 1,
        "heimdall_cache_misses_total{{role=\"recursive\"}} must be 1; metrics:\n{body}"
    );
    assert_eq!(
        hits, 1,
        "heimdall_cache_hits_total{{role=\"recursive\"}} must be 1; metrics:\n{body}"
    );

    drop(upstream);
}

// ── (b) Forwarder cache hit ───────────────────────────────────────────────────

/// Q1 is a cache miss — upstream latency ≥ 100 ms (200 ms injected).
/// Q2 is served from the in-process cache — < 150 ms.
/// `/metrics` must show exactly 1 miss and 1 hit for the forwarder role.
#[test]
fn forwarder_cache_hit_and_metrics() {
    let upstream_port = free_port();
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    let upstream = SlowDnsServer::start(upstream_addr, 200, Ipv4Addr::new(5, 6, 7, 8), 300);

    let fwd_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_forwarder(fwd_port, obs_port, "127.0.0.1", upstream_port);
    let server = TestServer::start_with_ports(BIN, &toml, fwd_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("forwarder server did not become ready");

    let fwd_addr: SocketAddr = format!("127.0.0.1:{fwd_port}").parse().unwrap();

    // Q1: cache miss — the upstream adds a 200 ms delay.
    let t1 = Instant::now();
    let r1 = dns_client::query_a(fwd_addr, "fwd.cache-test.");
    let q1_elapsed = t1.elapsed();

    assert_eq!(r1.rcode, 0, "Q1 must be NOERROR; got rcode={}", r1.rcode);
    assert!(
        q1_elapsed >= Duration::from_millis(100),
        "Q1 must take ≥ 100 ms (upstream miss with 200 ms delay); got {q1_elapsed:?}"
    );

    // Q2: cache hit — served from the in-process cache.
    let t2 = Instant::now();
    let r2 = dns_client::query_a(fwd_addr, "fwd.cache-test.");
    let q2_elapsed = t2.elapsed();

    assert_eq!(r2.rcode, 0, "Q2 must be NOERROR; got rcode={}", r2.rcode);
    assert!(
        q2_elapsed < Duration::from_millis(150),
        "Q2 must take < 150 ms (cache hit); got {q2_elapsed:?}"
    );

    std::thread::sleep(Duration::from_millis(100));

    let body = fetch_metrics(server.obs_addr());
    let misses = parse_labeled_counter(&body, "heimdall_cache_misses_total", "forwarder");
    let hits = parse_labeled_counter(&body, "heimdall_cache_hits_total", "forwarder");

    assert_eq!(
        misses, 1,
        "heimdall_cache_misses_total{{role=\"forwarder\"}} must be 1; metrics:\n{body}"
    );
    assert_eq!(
        hits, 1,
        "heimdall_cache_hits_total{{role=\"forwarder\"}} must be 1; metrics:\n{body}"
    );

    drop(upstream);
}

// ── (c) TTL expiry triggers upstream re-fetch ─────────────────────────────────

/// After Q1 (cache miss) and Q2 (fresh cache hit), waiting 2 s lets the
/// TTL=1 s record expire.  Q3 is served from stale cache but simultaneously
/// triggers a background re-resolution: `upstream.query_count()` must
/// increase beyond the count seen after Q1.
#[test]
fn recursive_ttl_expiry_triggers_upstream_refetch() {
    let upstream_port = free_port();
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    // No delay — we only care about the upstream query count, not timing.
    let upstream = SlowDnsServer::start(upstream_addr, 0, Ipv4Addr::new(9, 10, 11, 12), 1);

    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, "ns1.cache-root. 3600 IN A 127.0.0.1\n").expect("write root hints");

    let rec_port = free_port();
    let obs_port = free_port();
    // min_ttl_secs=1 so the 1-second TTL from SlowDnsServer is not raised
    // to the default 60-second minimum.
    let toml = config::minimal_recursive_custom_with_qname_min_and_min_ttl(
        rec_port,
        obs_port,
        &hints_path,
        upstream_port,
        "off",
        1,
    );
    let _server = TestServer::start_with_ports(BIN, &toml, rec_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("recursive server did not become ready");

    std::thread::sleep(Duration::from_millis(200));

    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_port}").parse().unwrap();

    // Q1: cache miss — upstream is queried.
    let r1 = dns_client::query_a(rec_addr, "ttl.cache-test.");
    assert_eq!(r1.rcode, 0, "Q1 must be NOERROR");
    let count_after_q1 = upstream.query_count();
    assert!(
        count_after_q1 >= 1,
        "Q1 must trigger at least one upstream query; got count={count_after_q1}"
    );

    // Q2: fresh cache hit — no new upstream query.
    let r2 = dns_client::query_a(rec_addr, "ttl.cache-test.");
    assert_eq!(r2.rcode, 0, "Q2 must be NOERROR");
    assert_eq!(
        upstream.query_count(),
        count_after_q1,
        "Q2 (fresh cache hit) must not trigger a new upstream query"
    );

    // Wait for TTL=1 s to expire.
    std::thread::sleep(Duration::from_secs(2));

    // Q3: stale cache hit — served from cache, but triggers background re-resolution.
    let r3 = dns_client::query_a(rec_addr, "ttl.cache-test.");
    assert_eq!(r3.rcode, 0, "Q3 (stale) must be NOERROR");

    // Allow the background refresh task to complete and query the upstream.
    std::thread::sleep(Duration::from_millis(500));

    let count_after_q3 = upstream.query_count();
    assert!(
        count_after_q3 > count_after_q1,
        "Q3 (stale cache hit) must trigger a background upstream re-fetch; \
        count_after_q1={count_after_q1}, count_after_q3={count_after_q3}"
    );
}
