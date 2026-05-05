// SPDX-License-Identifier: MIT

//! E2E: RRL on authoritative — statistical slip ratio, bucket independence,
//! default-on (Sprint 47 task #594, THREAT-048..050).
//!
//! Three sub-cases:
//!
//! (a) **Statistical slip ratio** — with `rate=1, slip_ratio=2`, send 41
//!     queries in a burst.  1 is allowed; the 40 over-budget are alternately
//!     Drop/Slip.  The count of TC=1 responses must fall within ±10% of the
//!     theoretical expectation (20 slips out of 40 over-budget queries).
//!
//! (b) **Bucket independence** — 4 distinct qname buckets (same source prefix,
//!     different qnames).  Exhausting one bucket must not affect the remaining
//!     three.  Each of the 4 first-queries must receive NOERROR, even after the
//!     other buckets have been exhausted.
//!
//! (c) **Default-on** — a `[rate_limit]` section that specifies only
//!     `responses_per_second = 1` (no explicit `enabled = true`) must still
//!     activate RRL, proving that `enabled` defaults to `true` (THREAT-050).

#![cfg(unix)]

use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
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

// ── Wire helpers (local, no harness dependency) ───────────────────────────────

/// Build a minimal A-type DNS query for `qname`.
fn build_query_wire(id: u16, qname: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&[0u8; 6]); // AN/NS/ARCOUNT=0

    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8);

    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    buf
}

/// Send `count` UDP queries for `qname` to `server` as fast as possible, then
/// collect all responses within a 300 ms window.
///
/// Returns `(noerror_count, tc_count)` — does NOT count drops (no response).
fn flood_and_count(server: SocketAddr, qname: &str, count: usize) -> (usize, usize) {
    let wire = build_query_wire(0xAB42, qname);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind flood socket");
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set_read_timeout");

    for _ in 0..count {
        sock.send_to(&wire, server).expect("send_to");
    }

    let mut noerror = 0usize;
    let mut tc = 0usize;
    let mut buf = [0u8; 512];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) if n >= 4 => {
                let flags = u16::from_be_bytes([buf[2], buf[3]]);
                let is_tc = (flags & 0x0200) != 0;
                let rcode = (flags & 0x000F) as u8;
                if is_tc {
                    tc += 1;
                } else if rcode == 0 {
                    noerror += 1;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
            Err(e) => panic!("unexpected recv error: {e}"),
        }
    }
    (noerror, tc)
}

// ── (a) Statistical slip ratio ────────────────────────────────────────────────

/// With `rate=1, slip_ratio=2`, send 41 queries in a burst.
///
/// Theoretical breakdown:
/// - 1 allowed (NOERROR).
/// - 40 over-budget: slip at every even slip_counter (2, 4, … 40) → 20 slips.
/// - Drop at every odd slip_counter (1, 3, … 39) → 20 drops.
///
/// The measured TC=1 count must be within ±10% of 20 (i.e., in [18, 22]).
#[test]
fn rrl_statistical_slip_ratio_within_ten_percent() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_rrl(dns_port, obs_port, "example.com.", zone_path(), 1);
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    let total = 41usize;
    let (_, tc_count) = flood_and_count(server.dns_addr(), "example.com.", total);

    // Expected: 20 slips (every other over-budget query, slip_ratio=2).
    let expected: f64 = 20.0;
    let tolerance = (expected * 0.10).ceil() as usize; // 2
    let lo = (expected as usize).saturating_sub(tolerance);
    let hi = expected as usize + tolerance;

    assert!(
        tc_count >= lo && tc_count <= hi,
        "RRL statistical slip test: expected TC=1 count in [{lo}, {hi}] \
         (±10% of {expected}); got {tc_count} out of {total} queries"
    );
}

// ── (b) Bucket independence ────────────────────────────────────────────────────

/// Exhausting the RRL bucket for qname A must not affect the budget of qname B.
///
/// Proof:
/// 1. Exhaust bucket `example.com.` — three sequential queries in the same
///    1-second window: NOERROR (Q1), Drop (Q2, 500 ms wait), Slip/TC=1 (Q3).
///    Q3 proves the bucket is fully exhausted.
/// 2. Send the FIRST query for each of three OTHER qnames (all happen within
///    the same 1-second window).  Each must be NOERROR because those buckets
///    are independent — they carry their own budget, unaffected by A.
///
/// If qnames incorrectly shared a single bucket, the first queries to B/C/D
/// would be rate-limited after A's budget was consumed.
#[test]
fn rrl_buckets_are_independent_across_qnames() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_rrl(dns_port, obs_port, "example.com.", zone_path(), 1);
    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // ── Step 1: exhaust bucket for "example.com." ─────────────────────────────
    // Q1: within budget → NOERROR.
    let a1 = dns_client::query_a(server.dns_addr(), "example.com.");
    assert_eq!(
        a1.rcode, 0,
        "Q1 for example.com. must be NOERROR (within budget)"
    );
    assert!(!a1.tc, "Q1 for example.com. must not be TC=1");

    // Q2: over-budget, slip_counter=1 (odd) → Drop (no response, 500 ms wait).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");

    // Q3: over-budget, slip_counter=2 (even) → Slip (TC=1).
    // This confirms the bucket is fully exhausted with slip firing.
    let a3 = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        a3.tc,
        "Q3 for example.com. must be TC=1 (slip_counter=2, slip_ratio=2); \
         got rcode={}, tc={}",
        a3.rcode, a3.tc
    );

    // ── Step 2: first queries for independent qnames must all be NOERROR ──────
    // All three queries arrive within the same 1-second window as the exhausted
    // bucket.  If the engine shared a budget across qnames, these would be
    // rate-limited — independence guarantees they are not.
    let independent = ["ns1.example.com.", "ns2.example.com.", "mail.example.com."];
    for name in independent {
        let resp = dns_client::query_a(server.dns_addr(), name);
        assert_eq!(
            resp.rcode, 0,
            "first query for {name} must be NOERROR — \
             bucket is independent from the exhausted example.com. bucket"
        );
        assert!(
            !resp.tc,
            "first query for {name} must not be TC=1 — bucket has full budget"
        );
    }
}

// ── (c) Default-on without explicit `enabled = true` ─────────────────────────

/// A `[rate_limit]` section with only `responses_per_second = 1` and no
/// `enabled` field must activate RRL because `enabled` defaults to `true`.
///
/// If `enabled` incorrectly defaulted to `false`, the rate limiter would be
/// bypassed and all queries would receive NOERROR — the TC=1 slip on the 3rd
/// query would never appear.
#[test]
fn rrl_enabled_by_default_without_explicit_enabled_flag() {
    let dns_port = free_port();
    let obs_port = free_port();

    // Config has `responses_per_second = 1` but NO `enabled = true`.
    // With `enabled` defaulting to `true`, this must activate RRL.
    let path_str = zone_path().to_str().expect("zone path is valid UTF-8");
    let toml = format!(
        r#"[roles]
authoritative = true

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "udp"

[[listeners]]
address = "127.0.0.1"
port = {dns_port}
transport = "tcp"

[observability]
metrics_addr = "127.0.0.1"
metrics_port = {obs_port}

[rate_limit]
responses_per_second = 1

[[zones.zone_files]]
origin = "example.com."
path   = "{path_str}"
"#
    );

    let server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready");

    // Q1: within budget → NOERROR.
    let first = dns_client::query_a(server.dns_addr(), "example.com.");
    assert_eq!(first.rcode, 0, "first query must be NOERROR");
    assert!(!first.tc, "first query must not be truncated");

    // Q2: budget exhausted, slip_counter=1 (odd) → Drop (no response).
    let _ = dns_client::try_query_a(server.dns_addr(), "example.com.");

    // Q3: budget exhausted, slip_counter=2 (even) → Slip (TC=1).
    // If `enabled` defaulted to `false`, this would be NOERROR (RRL bypassed).
    let slip = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        slip.tc,
        "third query must have TC=1 when `enabled` defaults to true \
         (responses_per_second=1 without explicit enabled=true); \
         got rcode={}, tc={}",
        slip.rcode, slip.tc,
    );
}
