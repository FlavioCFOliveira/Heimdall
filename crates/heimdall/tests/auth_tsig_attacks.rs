// SPDX-License-Identifier: MIT

//! E2E: TSIG attack scenarios — replay, bad MAC, fudge violation, truncated
//! TSIG record (Sprint 47 task #544).
//!
//! Four scenarios, each targeting a distinct TSIG attack vector:
//!
//! (a) **Replay** — same signed AXFR query sent twice with the identical
//!     `(key_name, time_signed)` tuple.  The second request is rejected;
//!     `heimdall_xfr_tsig_rejected_total` increments.
//!
//! (b) **Bad MAC** — valid TSIG structure but corrupted MAC bytes → REFUSED;
//!     counter increments.
//!
//! (c) **Fudge violation** — TSIG `time_signed = 1` (epoch + 1 s, far outside
//!     the ±300 s fudge window) → REFUSED; counter increments.
//!
//! (d) **Truncated TSIG RDATA** — TYPE=250 additional RR with 2-byte RDATA
//!     (malformed) → FORMERR (rcode=1); counter increments.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use heimdall_e2e_harness::{TestServer, dns_client, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

fn start_tsig_server() -> TestServer {
    TestServer::start_auth_with_tsig(
        BIN,
        "example.com.",
        zone_path(),
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    )
}

fn fetch_metrics(obs_addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect_timeout(&obs_addr, Duration::from_secs(3))
        .expect("TCP connect to observability");
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

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

// ── (a) Replay ────────────────────────────────────────────────────────────────

/// The second AXFR request with the same `(key_name, time_signed)` tuple is
/// rejected.  The `xfr_tsig_rejected_total` counter must be ≥ 1 afterwards.
#[test]
fn tsig_replay_is_refused() {
    let server = start_tsig_server();

    // query_axfr_replay sends the same signed query twice and returns the
    // second response.
    let resp = dns_client::query_axfr_replay(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
        tsig::KEY_BYTES,
    );

    assert_eq!(resp.rcode, 5, "replayed AXFR must be REFUSED (rcode=5); got {}", resp.rcode);

    let body = fetch_metrics(server.obs_addr());
    let rejected = parse_counter(&body, "heimdall_xfr_tsig_rejected_total");
    assert!(
        rejected >= 1,
        "xfr_tsig_rejected_total must be ≥ 1 after replay; metrics:\n{body}"
    );
}

// ── (b) Bad MAC ───────────────────────────────────────────────────────────────

/// An AXFR query signed with a valid TSIG structure but corrupted MAC bytes
/// must be REFUSED and increment the rejection counter.
#[test]
fn tsig_bad_mac_is_refused() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_bad_mac(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
        tsig::KEY_BYTES,
    );

    assert_eq!(resp.rcode, 5, "bad-MAC AXFR must be REFUSED (rcode=5); got {}", resp.rcode);

    let body = fetch_metrics(server.obs_addr());
    let rejected = parse_counter(&body, "heimdall_xfr_tsig_rejected_total");
    assert!(
        rejected >= 1,
        "xfr_tsig_rejected_total must be ≥ 1 after bad-MAC; metrics:\n{body}"
    );
}

// ── (c) Fudge violation ───────────────────────────────────────────────────────

/// An AXFR query signed with `time_signed = 1` (epoch + 1 s) is more than
/// 300 s outside the server's clock — the server must REFUSE and increment
/// the rejection counter.
#[test]
fn tsig_fudge_violation_is_refused() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_fudge_violation(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
        tsig::KEY_BYTES,
    );

    assert_eq!(
        resp.rcode, 5,
        "fudge-violation AXFR must be REFUSED (rcode=5); got {}",
        resp.rcode
    );

    let body = fetch_metrics(server.obs_addr());
    let rejected = parse_counter(&body, "heimdall_xfr_tsig_rejected_total");
    assert!(
        rejected >= 1,
        "xfr_tsig_rejected_total must be ≥ 1 after fudge violation; metrics:\n{body}"
    );
}

// ── (d) Truncated TSIG RDATA ──────────────────────────────────────────────────

/// An additional RR with TYPE=250 (TSIG) and only 2 bytes of RDATA is
/// malformed — the server must respond FORMERR (rcode=1) and increment the
/// rejection counter.
#[test]
fn tsig_truncated_record_returns_formerr() {
    let server = start_tsig_server();

    let resp = dns_client::query_axfr_truncated_tsig(
        server.dns_addr(),
        "example.com.",
        tsig::KEY_NAME,
    );

    assert_eq!(
        resp.rcode, 1,
        "truncated-TSIG AXFR must return FORMERR (rcode=1); got {}",
        resp.rcode
    );

    let body = fetch_metrics(server.obs_addr());
    let rejected = parse_counter(&body, "heimdall_xfr_tsig_rejected_total");
    assert!(
        rejected >= 1,
        "xfr_tsig_rejected_total must be ≥ 1 after malformed TSIG; metrics:\n{body}"
    );
}
