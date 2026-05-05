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

//! E2E: THREAT-143 structured anomaly event envelope.
//! (Sprint 47 task #608, THREAT-143/144)
//!
//! Verifies that anomaly events emitted to the daemon's stderr carry the
//! mandatory THREAT-143 base-envelope fields: `schema_version`, `event_type`,
//! and `correlation_id`.  The daemon auto-selects JSON log format when stderr
//! is not a TTY (see `crates/heimdall/src/logging.rs`); the test harness
//! pipes stderr, so every log line is a JSON object.
//!
//! Sub-cases:
//!
//! (i)   **ACL deny** (THREAT-116/117): configuring `deny_sources` causes the
//!       server to emit `event_type = "acl-deny"` on a denied UDP query.  The
//!       event MUST carry `schema_version = "1.0"` and a non-empty
//!       `correlation_id`.
//!
//! (ii)  **RRL fire** (THREAT-057): with `responses_per_second = 1` a burst of
//!       queries triggers either a drop or slip RRL decision.  At least one
//!       `event_type = "rrl-fired"` event MUST appear in stderr, with
//!       `schema_version = "1.0"` and a non-empty `correlation_id`.
//!
//! (iii) **Normal path — no anomaly events**: a server with a permissive ACL
//!       and no rate limiting returns NOERROR for a valid query.  Zero anomaly
//!       events (`schema_version` present) must appear in stderr.
//!
//! (iv)  **`OpenMetrics` format**: `/metrics` must be parseable as `OpenMetrics`
//!       text — the `# EOF` sentinel must be present and every non-comment,
//!       non-EOF line must be either a `# TYPE`/`# HELP` descriptor or a
//!       `<metric> <value>` sample line.

#![cfg(unix)]

use std::{
    net::{SocketAddr, UdpSocket},
    path::Path,
    time::Duration,
};

use heimdall_e2e_harness::{TestServer, config, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

/// Extract the value of a top-level string field from a minimal JSON object
/// line without pulling in a serde/json dependency.
///
/// Matches `"<key>":"<value>"` (with optional spaces around the colon).
fn json_string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    // Build a simple search pattern: `"<key>"`
    let key_token = format!("\"{key}\"");
    let key_pos = line.find(key_token.as_str())?;
    let after_key = &line[key_pos + key_token.len()..];
    // Skip optional whitespace and the colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    // Read the quoted value.
    let inner = after_colon.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(&inner[..end])
}

/// Returns true if the JSON line is an anomaly event (has `schema_version`).
fn is_anomaly_event(line: &str) -> bool {
    json_string_field(line, "schema_version").is_some()
}

/// Returns the `event_type` field of a JSON line, if present.
fn event_type(line: &str) -> Option<&str> {
    json_string_field(line, "event_type")
}

/// Returns the `correlation_id` field of a JSON line, if present.
fn correlation_id(line: &str) -> Option<&str> {
    json_string_field(line, "correlation_id")
}

// ── DNS wire helper ───────────────────────────────────────────────────────────

/// Send a single minimal A-query UDP datagram (no response expected on denied
/// queries); ignore I/O errors and timeouts.
fn send_query_no_wait(addr: SocketAddr, qname: &str) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP send socket");
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();

    let mut buf = Vec::new();
    buf.extend_from_slice(&0xAB_CDu16.to_be_bytes()); // ID
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

    let _ = sock.send_to(&buf, addr);
    // Drain a possible response (not needed for tests, but clears the buffer).
    let mut resp = [0u8; 512];
    let _ = sock.recv_from(&mut resp);
}

// ── (i) ACL deny event ───────────────────────────────────────────────────────

/// (i) An ACL-denied query causes the server to emit `event_type = "acl-deny"`
/// with `schema_version = "1.0"` and a non-empty `correlation_id` in its JSON
/// stderr (THREAT-116/117/143).
#[test]
fn acl_deny_emits_threat143_event() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_acl_deny(
        dns_port,
        obs_port,
        "example.com.",
        zone_path(),
        "127.0.0.1/32",
    );
    let mut server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready for anomaly ACL test");

    // Send a query that will be ACL-denied (127.0.0.1 is in deny_sources).
    send_query_no_wait(server.dns_addr(), "example.com.");

    // Allow the log to flush.
    std::thread::sleep(Duration::from_millis(200));

    let lines = server.stop_and_take_stderr_lines();

    let deny_events: Vec<&str> = lines
        .iter()
        .filter(|l| event_type(l) == Some("acl-deny"))
        .map(String::as_str)
        .collect();

    assert!(
        !deny_events.is_empty(),
        "(i) at least one 'acl-deny' anomaly event must appear in stderr JSON; \
         got {} stderr lines total",
        lines.len()
    );

    for ev in &deny_events {
        let sv = json_string_field(ev, "schema_version");
        assert_eq!(
            sv,
            Some("1.0"),
            "(i) acl-deny event must carry schema_version = \"1.0\"; got {sv:?}\nevent: {ev}"
        );

        let cid = correlation_id(ev);
        assert!(
            cid.is_some_and(|s| !s.is_empty()),
            "(i) acl-deny event must carry a non-empty correlation_id; got {cid:?}\nevent: {ev}"
        );
    }
}

// ── (ii) RRL fire event ──────────────────────────────────────────────────────

/// (ii) A burst of queries against a 1-rps RRL limit produces at least one
/// `event_type = "rrl-fired"` event carrying the mandatory THREAT-143 fields.
#[test]
fn rrl_fire_emits_threat143_event() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth_with_rrl(
        dns_port,
        obs_port,
        "example.com.",
        zone_path(),
        1, // responses_per_second = 1
    );
    let mut server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready for anomaly RRL test");

    // Send 5 rapid queries to the same qname from the same source.
    // With rate=1 and default slip_ratio=2, queries 2..5 produce drop or slip
    // decisions that emit rrl-fired events.
    let addr = server.dns_addr();
    for _ in 0..5 {
        send_query_no_wait(addr, "example.com.");
    }

    // Allow all queries to be processed and logged.
    std::thread::sleep(Duration::from_millis(300));

    let lines = server.stop_and_take_stderr_lines();

    let rrl_events: Vec<&str> = lines
        .iter()
        .filter(|l| event_type(l) == Some("rrl-fired"))
        .map(String::as_str)
        .collect();

    assert!(
        !rrl_events.is_empty(),
        "(ii) at least one 'rrl-fired' anomaly event must appear in stderr JSON; \
         got {} stderr lines total",
        lines.len()
    );

    for ev in &rrl_events {
        let sv = json_string_field(ev, "schema_version");
        assert_eq!(
            sv,
            Some("1.0"),
            "(ii) rrl-fired event must carry schema_version = \"1.0\"; got {sv:?}\nevent: {ev}"
        );

        let cid = correlation_id(ev);
        assert!(
            cid.is_some_and(|s| !s.is_empty()),
            "(ii) rrl-fired event must carry a non-empty correlation_id; got {cid:?}\nevent: {ev}"
        );
    }
}

// ── (iii) Normal path — no anomaly events ────────────────────────────────────

/// (iii) A normal successful query against a permissive server produces no
/// THREAT-143 anomaly events in stderr.
#[test]
fn normal_query_emits_no_anomaly_events() {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path());
    let mut server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready for normal-path anomaly test");

    // Send one query that should succeed (minimal_auth has no ACL deny or RRL).
    send_query_no_wait(server.dns_addr(), "example.com.");

    std::thread::sleep(Duration::from_millis(200));

    let lines = server.stop_and_take_stderr_lines();

    let anomaly_count = lines.iter().filter(|l| is_anomaly_event(l)).count();

    assert_eq!(
        anomaly_count,
        0,
        "(iii) normal successful query must emit zero anomaly events; got {anomaly_count}:\n{}",
        lines
            .iter()
            .filter(|l| is_anomaly_event(l))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ── (iv) OpenMetrics format ──────────────────────────────────────────────────

/// (iv) The `/metrics` endpoint MUST produce a valid `OpenMetrics` text body:
/// the `# EOF` sentinel must be present and every non-comment, non-sentinel,
/// non-blank line must follow `<metric_name>[{labels}] <value>[<timestamp>]`.
#[test]
fn metrics_endpoint_produces_valid_openmetrics() {
    use std::{
        io::{BufRead as _, BufReader, Write as _},
        net::TcpStream,
    };

    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path());
    let _server = TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("server did not become ready for OpenMetrics test");

    let obs_addr: SocketAddr = format!("127.0.0.1:{obs_port}").parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&obs_addr, Duration::from_secs(3))
        .expect("(iv) TCP connect to /metrics");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("(iv) send HTTP request");

    let mut reader = BufReader::new(stream);

    // Consume HTTP status line and headers.
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("status line");
    assert!(
        status_line.contains("200"),
        "(iv) /metrics must return HTTP 200; got: {status_line:?}"
    );
    loop {
        let mut hdr = String::new();
        reader.read_line(&mut hdr).expect("header line");
        if hdr == "\r\n" || hdr == "\n" {
            break;
        }
    }

    // Collect body lines.
    let mut body_lines: Vec<String> = Vec::new();
    for line in reader.lines() {
        match line {
            Ok(l) => body_lines.push(l),
            Err(_) => break,
        }
    }

    // Must end with `# EOF`.
    assert!(
        body_lines.iter().any(|l| l.trim() == "# EOF"),
        "(iv) OpenMetrics body must contain '# EOF' sentinel; got {} lines",
        body_lines.len()
    );

    // Every non-blank, non-comment, non-EOF line must be a sample line.
    for line in &body_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A sample line: starts with an ASCII identifier character.
        let first_char = trimmed.chars().next().unwrap_or(' ');
        assert!(
            first_char.is_ascii_alphabetic() || first_char == '_',
            "(iv) non-comment line must start with a metric name identifier; got: {trimmed:?}"
        );
        // Must contain at least one whitespace-separated token for the value.
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        assert!(
            parts.len() == 2,
            "(iv) sample line must have metric name and value separated by space; got: {trimmed:?}"
        );
    }
}
