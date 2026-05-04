// SPDX-License-Identifier: MIT

//! E2E: SIGHUP config reload — atomic swap, OPS-001..006/016..018.
//! (Sprint 47 task #606)
//!
//! Three sub-cases:
//!
//! (a) **Listeners remain bound**: after a valid SIGHUP reload the DNS port still
//!     answers queries — the listener is never torn down (OPS-004).
//!
//! (b) **Valid delta increments generation**: a well-formed config rewrite followed
//!     by SIGHUP causes `heimdall_reload_generation` to increment from 0 to 1,
//!     and the DNS listener continues answering (OPS-016/017).
//!
//! (c) **Invalid delta preserves generation**: a malformed TOML rewrite followed
//!     by SIGHUP leaves `heimdall_reload_generation` at 1 (OPS-003/004).

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_get_body(obs_addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream =
        TcpStream::connect_timeout(&obs_addr, Duration::from_millis(200)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    let mut reader = BufReader::new(stream);
    // Skip status line.
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    // Skip headers until blank line.
    loop {
        line.clear();
        reader.read_line(&mut line).ok()?;
        if line.trim().is_empty() {
            break;
        }
    }
    // Collect body.
    let mut body = String::new();
    for l in reader.lines() {
        match l {
            Ok(l) => {
                body.push_str(&l);
                body.push('\n');
            }
            Err(_) => break,
        }
    }
    Some(body)
}

/// Read the current value of the `heimdall_reload_generation` gauge/counter from
/// the `/metrics` endpoint.  Returns `None` if the endpoint is unreachable or the
/// metric is absent.
fn read_reload_generation(obs_addr: SocketAddr) -> Option<u64> {
    let body = http_get_body(obs_addr, "/metrics")?;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("heimdall_reload_generation ") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

/// Poll until `heimdall_reload_generation` equals `expected` or `timeout` elapses.
fn wait_for_generation(obs_addr: SocketAddr, expected: u64, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if read_reload_generation(obs_addr) == Some(expected) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ── Shared server boot ────────────────────────────────────────────────────────

fn start_auth_server(zone_path: &Path) -> TestServer {
    let dns_port = free_port();
    let obs_port = free_port();
    let toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path);
    TestServer::start_with_ports(BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("authoritative server did not become ready for SIGHUP test")
}

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

// ── (a) Listeners remain bound after a SIGHUP ────────────────────────────────

/// (a) Listeners remain bound: SIGHUP with the same valid config does not tear
/// down the DNS listener — queries still succeed (OPS-004).
#[test]
fn sighup_same_config_listener_stays_bound() {
    let server = start_auth_server(zone_path());

    // Baseline: DNS responds before any reload.
    let before = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        before.rcode == 0 || before.ancount > 0,
        "(a) baseline query must succeed before SIGHUP; got rcode={} ancount={}",
        before.rcode,
        before.ancount
    );

    // Rewrite the config with identical content and send SIGHUP.
    let current_toml = std::fs::read_to_string(server.config_path())
        .expect("read current config for (a)");
    server.write_config(&current_toml);
    server.send_sighup();

    // Allow up to 3 s for the reload cycle to complete.
    std::thread::sleep(Duration::from_millis(500));

    // DNS listener must still answer.
    let after = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        after.rcode == 0 || after.ancount > 0,
        "(a) post-SIGHUP query must still succeed; got rcode={} ancount={}",
        after.rcode,
        after.ancount
    );
}

// ── (b) Valid delta increments generation ────────────────────────────────────

/// (b) Valid config rewrite + SIGHUP: generation increments from 0 → 1, and the
/// DNS listener answers post-reload (OPS-016/017).
#[test]
fn sighup_valid_config_increments_generation_and_listener_responds() {
    let server = start_auth_server(zone_path());

    // Generation must be 0 before any reload.
    let gen0 = read_reload_generation(server.obs_addr()).unwrap_or(0);
    assert_eq!(
        gen0, 0,
        "(b) initial reload generation must be 0; got {gen0}"
    );

    // Write an equivalent valid config (same zone, same ports) and reload.
    let dns_port = server.dns_port;
    let obs_port = server.obs_port;
    let v2_toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path());
    server.write_config(&v2_toml);
    server.send_sighup();

    // Wait up to 5 s for the generation to reach 1.
    let advanced = wait_for_generation(server.obs_addr(), 1, Duration::from_secs(5));
    assert!(
        advanced,
        "(b) heimdall_reload_generation must reach 1 after valid SIGHUP reload"
    );

    // DNS listener must still respond after reload.
    let resp = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        resp.rcode == 0 || resp.ancount > 0,
        "(b) DNS listener must answer after valid reload; rcode={} ancount={}",
        resp.rcode,
        resp.ancount
    );
}

// ── (c) Invalid delta preserves generation ────────────────────────────────────

/// (c) Malformed TOML rewrite + SIGHUP: generation stays at 1 (rejected reload
/// does not increment the counter, OPS-003/004).
#[test]
fn sighup_invalid_config_preserves_generation() {
    let server = start_auth_server(zone_path());

    // First, apply a valid reload to bring generation to 1.
    let dns_port = server.dns_port;
    let obs_port = server.obs_port;
    let v2_toml = config::minimal_auth(dns_port, obs_port, "example.com.", zone_path());
    server.write_config(&v2_toml);
    server.send_sighup();

    let advanced = wait_for_generation(server.obs_addr(), 1, Duration::from_secs(5));
    assert!(
        advanced,
        "(c) prerequisite: generation must reach 1 before invalid-reload sub-test"
    );

    // Now write syntactically invalid TOML and send another SIGHUP.
    server.write_config("this is not valid toml ][[ garbage");
    server.send_sighup();

    // Allow up to 2 s for the daemon to process the signal.
    std::thread::sleep(Duration::from_millis(1_500));

    // Generation must still be 1 — parse failure must not advance the counter.
    let generation = read_reload_generation(server.obs_addr()).unwrap_or(0);
    assert_eq!(
        generation, 1,
        "(c) failed reload must not increment generation; got {generation}"
    );

    // DNS listener must still answer with the last valid config.
    let resp = dns_client::query_a(server.dns_addr(), "example.com.");
    assert!(
        resp.rcode == 0 || resp.ancount > 0,
        "(c) DNS listener must answer with prior config after rejected reload; rcode={} ancount={}",
        resp.rcode,
        resp.ancount
    );
}
