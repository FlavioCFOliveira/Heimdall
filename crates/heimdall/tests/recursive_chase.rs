// SPDX-License-Identifier: MIT

//! E2E: full iterative resolution — root → TLD → leaf delegation chase
//! (Sprint 47 task #472).
//!
//! ## Delegation hierarchy
//!
//! ```text
//! recursive ──→ 127.0.0.2:<AUTH_PORT>  (root `.` + test. zones)
//!                  │ referral from `.` zone: test. NS ns1.root-test. A 127.0.0.2
//!                  └ referral from test. zone: example.test. NS ns1.example.test. A 127.0.0.3
//! recursive ──→ 127.0.0.3:<AUTH_PORT>  (example.test. leaf zone)
//!                  └ answer: foo A 192.0.2.42
//! ```
//!
//! A single server at `127.0.0.2` serves both the root zone (`.`) and the
//! `test.` TLD zone.  When the recursive queries it for `foo.example.test.`,
//! the server first returns a referral from the root context (to `test.`) and
//! then — queried again — a referral from the `test.` context (to
//! `example.test.`).
//!
//! ## Why Linux-only
//!
//! Binding to `127.0.0.2` / `127.0.0.3` on macOS requires `sudo ifconfig lo0
//! alias 127.0.0.x` (elevated privileges). On Linux the entire `127.0.0.0/8`
//! range routes to `lo` and any address within it can be bound without root.
//!
//! ## Acceptance criteria (task #472)
//!
//! - `foo.example.test. A` resolves to `192.0.2.42` via the full chain.
//! - AD bit absent (no DNSSEC chain for unsigned zones).
//! - RCODE = NOERROR.

#![cfg(all(unix, target_os = "linux"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn root_zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/root.zone"
    ))
}

fn tld_zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/tld-test.zone"
    ))
}

fn leaf_zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/leaf-example-test.zone"
    ))
}

/// Full iterative resolution chase: root → TLD (via referral) → leaf (via referral).
///
/// Acceptance criteria (task #472):
/// - `foo.example.test. A` resolves to `192.0.2.42`.
/// - RCODE = NOERROR.
/// - AD bit absent (no DNSSEC chain).
#[test]
fn recursive_full_delegation_chase() {
    // One shared port for all in-test authoritative servers.
    let auth_port = free_port();

    // ── Root+TLD server on 127.0.0.2 ─────────────────────────────────────────
    // Serves both the root zone (`.`) and the TLD zone (`test.`) on a single
    // process.  When queried for `foo.example.test.`, it returns a referral
    // from the `.` zone first, then a referral from the `test.` zone.
    let combined_obs = free_port();
    let combined_toml = config::minimal_auth_two_zones(
        "127.0.0.2",
        auth_port,
        combined_obs,
        ".",
        root_zone_path(),
        "test.",
        tld_zone_path(),
    );
    let _combined = TestServer::start_with_ports(BIN, &combined_toml, auth_port, combined_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("root+TLD server (127.0.0.2) did not become ready");

    // ── Leaf server on 127.0.0.3 ─────────────────────────────────────────────
    let leaf_obs = free_port();
    let leaf_toml = config::minimal_auth_on_addr(
        "127.0.0.3",
        auth_port,
        leaf_obs,
        "example.test.",
        leaf_zone_path(),
    );
    let _leaf = TestServer::start_with_ports(BIN, &leaf_toml, auth_port, leaf_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("leaf server (127.0.0.3) did not become ready");

    // ── Root hints file ───────────────────────────────────────────────────────
    // Points the recursive resolver at 127.0.0.2 as its sole root nameserver.
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(
        &hints_path,
        "ns1.root-test. 3600 IN A 127.0.0.2\n",
    )
    .expect("write root hints");

    // ── Recursive server ──────────────────────────────────────────────────────
    let rec_dns = free_port();
    let rec_obs = free_port();
    let rec_toml =
        config::minimal_recursive_custom(rec_dns, rec_obs, &hints_path, auth_port);
    let recursive = TestServer::start_with_ports(BIN, &rec_toml, rec_dns, rec_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("recursive server did not become ready");

    // Allow everyone to settle.
    std::thread::sleep(Duration::from_millis(300));

    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_dns}").parse().unwrap();

    // ── Assert: answer matches expected RDATA ─────────────────────────────────
    let addr = dns_client::query_a_addr(rec_addr, "foo.example.test.");
    assert_eq!(
        addr,
        Some(Ipv4Addr::new(192, 0, 2, 42)),
        "recursive must resolve foo.example.test. to 192.0.2.42 via the full delegation chain"
    );

    // ── Assert: RCODE = NOERROR ───────────────────────────────────────────────
    let resp = dns_client::query_a(rec_addr, "foo.example.test.");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");

    // ── Assert: AD bit absent (no DNSSEC chain for unsigned zones) ────────────
    // DNS flags are at wire[2..4]; AD bit is bit 5 of the second flags byte.
    let ad_bit = resp.wire.len() >= 4 && (resp.wire[3] & 0x20) != 0;
    assert!(!ad_bit, "AD bit must be absent for unsigned zones");
}
