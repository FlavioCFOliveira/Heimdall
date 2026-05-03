// SPDX-License-Identifier: MIT

//! E2E: Aggressive NSEC synthesis from validated DNSSEC cache (RFC 8198).
//! Sprint 47 task #542.
//!
//! ## Strategy
//!
//! A single authoritative server serves a DNSSEC-signed zone with a full NSEC
//! chain.  The recursive resolver queries a non-existent name:
//! - First query hits the auth server → NXDOMAIN + NSEC authority proof.
//! - The resolver validates the NSEC RRSIG and caches the NSEC as Secure.
//! - Auth server is stopped.
//! - Second query for a different non-existent name in the same NSEC interval:
//!   resolver synthesises NXDOMAIN from cache → no upstream query needed.
//!
//! If synthesis does NOT work, the resolver would send an upstream query that
//! times out, returning SERVFAIL.  NXDOMAIN therefore proves synthesis happened.

#![cfg(all(unix, target_os = "linux"))]

use std::net::SocketAddr;
use std::time::Duration;

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, zones};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

/// NXDOMAIN rcode value per RFC 1035.
const RCODE_NXDOMAIN: u8 = 3;

/// Set up an auth + recursive server pair for the NSEC zone.
///
/// Returns `(auth_server, rec_server, rec_addr, temp_dirs)`.
fn setup_nsec_env(origin: &str) -> (TestServer, TestServer, SocketAddr, [tempfile::TempDir; 2]) {
    let auth_port = free_port();
    let auth_obs = free_port();

    let zone_dir = tempfile::TempDir::new().expect("tempdir for NSEC zone");
    let zone_path = zone_dir.path().join("nsec.zone");
    std::fs::write(&zone_path, zones::generate_nsec_zone(origin))
        .expect("write NSEC zone file");

    let auth_toml = config::minimal_auth(auth_port, auth_obs, origin, &zone_path);
    let auth = TestServer::start_with_ports(BIN, &auth_toml, auth_port, auth_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("NSEC auth server did not become ready");

    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(
        &hints_path,
        "ns1.root-test. 3600 IN A 127.0.0.1\n",
    )
    .expect("write root hints");

    let rec_port = free_port();
    let rec_obs = free_port();
    let rec_toml = config::minimal_recursive_custom(rec_port, rec_obs, &hints_path, auth_port);
    let rec = TestServer::start_with_ports(BIN, &rec_toml, rec_port, rec_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("NSEC recursive resolver did not become ready");

    std::thread::sleep(Duration::from_millis(300));
    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_port}").parse().unwrap();

    (auth, rec, rec_addr, [zone_dir, hints_dir])
}

/// NSEC synthesis: after the auth server is stopped, a second non-existent-name
/// query in the same NSEC interval is answered NXDOMAIN from cache.
#[test]
fn aggressive_nsec_synthesis_avoids_upstream_query() {
    let origin = "nsec.test.";
    let (auth, _rec, rec_addr, _dirs) = setup_nsec_env(origin);

    // First query: hits the auth server; populates NSEC cache.
    let first = dns_client::query_a_with_do(rec_addr, "alpha.nsec.test.");
    assert_eq!(
        first.rcode,
        RCODE_NXDOMAIN,
        "first query must return NXDOMAIN (rcode=3); got {}",
        first.rcode,
    );

    // Give the resolver time to process and cache the NSEC records.
    std::thread::sleep(Duration::from_millis(200));

    // Stop the auth server — all subsequent upstream queries will fail.
    drop(auth);
    std::thread::sleep(Duration::from_millis(200));

    // Second query: beta.nsec.test. is also between the apex and host. in canonical
    // order, so the cached NSEC at apex must synthesise NXDOMAIN without upstream.
    let second = dns_client::query_a_with_do(rec_addr, "beta.nsec.test.");
    assert_eq!(
        second.rcode,
        RCODE_NXDOMAIN,
        "second query must be synthesised as NXDOMAIN (no upstream); got {}",
        second.rcode,
    );
}
