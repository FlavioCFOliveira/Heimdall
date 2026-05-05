// SPDX-License-Identifier: MIT

//! E2E: DNSSEC validation — secure, bogus, and insecure paths
//! (Sprint 47 task #473).
//!
//! ## Architecture
//!
//! A single authoritative server on `127.0.0.1:<auth_port>` serves three zones:
//!
//! - `signed.test.`   — real Ed25519 signatures (RFC 8080 / RFC 8032 §6.1 key).
//! - `bogus.test.`    — same structure but zero-byte RRSIG signatures.
//! - `insecure.test.` — no DNSSEC records at all.
//!
//! The recursive resolver is configured with root hints pointing to the auth
//! server.  The auth server uses `longest_suffix_match` so it answers AA=1
//! directly on the first hop — no delegation chain needed.
//!
//! ## Acceptance criteria (task #473)
//!
//! 1. Secure path: `host.signed.test. A` with DO=1 → NOERROR, AD=1.
//! 2. Bogus path:  `host.bogus.test.  A`         → SERVFAIL, EDE INFO-CODE 6.
//! 3. Insecure path: `host.insecure.test. A`      → NOERROR, AD=0.

use std::{net::SocketAddr, time::Duration};

use heimdall_e2e_harness::{TestServer, config, dns_client, free_port, zones};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

// ── Shared test environment ───────────────────────────────────────────────────

struct DnssecEnv {
    _auth: TestServer,
    _rec: TestServer,
    // Keep TempDirs alive for the duration of the test.
    _signed_dir: tempfile::TempDir,
    _bogus_dir: tempfile::TempDir,
    _insecure_dir: tempfile::TempDir,
    _hints_dir: tempfile::TempDir,
    /// Address of the recursive resolver under test.
    rec_addr: SocketAddr,
}

fn setup_dnssec_env() -> DnssecEnv {
    let auth_port = free_port();
    let auth_obs = free_port();

    // Write zone files to temporary directories.
    let signed_dir = tempfile::TempDir::new().expect("tempdir for signed zone");
    let bogus_dir = tempfile::TempDir::new().expect("tempdir for bogus zone");
    let insecure_dir = tempfile::TempDir::new().expect("tempdir for insecure zone");

    let signed_path = signed_dir.path().join("signed.test.zone");
    let bogus_path = bogus_dir.path().join("bogus.test.zone");
    let insecure_path = insecure_dir.path().join("insecure.test.zone");

    std::fs::write(&signed_path, zones::generate_valid_zone("signed.test."))
        .expect("write signed zone file");
    std::fs::write(&bogus_path, zones::generate_bogus_zone("bogus.test."))
        .expect("write bogus zone file");
    std::fs::write(
        &insecure_path,
        zones::generate_insecure_zone("insecure.test."),
    )
    .expect("write insecure zone file");

    let auth_toml = config::minimal_auth_three_zones(
        auth_port,
        auth_obs,
        "signed.test.",
        &signed_path,
        "bogus.test.",
        &bogus_path,
        "insecure.test.",
        &insecure_path,
    );

    let _auth = TestServer::start_with_ports(BIN, &auth_toml, auth_port, auth_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("DNSSEC auth server did not become ready");

    // Root hints pointing at the single auth server on 127.0.0.1.
    let hints_dir = tempfile::TempDir::new().expect("tempdir for root hints");
    let hints_path = hints_dir.path().join("root.hints");
    std::fs::write(&hints_path, format!("ns1.root-test. 3600 IN A 127.0.0.1\n"))
        .expect("write root hints");

    let rec_port = free_port();
    let rec_obs = free_port();
    let rec_toml = config::minimal_recursive_custom(rec_port, rec_obs, &hints_path, auth_port);

    let _rec = TestServer::start_with_ports(BIN, &rec_toml, rec_port, rec_obs)
        .wait_ready(Duration::from_secs(3))
        .expect("DNSSEC recursive resolver did not become ready");

    std::thread::sleep(Duration::from_millis(300));

    let rec_addr: SocketAddr = format!("127.0.0.1:{rec_port}").parse().unwrap();

    DnssecEnv {
        _auth,
        _rec,
        _signed_dir: signed_dir,
        _bogus_dir: bogus_dir,
        _insecure_dir: insecure_dir,
        _hints_dir: hints_dir,
        rec_addr,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Secure path: valid Ed25519 signatures → NOERROR, AD=1.
///
/// Acceptance criteria:
/// - RCODE = NOERROR (0).
/// - AD bit set (the recursive resolver validated the RRSIG with the DNSKEY).
#[test]
fn dnssec_secure_path_ad_bit_set() {
    let env = setup_dnssec_env();

    let resp = dns_client::query_a_with_do(env.rec_addr, "host.signed.test.");

    assert_eq!(resp.rcode, 0, "secure path: RCODE must be NOERROR");
    assert!(
        resp.ad,
        "secure path: AD bit must be set for a cryptographically verified response"
    );
}

/// Bogus path: zero-byte RRSIG signatures → SERVFAIL, EDE INFO-CODE 6.
///
/// Acceptance criteria:
/// - RCODE = SERVFAIL (2).
/// - EDE INFO-CODE = 6 (DNSSEC Bogus, RFC 8914 §4.6).
#[test]
fn dnssec_bogus_path_servfail_ede6() {
    let env = setup_dnssec_env();

    let resp = dns_client::query_a(env.rec_addr, "host.bogus.test.");

    assert_eq!(resp.rcode, 2, "bogus path: RCODE must be SERVFAIL");
    assert_eq!(
        resp.opt_ede_code,
        Some(6),
        "bogus path: EDE INFO-CODE 6 (DNSSEC Bogus) must be present"
    );
}

/// Insecure path: no DNSSEC records → NOERROR, AD=0.
///
/// Acceptance criteria:
/// - RCODE = NOERROR (0).
/// - AD bit absent (unsigned zone is treated as insecure, not bogus).
#[test]
fn dnssec_insecure_path_ad_bit_clear() {
    let env = setup_dnssec_env();

    let resp = dns_client::query_a(env.rec_addr, "host.insecure.test.");

    assert_eq!(resp.rcode, 0, "insecure path: RCODE must be NOERROR");
    assert!(
        !resp.ad,
        "insecure path: AD bit must be absent for an unsigned zone"
    );
}
