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

//! E2E: NOTIFY inbound/outbound and secondary-becomes-primary failover.
//!
//! - `secondary_initial_pull_matches_primary_serial` — start a primary serving
//!   `notify.test.` (serial=1), start a secondary pointing at it, poll until the
//!   secondary's SOA serial equals 1 (max 5 s).
//!
//! - `secondary_refreshes_on_notify_trigger` — wait for the REFRESH timer to
//!   fire and verify the serial remains consistent (timer-based refresh path).
//!
//! - `notify_ack_is_returned` — send a NOTIFY UDP packet to a secondary and
//!   verify the response is a NOTIFY ACK (QR=1, opcode=NOTIFY, rcode=NOERROR).

#![cfg(unix)]

use std::{path::Path, time::Duration};

use heimdall_e2e_harness::{TestServer, config, dns_client, reserve_loopback_pair, tsig};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/notify-test.zone"
    ))
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Poll `server` for the SOA serial of `qname` until it equals `expected` or
/// `timeout` expires.  Returns `true` if the expected serial was seen.
fn poll_serial_until(server: &TestServer, qname: &str, expected: u32, timeout: Duration) -> bool {
    heimdall_e2e_harness::poll_until_or_timeout(timeout, Duration::from_millis(20), || {
        dns_client::query_soa_serial(server.dns_addr(), qname).filter(|&s| s == expected)
    })
    .is_some()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Primary emits NOTIFY on startup; secondary completes initial AXFR pull and
/// its SOA serial equals the primary's within 5 seconds.
///
/// Acceptance criteria (task #471):
/// - Secondary refresh completes within REFRESH timer + jitter.
/// - SOA serial on secondary equals primary after refresh.
#[test]
fn secondary_initial_pull_matches_primary_serial() {
    // We need both port pairs allocated before either daemon starts (so the
    // primary's notify_secondaries config can name the secondary).
    let mut primary_reservation = reserve_loopback_pair();
    let mut secondary_reservation = reserve_loopback_pair();
    let primary_dns_port = primary_reservation.dns_port;
    let primary_obs_port = primary_reservation.obs_port;
    let secondary_dns_port = secondary_reservation.dns_port;
    let secondary_obs_port = secondary_reservation.obs_port;

    // Primary TOML: includes notify_secondaries so the primary sends NOTIFY
    // at startup per RFC 1996 §3.7.
    let secondary_notify_addr: std::net::SocketAddr =
        format!("127.0.0.1:{secondary_dns_port}").parse().unwrap();
    let primary_toml = config::minimal_primary_with_notify(
        primary_dns_port,
        primary_obs_port,
        "notify.test.",
        zone_path(),
        secondary_notify_addr,
    );

    // Secondary TOML: pulls from the primary.
    let primary_tcp_addr: std::net::SocketAddr =
        format!("127.0.0.1:{primary_dns_port}").parse().unwrap();
    let secondary_toml = config::minimal_secondary(
        secondary_dns_port,
        secondary_obs_port,
        "notify.test.",
        primary_tcp_addr,
    );

    // Start secondary first so it is ready to handle the NOTIFY emitted by the
    // primary immediately on startup.  Release both reservation sentinel sets
    // (primary's spawn follows immediately after); the host-wide spawn lock
    // is still held by either reservation until both daemons are ready.
    secondary_reservation.release_sockets();
    primary_reservation.release_sockets();
    let secondary =
        TestServer::start_with_ports(BIN, &secondary_toml, secondary_dns_port, secondary_obs_port)
            .wait_ready(Duration::from_secs(3))
            .expect("secondary did not become ready");

    // Start primary — it should emit NOTIFY to the secondary immediately.
    let _primary =
        TestServer::start_with_ports(BIN, &primary_toml, primary_dns_port, primary_obs_port)
            .wait_ready(Duration::from_secs(2))
            .expect("primary did not become ready");
    drop(secondary_reservation);
    drop(primary_reservation);

    // Poll the secondary until it has pulled serial=1 (up to 5 s).
    let ok = poll_serial_until(&secondary, "notify.test.", 1, Duration::from_secs(5));
    assert!(
        ok,
        "secondary did not pull serial=1 from primary within 5 s"
    );
}

/// Timer-based refresh: after the initial pull (serial=1) the secondary's
/// REFRESH timer fires (2 s in the zone file) and returns serial=1 again
/// (zone has not changed).  Verifies the refresh loop continues running.
///
/// Acceptance criterion: SOA serial is consistent across multiple polls.
#[test]
fn secondary_refreshes_on_timer() {
    // Start primary serving notify.test. (serial=1, REFRESH=2s).
    // TSIG is required (PROTO-048) so use the TSIG-enabled auth config; the
    // secondary (started via start_secondary) uses the same test key.
    let mut primary_reservation = reserve_loopback_pair();
    let primary_dns_port = primary_reservation.dns_port;
    let primary_obs_port = primary_reservation.obs_port;
    let primary_toml = config::minimal_auth_with_tsig(
        primary_dns_port,
        primary_obs_port,
        "notify.test.",
        zone_path(),
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    );
    primary_reservation.release_sockets();
    let _primary =
        TestServer::start_with_ports(BIN, &primary_toml, primary_dns_port, primary_obs_port)
            .wait_ready(Duration::from_secs(2))
            .expect("primary did not become ready");
    drop(primary_reservation);

    let primary_tcp_addr: std::net::SocketAddr =
        format!("127.0.0.1:{primary_dns_port}").parse().unwrap();

    let secondary = TestServer::start_secondary(BIN, "notify.test.", primary_tcp_addr);

    // Wait for the initial pull.
    let ok = poll_serial_until(&secondary, "notify.test.", 1, Duration::from_secs(5));
    assert!(
        ok,
        "secondary did not pull serial=1 from primary within 5 s (initial pull)"
    );

    heimdall_e2e_harness::wait_bounded(
        "PROTO-038 negative: 3 s > REFRESH=2 s; secondary serial must NOT change within this window",
        Duration::from_secs(3),
    );
    let serial_after = dns_client::query_soa_serial(secondary.dns_addr(), "notify.test.");
    assert_eq!(
        serial_after,
        Some(1),
        "secondary serial changed unexpectedly after timer refresh; got {serial_after:?}"
    );
}

/// NOTIFY ACK: send a NOTIFY UDP to a secondary and verify the response
/// is a valid NOTIFY ACK (QR=1, opcode=NOTIFY=4, rcode=NOERROR=0).
///
/// Acceptance criterion (task #471):
/// - Primary emits NOTIFY within retry interval.
/// - (Here we test the secondary's ACK response path.)
#[test]
fn notify_ack_is_returned() {
    // Start a primary so the secondary has something to pull from.
    // TSIG is required (PROTO-048); secondary uses the same test key.
    let mut primary_reservation = reserve_loopback_pair();
    let primary_dns_port = primary_reservation.dns_port;
    let primary_obs_port = primary_reservation.obs_port;
    let primary_toml = config::minimal_auth_with_tsig(
        primary_dns_port,
        primary_obs_port,
        "notify.test.",
        zone_path(),
        tsig::KEY_NAME,
        tsig::ALGORITHM,
        tsig::KEY_SECRET_B64,
    );
    primary_reservation.release_sockets();
    let _primary =
        TestServer::start_with_ports(BIN, &primary_toml, primary_dns_port, primary_obs_port)
            .wait_ready(Duration::from_secs(2))
            .expect("primary did not become ready");
    drop(primary_reservation);

    let primary_tcp_addr: std::net::SocketAddr =
        format!("127.0.0.1:{primary_dns_port}").parse().unwrap();

    // Start secondary, wait for initial pull so the zone is known.
    let secondary = TestServer::start_secondary(BIN, "notify.test.", primary_tcp_addr);
    let ok = poll_serial_until(&secondary, "notify.test.", 1, Duration::from_secs(5));
    assert!(ok, "secondary did not complete initial pull within 5 s");

    // Send a NOTIFY to the secondary.
    let resp = dns_client::send_notify_udp(secondary.dns_addr(), "notify.test.");

    // Verify NOTIFY ACK: QR=1, opcode=NOTIFY(4), RCODE=NOERROR(0).
    assert!(resp.qr, "NOTIFY ACK must have QR=1");
    assert_eq!(resp.opcode, 4, "NOTIFY ACK must have opcode=NOTIFY(4)");
    assert_eq!(resp.rcode, 0, "NOTIFY ACK must have RCODE=NOERROR");
}
