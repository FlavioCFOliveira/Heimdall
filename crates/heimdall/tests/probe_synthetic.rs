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

//! End-to-end tests for the ENV-065 synthetic `health.heimdall.internal.`
//! zone (rmp task #662).
//!
//! Two scenarios:
//!
//! 1. **Probe against a live recursive server** — spawns `heimdall` configured
//!    as a recursive resolver (no real upstream connectivity in CI), runs the
//!    production `heimdall-probe` binary against the listener, asserts exit
//!    code 0 within 2 seconds.  Without the synthetic-zone fix the recursive
//!    role would attempt upstream resolution for `health.heimdall.internal.`
//!    and time the probe out.
//!
//! 2. **Probe against a black-hole port** — runs `heimdall-probe` with the
//!    sentinel UDP socket from [`reserve_loopback_pair`] absorbing the
//!    datagram (no ICMP, no response).  Asserts exit code 1 with elapsed
//!    time in `[2s, 3s]`, locking in ENV-065's 2-second deadline so any
//!    regression that makes the probe block forever or fail-fast in less
//!    than 2 s is caught here.
//!
//! Lives next to the other `heimdall` E2E tests rather than in
//! `heimdall-integration-tests/` because Cargo populates
//! `CARGO_BIN_EXE_heimdall` only inside the binary crate's own `tests/`
//! directory — binary-only crates cannot be declared as path
//! dev-dependencies elsewhere.  The probe binary path is derived from
//! `CARGO_BIN_EXE_heimdall`'s parent so the same workspace target dir is
//! used for both binaries.

#![cfg(unix)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

use heimdall_e2e_harness::{TestServer, config, reserve_loopback_pair};

/// The `heimdall` server binary under test.
const HEIMDALL_BIN: &str = env!("CARGO_BIN_EXE_heimdall");

/// The fixed 2-second deadline from ENV-065.  Used as the upper bound on the
/// success-case elapsed time and the lower bound on the timeout case.
const PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// Upper bound on the timeout case's elapsed time.  ENV-065 fixes the
/// deadline at exactly 2 s; we allow up to 3 s to absorb process-spawn
/// overhead and kernel-scheduling jitter without making the assertion flaky
/// on loaded CI runners.
const PROBE_TIMEOUT_UPPER: Duration = Duration::from_secs(3);

/// Locates `heimdall-probe` in the same `target/<profile>/` directory that
/// holds `heimdall`.
///
/// The Cargo workspace builds every workspace member into the same target
/// directory, so deriving the probe path from `CARGO_BIN_EXE_heimdall`'s
/// parent is sound regardless of profile (`debug` vs `release`) or extra
/// `--target-dir` overrides.
fn probe_bin_path() -> PathBuf {
    let heimdall = PathBuf::from(HEIMDALL_BIN);
    let dir = heimdall
        .parent()
        .expect("CARGO_BIN_EXE_heimdall must have a parent directory");
    dir.join("heimdall-probe")
}

/// Runs `heimdall-probe <host> <port>` and returns `(exit_code, elapsed)`.
///
/// The probe binary inherits stdin/stdout/stderr from the test runner so any
/// diagnostic it writes is visible in test logs on failure.  An outer 5 s
/// wait guards against a hung probe so the test exits with a useful message
/// rather than hanging — the elapsed-time assertion is the real check.
fn run_probe(addr: SocketAddr) -> (i32, Duration) {
    let probe = probe_bin_path();
    assert!(
        probe.exists(),
        "heimdall-probe binary not found at {} — run `cargo build -p heimdall-probe` first \
         or invoke this test via `cargo test --workspace`",
        probe.display()
    );

    let host = addr.ip().to_string();
    let port = addr.port().to_string();

    let start = Instant::now();
    let mut child = Command::new(&probe)
        .args([&host, &port])
        .spawn()
        .expect("spawn heimdall-probe binary");

    let outer_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait().expect("try_wait on heimdall-probe") {
            Some(status) => {
                let elapsed = start.elapsed();
                let code = status.code().unwrap_or(-1);
                return (code, elapsed);
            }
            None if Instant::now() < outer_deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "heimdall-probe did not exit within 5 s — likely a deadlock or blocking \
                     call inside the probe; ENV-065 demands a 2-second deadline"
                );
            }
        }
    }
}

// ── Scenario 1: live server ─────────────────────────────────────────────────

/// Probe against a recursive Heimdall instance must succeed within 2 s.
///
/// Pre-fix this would time out: the recursive role would attempt to resolve
/// `health.heimdall.internal.` via upstream root servers that are not
/// reachable from CI, and the probe's 2-second read deadline would elapse
/// before any response arrived.  The synthetic-zone fix makes the listener
/// answer locally and the probe exits 0.
#[test]
fn probe_succeeds_against_recursive_server() {
    let mut reservation = reserve_loopback_pair();
    let dns_port = reservation.dns_port;
    let obs_port = reservation.obs_port;
    let toml = config::minimal_recursive(dns_port, obs_port);
    reservation.release_sockets();

    let _server = TestServer::start_with_ports(HEIMDALL_BIN, &toml, dns_port, obs_port)
        .wait_ready(Duration::from_secs(5))
        .expect("recursive heimdall did not become ready within 5 s");
    drop(reservation);

    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();
    let (code, elapsed) = run_probe(dns_addr);

    assert_eq!(
        code, 0,
        "ENV-065: heimdall-probe must exit 0 against a live listener; got exit code {code}"
    );
    assert!(
        elapsed < PROBE_DEADLINE,
        "ENV-065: heimdall-probe must succeed within the 2-second deadline; \
         elapsed = {elapsed:?}"
    );
}

// ── Scenario 2: black-hole port ─────────────────────────────────────────────

/// Probe against a black-hole port must fail with exit 1 in `[2s, 3s]`.
///
/// The semantics here are subtle and worth spelling out:
///
/// - If we send a UDP datagram to `127.0.0.1:<port>` and **nothing** is bound
///   there, the kernel typically delivers an ICMP Port Unreachable back to
///   the sender.  The next `recv_from()` then returns `ECONNREFUSED`
///   immediately, **not** at the 2-second deadline.  That would not exercise
///   the ENV-065 timeout path at all.
/// - If we keep the [`reserve_loopback_pair`] UDP sentinel **bound** on the
///   port without ever reading from it, the datagram is silently absorbed by
///   the sentinel socket (no ICMP is generated), and the probe waits for a
///   response that never comes — its 2-second read-timeout then fires and it
///   exits 1.  This is the case we want.
///
/// Therefore this test deliberately does **not** call `release_sockets()` on
/// the reservation.  The sentinel UDP socket on `dns_port` acts as a black
/// hole; the probe's datagram lands in its receive queue and is never read.
#[test]
fn probe_times_out_when_nothing_listens() {
    let reservation = reserve_loopback_pair();
    let dns_port = reservation.dns_port;

    let dns_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();
    let (code, elapsed) = run_probe(dns_addr);

    // Reservation dropped after probe so the sentinel UDP socket lives
    // through the entire probe run.
    drop(reservation);

    assert_eq!(
        code, 1,
        "ENV-065: heimdall-probe must exit 1 when no server responds; got exit code {code}"
    );
    assert!(
        elapsed >= PROBE_DEADLINE,
        "ENV-065: heimdall-probe must wait at least the full 2-second deadline before giving \
         up; elapsed = {elapsed:?}"
    );
    assert!(
        elapsed <= PROBE_TIMEOUT_UPPER,
        "ENV-065: heimdall-probe must give up within ~1 s of the 2-second deadline; \
         elapsed = {elapsed:?} — a much longer delay would indicate the probe is not honouring \
         its read-timeout"
    );
}
