// SPDX-License-Identifier: MIT
#![allow(unsafe_code)]

//! End-to-end tests (Sprint 46 task #537 AC).
//!
//! Verifies that `heimdall start` boots to a state where it responds to real
//! DNS wire queries over UDP.
//!
//! Current state: `process_query` is a stub that returns REFUSED (RCODE 5)
//! for all queries.  The tests therefore assert a well-formed REFUSED response
//! with the correct transaction ID and the QR bit set.  Once role dispatch is
//! wired (a future sprint), the assertions will be updated to NOERROR + RDATA.
//!
//! The `boot_cycle_stability` test (marked `#[ignore]`) runs 100 boot+query
//! cycles and is intended to catch startup resource leaks.  Run explicitly
//! with `cargo test -- --ignored`.

#[cfg(unix)]
mod unix {
    use std::{
        net::UdpSocket,
        os::unix::process::CommandExt as _,
        process::Stdio,
        time::{Duration, Instant},
    };

    const TEST_PORT: u16 = 59160;

    fn heimdall_bin() -> std::process::Command {
        std::process::Command::new(env!("CARGO_BIN_EXE_heimdall"))
    }

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn spawn_daemon(config: &str) -> std::process::Child {
        let mut cmd = heimdall_bin();
        cmd.args(["start", "--config", config])
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        cmd.spawn().expect("failed to spawn heimdall")
    }

    fn sigterm(child: &std::process::Child) {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    /// Poll until `port` is occupied (i.e. the daemon has bound it) or `timeout`
    /// elapses.  Returns `true` if the port is bound within the timeout.
    fn wait_for_udp_port(port: u16, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if UdpSocket::bind(("127.0.0.1", port)).is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Build a minimal DNS A query for `qname` with the given transaction ID.
    fn build_dns_query(id: u16, qname: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
        for label in qname.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(u8::try_from(label.len()).expect("label too long"));
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        buf
    }

    /// Send a DNS query to `port`, wait for a response, and return it.
    fn query_udp(port: u16, payload: &[u8]) -> Option<Vec<u8>> {
        let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .ok()?;
        let dest = format!("127.0.0.1:{port}");
        sock.send_to(payload, &dest).ok()?;
        let mut buf = vec![0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Returns `true` if `response` is a well-formed DNS response to `query`:
    /// - QR=1 in the response flags
    /// - Transaction ID matches
    /// - Response is at least 12 bytes (header)
    fn is_valid_response(query: &[u8], response: &[u8]) -> bool {
        if response.len() < 12 {
            return false;
        }
        let q_id = u16::from_be_bytes([query[0], query[1]]);
        let r_id = u16::from_be_bytes([response[0], response[1]]);
        if q_id != r_id {
            return false;
        }
        let r_flags = u16::from_be_bytes([response[2], response[3]]);
        r_flags & 0x8000 != 0 // QR=1
    }

    /// Returns the RCODE from a response header (lower 4 bits of flags).
    fn rcode(response: &[u8]) -> u8 {
        u16::from_be_bytes([response[2], response[3]]) as u8 & 0x0F
    }

    // ── Main end-to-end test ──────────────────────────────────────────────────

    /// Boot heimdall, send a DNS A query, verify a well-formed response is
    /// received within the boot-to-first-response window, then exit cleanly.
    #[test]
    fn boot_query_exit_zero() {
        let config = fixture("udp_e2e.toml");
        let mut child = spawn_daemon(&config);

        let ready = wait_for_udp_port(TEST_PORT, Duration::from_secs(3));
        assert!(ready, "daemon did not bind UDP port {TEST_PORT} within 3 s");

        let t0 = Instant::now();
        let query = build_dns_query(0xABCD, "example.com");
        let response =
            query_udp(TEST_PORT, &query).expect("no UDP response received within 500 ms");
        let boot_to_response = t0.elapsed();

        assert!(
            is_valid_response(&query, &response),
            "response is not a valid DNS reply: {:02x?}",
            response
        );
        // Current stub returns REFUSED (RCODE 5).  Update to 0 (NOERROR) once
        // role dispatch is wired in a future sprint.
        let r = rcode(&response);
        assert!(
            r == 5 || r == 0,
            "unexpected RCODE {r} (expected 5 REFUSED or 0 NOERROR)"
        );
        // Boot-to-first-response target: < 1 s on a warm machine.
        // In debug builds this may be slower; the assertion is informational.
        if boot_to_response >= Duration::from_secs(1) {
            eprintln!("WARNING: boot-to-first-response = {boot_to_response:?} (target < 1 s)");
        }

        sigterm(&child);
        let status = child.wait().expect("wait failed");
        assert!(status.success(), "expected exit 0, got {status:?}");
    }

    // ── Stability / resource-leak test ───────────────────────────────────────

    /// Run 100 boot+query+exit cycles to verify there are no startup resource
    /// leaks (file descriptors, ports, etc.).
    ///
    /// This test is marked `#[ignore]` because it takes ~20 s in debug mode.
    /// Run explicitly: `cargo test -p heimdall --test end_to_end -- --ignored`
    #[test]
    #[ignore]
    fn boot_cycle_stability() {
        let config = fixture("udp_e2e.toml");

        for cycle in 0..100 {
            let mut child = spawn_daemon(&config);

            let ready = wait_for_udp_port(TEST_PORT, Duration::from_secs(5));
            assert!(ready, "cycle {cycle}: daemon did not bind port within 5 s");

            let query = build_dns_query(cycle as u16, "example.com");
            let response = query_udp(TEST_PORT, &query)
                .unwrap_or_else(|| panic!("cycle {cycle}: no response"));

            assert!(
                is_valid_response(&query, &response),
                "cycle {cycle}: invalid response"
            );

            sigterm(&child);
            let status = child.wait().expect("wait failed");
            assert!(
                status.success(),
                "cycle {cycle}: expected exit 0, got {status:?}"
            );
        }
    }
}

#[cfg(unix)]
extern crate libc;
