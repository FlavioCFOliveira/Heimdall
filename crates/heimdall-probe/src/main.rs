// SPDX-License-Identifier: MIT

//! Minimal DNS health-check probe for the Dockerfile `HEALTHCHECK` directive
//! (ENV-065).
//!
//! Per ENV-065 in `specification/009-target-environment.md` §2.20, the probe
//! sends a minimal UDP DNS query (`QTYPE=A`, `QNAME=health.heimdall.internal.`)
//! to `127.0.0.1` on the configured DNS port (default `53`) and exits 0 if a
//! valid DNS response is received within 2 seconds, or 1 on timeout or any
//! network error.  The binary is statically linked against musl with **zero
//! external crate dependencies** (stdlib only); the wire-format work is
//! done inline.
//!
//! # Usage
//!
//! ```text
//! heimdall-probe [<host>] [<port>]
//! ```
//!
//! Defaults: `host = 127.0.0.1`, `port = 53`.  Both may be overridden from
//! the environment (`HEIMDALL_PROBE_HOST`, `HEIMDALL_PROBE_PORT`), which
//! takes priority over the positional arguments.  The 2-second timeout is
//! fixed by ENV-065 and is not configurable.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | A well-formed DNS response was received within 2 seconds. |
//! | 1    | Timeout, network error, or malformed response. |
//!
//! "Well-formed" means: at least 12 bytes (a complete header), the response
//! `ID` matches the query `ID`, and the `QR` bit is set.  Any `RCODE` is
//! accepted because the contract is "the listener is alive and processing
//! queries"; `NOERROR`, `NXDOMAIN`, and `REFUSED` all confirm liveness.

#![deny(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests may panic on assertion failure; unwrap/expect are idiomatic here"
    )
)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Pre-encoded question section for `health.heimdall.internal.` `QTYPE=A`
/// `QCLASS=IN`.  The QNAME labels are length-prefixed (RFC 1035 §3.1):
/// `0x06 "health"  0x08 "heimdall"  0x08 "internal"  0x00`, followed by
/// `QTYPE=0x0001` (A, RFC 1035 §3.2.2) and `QCLASS=0x0001` (IN, RFC 1035
/// §3.2.4).  Encoded as a byte literal to avoid any runtime arithmetic
/// over the label lengths.
const QUESTION_SECTION: &[u8] = b"\x06health\x08heimdall\x08internal\x00\x00\x01\x00\x01";

/// Fixed 2-second deadline per ENV-065.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Receive buffer size; classic UDP DNS caps at 512 bytes, but we accept
/// up to 4096 to tolerate EDNS responses from mis-configured servers.
const RECV_BUF: usize = 4096;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Resolution order for each parameter: env var > positional arg > default.
    let host_str: String = std::env::var("HEIMDALL_PROBE_HOST")
        .ok()
        .or_else(|| args.get(1).cloned())
        .unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = std::env::var("HEIMDALL_PROBE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| args.get(2).and_then(|s| s.parse().ok()))
        .unwrap_or(53);

    let host: IpAddr = match host_str.parse() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("heimdall-probe: invalid host {host_str:?}: {e}");
            std::process::exit(1);
        }
    };

    let addr = SocketAddr::new(host, port);
    std::process::exit(probe(addr));
}

fn probe(addr: SocketAddr) -> i32 {
    let id = random_id();
    let query = build_query(id);

    // Bind a local UDP socket on an ephemeral port matching the address
    // family of the target.  Constructed directly from typed constants to
    // avoid runtime parsing of literal strings.
    let bind_addr: SocketAddr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("heimdall-probe: bind {bind_addr}: {e}");
            return 1;
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(TIMEOUT)) {
        eprintln!("heimdall-probe: set_read_timeout: {e}");
        return 1;
    }
    if let Err(e) = socket.set_write_timeout(Some(TIMEOUT)) {
        eprintln!("heimdall-probe: set_write_timeout: {e}");
        return 1;
    }

    if let Err(e) = socket.send_to(&query, addr) {
        eprintln!("heimdall-probe: send to {addr}: {e}");
        return 1;
    }

    let mut buf = [0u8; RECV_BUF];
    let n = match socket.recv_from(&mut buf) {
        Ok((n, _src)) => n,
        Err(e) => {
            eprintln!("heimdall-probe: recv from {addr}: {e}");
            return 1;
        }
    };

    match validate_response(&buf[..n], id) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("heimdall-probe: invalid response: {e}");
            1
        }
    }
}

/// Build a minimal DNS query for `health.heimdall.internal.` `QTYPE=A`
/// `QCLASS=IN`.
///
/// Header (12 bytes, RFC 1035 §4.1.1):
/// ```text
///     ID:       2 bytes (caller-supplied)
///     Flags:    2 bytes (0x0000 — QR=0, OPCODE=QUERY, RD=0; minimal query)
///     QDCOUNT:  2 bytes (1)
///     ANCOUNT:  2 bytes (0)
///     NSCOUNT:  2 bytes (0)
///     ARCOUNT:  2 bytes (0)
/// ```
///
/// Question (RFC 1035 §4.1.2): pre-encoded in [`QUESTION_SECTION`].
fn build_query(id: u16) -> Vec<u8> {
    // 12 (header) + 25 (QNAME + QTYPE + QCLASS) = 37 bytes.
    let mut buf = Vec::with_capacity(12 + QUESTION_SECTION.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0_u16.to_be_bytes()); // flags
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    buf.extend_from_slice(QUESTION_SECTION);
    buf
}

/// Validate a DNS response: at least 12 bytes (header), `ID` matches the
/// query, and the `QR` bit is set.  Any `RCODE` is accepted.
fn validate_response(buf: &[u8], expected_id: u16) -> Result<(), String> {
    if buf.len() < 12 {
        return Err(format!("response too short: {} bytes (< 12)", buf.len()));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(format!("id mismatch: got {id}, expected {expected_id}"));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err("QR bit not set in response (server replied as if it were a query)".into());
    }
    Ok(())
}

/// Generate a 16-bit identifier from PID and current sub-second time.
/// Not cryptographic; sufficient for collision avoidance on a single-shot
/// probe whose lifetime is bounded by the 2-second deadline.
fn random_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let pid = std::process::id();
    let mixed = (nanos ^ pid) & 0xFFFF;
    // mixed is masked to 16 bits, so the truncation to u16 is exact.
    #[allow(clippy::cast_possible_truncation)]
    let id = mixed as u16;
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_layout_is_correct() {
        let q = build_query(0x1234);

        // Header
        assert_eq!(&q[0..2], &[0x12, 0x34], "ID");
        assert_eq!(&q[2..4], &[0x00, 0x00], "flags");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT=1");
        assert_eq!(&q[6..8], &[0x00, 0x00], "ANCOUNT=0");
        assert_eq!(&q[8..10], &[0x00, 0x00], "NSCOUNT=0");
        assert_eq!(&q[10..12], &[0x00, 0x00], "ARCOUNT=0");

        // QNAME: 6"health" 8"heimdall" 8"internal" 0
        assert_eq!(q[12], 6);
        assert_eq!(&q[13..19], b"health");
        assert_eq!(q[19], 8);
        assert_eq!(&q[20..28], b"heimdall");
        assert_eq!(q[28], 8);
        assert_eq!(&q[29..37], b"internal");
        assert_eq!(q[37], 0, "QNAME root terminator");

        // QTYPE/QCLASS
        assert_eq!(&q[38..40], &[0x00, 0x01], "QTYPE=A");
        assert_eq!(&q[40..42], &[0x00, 0x01], "QCLASS=IN");

        assert_eq!(q.len(), 42, "total query length");
    }

    #[test]
    fn validate_response_accepts_well_formed() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&0xABCD_u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x8000_u16.to_be_bytes()); // QR=1
        assert!(validate_response(&buf, 0xABCD).is_ok());
    }

    #[test]
    fn validate_response_accepts_any_rcode() {
        // QR=1, RCODE=2 (SERVFAIL) — still a valid DNS response per ENV-065.
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&0x0042_u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x8002_u16.to_be_bytes());
        assert!(validate_response(&buf, 0x0042).is_ok());
        // QR=1, RCODE=5 (REFUSED).
        buf[2..4].copy_from_slice(&0x8005_u16.to_be_bytes());
        assert!(validate_response(&buf, 0x0042).is_ok());
    }

    #[test]
    fn validate_response_rejects_short() {
        let buf = vec![0u8; 11];
        let err = validate_response(&buf, 0).unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn validate_response_rejects_id_mismatch() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&0x1111_u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x8000_u16.to_be_bytes());
        let err = validate_response(&buf, 0x2222).unwrap_err();
        assert!(err.contains("id mismatch"), "got: {err}");
    }

    #[test]
    fn validate_response_rejects_query_bit() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&0xABCD_u16.to_be_bytes());
        // flags=0 → QR=0 — server replied as if this were a query.
        let err = validate_response(&buf, 0xABCD).unwrap_err();
        assert!(err.contains("QR bit not set"), "got: {err}");
    }

    #[test]
    fn random_id_returns_a_u16() {
        // The function is non-deterministic; the only invariant we can check
        // is that it produces a u16 (statically guaranteed by the type).
        // This test exists so CI exercises the branch.
        let _ = random_id();
    }
}
