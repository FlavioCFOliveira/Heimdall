// SPDX-License-Identifier: MIT

//! Minimal DNS health-check probe for the Dockerfile `HEALTHCHECK` directive.
//!
//! Sends a single UDP DNS query for `health.heimdall.internal.` (type A) to the
//! configured target and exits 0 if a valid DNS response is received within the
//! deadline, or 1 on timeout, connection error, or a malformed response.
//!
//! # Usage
//!
//! ```text
//! heimdall-probe [<host>] [<port>] [<timeout_ms>]
//! ```
//!
//! Defaults: host = `127.0.0.1`, port = `53`, timeout = `2000` ms.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | DNS response received (any RCODE) |
//! | 1    | Timeout, socket error, or malformed response |
//!
//! The probe treats *any* DNS response as healthy: NXDOMAIN is fine because
//! `health.heimdall.internal.` deliberately has no real record — the probe
//! only needs to confirm that the DNS listener is up and responding on the wire.
//!
//! # Wire format
//!
//! The query is hand-built to avoid any dependency on `heimdall-core`.  The
//! DNS message structure follows RFC 1035 §4:
//!
//! ```text
//! Header  (12 bytes): ID | FLAGS | QDCOUNT=1 | ANCOUNT=0 | NSCOUNT=0 | ARCOUNT=0
//! QNAME            : \x06health\x08heimdall\x08internal\x00
//! QTYPE  (2 bytes) : 0x0001 (A)
//! QCLASS (2 bytes) : 0x0001 (IN)
//! ```

#![deny(unsafe_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

// ── Wire-format constants ──────────────────────────────────────────────────────

const QUERY_ID: u16 = 0xAB_CD;
const FLAGS_RD: u16 = 0x01_00; // QR=0 QUERY, RD=1

// DNS encoded name for `health.heimdall.internal.`
//   \x06health  = length-prefixed "health"
//   \x08heimdall = length-prefixed "heimdall"
//   \x08internal = length-prefixed "internal"
//   \x00        = root label
const QNAME: &[u8] = b"\x06health\x08heimdall\x08internal\x00";
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;

// A valid DNS response has the QR bit (bit 15) set in the FLAGS word.
const DNS_QR_BIT: u8 = 0x80;

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).map_or("127.0.0.1", String::as_str);
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(53);
    let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2_000);

    let target: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("heimdall-probe: invalid target {host}:{port}: {e}");
            std::process::exit(1);
        }
    };

    std::process::exit(probe(target, Duration::from_millis(timeout_ms)));
}

// ── Probe logic ───────────────────────────────────────────────────────────────

fn probe(target: SocketAddr, timeout: Duration) -> i32 {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("heimdall-probe: bind: {e}");
            return 1;
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(timeout)) {
        eprintln!("heimdall-probe: set_read_timeout: {e}");
        return 1;
    }

    let query = build_query();

    if let Err(e) = socket.send_to(&query, target) {
        eprintln!("heimdall-probe: send_to {target}: {e}");
        return 1;
    }

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _src)) => {
            if is_valid_response(&buf[..n]) {
                0
            } else {
                eprintln!("heimdall-probe: malformed response ({n} bytes)");
                1
            }
        }
        Err(e) => {
            eprintln!("heimdall-probe: recv: {e}");
            1
        }
    }
}

// ── DNS wire-format helpers ───────────────────────────────────────────────────

fn build_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + QNAME.len() + 4);
    push_u16(&mut pkt, QUERY_ID);
    push_u16(&mut pkt, FLAGS_RD);
    push_u16(&mut pkt, 1); // QDCOUNT
    push_u16(&mut pkt, 0); // ANCOUNT
    push_u16(&mut pkt, 0); // NSCOUNT
    push_u16(&mut pkt, 0); // ARCOUNT
    pkt.extend_from_slice(QNAME);
    push_u16(&mut pkt, QTYPE_A);
    push_u16(&mut pkt, QCLASS_IN);
    pkt
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xFF) as u8);
}

fn is_valid_response(pkt: &[u8]) -> bool {
    // Minimum DNS header is 12 bytes; QR bit is bit 15 of FLAGS (byte 2).
    pkt.len() >= 12 && pkt[2] & DNS_QR_BIT != 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_correct_header() {
        let q = build_query();
        // Minimum size: 12 header + QNAME.len() + 4 (QTYPE + QCLASS)
        assert!(q.len() >= 12 + QNAME.len() + 4);
        // ID
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), QUERY_ID);
        // FLAGS: RD bit set, QR=0 (query)
        let flags = u16::from_be_bytes([q[2], q[3]]);
        assert_eq!(flags & 0x01_00, 0x01_00, "RD bit must be set");
        assert_eq!(flags & 0x80_00, 0, "QR bit must be 0 (query)");
        // QDCOUNT = 1
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
    }

    #[test]
    fn qname_encodes_health_heimdall_internal() {
        let q = build_query();
        let name_start = 12;
        let name_end = name_start + QNAME.len();
        assert_eq!(&q[name_start..name_end], QNAME);
    }

    #[test]
    fn qtype_and_qclass_are_a_in() {
        let q = build_query();
        let offset = 12 + QNAME.len();
        let qtype = u16::from_be_bytes([q[offset], q[offset + 1]]);
        let qclass = u16::from_be_bytes([q[offset + 2], q[offset + 3]]);
        assert_eq!(qtype, QTYPE_A);
        assert_eq!(qclass, QCLASS_IN);
    }

    #[test]
    fn is_valid_response_requires_qr_bit() {
        // Too short
        assert!(!is_valid_response(&[0u8; 11]));
        // QR bit not set (query, not response)
        let mut pkt = [0u8; 12];
        assert!(!is_valid_response(&pkt));
        // QR bit set
        pkt[2] = 0x80;
        assert!(is_valid_response(&pkt));
    }

    #[test]
    fn is_valid_response_accepts_any_rcode() {
        let mut pkt = [0u8; 12];
        pkt[2] = 0x81; // QR=1, RD=1
        pkt[3] = 0x03; // RCODE=3 (NXDOMAIN)
        assert!(is_valid_response(&pkt));
    }
}
