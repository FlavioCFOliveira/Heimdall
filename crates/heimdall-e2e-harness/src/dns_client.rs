// SPDX-License-Identifier: MIT

//! Minimal synchronous DNS-over-UDP/TCP test client.
//!
//! Used in E2E tests to send queries and inspect responses without pulling in a
//! full resolver library.  Only the fields needed for correctness assertions are
//! decoded.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// A decoded DNS response for test assertions.
#[derive(Debug)]
pub struct DnsResponse {
    /// Transaction ID copied from the query.
    pub id: u16,
    /// `QR` bit.
    pub qr: bool,
    /// RCODE (lower 4 bits of flags).
    pub rcode: u8,
    /// Number of answer records.
    pub ancount: u16,
    /// Raw wire bytes of the response.
    pub wire: Vec<u8>,
}

/// Send a single A-type query for `qname` to `server` over UDP and return the
/// decoded response.
///
/// Timeout is 2 seconds.
///
/// # Panics
///
/// Panics on any I/O or parse error — acceptable in test code.
pub fn query_a(server: SocketAddr, qname: &str) -> DnsResponse {
    query(server, qname, 1 /* A */)
}

/// Send a single AAAA-type query.
pub fn query_aaaa(server: SocketAddr, qname: &str) -> DnsResponse {
    query(server, qname, 28 /* AAAA */)
}

/// Send a single MX-type query.
pub fn query_mx(server: SocketAddr, qname: &str) -> DnsResponse {
    query(server, qname, 15 /* MX */)
}

/// Send a single SOA-type query.
pub fn query_soa(server: SocketAddr, qname: &str) -> DnsResponse {
    query(server, qname, 6 /* SOA */)
}

/// Build a minimal query wire message.
fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header: ID, FLAGS=RD, QDCOUNT=1, rest 0.
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes());       // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes());       // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());       // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());       // ARCOUNT

    // QNAME as wire-encoded labels.
    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8); // root label

    // QTYPE + QCLASS (IN = 1)
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    buf
}

fn query(server: SocketAddr, qname: &str, qtype: u16) -> DnsResponse {
    let id: u16 = 0xAB42;
    let wire_query = build_query(id, qname, qtype);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");
    sock.send_to(&wire_query, server).expect("send DNS query");

    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).expect("recv DNS response");
    let wire = buf[..n].to_vec();

    parse_response(wire)
}

fn parse_response(wire: Vec<u8>) -> DnsResponse {
    assert!(wire.len() >= 12, "response too short: {} bytes", wire.len());

    let id = u16::from_be_bytes([wire[0], wire[1]]);
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let ancount = u16::from_be_bytes([wire[6], wire[7]]);

    DnsResponse {
        id,
        qr: (flags & 0x8000) != 0,
        rcode: (flags & 0x000F) as u8,
        ancount,
        wire,
    }
}
