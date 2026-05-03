// SPDX-License-Identifier: MIT

//! Minimal synchronous DNS-over-UDP test client.
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
    /// `AA` (Authoritative Answer) bit.
    pub aa: bool,
    /// RCODE (lower 4 bits of flags).
    pub rcode: u8,
    /// Number of answer records (from header).
    pub ancount: u16,
    /// Number of authority records (from header).
    pub nscount: u16,
    /// Record TYPE values present in the answer section.
    pub answer_types: Vec<u16>,
    /// TTL of the first authority-section record, if any.
    pub authority_first_ttl: Option<u32>,
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

    let id      = u16::from_be_bytes([wire[0], wire[1]]);
    let flags   = u16::from_be_bytes([wire[2], wire[3]]);
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]);
    let nscount = u16::from_be_bytes([wire[8], wire[9]]);

    let mut pos = 12;

    // Skip question section.
    for _ in 0..qdcount {
        pos = skip_name(&wire, pos);
        pos += 4; // QTYPE + QCLASS
    }

    // Decode answer section: collect record types.
    let mut answer_types = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        if pos >= wire.len() { break; }
        answer_types.push(read_rr_type(&wire, pos));
        pos = skip_rr(&wire, pos);
    }

    // First authority record TTL.
    let authority_first_ttl = if nscount > 0 && pos < wire.len() {
        Some(read_rr_ttl(&wire, pos))
    } else {
        None
    };

    DnsResponse {
        id,
        qr:  (flags & 0x8000) != 0,
        aa:  (flags & 0x0400) != 0,
        rcode: (flags & 0x000F) as u8,
        ancount,
        nscount,
        answer_types,
        authority_first_ttl,
        wire,
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Skip a DNS name (handles compression pointers) and return the position after it.
fn skip_name(wire: &[u8], pos: usize) -> usize {
    let mut p = pos;
    loop {
        if p >= wire.len() { return p; }
        let b = wire[p];
        if b == 0 {
            return p + 1;
        } else if (b & 0xC0) == 0xC0 {
            return p + 2;
        } else {
            p += 1 + b as usize;
        }
    }
}

/// Skip an entire RR (name + fixed header + RDATA) and return the next position.
fn skip_rr(wire: &[u8], pos: usize) -> usize {
    let name_end = skip_name(wire, pos);
    if name_end + 10 > wire.len() { return wire.len(); }
    let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
    name_end + 10 + rdlen
}

/// Read the TYPE field of an RR at `pos`.
fn read_rr_type(wire: &[u8], pos: usize) -> u16 {
    let name_end = skip_name(wire, pos);
    if name_end + 2 > wire.len() { return 0; }
    u16::from_be_bytes([wire[name_end], wire[name_end + 1]])
}

/// Read the TTL field (bytes 4-7 after the name end) of an RR at `pos`.
fn read_rr_ttl(wire: &[u8], pos: usize) -> u32 {
    let name_end = skip_name(wire, pos);
    if name_end + 8 > wire.len() { return 0; }
    u32::from_be_bytes([
        wire[name_end + 4],
        wire[name_end + 5],
        wire[name_end + 6],
        wire[name_end + 7],
    ])
}
