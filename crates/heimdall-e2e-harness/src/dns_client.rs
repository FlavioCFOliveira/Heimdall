// SPDX-License-Identifier: MIT

//! Minimal synchronous DNS test client (UDP + TCP).
//!
//! Used in E2E tests to send queries and inspect responses without pulling in a
//! full resolver library.  Only the fields needed for correctness assertions are
//! decoded.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
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

/// Send a single A-type query over DNS-over-TLS (RFC 7858).
///
/// Establishes a TLS connection to `server`, validating the server cert against
/// `ca_cert_pem` (PEM-encoded root CA).  The TLS server name is `"localhost"`.
///
/// Timeout is 2 seconds.  Panics on any I/O, TLS, or parse error.
pub fn query_a_dot(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    use rustls::pki_types::{CertificateDer, ServerName};

    // Ensure the ring CryptoProvider is installed; safe to call multiple times.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert to root store");
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .expect("create TLS client connection");

    let tcp = TcpStream::connect(server).expect("TCP connect for DoT");
    tcp.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");

    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let id: u16 = 0xD07A;
    let wire_query = build_query(id, qname, 1 /* A */);

    // RFC 7858 §3.3 — DNS message prefixed with a 2-octet length field.
    let len = wire_query.len() as u16;
    tls.write_all(&len.to_be_bytes()).expect("DoT: write length prefix");
    tls.write_all(&wire_query).expect("DoT: write DNS query");

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).expect("DoT: read response length");
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut body = vec![0u8; resp_len];
    tls.read_exact(&mut body).expect("DoT: read response body");

    parse_response(body)
}

extern crate rustls;
extern crate rustls_pemfile;

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

// ── Zone transfer (AXFR / IXFR) over TCP ─────────────────────────────────────

/// Decoded summary of an AXFR or IXFR response stream.
#[derive(Debug, Default)]
pub struct XfrResponse {
    /// Total number of TCP frames (2-byte-framed messages) received.
    pub frames: usize,
    /// RCODE from the first frame (0 = NOERROR, 5 = REFUSED, etc.).
    pub rcode: u8,
    /// SOA serial from the first SOA record in the response.
    pub soa_serial: u32,
    /// Total count of resource records across all answer sections.
    pub answer_count: usize,
    /// How many frames carry a TSIG record (TYPE 250) in the additional section.
    pub tsig_frames: usize,
}

/// Send an AXFR query (optionally TSIG-signed) over TCP and collect all response frames.
///
/// If `tsig_key_name` is `Some`, the query is signed with `key_bytes` using HMAC-SHA256.
/// Reads up to 128 frames or until a read timeout, whichever comes first.
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_axfr_tcp(
    server: SocketAddr,
    qname: &str,
    tsig_key_name: Option<&str>,
    key_bytes: Option<&[u8]>,
) -> XfrResponse {
    let query_wire = build_xfr_query(qname, 252 /* AXFR */, tsig_key_name, key_bytes, None);
    send_xfr_tcp(server, &query_wire)
}

/// Send an IXFR query (optionally TSIG-signed) over TCP and collect all response frames.
///
/// `client_serial` is the SOA serial the client already has (placed in the
/// authority section per RFC 1995).
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_ixfr_tcp(
    server: SocketAddr,
    qname: &str,
    client_serial: u32,
    tsig_key_name: Option<&str>,
    key_bytes: Option<&[u8]>,
) -> XfrResponse {
    let query_wire = build_xfr_query(
        qname,
        251, /* IXFR */
        tsig_key_name,
        key_bytes,
        Some(client_serial),
    );
    send_xfr_tcp(server, &query_wire)
}

/// Build a raw zone-transfer query wire message.
///
/// If `tsig_key_name` is `Some`, appends a TSIG record signed with HMAC-SHA256.
/// If `ixfr_serial` is `Some`, appends a SOA authority record (IXFR format).
fn build_xfr_query(
    qname: &str,
    qtype: u16,
    tsig_key_name: Option<&str>,
    key_bytes: Option<&[u8]>,
    ixfr_serial: Option<u32>,
) -> Vec<u8> {
    let id: u16 = 0xBB01;
    let mut buf = Vec::new();

    // Header: ID, FLAGS=0 (no RD for XFR), QDCOUNT=1, ANCOUNT=0,
    // NSCOUNT = (1 if IXFR), ARCOUNT = (1 if TSIG).
    let nscount: u16 = if ixfr_serial.is_some() { 1 } else { 0 };
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0000u16.to_be_bytes()); // FLAGS: plain query
    buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT
    buf.extend_from_slice(&nscount.to_be_bytes());   // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT (updated below if TSIG)

    // QNAME
    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8);

    // QTYPE + QCLASS IN
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    // IXFR authority SOA (RFC 1995): tells server the client's current serial.
    if let Some(serial) = ixfr_serial {
        buf.extend_from_slice(encode_qname_wire(qname).as_slice()); // owner = zone apex
        buf.extend_from_slice(&6u16.to_be_bytes()); // TYPE = SOA
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&300u32.to_be_bytes()); // TTL

        // RDATA: mname(.) rname(.) serial refresh retry expire minimum
        let mut rdata = Vec::new();
        rdata.push(0u8); // mname = root
        rdata.push(0u8); // rname = root
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // refresh
        rdata.extend_from_slice(&900u32.to_be_bytes());  // retry
        rdata.extend_from_slice(&604800u32.to_be_bytes()); // expire
        rdata.extend_from_slice(&300u32.to_be_bytes());  // minimum
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }

    // Optional TSIG record in additional section.
    if let (Some(key_name), Some(key_bytes)) = (tsig_key_name, key_bytes) {
        use heimdall_core::{TsigAlgorithm, TsigSigner};
        use std::str::FromStr as _;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let key_name_parsed =
            heimdall_core::Name::from_str(key_name).expect("valid TSIG key name");
        let signer = TsigSigner::new(key_name_parsed, TsigAlgorithm::HmacSha256, key_bytes, 300);

        let tsig_rec = signer.sign(&buf, now);
        tsig_rec.write_to(&mut buf);

        // Increment ARCOUNT (bytes 10-11).
        let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
        buf[10] = (ar >> 8) as u8;
        buf[11] = (ar & 0xFF) as u8;
    }

    buf
}

/// Encode a FQDN as wire-format label sequence (no compression).
fn encode_qname_wire(qname: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8);
    buf
}

/// Send a query over TCP with 2-byte framing and collect all response frames.
fn send_xfr_tcp(server: SocketAddr, query_wire: &[u8]) -> XfrResponse {
    let mut stream = TcpStream::connect(server).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set_read_timeout");

    // Send with 2-byte length prefix.
    let len = query_wire.len() as u16;
    stream.write_all(&len.to_be_bytes()).expect("write length");
    stream.write_all(query_wire).expect("write query");

    // Read response frames until timeout or max count.
    let mut resp = XfrResponse::default();
    let mut soa_count = 0usize;

    for _ in 0..256 {
        // Read 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => break, // timeout or FIN
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }

        let mut body = vec![0u8; msg_len];
        if stream.read_exact(&mut body).is_err() {
            break;
        }

        resp.frames += 1;
        decode_xfr_frame(&body, &mut resp, &mut soa_count);

        // AXFR terminates when we've seen 2 SOA records.
        if soa_count >= 2 {
            break;
        }
    }

    resp
}

/// Decode one XFR frame and accumulate statistics into `resp`.
fn decode_xfr_frame(wire: &[u8], resp: &mut XfrResponse, soa_count: &mut usize) {
    if wire.len() < 12 {
        return;
    }

    if resp.frames == 1 {
        resp.rcode = (u16::from_be_bytes([wire[2], wire[3]]) & 0x000F) as u8;
    }

    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let nscount = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

    // Skip question section.
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(wire, pos);
        pos += 4;
        if pos > wire.len() {
            return;
        }
    }

    // Decode answer section — track SOA records and total records.
    for _ in 0..ancount {
        if pos >= wire.len() {
            break;
        }
        let rtype = read_rr_type(wire, pos);
        if rtype == 6 {
            // SOA
            if *soa_count == 0 {
                // Extract serial from first SOA.
                let name_end = skip_name(wire, pos);
                // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes, then rdata.
                // SOA rdata: mname + rname + serial(4) + refresh(4) + retry(4) + expire(4) + minimum(4)
                let rdata_start = name_end + 10;
                if rdata_start < wire.len() {
                    let mname_end = skip_name(wire, rdata_start);
                    let rname_end = skip_name(wire, mname_end);
                    if rname_end + 4 <= wire.len() {
                        resp.soa_serial = u32::from_be_bytes([
                            wire[rname_end],
                            wire[rname_end + 1],
                            wire[rname_end + 2],
                            wire[rname_end + 3],
                        ]);
                    }
                }
            }
            *soa_count += 1;
        }
        resp.answer_count += 1;
        pos = skip_rr(wire, pos);
    }

    // Skip authority section.
    for _ in 0..nscount {
        if pos >= wire.len() {
            break;
        }
        pos = skip_rr(wire, pos);
    }

    // Check additional section for TSIG (TYPE 250).
    for _ in 0..arcount {
        if pos >= wire.len() {
            break;
        }
        let rtype = read_rr_type(wire, pos);
        if rtype == 250 {
            resp.tsig_frames += 1;
            break;
        }
        pos = skip_rr(wire, pos);
    }
}
