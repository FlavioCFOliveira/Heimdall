// SPDX-License-Identifier: MIT

//! Minimal in-process UDP DNS server that records received query names.
//!
//! Used by QNAME minimisation E2E tests (Sprint 47 task #474) to observe
//! exactly which QNAME/QTYPE the recursive resolver sends to each server in the
//! delegation chain.
//!
//! ## Design
//!
//! `SpyDnsServer` binds a UDP socket on a caller-supplied address, runs a
//! background thread that reads incoming packets, decodes the QNAME (lowercased
//! for case-insensitive comparison), appends it to a shared `Vec`, and returns
//! a pre-configured DNS response.
//!
//! Responses are selected from an ordered sequence: the nth query (0-indexed)
//! picks `responses[n]`, or `responses[last]` once the list is exhausted.  This
//! allows a single spy to serve both the root zone and a TLD zone — returning
//! different NS referrals for the first and second queries.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single pre-configured response the spy server can return.
#[derive(Clone)]
pub enum SpyResponse {
    /// Return an NS referral: `<zone> NS <ns_name>`, glue `<ns_name> A <glue_ip>`.
    Referral {
        zone: String,
        ns_name: String,
        glue_ip: Ipv4Addr,
    },
    /// Return an authoritative A-record answer for the incoming QNAME.
    Answer { ip: Ipv4Addr },
}

/// In-process UDP DNS server that records incoming query names.
///
/// Responses are served in sequence: the nth query uses `responses[n]` (or the
/// last element once the list is exhausted).
///
/// Drop this value to stop the background thread.
pub struct SpyDnsServer {
    /// The address this server is bound to.
    pub addr: SocketAddr,
    /// Lowercased (qname, qtype) of all queries received so far.
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    _socket: Arc<UdpSocket>,
}

impl SpyDnsServer {
    /// Binds a UDP socket on `bind_addr` and starts the background thread.
    ///
    /// `responses[n]` is used for the nth incoming query.  The last response
    /// repeats once the list is exhausted.
    pub fn start(bind_addr: SocketAddr, responses: Vec<SpyResponse>) -> Self {
        let socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .unwrap_or_else(|e| panic!("SpyDnsServer: bind {bind_addr}: {e}")),
        );
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .expect("set_read_timeout");
        let addr = socket.local_addr().expect("local_addr");
        let queries: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicUsize::new(0));

        let thread_socket = Arc::clone(&socket);
        let thread_queries = Arc::clone(&queries);
        thread::spawn(move || {
            spy_server_loop(&thread_socket, &thread_queries, &counter, &responses);
        });

        Self {
            addr,
            queries,
            _socket: socket,
        }
    }

    /// Returns a snapshot of all `(qname_lowercase, qtype)` pairs received so far.
    pub fn received(&self) -> Vec<(String, u16)> {
        self.queries
            .lock()
            .expect("SpyDnsServer mutex poisoned")
            .clone()
    }
}

// ── Server loop ───────────────────────────────────────────────────────────────

fn spy_server_loop(
    socket: &UdpSocket,
    queries: &Arc<Mutex<Vec<(String, u16)>>>,
    counter: &Arc<AtomicUsize>,
    responses: &[SpyResponse],
) {
    assert!(!responses.is_empty(), "SpyDnsServer requires at least one response");
    let mut buf = [0u8; 4096];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return,
        };

        let pkt = &buf[..len];
        let Some((qname_lower, qtype)) = parse_qname_qtype(pkt) else {
            continue;
        };

        queries
            .lock()
            .expect("SpyDnsServer mutex poisoned")
            .push((qname_lower.clone(), qtype));

        let idx = counter.fetch_add(1, Ordering::Relaxed);
        let resp = &responses[idx.min(responses.len() - 1)];
        let reply = build_response(pkt, resp);
        let _ = socket.send_to(&reply, src);
    }
}

// ── DNS wire parsing ──────────────────────────────────────────────────────────

/// Extracts the QNAME (lowercased) and QTYPE from a DNS query packet.
fn parse_qname_qtype(pkt: &[u8]) -> Option<(String, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();

    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > pkt.len() {
            return None;
        }
        let label = &pkt[pos + 1..pos + 1 + len];
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        pos += 1 + len;
    }

    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);

    let qname = if labels.is_empty() {
        ".".to_owned()
    } else {
        labels.join(".") + "."
    };

    Some((qname, qtype))
}

// ── DNS wire building ─────────────────────────────────────────────────────────

fn build_response(query: &[u8], resp: &SpyResponse) -> Vec<u8> {
    match resp {
        SpyResponse::Referral {
            zone,
            ns_name,
            glue_ip,
        } => build_ns_referral(query, zone, ns_name, *glue_ip),
        SpyResponse::Answer { ip } => build_a_answer(query, *ip),
    }
}

/// Builds an NS referral: AA=0, authority NS, additional glue A.
fn build_ns_referral(query: &[u8], zone: &str, ns_name: &str, glue_ip: Ipv4Addr) -> Vec<u8> {
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let question_bytes = extract_question_bytes(query);

    let zone_wire = name_to_wire(zone);
    let ns_wire = name_to_wire(ns_name);

    // Authority: <zone> 300 IN NS <ns_name>
    let mut authority = Vec::new();
    authority.extend_from_slice(&zone_wire);
    authority.extend_from_slice(&2u16.to_be_bytes()); // TYPE NS
    authority.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    authority.extend_from_slice(&300u32.to_be_bytes()); // TTL
    authority.extend_from_slice(&(ns_wire.len() as u16).to_be_bytes()); // RDLENGTH
    authority.extend_from_slice(&ns_wire);

    // Additional: <ns_name> 300 IN A <glue_ip>
    let mut additional = Vec::new();
    additional.extend_from_slice(&ns_wire);
    additional.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    additional.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    additional.extend_from_slice(&300u32.to_be_bytes()); // TTL
    additional.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    additional.extend_from_slice(&glue_ip.octets());

    let mut out =
        Vec::with_capacity(12 + question_bytes.len() + authority.len() + additional.len());
    out.extend_from_slice(id);
    out.extend_from_slice(&0x8000u16.to_be_bytes()); // QR=1, AA=0, RCODE=0
    out.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&question_bytes);
    out.extend_from_slice(&authority);
    out.extend_from_slice(&additional);
    out
}

/// Builds an authoritative A-record answer: AA=1, answer A.
fn build_a_answer(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let question_bytes = extract_question_bytes(query);
    let qname_wire = extract_qname_wire(query);

    // Answer: <qname> 300 IN A <ip>
    let mut answer = Vec::new();
    answer.extend_from_slice(&qname_wire);
    answer.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    answer.extend_from_slice(&300u32.to_be_bytes()); // TTL
    answer.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    answer.extend_from_slice(&ip.octets());

    let mut out = Vec::with_capacity(12 + question_bytes.len() + answer.len());
    out.extend_from_slice(id);
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1, RCODE=0
    out.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&question_bytes);
    out.extend_from_slice(&answer);
    out
}

/// Encodes a domain name as uncompressed DNS wire bytes.
fn name_to_wire(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
    }
    wire.push(0); // root label
    wire
}

/// Extracts the raw question section bytes (QNAME + QTYPE + QCLASS).
fn extract_question_bytes(pkt: &[u8]) -> Vec<u8> {
    if pkt.len() < 12 {
        return Vec::new();
    }
    let mut pos = 12;
    loop {
        if pos >= pkt.len() {
            return Vec::new();
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len;
    }
    let end = pos + 4;
    if end > pkt.len() {
        return Vec::new();
    }
    pkt[12..end].to_vec()
}

/// Extracts just the QNAME wire bytes from the question section.
fn extract_qname_wire(pkt: &[u8]) -> Vec<u8> {
    if pkt.len() < 12 {
        return vec![0];
    }
    let mut pos = 12;
    let start = pos;
    loop {
        if pos >= pkt.len() {
            return vec![0];
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len;
    }
    pkt[start..pos].to_vec()
}
