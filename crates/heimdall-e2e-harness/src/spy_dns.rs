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

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

// ── SlowDnsServer ─────────────────────────────────────────────────────────────

/// In-process UDP DNS server that responds to any A-type query with a
/// configurable delay and a fixed IPv4 address.
///
/// Used in cache E2E tests to inject upstream latency and verify that the
/// second query is served from cache (and is therefore faster than the first).
///
/// Drop this value to stop the background thread.
pub struct SlowDnsServer {
    /// The address this server is bound to.
    pub addr: SocketAddr,
    /// Total number of queries received so far.
    query_count: Arc<AtomicUsize>,
    _socket: Arc<UdpSocket>,
}

impl SlowDnsServer {
    /// Binds a UDP socket on `bind_addr` and starts the background thread.
    ///
    /// Every incoming query is answered after `delay_ms` milliseconds with an
    /// A record for the queried name, using `ip` as the address and `ttl` as
    /// the record TTL.
    pub fn start(bind_addr: SocketAddr, delay_ms: u64, ip: Ipv4Addr, ttl: u32) -> Self {
        let socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .unwrap_or_else(|e| panic!("SlowDnsServer: bind {bind_addr}: {e}")),
        );
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set_read_timeout");
        let addr = socket.local_addr().expect("local_addr");
        let query_count = Arc::new(AtomicUsize::new(0));

        let thread_socket = Arc::clone(&socket);
        let thread_count = Arc::clone(&query_count);
        thread::spawn(move || {
            slow_server_loop(&thread_socket, &thread_count, delay_ms, ip, ttl);
        });

        Self {
            addr,
            query_count,
            _socket: socket,
        }
    }

    /// Returns the total number of queries received so far.
    pub fn query_count(&self) -> usize {
        self.query_count.load(Ordering::Relaxed)
    }
}

fn slow_server_loop(
    socket: &UdpSocket,
    query_count: &Arc<AtomicUsize>,
    delay_ms: u64,
    ip: Ipv4Addr,
    ttl: u32,
) {
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

        query_count.fetch_add(1, Ordering::Relaxed);

        if delay_ms > 0 {
            thread::sleep(Duration::from_millis(delay_ms));
        }

        let reply = build_a_answer_with_ttl(&buf[..len], ip, ttl);
        let _ = socket.send_to(&reply, src);
    }
}

/// Build an authoritative A-record answer with a custom TTL.
fn build_a_answer_with_ttl(query: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let question_bytes = extract_question_bytes(query);
    let qname_wire = extract_qname_wire(query);

    // Answer: <qname> <ttl> IN A <ip>
    let mut answer = Vec::new();
    answer.extend_from_slice(&qname_wire);
    answer.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    answer.extend_from_slice(&ttl.to_be_bytes()); // TTL (configurable)
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
    /// Return an NS referral with multiple NS/glue entries.
    ///
    /// Each `(ns_name, glue_ip)` pair becomes one NS record in the authority section
    /// and one A glue record in the additional section.  Useful for testing mixed
    /// in-bailiwick + out-of-bailiwick glue scenarios.
    ReferralMultiNs {
        zone: String,
        entries: Vec<(String, Ipv4Addr)>,
    },
    /// Return an authoritative A-record answer for the incoming QNAME.
    ///
    /// Echoes the exact question section from the query (0x20 conformant).
    Answer { ip: Ipv4Addr },
    /// Like `Answer` but also includes an NS record in the authority section
    /// and a glue A record in the additional section.
    ///
    /// Used to exercise RPZ NSIP and NSDNAME trigger paths: the recursive
    /// resolver extracts `ns_name` and `ns_ip` from the authority/additional
    /// sections of the final answer for post-resolution RPZ evaluation.
    AnswerWithAuthority {
        ip: Ipv4Addr,
        ns_name: String,
        ns_ip: Ipv4Addr,
    },
    /// Like `Answer` but returns the QNAME lowercased in the question section.
    ///
    /// Used to simulate a 0x20-intolerant server; the resolver's conformance
    /// check fails and eventually disables 0x20 for this upstream.
    NonConformantAnswer { ip: Ipv4Addr },
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
    /// Pre-lowercase (qname, qtype) of all queries received so far.
    queries_raw: Arc<Mutex<Vec<(String, u16)>>>,
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
        let queries_raw: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicUsize::new(0));

        let thread_socket = Arc::clone(&socket);
        let thread_queries = Arc::clone(&queries);
        let thread_queries_raw = Arc::clone(&queries_raw);
        thread::spawn(move || {
            spy_server_loop(
                &thread_socket,
                &thread_queries,
                &thread_queries_raw,
                &counter,
                &responses,
            );
        });

        Self {
            addr,
            queries,
            queries_raw,
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

    /// Returns a snapshot of all `(qname_original_case, qtype)` pairs received so far.
    ///
    /// Unlike `received`, the QNAME strings are NOT lowercased, allowing callers
    /// to detect whether the resolver applied 0x20 case randomisation.
    pub fn received_raw(&self) -> Vec<(String, u16)> {
        self.queries_raw
            .lock()
            .expect("SpyDnsServer mutex poisoned")
            .clone()
    }
}

// ── Server loop ───────────────────────────────────────────────────────────────

fn spy_server_loop(
    socket: &UdpSocket,
    queries: &Arc<Mutex<Vec<(String, u16)>>>,
    queries_raw: &Arc<Mutex<Vec<(String, u16)>>>,
    counter: &Arc<AtomicUsize>,
    responses: &[SpyResponse],
) {
    assert!(
        !responses.is_empty(),
        "SpyDnsServer requires at least one response"
    );
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
        let Some((qname_raw, qtype)) = parse_qname_qtype_raw(pkt) else {
            continue;
        };
        let qname_lower = qname_raw.to_lowercase();

        queries
            .lock()
            .expect("SpyDnsServer mutex poisoned")
            .push((qname_lower, qtype));

        queries_raw
            .lock()
            .expect("SpyDnsServer mutex poisoned")
            .push((qname_raw, qtype));

        let idx = counter.fetch_add(1, Ordering::Relaxed);
        let resp = &responses[idx.min(responses.len() - 1)];
        let reply = build_response(pkt, resp);
        let _ = socket.send_to(&reply, src);
    }
}

// ── DNS wire parsing ──────────────────────────────────────────────────────────

/// Extracts the QNAME (preserving original case) and QTYPE from a DNS query packet.
fn parse_qname_qtype_raw(pkt: &[u8]) -> Option<(String, u16)> {
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
        labels.push(String::from_utf8_lossy(label).into_owned());
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
        SpyResponse::ReferralMultiNs { zone, entries } => {
            build_multi_ns_referral(query, zone, entries)
        }
        SpyResponse::Answer { ip } => build_a_answer(query, *ip, false),
        SpyResponse::AnswerWithAuthority { ip, ns_name, ns_ip } => {
            build_a_answer_with_authority(query, *ip, ns_name, *ns_ip)
        }
        SpyResponse::NonConformantAnswer { ip } => build_a_answer(query, *ip, true),
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

/// Builds an NS referral with multiple NS/glue entries: AA=0, N authority NS
/// records, N additional A glue records.
fn build_multi_ns_referral(query: &[u8], zone: &str, entries: &[(String, Ipv4Addr)]) -> Vec<u8> {
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let question_bytes = extract_question_bytes(query);
    let zone_wire = name_to_wire(zone);

    let mut authority = Vec::new();
    let mut additional = Vec::new();

    for (ns_name, glue_ip) in entries {
        let ns_wire = name_to_wire(ns_name);

        // Authority: <zone> 300 IN NS <ns_name>
        authority.extend_from_slice(&zone_wire);
        authority.extend_from_slice(&2u16.to_be_bytes()); // TYPE NS
        authority.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        authority.extend_from_slice(&300u32.to_be_bytes()); // TTL
        authority.extend_from_slice(&(ns_wire.len() as u16).to_be_bytes());
        authority.extend_from_slice(&ns_wire);

        // Additional: <ns_name> 300 IN A <glue_ip>
        additional.extend_from_slice(&ns_wire);
        additional.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        additional.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        additional.extend_from_slice(&300u32.to_be_bytes()); // TTL
        additional.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        additional.extend_from_slice(&glue_ip.octets());
    }

    let n = entries.len() as u16;
    let mut out =
        Vec::with_capacity(12 + question_bytes.len() + authority.len() + additional.len());
    out.extend_from_slice(id);
    out.extend_from_slice(&0x8000u16.to_be_bytes()); // QR=1, AA=0, RCODE=0
    out.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&n.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&n.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&question_bytes);
    out.extend_from_slice(&authority);
    out.extend_from_slice(&additional);
    out
}

/// Builds an authoritative A-record answer: AA=1, answer A.
///
/// If `lowercase_question` is `true`, the question section uses a lowercased
/// QNAME instead of echoing the exact wire bytes from the query.  This simulates
/// a 0x20-intolerant server, causing the resolver's conformance check to fail.
fn build_a_answer(query: &[u8], ip: Ipv4Addr, lowercase_question: bool) -> Vec<u8> {
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    // Derive question bytes — either echoed or lowercased.
    let question_bytes = if lowercase_question {
        build_lowercase_question(query)
    } else {
        extract_question_bytes(query)
    };

    // RDATA name: use lowercased wire when non-conformant so the answer also
    // matches the lowercased question (keeps the response parseable).
    let qname_wire = if lowercase_question {
        lowercase_qname_wire(query)
    } else {
        extract_qname_wire(query)
    };

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

/// Builds an authoritative A-record answer that also includes an NS record in
/// the authority section and a glue A record in the additional section.
///
/// This simulates an authoritative server that includes delegation information
/// alongside its answer — used to populate RPZ NSIP / NSDNAME contexts.
fn build_a_answer_with_authority(
    query: &[u8],
    ip: Ipv4Addr,
    ns_name: &str,
    ns_ip: Ipv4Addr,
) -> Vec<u8> {
    let id = &query[0..2];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    let question_bytes = extract_question_bytes(query);
    let qname_wire = extract_qname_wire(query);
    let ns_wire = name_to_wire(ns_name);

    // Answer: <qname> 300 IN A <ip>
    let mut answer = Vec::new();
    answer.extend_from_slice(&qname_wire);
    answer.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    answer.extend_from_slice(&300u32.to_be_bytes()); // TTL
    answer.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    answer.extend_from_slice(&ip.octets());

    // Authority: <qname> 300 IN NS <ns_name>
    let mut authority = Vec::new();
    authority.extend_from_slice(&qname_wire);
    authority.extend_from_slice(&2u16.to_be_bytes()); // TYPE NS
    authority.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    authority.extend_from_slice(&300u32.to_be_bytes()); // TTL
    authority.extend_from_slice(&(ns_wire.len() as u16).to_be_bytes());
    authority.extend_from_slice(&ns_wire);

    // Additional: <ns_name> 300 IN A <ns_ip>
    let mut additional = Vec::new();
    additional.extend_from_slice(&ns_wire);
    additional.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    additional.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    additional.extend_from_slice(&300u32.to_be_bytes()); // TTL
    additional.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    additional.extend_from_slice(&ns_ip.octets());

    let mut out = Vec::with_capacity(
        12 + question_bytes.len() + answer.len() + authority.len() + additional.len(),
    );
    out.extend_from_slice(id);
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // QR=1, AA=1, RCODE=0
    out.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&question_bytes);
    out.extend_from_slice(&answer);
    out.extend_from_slice(&authority);
    out.extend_from_slice(&additional);
    out
}

/// Builds a question section with the QNAME lowercased.
fn build_lowercase_question(query: &[u8]) -> Vec<u8> {
    let orig = extract_question_bytes(query);
    // orig = [QNAME wire...][QTYPE 2B][QCLASS 2B]
    // Walk the QNAME wire, lowercase each byte.
    let mut result = orig.clone();
    let mut pos = 0;
    while pos < result.len() {
        let len = result[pos] as usize;
        if len == 0 {
            break;
        }
        for byte in result.iter_mut().skip(pos + 1).take(len) {
            *byte = byte.to_ascii_lowercase();
        }
        pos += 1 + len;
    }
    result
}

/// Returns the QNAME wire bytes from the query with all labels lowercased.
fn lowercase_qname_wire(query: &[u8]) -> Vec<u8> {
    let mut wire = extract_qname_wire(query);
    let mut pos = 0;
    while pos < wire.len() {
        let len = wire[pos] as usize;
        if len == 0 {
            break;
        }
        for byte in wire.iter_mut().skip(pos + 1).take(len) {
            *byte = byte.to_ascii_lowercase();
        }
        pos += 1 + len;
    }
    wire
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
