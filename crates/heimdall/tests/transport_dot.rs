// SPDX-License-Identifier: MIT

//! E2E: DoT (DNS-over-TLS, RFC 7858) inbound transport (Sprint 47 task #575).
//!
//! Starts a real `heimdall` process with a DoT listener backed by the test PKI,
//! sends an A query over TLS, and asserts a valid authoritative NOERROR response.
//! Also verifies that the DoT port rejects plaintext TCP connections.

#![cfg(unix)]

use std::{
    io::{Read, Write as _},
    net::TcpStream,
    path::Path,
    time::Duration,
};

use heimdall_e2e_harness::{TestServer, dns_client, pki::TestPki};

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn zone_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/zones/example.com.zone"
    ))
}

/// DoT query for an A record returns NOERROR with at least one answer.
#[test]
fn dot_server_basic_query_noerror() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_dot(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let resp = dns_client::query_a_dot(server.dns_addr(), "example.com.", &pki.ca_cert_pem);

    assert!(resp.qr, "QR bit must be set");
    assert_eq!(resp.rcode, 0, "RCODE must be NOERROR");
    assert!(resp.ancount >= 1, "must have at least one answer record");
}

/// The DoT port must reject plaintext TCP connections — no TLS fallback.
///
/// When a plain 2-byte-framed DNS query is sent to the DoT port without a TLS
/// handshake, the connection must be closed without returning a valid DNS
/// response (RFC 7858 §3.3 — only RFC 7858-compliant TLS is accepted).
#[test]
fn dot_server_no_plaintext_fallback() {
    let pki = TestPki::generate();
    let server = TestServer::start_auth_dot(
        BIN,
        "example.com.",
        zone_path(),
        &pki.server_cert_path,
        &pki.server_key_path,
    );

    let mut tcp = TcpStream::connect(server.dns_addr()).expect("TCP connect");
    tcp.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set_read_timeout");

    // Build a plain 2-byte-framed A query for example.com.
    let id: u16 = 0xAB42;
    let mut dns_msg = Vec::new();
    dns_msg.extend_from_slice(&id.to_be_bytes());
    dns_msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    dns_msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    dns_msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN=0 NS=0 AR=0
    dns_msg.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    dns_msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    dns_msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

    let mut framed = Vec::new();
    framed.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&dns_msg);

    let _ = tcp.write_all(&framed);

    // The DoT listener expects a TLS ClientHello; plaintext bytes will cause
    // a TLS handshake failure and connection close.
    let mut buf = [0u8; 64];
    match tcp.read(&mut buf) {
        Ok(0) | Err(_) => {
            // Connection closed or timed out — correct DoT behaviour.
        }
        Ok(n) => {
            // Some bytes received; must NOT be a 2-byte-framed DNS response with QR=1.
            // A valid TCP-framed DNS answer is at minimum 14 bytes (2 len + 12 hdr).
            assert!(
                n < 14 || (buf[2] & 0x80) == 0,
                "DoT port must not respond to plaintext DNS with a valid DNS response; \
                 received {n} bytes: {:?}",
                &buf[..n]
            );
        }
    }
}
