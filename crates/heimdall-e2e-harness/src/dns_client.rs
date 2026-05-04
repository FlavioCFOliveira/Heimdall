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
    /// `TC` (Truncated) bit — set when the response was truncated (PROTO-008).
    pub tc: bool,
    /// Full 12-bit extended RCODE combining header bits and OPT `extended_rcode`
    /// field per RFC 6891.  Equal to `rcode` when no OPT RR is present.
    ///
    /// Examples: NOERROR=0, BADCOOKIE=23.
    pub rcode_ext: u16,
    /// Opcode from bits 11–14 of the DNS header flags field.
    ///
    /// Standard values: 0 = QUERY, 4 = NOTIFY, 5 = UPDATE.
    pub opcode: u8,
    /// Number of answer records (from header).
    pub ancount: u16,
    /// Number of authority records (from header).
    pub nscount: u16,
    /// Record TYPE values present in the answer section.
    pub answer_types: Vec<u16>,
    /// TTL of the first authority-section record, if any.
    pub authority_first_ttl: Option<u32>,
    /// Server cookie bytes from the OPT RR Cookie option in the response,
    /// if present.  `None` when no OPT, no Cookie option, or client-only cookie.
    pub opt_server_cookie: Option<Vec<u8>>,
    /// `true` when the OPT RR contains a Padding option (option code 12, RFC 7830).
    pub opt_has_padding: bool,
    /// `AD` (Authentic Data) bit — set by a DNSSEC-validating resolver when the
    /// response data has been cryptographically verified (RFC 4035 §3.2.3).
    pub ad: bool,
    /// Extended DNS Error INFO-CODE from the OPT EDE option (option code 15,
    /// RFC 8914) if present.  The first 2 bytes of the OPTION-DATA.
    pub opt_ede_code: Option<u16>,
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

/// Send a single A-type query for `qname` to `server` over UDP.
///
/// Returns `None` when no response is received within the 500ms timeout
/// (expected for ACL-denied sources that receive a silent drop).
/// Returns `Some(resp)` otherwise.
///
/// # Panics
///
/// Panics on any I/O error other than timeout — acceptable in test code.
pub fn try_query_a(server: SocketAddr, qname: &str) -> Option<DnsResponse> {
    let id: u16 = 0xAB43;
    let wire_query = build_query(id, qname, 1 /* A */);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set_read_timeout");
    sock.send_to(&wire_query, server).expect("send DNS query");

    let mut buf = vec![0u8; 4096];
    match sock.recv(&mut buf) {
        Ok(n) => Some(parse_response(buf[..n].to_vec())),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut => None,
        Err(e) => panic!("unexpected UDP receive error: {e}"),
    }
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

/// Send a single TXT-type query over UDP.
pub fn query_txt(server: SocketAddr, qname: &str) -> DnsResponse {
    query(server, qname, 16 /* TXT */)
}

/// Send a single TXT-type query over UDP, advertising `udp_size` bytes as the
/// EDNS requestor payload size (RFC 6891).  Use `512` to exercise the
/// TC=1 truncation path for large TXT responses.
pub fn query_txt_edns(server: SocketAddr, qname: &str, udp_size: u16) -> DnsResponse {
    let id: u16 = 0xAB50;
    let wire = build_query_with_edns(id, qname, 16 /* TXT */, udp_size);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");
    sock.send_to(&wire, server).expect("send DNS query");

    let mut buf = vec![0u8; 65535];
    let n = sock.recv(&mut buf).expect("recv DNS response");
    parse_response(buf[..n].to_vec())
}

/// Send a single TXT-type query over TCP (2-byte framing, RFC 1035 §4.2.2).
///
/// Use this as the retry path after a UDP response with TC=1.
pub fn query_txt_tcp(server: SocketAddr, qname: &str) -> DnsResponse {
    query_tcp(server, qname, 16 /* TXT */)
}

/// Send a DNS query over TCP with 2-byte length framing (RFC 1035 §4.2.2).
///
/// Timeout is 2 seconds.  Panics on any I/O or parse error.
pub fn query_tcp(server: SocketAddr, qname: &str, qtype: u16) -> DnsResponse {
    let id: u16 = 0xAB44;
    let wire_query = build_query(id, qname, qtype);

    let mut stream = TcpStream::connect(server).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");

    let len = wire_query.len() as u16;
    stream.write_all(&len.to_be_bytes()).expect("TCP: write length prefix");
    stream.write_all(&wire_query).expect("TCP: write query");

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).expect("TCP: read response length");
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; resp_len];
    stream.read_exact(&mut body).expect("TCP: read response body");
    parse_response(body)
}

/// Send a single A-type query over DNS-over-TLS (RFC 7858).
///
/// Establishes a TLS connection to `server`, validating the server cert against
/// `ca_cert_pem` (PEM-encoded root CA).  The TLS server name is `"localhost"`.
///
/// Timeout is 2 seconds.  Panics on any I/O, TLS, or parse error.
pub fn query_a_dot(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    use rustls::pki_types::ServerName;

    // Ensure the ring CryptoProvider is installed; safe to call multiple times.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = build_rustls_client_config(ca_cert_pem);
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

/// Send a single A-type query over DoH/2 (RFC 8484) using HTTP GET.
///
/// Uses Base64url encoding of the wire query in the `?dns=` query parameter.
/// Validates the TLS server cert against `ca_cert_pem` (PEM root CA).
/// Asserts HTTP 200 and `Content-Type: application/dns-message`.
///
/// Panics on any I/O, TLS, HTTP, or parse error.
pub fn query_a_doh2_get(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_config = build_rustls_client_config(ca_cert_pem);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for DoH/2 GET client");

    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

    let id: u16 = 0xD020;
    let wire_query = build_query(id, qname, 1 /* A */);
    let encoded = base64_url_no_pad(&wire_query);
    let uri = format!("https://localhost:{}/dns-query?dns={}", server.port(), encoded);

    let req = Request::builder()
        .method("GET")
        .uri(uri.as_str())
        .header("accept", "application/dns-message")
        .body(Empty::<Bytes>::new())
        .expect("build DoH/2 GET request");

    let resp = rt.block_on(client.request(req)).expect("DoH/2 GET request failed");
    assert_eq!(resp.status().as_u16(), 200, "DoH/2 GET must return HTTP 200");
    let ct = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/dns-message"),
        "DoH/2 GET: expected Content-Type application/dns-message; got {ct:?}"
    );

    let body = rt
        .block_on(resp.into_body().collect())
        .expect("collect DoH/2 GET response body");
    parse_response(body.to_bytes().to_vec())
}

/// Send a single A-type query over DoH/2 (RFC 8484) using HTTP POST.
///
/// Posts the raw wire query as `application/dns-message` body.
/// Validates the TLS server cert against `ca_cert_pem` (PEM root CA).
/// Asserts HTTP 200 and `Content-Type: application/dns-message`.
///
/// Panics on any I/O, TLS, HTTP, or parse error.
pub fn query_a_doh2_post(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::Request;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_config = build_rustls_client_config(ca_cert_pem);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for DoH/2 POST client");

    let id: u16 = 0xD021;
    let wire_query = build_query(id, qname, 1 /* A */);
    let uri = format!("https://localhost:{}/dns-query", server.port());

    let req = Request::builder()
        .method("POST")
        .uri(uri.as_str())
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(&wire_query)))
        .expect("build DoH/2 POST request");

    let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);
    let resp = rt.block_on(client.request(req)).expect("DoH/2 POST request failed");
    assert_eq!(resp.status().as_u16(), 200, "DoH/2 POST must return HTTP 200");
    let ct = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/dns-message"),
        "DoH/2 POST: expected Content-Type application/dns-message; got {ct:?}"
    );

    let body = rt
        .block_on(resp.into_body().collect())
        .expect("collect DoH/2 POST response body");
    parse_response(body.to_bytes().to_vec())
}

/// Send a single A-type query over DoH/3 (RFC 8484 over HTTP/3 / RFC 9114) using
/// HTTP GET.
///
/// Establishes a QUIC connection to `server` with ALPN `"h3"`, validates the
/// server cert against `ca_cert_pem` (PEM root CA), and sends a DNS query
/// via HTTP/3 GET with Base64url-encoded `?dns=` parameter.
///
/// Panics on any I/O, QUIC, TLS, HTTP, or parse error.
pub fn query_a_doh3_get(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for DoH/3 GET client");

    rt.block_on(async {
        let client_ep = make_doh3_client_endpoint(ca_cert_pem);
        let id: u16 = 0xD030;
        let wire_query = build_query(id, qname, 1 /* A */);
        let (status, body_opt) = doh3_get_async(server, &client_ep, wire_query).await;
        assert_eq!(status, 200, "DoH/3 GET must return HTTP 200");
        parse_response(body_opt.expect("DoH/3 GET: expected response body"))
    })
}

/// Send a single A-type query over DoH/3 (RFC 8484 over HTTP/3 / RFC 9114) using
/// HTTP POST.
///
/// Panics on any I/O, QUIC, TLS, HTTP, or parse error.
pub fn query_a_doh3_post(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for DoH/3 POST client");

    rt.block_on(async {
        let client_ep = make_doh3_client_endpoint(ca_cert_pem);
        let id: u16 = 0xD031;
        let wire_query = build_query(id, qname, 1 /* A */);
        let (status, body_opt) = doh3_post_async(server, &client_ep, wire_query).await;
        assert_eq!(status, 200, "DoH/3 POST must return HTTP 200");
        parse_response(body_opt.expect("DoH/3 POST: expected response body"))
    })
}

/// Send a single A-type query over DNS-over-QUIC (RFC 9250).
///
/// Establishes a QUIC connection to `server` (no ALPN enforcement — RFC 9250
/// does not mandate a specific ALPN value and the DoQ server does not check),
/// validates the server cert against `ca_cert_pem` (PEM root CA), opens a
/// bidirectional QUIC stream, and exchanges a 2-byte-framed DNS message
/// per RFC 9250 §4.2.
///
/// Panics on any I/O, QUIC, TLS, or parse error.
pub fn query_a_doq(server: SocketAddr, qname: &str, ca_cert_pem: &str) -> DnsResponse {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for DoQ client");

    rt.block_on(async {
        let ep = make_doq_client_endpoint(ca_cert_pem);
        let id: u16 = 0xD040;
        let wire_query = build_query(id, qname, 1 /* A */);
        let body = doq_send_query_async(server, &ep, &wire_query).await;
        parse_response(body)
    })
}

fn make_doq_client_endpoint(ca_cert_pem: &str) -> quinn::Endpoint {
    use rustls::pki_types::CertificateDer;

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert");
    }

    // DoQ (RFC 9250): no ALPN set — the DoQ server does not enforce ALPN.
    let client_tls =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
        .expect("QUIC client TLS config for DoQ");
    let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).expect("idle timeout"),
    ));
    quinn_cfg.transport_config(Arc::new(transport));

    let mut ep =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("client bind addr"))
            .expect("QUIC client endpoint for DoQ");
    ep.set_default_client_config(quinn_cfg);
    ep
}

async fn doq_send_query_async(
    server_addr: SocketAddr,
    ep: &quinn::Endpoint,
    query_wire: &[u8],
) -> Vec<u8> {
    let conn = ep
        .connect(server_addr, "localhost")
        .expect("QUIC connect for DoQ")
        .await
        .expect("QUIC handshake for DoQ");

    // RFC 9250 §4.2: each DNS message on its own bidirectional stream,
    // preceded by a 2-octet length field (same framing as TCP/DoT).
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi for DoQ");
    let len = u16::try_from(query_wire.len()).expect("query fits in u16");
    send.write_all(&len.to_be_bytes()).await.expect("DoQ: write length prefix");
    send.write_all(query_wire).await.expect("DoQ: write query");
    send.finish().expect("DoQ: finish send stream");

    let mut resp_len_buf = [0u8; 2];
    recv.read_exact(&mut resp_len_buf).await.expect("DoQ: read response length");
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp_wire = vec![0u8; resp_len];
    recv.read_exact(&mut resp_wire).await.expect("DoQ: read response body");
    resp_wire
}

fn make_doh3_client_endpoint(ca_cert_pem: &str) -> quinn::Endpoint {
    use rustls::pki_types::CertificateDer;

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert");
    }

    let mut client_tls =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
        .expect("QUIC client TLS config");
    let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(5)).expect("idle timeout"),
        ));
    quinn_cfg.transport_config(Arc::new(transport));

    let mut ep =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("client bind addr"))
            .expect("QUIC client endpoint");
    ep.set_default_client_config(quinn_cfg);
    ep
}

async fn doh3_get_async(
    server_addr: SocketAddr,
    ep: &quinn::Endpoint,
    wire_query: Vec<u8>,
) -> (u16, Option<Vec<u8>>) {
    use bytes::Buf as _;
    let encoded = base64_url_no_pad(&wire_query);
    let uri = format!(
        "https://localhost:{}/dns-query?dns={}",
        server_addr.port(),
        encoded
    );

    let conn = ep
        .connect(server_addr, "localhost")
        .expect("QUIC connect")
        .await
        .expect("QUIC handshake");

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client::new");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = hyper::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("accept", "application/dns-message")
        .body(())
        .expect("build DoH/3 GET request");

    let mut stream = send_req.send_request(req).await.expect("send_request");
    stream.finish().await.expect("finish");

    let resp = stream.recv_response().await.expect("recv_response");
    let status = resp.status().as_u16();

    let body = if status == 200 {
        let mut body_bytes = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            body_bytes.extend_from_slice(chunk.chunk());
        }
        Some(body_bytes)
    } else {
        None
    };
    (status, body)
}

async fn doh3_post_async(
    server_addr: SocketAddr,
    ep: &quinn::Endpoint,
    wire_query: Vec<u8>,
) -> (u16, Option<Vec<u8>>) {
    use bytes::Buf as _;

    let conn = ep
        .connect(server_addr, "localhost")
        .expect("QUIC connect")
        .await
        .expect("QUIC handshake");

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client::new");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = hyper::http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost:{}/dns-query",
            server_addr.port()
        ))
        .header("content-type", "application/dns-message")
        .header("content-length", wire_query.len())
        .header("accept", "application/dns-message")
        .body(())
        .expect("build DoH/3 POST request");

    let mut stream = send_req.send_request(req).await.expect("send_request");
    stream
        .send_data(bytes::Bytes::from(wire_query))
        .await
        .expect("send_data");
    stream.finish().await.expect("finish");

    let resp = stream.recv_response().await.expect("recv_response");
    let status = resp.status().as_u16();

    let body = if status == 200 {
        let mut body_bytes = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            body_bytes.extend_from_slice(chunk.chunk());
        }
        Some(body_bytes)
    } else {
        None
    };
    (status, body)
}

/// Send a single A-type query over UDP that sets the DNSSEC OK (DO) bit in the
/// OPT RR (RFC 4035 §4.9.1).
///
/// The DO bit signals to the server that the client wants DNSSEC-related RRs
/// (RRSIG, DNSKEY) included in the response.  Required for the recursive
/// resolver to set AD=1 on a validated response.
///
/// Panics on any I/O or parse error — acceptable in test code.
pub fn query_a_with_do(server: SocketAddr, qname: &str) -> DnsResponse {
    let id: u16 = 0xAB45;
    let mut buf = build_query(id, qname, 1 /* A */);

    // OPT pseudo-RR with DO=1 (RFC 6891 §6.1.3):
    // NAME=root(0x00), TYPE=41, CLASS=1232 (requestor payload size),
    // TTL=0x00008000 (DO bit at bit 15 of the 32-bit TTL field), RDLENGTH=0.
    buf.push(0u8);
    buf.extend_from_slice(&41u16.to_be_bytes());
    buf.extend_from_slice(&1232u16.to_be_bytes());
    buf.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // DO=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH=0

    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");
    sock.send_to(&buf, server).expect("send DNS query with DO=1");

    let mut recv_buf = vec![0u8; 4096];
    let n = sock.recv(&mut recv_buf).expect("recv DNS response");
    parse_response(recv_buf[..n].to_vec())
}

/// Send a single A-type query over UDP that includes a DNS Cookie option
/// (RFC 7873) in the OPT RR.
///
/// `client_cookie` — the 8-byte client cookie to include.
///
/// `server_cookie` — optional server cookie bytes.  Pass `None` for a
/// first-contact query (client-cookie only); pass `Some(sc)` to present a
/// previously obtained or deliberately wrong server cookie.
///
/// Panics on any I/O or parse error.
pub fn query_a_with_cookie(
    server: SocketAddr,
    qname: &str,
    client_cookie: [u8; 8],
    server_cookie: Option<&[u8]>,
) -> DnsResponse {
    let id: u16 = 0xC001;
    let wire_query = build_query_with_cookie(id, qname, 1, client_cookie, server_cookie);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client socket");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout");
    sock.send_to(&wire_query, server).expect("send DNS query with cookie");

    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).expect("recv DNS response");
    let wire = buf[..n].to_vec();
    parse_response(wire)
}

/// Send a NOTIFY UDP packet for `qname` to `server` and return the decoded response.
///
/// The NOTIFY message has:
/// - `QR = 0` (query direction)
/// - `opcode = NOTIFY` (4)
/// - `AA = 1` (authoritative, per RFC 1996 §3.3)
/// - `QDCOUNT = 1`, `QTYPE = SOA`, `QCLASS = IN`
///
/// Timeout is 2 seconds.
///
/// # Panics
///
/// Panics on any I/O or parse error — acceptable in test code.
#[must_use]
pub fn send_notify_udp(server: SocketAddr, qname: &str) -> DnsResponse {
    let id: u16 = 0xAB99;
    let wire = build_notify_query(id, qname);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket for NOTIFY");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set_read_timeout for NOTIFY");
    sock.send_to(&wire, server).expect("send NOTIFY query");

    let mut buf = vec![0u8; 512];
    let n = sock.recv(&mut buf).expect("recv NOTIFY response");
    parse_response(buf[..n].to_vec())
}

/// Build a raw NOTIFY query wire message for `qname` (QTYPE=SOA).
fn build_notify_query(id: u16, qname: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // Flags: QR=0, OPCODE=4 (NOTIFY), AA=1, rest 0.
    // flags = 0b0_0100_1_0_0_0_0000 = 0x2400
    let flags: u16 = (4u16 << 11) | (1u16 << 10); // OPCODE=4, AA=1

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // QNAME
    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        buf.push(lb.len() as u8); // label length ≤ 63 per RFC 1035
        buf.extend_from_slice(lb);
    }
    buf.push(0u8); // root label

    // QTYPE=SOA(6) + QCLASS=IN(1)
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    buf
}

// ── SOA serial extraction ─────────────────────────────────────────────────────

/// Query a SOA record for `qname` over UDP and return the serial from the
/// first SOA answer record.
///
/// Returns `None` if the response is not `NOERROR`, has no answers, or the
/// first answer is not a SOA record.
///
/// Timeout is 2 seconds.
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
#[must_use]
pub fn query_soa_serial(server: SocketAddr, qname: &str) -> Option<u32> {
    let resp = query_soa(server, qname);
    if resp.rcode != 0 {
        return None;
    }
    // Parse the SOA serial from the wire bytes.
    parse_soa_serial_from_response(&resp.wire)
}

/// Extract the SOA serial from the first SOA answer record in the raw wire response.
fn parse_soa_serial_from_response(wire: &[u8]) -> Option<u32> {
    if wire.len() < 12 { return None; }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut pos = 12;
    // Skip questions.
    for _ in 0..qdcount {
        pos = skip_name(wire, pos);
        pos += 4;
        if pos > wire.len() { return None; }
    }

    // Scan answers for SOA.
    for _ in 0..ancount {
        if pos >= wire.len() { break; }
        let name_end = skip_name(wire, pos);
        if name_end + 10 > wire.len() { break; }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        if rtype == 6 {
            // SOA RDATA: MNAME (variable) + RNAME (variable) + serial (4 bytes) + ...
            let rdata_start = name_end + 10;
            if rdata_start + rdlen > wire.len() { break; }
            let rdata = &wire[rdata_start..rdata_start + rdlen];
            // Skip MNAME and RNAME (both DNS names, no compression in RDATA).
            let mname_end = skip_name(rdata, 0);
            let rname_end = skip_name(rdata, mname_end);
            if rname_end + 4 <= rdata.len() {
                let serial = u32::from_be_bytes([
                    rdata[rname_end],
                    rdata[rname_end + 1],
                    rdata[rname_end + 2],
                    rdata[rname_end + 3],
                ]);
                return Some(serial);
            }
            break;
        }
        pos = skip_rr(wire, pos);
    }
    None
}

/// Query an A record for `qname` and return the first IPv4 address in the
/// answer section, or `None` when the answer is absent or RCODE is not NOERROR.
pub fn query_a_addr(server: SocketAddr, qname: &str) -> Option<std::net::Ipv4Addr> {
    let resp = query_a(server, qname);
    if resp.rcode != 0 || resp.ancount == 0 {
        return None;
    }
    extract_first_a_rdata(&resp.wire)
}

/// Extract the first A-record IPv4 address from the answer section.
fn extract_first_a_rdata(wire: &[u8]) -> Option<std::net::Ipv4Addr> {
    if wire.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(wire, pos);
        pos += 4;
        if pos > wire.len() {
            return None;
        }
    }

    for _ in 0..ancount {
        if pos >= wire.len() {
            break;
        }
        let name_end = skip_name(wire, pos);
        if name_end + 10 > wire.len() {
            break;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        if rtype == 1 && rdlen == 4 {
            // A record: 4 bytes of IPv4 address.
            let rdata_start = name_end + 10;
            if rdata_start + 4 <= wire.len() {
                return Some(std::net::Ipv4Addr::new(
                    wire[rdata_start],
                    wire[rdata_start + 1],
                    wire[rdata_start + 2],
                    wire[rdata_start + 3],
                ));
            }
        }
        pos = skip_rr(wire, pos);
    }
    None
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_rustls_client_config(ca_cert_pem: &str) -> rustls::ClientConfig {
    use rustls::pki_types::CertificateDer;

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert to root store");
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn base64_url_no_pad(input: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
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

/// Build a query wire message with an OPT RR advertising `udp_size` as the
/// EDNS requestor payload size (RFC 6891, no options).
fn build_query_with_edns(id: u16, qname: &str, qtype: u16, udp_size: u16) -> Vec<u8> {
    let mut buf = build_query(id, qname, qtype);
    // OPT pseudo-RR: NAME=root(0x00), TYPE=41, CLASS=udp_size, TTL=0, RDLENGTH=0.
    buf.push(0u8);
    buf.extend_from_slice(&41u16.to_be_bytes());    // TYPE OPT
    buf.extend_from_slice(&udp_size.to_be_bytes()); // UDP payload size
    buf.extend_from_slice(&0u32.to_be_bytes());     // TTL: ext_rcode=0, version=0, flags=0
    buf.extend_from_slice(&0u16.to_be_bytes());     // RDLENGTH=0 (no options)
    // Increment ARCOUNT (bytes 10-11).
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;
    buf
}

/// Build a query wire message that includes an OPT RR with a Cookie option.
///
/// `server_cookie` is optional; when `None`, only the client cookie is included
/// (first-contact query).
fn build_query_with_cookie(
    id: u16,
    qname: &str,
    qtype: u16,
    client_cookie: [u8; 8],
    server_cookie: Option<&[u8]>,
) -> Vec<u8> {
    // Base query (no OPT yet).
    let mut buf = build_query(id, qname, qtype);

    // Cookie OPTION-DATA: client_cookie + optional server_cookie.
    let mut cookie_data = client_cookie.to_vec();
    if let Some(sc) = server_cookie {
        cookie_data.extend_from_slice(sc);
    }

    // Cookie OPTION-CODE = 10, OPTION-LENGTH, OPTION-DATA.
    let opt_code: u16 = 10;
    let opt_len = cookie_data.len() as u16;
    let mut cookie_opt = Vec::new();
    cookie_opt.extend_from_slice(&opt_code.to_be_bytes());
    cookie_opt.extend_from_slice(&opt_len.to_be_bytes());
    cookie_opt.extend_from_slice(&cookie_data);

    // OPT pseudo-RR:
    // NAME=root(0x00), TYPE=41, CLASS=UDP_payload_size, TTL=0, RDLENGTH, RDATA.
    let rdlength = cookie_opt.len() as u16;
    buf.push(0u8);                              // root name
    buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE OPT
    buf.extend_from_slice(&1232u16.to_be_bytes()); // UDP payload size
    buf.extend_from_slice(&0u32.to_be_bytes()); // TTL: extended_rcode=0, version=0, flags=0
    buf.extend_from_slice(&rdlength.to_be_bytes());
    buf.extend_from_slice(&cookie_opt);

    // Increment ARCOUNT (bytes 10-11).
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

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
    let arcount = u16::from_be_bytes([wire[10], wire[11]]) as usize;

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

    // Skip authority section.
    for _ in 0..nscount {
        if pos >= wire.len() { break; }
        pos = skip_rr(&wire, pos);
    }

    // Scan additional section for OPT RR (TYPE 41).
    // Extract extended_rcode, server cookie, padding flag, and EDE code for callers.
    let mut opt_extended_rcode: u8 = 0;
    let mut opt_server_cookie: Option<Vec<u8>> = None;
    let mut opt_has_padding = false;
    let mut opt_ede_code: Option<u16> = None;
    for _ in 0..arcount {
        if pos >= wire.len() { break; }
        let name_end = skip_name(&wire, pos);
        if name_end + 10 > wire.len() { break; }
        let rr_type = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        if rr_type == 41 {
            // OPT RR: TTL byte 0 = extended_rcode (RFC 6891 §6.1.3).
            opt_extended_rcode = wire[name_end + 4];
            let rdlen = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
            let rdata_start = name_end + 10;
            if rdata_start + rdlen <= wire.len() {
                let rdata = &wire[rdata_start..rdata_start + rdlen];
                opt_server_cookie = extract_opt_server_cookie(rdata);
                opt_has_padding = extract_opt_has_padding(rdata);
                opt_ede_code = extract_opt_ede_code(rdata);
            }
        }
        pos = skip_rr(&wire, pos);
    }

    // Full 12-bit extended RCODE = (OPT.extended_rcode << 4) | header_rcode (RFC 6891).
    let header_rcode = (flags & 0x000F) as u8;
    let rcode_ext = ((opt_extended_rcode as u16) << 4) | (header_rcode as u16);

    // Opcode is bits 11–14 of the flags word (bits [14:11] of the 16-bit field).
    // DNS flags: QR(15) OPCODE(14-11) AA(10) TC(9) RD(8) RA(7) Z(6) AD(5) CD(4) RCODE(3-0)
    let opcode = ((flags >> 11) & 0x000F) as u8;

    DnsResponse {
        id,
        qr:  (flags & 0x8000) != 0,
        tc:  (flags & 0x0200) != 0,
        aa:  (flags & 0x0400) != 0,
        rcode: header_rcode,
        rcode_ext,
        opcode,
        ancount,
        nscount,
        answer_types,
        authority_first_ttl,
        opt_server_cookie,
        opt_has_padding,
        ad: (flags & 0x0020) != 0,
        opt_ede_code,
        wire,
    }
}

/// Returns `true` if the OPT RDATA contains a Padding option (option code 12,
/// RFC 7830).
fn extract_opt_has_padding(rdata: &[u8]) -> bool {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len  = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + opt_len > rdata.len() { break; }
        if opt_code == 12 {
            return true;
        }
        pos += opt_len;
    }
    false
}

/// Extract the server cookie bytes from OPT RDATA (Cookie option code = 10).
///
/// Returns `None` if no Cookie option is present or the option carries only a
/// client cookie (8 bytes with no server cookie following it).
fn extract_opt_server_cookie(rdata: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len  = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + opt_len > rdata.len() { break; }
        if opt_code == 10 {
            // Cookie option: first 8 bytes = client cookie, rest = server cookie.
            let cookie_data = &rdata[pos..pos + opt_len];
            if cookie_data.len() > 8 {
                return Some(cookie_data[8..].to_vec());
            }
        }
        pos += opt_len;
    }
    None
}

/// Extract the Extended DNS Error (EDE) INFO-CODE from OPT RDATA (RFC 8914).
///
/// EDE option code = 15; OPTION-DATA = INFO-CODE (2 bytes BE) + EXTRA-TEXT (optional).
fn extract_opt_ede_code(rdata: &[u8]) -> Option<u16> {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len  = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + opt_len > rdata.len() { break; }
        if opt_code == 15 && opt_len >= 2 {
            return Some(u16::from_be_bytes([rdata[pos], rdata[pos + 1]]));
        }
        pos += opt_len;
    }
    None
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

// ── TSIG attack helpers ───────────────────────────────────────────────────────

/// Send an AXFR query with a corrupted (all-zero) MAC to test BADSIG rejection.
///
/// The query is first signed correctly, then the MAC bytes in the wire format
/// are overwritten with zeros before transmission.
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_axfr_bad_mac(
    server: SocketAddr,
    qname: &str,
    tsig_key_name: &str,
    key_bytes: &[u8],
) -> XfrResponse {
    use std::str::FromStr as _;
    use std::time::{SystemTime, UNIX_EPOCH};
    use heimdall_core::{TsigAlgorithm, TsigSigner};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Build base query and sign it.
    let mut buf = build_axfr_header(qname);
    let key_name_parsed =
        heimdall_core::Name::from_str(tsig_key_name).expect("valid TSIG key name");
    let signer = TsigSigner::new(key_name_parsed, TsigAlgorithm::HmacSha256, key_bytes, 300);
    let mut tsig_rec = signer.sign(&buf, now);

    // Corrupt only the MAC bytes — the TSIG structure remains valid so the
    // server can parse the record and attempt verification before rejecting.
    for b in &mut tsig_rec.mac {
        *b ^= 0xFF;
    }

    tsig_rec.write_to(&mut buf);
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

    send_xfr_tcp(server, &buf)
}

/// Send an AXFR query signed with a timestamp far in the past (fudge violation).
///
/// Uses `time_signed = 1` (epoch + 1 second), which is >300 s in the past.
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_axfr_fudge_violation(
    server: SocketAddr,
    qname: &str,
    tsig_key_name: &str,
    key_bytes: &[u8],
) -> XfrResponse {
    use std::str::FromStr as _;
    use heimdall_core::{TsigAlgorithm, TsigSigner};

    let mut buf = build_axfr_header(qname);
    let key_name_parsed =
        heimdall_core::Name::from_str(tsig_key_name).expect("valid TSIG key name");
    let signer = TsigSigner::new(key_name_parsed, TsigAlgorithm::HmacSha256, key_bytes, 300);

    // Sign with timestamp = 1 (epoch + 1s → guaranteed >300s in the past).
    let tsig_rec = signer.sign(&buf, 1u64);
    tsig_rec.write_to(&mut buf);
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

    send_xfr_tcp(server, &buf)
}

/// Send an AXFR query with a truncated (malformed) TSIG record in the
/// additional section.  The TSIG TYPE code (250) is present in the additional
/// section but the RDATA is shorter than a valid TSIG record — the server
/// must respond with FORMERR (RFC 8945 §4.5.1).
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_axfr_truncated_tsig(
    server: SocketAddr,
    qname: &str,
    tsig_key_name: &str,
) -> XfrResponse {
    let mut buf = build_axfr_header(qname);

    // Append a TSIG-typed additional RR with truncated (2-byte) RDATA.
    // Owner name: encode tsig_key_name as wire labels.
    let name = tsig_key_name.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8); // root label
    buf.extend_from_slice(&250u16.to_be_bytes()); // TYPE TSIG
    buf.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
    buf.extend_from_slice(&0u32.to_be_bytes());   // TTL 0
    // RDLENGTH = 2, but RDATA is just 2 garbage bytes — far too short for a
    // valid TSIG record, which needs at least algorithm name + 6+2+2 + mac.
    buf.extend_from_slice(&2u16.to_be_bytes()); // RDLENGTH = 2
    buf.extend_from_slice(&[0xDE, 0xAD]);       // truncated RDATA

    // Increment ARCOUNT.
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

    send_xfr_tcp(server, &buf)
}

/// Send the same valid AXFR query twice with the same `time_signed` value to
/// test replay detection.
///
/// Returns the response to the **second** (replay) attempt.
///
/// # Panics
///
/// Panics on any I/O error — acceptable in test code.
pub fn query_axfr_replay(
    server: SocketAddr,
    qname: &str,
    tsig_key_name: &str,
    key_bytes: &[u8],
) -> XfrResponse {
    use std::str::FromStr as _;
    use std::time::{SystemTime, UNIX_EPOCH};
    use heimdall_core::{TsigAlgorithm, TsigSigner};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut buf = build_axfr_header(qname);
    let key_name_parsed =
        heimdall_core::Name::from_str(tsig_key_name).expect("valid TSIG key name");
    let signer = TsigSigner::new(key_name_parsed, TsigAlgorithm::HmacSha256, key_bytes, 300);
    let tsig_rec = signer.sign(&buf, now);
    tsig_rec.write_to(&mut buf);
    let ar = u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
    buf[10] = (ar >> 8) as u8;
    buf[11] = (ar & 0xFF) as u8;

    // First request (should succeed — primes the replay cache).
    let _ = send_xfr_tcp(server, &buf);

    // Second request with identical wire bytes — replay.
    send_xfr_tcp(server, &buf)
}

/// Build a minimal AXFR query header (no TSIG) for `qname`.
fn build_axfr_header(qname: &str) -> Vec<u8> {
    let id: u16 = 0xBB02;
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0000u16.to_be_bytes()); // FLAGS: plain query
    buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT

    let name = qname.trim_end_matches('.');
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0u8);
    buf.extend_from_slice(&252u16.to_be_bytes()); // QTYPE AXFR
    buf.extend_from_slice(&1u16.to_be_bytes());   // QCLASS IN
    buf
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
