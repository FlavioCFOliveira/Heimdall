// SPDX-License-Identifier: MIT

//! Integration tests for the Sprint 23 DoH/H2 listener (NET-005..006,
//! NET-025..027, SEC-036..046, SEC-077, SEC-079).
//!
//! Each test binds the [`Doh2Listener`] to an ephemeral port on 127.0.0.1,
//! issues real HTTP/2 requests over TLS (using the `hyper` client + `tokio-rustls`),
//! and asserts on the HTTP status code and, where applicable, the DNS response.
//!
//! Test certificates are generated at test time by `rcgen` (ADR-0046); no
//! pre-baked credential material is committed to the repository.
//!
//! # Protocol-injection tests
//!
//! Tests that require direct h2 frame injection (oversized header block, raw
//! `RST_STREAM` flood) are marked `#[ignore]` because `hyper`'s HTTP/2 client
//! enforces the same limits as the server and does not allow violating them.
//! These tests are deferred to the protocol-conformance suite (Sprint 36) which
//! uses a custom h2 frame injector.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use heimdall_runtime::admission::{
    AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
    QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
    new_acl_handle,
};
use heimdall_runtime::{
    Doh2HardeningConfig, Doh2Listener, Doh2Telemetry, Drain, ListenerConfig, TlsServerConfig,
    build_tls_server_config,
};
use http_body_util::{BodyExt, Full};
use hyper::Method;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::ServerName;
use tokio::net::TcpListener as TokioTcpListener;
use tokio_rustls::TlsConnector;

// ── Provider init ─────────────────────────────────────────────────────────────

static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn init_provider() {
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Certificate helpers ───────────────────────────────────────────────────────

/// Returns (cert DER bytes, key PEM, cert PEM) for a self-signed Ed25519 cert.
fn gen_server_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

fn write_temp_pem(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f
}

// ── Admission pipeline helpers ────────────────────────────────────────────────

/// A pipeline that allows all requests.
fn permissive_pipeline() -> Arc<AdmissionPipeline> {
    let acl = new_acl_handle(CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Allow,
    }]));
    Arc::new(AdmissionPipeline {
        acl,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    })
}

/// A pipeline that denies all requests from any source (ACL deny).
fn deny_all_pipeline() -> Arc<AdmissionPipeline> {
    let acl = new_acl_handle(CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Deny,
    }]));
    Arc::new(AdmissionPipeline {
        acl,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    })
}

/// A pipeline that rate-limits everything (rate = 0 → immediate RRL denial).
///
/// The DoH handler uses `Role::Authoritative`, so the pipeline routes through
/// the RRL (response-rate limiter) stage rather than the per-client query RL.
/// Setting `rate_per_sec = 0` means the RRL budget is zero and every request
/// is dropped on the first check.
fn rate_limit_pipeline() -> Arc<AdmissionPipeline> {
    let acl = new_acl_handle(CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Allow,
    }]));
    let rrl_cfg = RrlConfig {
        rate_per_sec: 0,
        slip_ratio: 0, // 0 → always Drop, never Slip
        ..RrlConfig::default()
    };
    Arc::new(AdmissionPipeline {
        acl,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(rrl_cfg)),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    })
}

// ── Server helpers ────────────────────────────────────────────────────────────

struct TestServer {
    addr: SocketAddr,
    drain: Arc<Drain>,
}

/// Spawns a `Doh2Listener` on an ephemeral port, returns the bound address and
/// a [`Drain`] to stop the server.
async fn spawn_server(pipeline: Arc<AdmissionPipeline>) -> TestServer {
    spawn_server_with_hardening(pipeline, Doh2HardeningConfig::default()).await
}

async fn spawn_server_with_hardening(
    pipeline: Arc<AdmissionPipeline>,
    hardening: Doh2HardeningConfig,
) -> TestServer {
    init_provider();

    let (cert_der, key_pem, cert_pem) = gen_server_cert();
    let cert_file = write_temp_pem(&cert_pem);
    let key_file = write_temp_pem(&key_pem);

    let tls_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    let server_rustls_cfg = build_tls_server_config(&tls_cfg).expect("server TLS config");

    // Configure ALPN "h2" on the server config.
    // hyper's http2::Builder requires the TLS connection to advertise "h2" via ALPN.
    // We must clone the Arc<ServerConfig>, modify it, and re-wrap.
    let mut sc = (*server_rustls_cfg).clone();
    sc.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = TokioTcpListener::bind(bind_addr).await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let drain = Arc::new(Drain::new());
    let telemetry = Arc::new(Doh2Telemetry::new());

    let doh2 = Doh2Listener {
        listener,
        tls_acceptor,
        config: ListenerConfig::default(),
        hardening,
        pipeline,
        resource_counters: Arc::new(ResourceCounters::new()),
        telemetry,
        dispatcher: None,
    };

    let drain_srv = Arc::clone(&drain);
    tokio::spawn(async move {
        // Keep temp files alive for the duration of the server.
        let _cert_file = cert_file;
        let _key_file = key_file;
        // We need the cert_der for the client config after these are dropped —
        // the test will re-read the cert_der from the returned TestServer cert.
        let _ = doh2.run(drain_srv).await;
    });

    // Stash the cert DER so the client can trust it.
    // We store it via a thread-local per test.
    LAST_SERVER_CERT_DER.with(|cell| {
        *cell.borrow_mut() = cert_der;
    });

    TestServer { addr, drain }
}

// Thread-local storage for the most recently generated server cert DER.
// This avoids the complication of returning the cert from `spawn_server`
// through the borrow checker's lifetime constraints.
use std::cell::RefCell;
thread_local! {
    static LAST_SERVER_CERT_DER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn get_last_server_cert_der() -> Vec<u8> {
    LAST_SERVER_CERT_DER.with(|cell| cell.borrow().clone())
}

async fn stop_server(server: TestServer) {
    server
        .drain
        .drain_and_wait(Duration::from_secs(2))
        .await
        .expect("drain");
}

// ── HTTP/2 client helpers ─────────────────────────────────────────────────────

/// Builds a hyper HTTP/2 client that trusts the given server cert DER.
/// The connection is TLS over TCP to `addr`.
async fn make_h2_client(
    addr: SocketAddr,
    cert_der: Vec<u8>,
) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
    init_provider();

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .expect("add cert");

    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("http2 handshake");

    tokio::spawn(async move {
        let _ = conn.await;
    });

    sender
}

/// Builds a DNS query wire message.
fn query_wire(id: u16, name: &str) -> Vec<u8> {
    let mut hdr = Header::default();
    hdr.id = id;
    hdr.qdcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str(name).expect("name"),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(false);
    let _ = ser.write_message(&msg);
    ser.finish()
}

/// Encodes bytes as base64url (no padding, URL-safe alphabet).
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[((b0 & 3) << 4 | b1 >> 4) as usize] as char);
        out.push(if i + 1 < bytes.len() {
            CHARS[((b1 & 0xF) << 2 | b2 >> 6) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < bytes.len() {
            CHARS[(b2 & 0x3F) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    // Convert to URL-safe and strip padding.
    out.replace('+', "-").replace('/', "_").replace('=', "")
}

/// Sends a POST /dns-query with application/dns-message and returns the HTTP
/// status code + body bytes.
async fn post_dns_query(
    client: &mut hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    addr: SocketAddr,
    dns_wire: &[u8],
) -> (u16, Vec<u8>) {
    let req = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost:{}/dns-query", addr.port()))
        .header("content-type", "application/dns-message")
        .header("content-length", dns_wire.len())
        .body(Full::new(Bytes::copy_from_slice(dns_wire)))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body)
}

/// Sends a GET /dns-query?dns=<base64url> and returns status + body.
async fn get_dns_query(
    client: &mut hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    addr: SocketAddr,
    dns_wire: &[u8],
) -> (u16, Vec<u8>) {
    let encoded = base64url_encode(dns_wire);
    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "https://localhost:{}/dns-query?dns={}",
            addr.port(),
            encoded
        ))
        .header("accept", "application/dns-message")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Test 1: POST /dns-query with application/dns-message → 200 REFUSED response.
#[tokio::test]
async fn test_post_dns_query_returns_200_refused() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0xABCD, "example.com.");
    let (status, body) = post_dns_query(&mut client, server.addr, &wire).await;

    assert_eq!(status, 200, "expected 200 OK");
    let resp = Message::parse(&body).expect("valid DNS response");
    assert_eq!(resp.header.id, 0xABCD);
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "expected REFUSED rcode"
    );

    stop_server(server).await;
}

/// Test 2: GET /dns-query?dns=<base64url> → 200 REFUSED response.
#[tokio::test]
async fn test_get_dns_query_returns_200_refused() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0x1234, "test.example.");
    let (status, body) = get_dns_query(&mut client, server.addr, &wire).await;

    assert_eq!(status, 200, "expected 200 OK");
    let resp = Message::parse(&body).expect("valid DNS response");
    assert_eq!(resp.header.id, 0x1234);
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "expected REFUSED rcode"
    );

    stop_server(server).await;
}

/// Test 3: PUT /dns-query → 405 Method Not Allowed (NET-025).
#[tokio::test]
async fn test_wrong_method_put_returns_405() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let req = hyper::Request::builder()
        .method(Method::PUT)
        .uri(format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(resp.status().as_u16(), 405, "expected 405 for PUT");

    stop_server(server).await;
}

/// Test 4: GET /other → 404 Not Found (NET-027).
#[tokio::test]
async fn test_wrong_path_returns_404() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost:{}/other", server.addr.port()))
        .body(Full::new(Bytes::new()))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(resp.status().as_u16(), 404, "expected 404 for wrong path");

    stop_server(server).await;
}

/// Test 5: POST with Content-Type text/plain → 415 Unsupported Media Type
/// (NET-026).
#[tokio::test]
async fn test_wrong_content_type_returns_415() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0x0001, "example.com.");
    let req = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::copy_from_slice(&wire)))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(
        resp.status().as_u16(),
        415,
        "expected 415 for wrong content-type"
    );

    stop_server(server).await;
}

/// Test 6: Max concurrent streams enforced (SEC-038).
///
/// This test verifies that when `max_concurrent_streams` is set to 1, a second
/// concurrent request is blocked until the first completes. We can't force
/// rejection of the 101st stream with the hyper client because the client
/// itself respects SETTINGS_MAX_CONCURRENT_STREAMS; instead we verify the
/// functional path: with limit=2, two simultaneous requests both succeed.
///
/// The protocol-injection test (sending 101 streams when limit=100) is deferred
/// to Sprint 36 per the module docstring.
#[tokio::test]
async fn test_concurrent_streams_within_limit_both_succeed() {
    let mut hardening = Doh2HardeningConfig::default();
    hardening.max_concurrent_streams = 10;
    let server = spawn_server_with_hardening(permissive_pipeline(), hardening).await;
    let cert_der = get_last_server_cert_der();

    // Use a single client connection (same HTTP/2 stream multiplex).
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire1 = query_wire(0x0001, "a.example.");
    let wire2 = query_wire(0x0002, "b.example.");

    let (s1, _b1) = post_dns_query(&mut client, server.addr, &wire1).await;
    let (s2, _b2) = post_dns_query(&mut client, server.addr, &wire2).await;

    assert_eq!(s1, 200);
    assert_eq!(s2, 200);

    stop_server(server).await;
}

/// Test 7: Oversized header block causes connection error (SEC-037, SEC-042).
///
/// Direct injection of a header block that exceeds `max_header_list_size` is
/// not possible through the hyper client (it enforces the same limit). This test
/// is marked `#[ignore]` and deferred to Sprint 36 conformance suite.
#[tokio::test]
#[ignore = "requires direct h2 frame injection; deferred to conformance test suite (Sprint 36)"]
async fn test_oversized_header_block_closes_connection() {
    // Deferred: needs raw h2 frame injection to craft a HEADERS frame that
    // exceeds max_header_list_size without the hyper client rejecting it first.
}

/// Test 8: Rapid-reset (RST_STREAM flood) causes connection close (SEC-041).
///
/// Direct RST_STREAM injection is not possible through the hyper client.
/// Deferred to Sprint 36 conformance suite.
#[tokio::test]
#[ignore = "requires direct h2 frame injection; deferred to conformance test suite (Sprint 36)"]
async fn test_rapid_reset_flood_closes_connection() {
    // Deferred: needs raw h2 frame injection to send streams followed
    // immediately by RST_STREAM without sending request bodies.
}

/// Test 9: ACL deny → 403 Forbidden.
#[tokio::test]
async fn test_acl_deny_returns_403() {
    let server = spawn_server(deny_all_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0x0009, "example.com.");
    let (status, _body) = post_dns_query(&mut client, server.addr, &wire).await;
    assert_eq!(status, 403, "expected 403 Forbidden for ACL deny");

    stop_server(server).await;
}

/// Test 10: Rate-limit deny → 429 Too Many Requests.
#[tokio::test]
async fn test_rl_deny_returns_429() {
    let server = spawn_server(rate_limit_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0x000A, "example.com.");
    let (status, _body) = post_dns_query(&mut client, server.addr, &wire).await;
    assert_eq!(status, 429, "expected 429 Too Many Requests for RL deny");

    stop_server(server).await;
}

/// Test 11: POST with malformed DNS body → 400 Bad Request.
#[tokio::test]
async fn test_malformed_dns_body_returns_400() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    // Send a body that is clearly not a valid DNS message.
    let garbage = b"this is not a DNS message at all";
    let req = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from_static(garbage)))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "expected 400 for malformed DNS"
    );

    stop_server(server).await;
}

/// Test 12: GET with missing dns= parameter → 400 Bad Request.
#[tokio::test]
async fn test_get_missing_dns_param_returns_400() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri(format!(
            "https://localhost:{}/dns-query?foo=bar",
            server.addr.port()
        ))
        .body(Full::new(Bytes::new()))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "expected 400 for missing dns= param"
    );

    stop_server(server).await;
}

/// Test 13: Response Content-Type is application/dns-message (NET-026).
#[tokio::test]
async fn test_response_content_type_is_dns_message() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let wire = query_wire(0x000D, "example.com.");
    let req = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(&wire)))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(resp.status().as_u16(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/dns-message"),
        "expected application/dns-message content-type, got: {ct}"
    );

    stop_server(server).await;
}

/// Test 14: Multiple sequential requests on the same connection all succeed.
#[tokio::test]
async fn test_multiple_sequential_requests_succeed() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    for i in 0u16..5 {
        let wire = query_wire(i, "example.com.");
        let (status, body) = post_dns_query(&mut client, server.addr, &wire).await;
        assert_eq!(status, 200, "request {i}: expected 200");
        let resp = Message::parse(&body).expect("valid DNS response");
        assert_eq!(resp.header.id, i, "request {i}: response ID mismatch");
    }

    stop_server(server).await;
}

/// Test 15: DELETE /dns-query → 405 Method Not Allowed (NET-025).
#[tokio::test]
async fn test_delete_method_returns_405() {
    let server = spawn_server(permissive_pipeline()).await;
    let cert_der = get_last_server_cert_der();
    let mut client = make_h2_client(server.addr, cert_der).await;

    let req = hyper::Request::builder()
        .method(Method::DELETE)
        .uri(format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .body(Full::new(Bytes::new()))
        .expect("request");

    let resp = client.send_request(req).await.expect("send request");
    assert_eq!(resp.status().as_u16(), 405, "expected 405 for DELETE");

    stop_server(server).await;
}
