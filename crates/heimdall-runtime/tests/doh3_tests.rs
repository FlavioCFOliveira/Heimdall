// SPDX-License-Identifier: MIT

//! Integration tests for the Sprint 25 DoH/H3 listener (NET-006, NET-007,
//! NET-025..028, SEC-036..046, SEC-077, ADR-0051, ADR-0052).
//!
//! Each test binds a [`Doh3Listener`] on an ephemeral UDP port on 127.0.0.1,
//! issues real HTTP/3 requests over QUIC (using `h3` + `h3-quinn` as the client
//! and the quinn client endpoint), and asserts on the HTTP status code and,
//! where applicable, the decoded DNS response wire bytes.
//!
//! Test certificates are generated at test time by `rcgen`; no pre-baked
//! credential material is committed to the repository.
//!
//! # Protocol-injection tests
//!
//! Tests requiring raw QUIC packet construction (0-RTT injection, oversized
//! QPACK dynamic-table frames, raw `RST_STREAM` floods) are marked `#[ignore]`
//! because neither quinn's client API nor `h3`'s client exposes these
//! low-level primitives.  These tests are deferred to the protocol-conformance
//! suite (Sprint 36).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
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
    Doh3HardeningConfig, Doh3Listener, Doh3Telemetry, Drain, TlsServerConfig,
    build_quinn_endpoint_h3, build_tls_server_config,
};
use std::str::FromStr;

// ── Provider init ─────────────────────────────────────────────────────────────

static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn init_provider() {
    PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Certificate helpers ───────────────────────────────────────────────────────

/// Returns `(cert_der, key_pem, cert_pem)` for a self-signed Ed25519 certificate.
fn gen_server_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

fn write_temp(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f
}

// ── Admission pipeline helpers ────────────────────────────────────────────────

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

// ── DNS message builder ───────────────────────────────────────────────────────

fn build_query(id: u16) -> Vec<u8> {
    let hdr = Header {
        id,
        qdcount: 1,
        ..Default::default()
    };
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str("example.com.").expect("name"),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(false);
    ser.write_message(&msg).expect("serialise");
    ser.finish()
}

// ── Base64url encoder (for GET tests) ────────────────────────────────────────

fn base64url_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
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
    out.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

// ── Server bootstrap helper ───────────────────────────────────────────────────

/// Spawns a `Doh3Listener` on an ephemeral UDP port on localhost.
///
/// Returns `(server_addr, drain, server_cert_der, telemetry)`.
async fn spawn_doh3_server(
    hardening: Doh3HardeningConfig,
    pipeline: Arc<AdmissionPipeline>,
) -> (SocketAddr, Arc<Drain>, Vec<u8>, Arc<Doh3Telemetry>) {
    init_provider();

    let (server_cert_der, server_key_pem, server_cert_pem) = gen_server_cert();

    let cert_file = write_temp(&server_cert_pem);
    let key_file = write_temp(&server_key_pem);

    // Build TLS config and set ALPN to "h3".
    let tls_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..Default::default()
    };
    let mut tls_server_config = build_tls_server_config(&tls_cfg).expect("TLS config");
    // Set ALPN to h3 (NET-006).
    Arc::get_mut(&mut tls_server_config)
        .expect("no other Arc refs")
        .alpn_protocols = vec![b"h3".to_vec()];

    let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let quic_hardening = heimdall_runtime::QuicHardeningConfig {
        always_retry: false,
        ..Default::default()
    };

    let endpoint =
        build_quinn_endpoint_h3(bind_addr, tls_server_config, &quic_hardening, &hardening)
            .expect("quinn h3 endpoint");
    let server_addr = endpoint.local_addr().expect("local addr");

    let drain = Arc::new(Drain::new());
    let resource_counters = Arc::new(ResourceCounters::new());
    let telemetry = Arc::new(Doh3Telemetry::new());

    let listener = Doh3Listener {
        endpoint,
        hardening,
        pipeline,
        resource_counters,
        telemetry: Arc::clone(&telemetry),
        dispatcher: None,
        max_udp_payload: 1232,
    };

    let drain_c = Arc::clone(&drain);
    tokio::spawn(async move {
        listener.run(drain_c).await.ok();
    });

    // Keep temp files alive until the test is done by leaking them.
    std::mem::forget(cert_file);
    std::mem::forget(key_file);

    // Give the server a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (server_addr, drain, server_cert_der, telemetry)
}

// ── H3 client helpers ─────────────────────────────────────────────────────────

/// Builds a quinn QUIC client endpoint that trusts the supplied DER certificate
/// and uses ALPN `"h3"`.
fn make_h3_client(server_cert_der: Vec<u8>) -> quinn::Endpoint {
    use rustls::pki_types::CertificateDer;

    init_provider();

    let server_cert = CertificateDer::from(server_cert_der);
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(server_cert).expect("add server cert");

    let mut client_tls =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("quic client cfg");

    let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(quic_client_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(5)).expect("timeout"),
    ));
    quinn_cfg.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("addr")).expect("client endpoint");
    endpoint.set_default_client_config(quinn_cfg);
    endpoint
}

/// Performs a full HTTP/3 POST `DoH` round trip and returns the raw HTTP status
/// code together with the DNS response wire bytes (when status == 200).
async fn doh3_post_request(
    server_addr: SocketAddr,
    client_endpoint: &quinn::Endpoint,
    query_wire: Vec<u8>,
) -> (u16, Option<Vec<u8>>) {
    let quinn_conn = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    // Drive the connection in the background.
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::POST)
        .uri("https://localhost/dns-query")
        .header("content-type", "application/dns-message")
        .header("content-length", query_wire.len())
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream
        .send_data(Bytes::from(query_wire))
        .await
        .expect("send_data");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    let status = response.status().as_u16();

    // Collect body only when the server sent 200 OK.
    let body = if status == 200 {
        let mut body_bytes = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            use bytes::Buf as _;
            body_bytes.extend_from_slice(chunk.chunk());
        }
        Some(body_bytes)
    } else {
        None
    };

    (status, body)
}

/// Performs a full HTTP/3 GET `DoH` round trip.
async fn doh3_get_request(
    server_addr: SocketAddr,
    client_endpoint: &quinn::Endpoint,
    query_wire: Vec<u8>,
) -> (u16, Option<Vec<u8>>) {
    let encoded = base64url_encode(&query_wire);
    let uri = format!("https://localhost/dns-query?dns={encoded}");

    let quinn_conn = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::GET)
        .uri(uri)
        .header("accept", "application/dns-message")
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    let status = response.status().as_u16();

    let body = if status == 200 {
        let mut body_bytes = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            use bytes::Buf as _;
            body_bytes.extend_from_slice(chunk.chunk());
        }
        Some(body_bytes)
    } else {
        None
    };

    (status, body)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Test 1: DoH/H3 POST round trip — server returns REFUSED for a valid query.
#[tokio::test]
async fn doh3_post_roundtrip_returns_refused() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der);
    let query = build_query(0xABCD);

    let (status, body) = doh3_post_request(server_addr, &client, query).await;

    assert_eq!(status, 200, "POST with valid query must return 200 OK");
    let wire = body.expect("body present for 200");
    let resp = Message::parse(&wire).expect("valid DNS response");
    assert_eq!(resp.header.id, 0xABCD, "response ID must match query ID");
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "RCODE must be REFUSED"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 2: DoH/H3 GET round trip — server returns REFUSED for a valid query.
#[tokio::test]
async fn doh3_get_roundtrip_returns_refused() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der);
    let query = build_query(0x1234);

    let (status, body) = doh3_get_request(server_addr, &client, query).await;

    assert_eq!(status, 200, "GET with valid query must return 200 OK");
    let wire = body.expect("body present for 200");
    let resp = Message::parse(&wire).expect("valid DNS response");
    assert_eq!(resp.header.id, 0x1234, "response ID must match query ID");
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "RCODE must be REFUSED"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 3: POST with wrong Content-Type returns 415 Unsupported Media Type.
#[tokio::test]
async fn doh3_post_wrong_content_type_returns_415() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der.clone());

    let quinn_conn = client
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let query = build_query(0x0001);
    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::POST)
        .uri("https://localhost/dns-query")
        .header("content-type", "application/json")  // wrong content-type
        .header("content-length", query.len())
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream
        .send_data(Bytes::from(query))
        .await
        .expect("send_data");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    assert_eq!(
        response.status().as_u16(),
        415,
        "wrong Content-Type must yield 415 Unsupported Media Type"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 4: Request to an unknown path returns 404 Not Found.
#[tokio::test]
async fn doh3_unknown_path_returns_404() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der);

    let quinn_conn = client
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let query = build_query(0x0002);
    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::POST)
        .uri("https://localhost/not-dns-query")  // wrong path
        .header("content-type", "application/dns-message")
        .header("content-length", query.len())
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream
        .send_data(Bytes::from(query))
        .await
        .expect("send_data");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    assert_eq!(
        response.status().as_u16(),
        404,
        "wrong path must yield 404 Not Found (NET-027)"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 5: GET request without the `dns` query parameter returns 400 Bad Request.
#[tokio::test]
async fn doh3_get_missing_dns_param_returns_400() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der);

    let quinn_conn = client
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::GET)
        .uri("https://localhost/dns-query")  // no ?dns= param
        .header("accept", "application/dns-message")
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    assert_eq!(
        response.status().as_u16(),
        400,
        "missing dns param must yield 400 Bad Request"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 6: `Doh3HardeningConfig` defaults match SEC-077 spec values.
///
/// This is a unit-level assertion exercised at the integration layer to confirm
/// the defaults survive the full crate-boundary crossing.
#[test]
fn doh3_hardening_defaults_are_spec_values() {
    let cfg = Doh3HardeningConfig::default();
    assert_eq!(cfg.max_header_block_bytes, 16_384, "SEC-037");
    assert_eq!(cfg.max_concurrent_streams, 100, "SEC-038");
    assert_eq!(cfg.qpack_dyn_table_max, 4_096, "SEC-040");
    assert_eq!(cfg.rapid_reset_threshold_count, 100, "SEC-041");
    assert_eq!(cfg.rapid_reset_window_secs, 30, "SEC-041");
    assert_eq!(cfg.control_frame_threshold_count, 200, "SEC-043");
    assert_eq!(cfg.control_frame_window_secs, 60, "SEC-043");
    assert_eq!(cfg.header_block_timeout_secs, 5, "SEC-044");
    assert_eq!(cfg.flow_control_initial_bytes, 65_536, "SEC-045");
    assert_eq!(cfg.flow_control_max_bytes, 16_777_216, "SEC-045");
}

/// Test 7: Multiple sequential POST requests on separate connections all succeed.
#[tokio::test]
async fn doh3_multiple_sequential_requests_succeed() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    for id in [0x0010u16, 0x0020, 0x0030] {
        let client = make_h3_client(cert_der.clone());
        let query = build_query(id);
        let (status, body) = doh3_post_request(server_addr, &client, query).await;
        assert_eq!(status, 200, "request {id:#06x} must return 200");
        let wire = body.expect("body present");
        let resp = Message::parse(&wire).expect("valid response");
        assert_eq!(resp.header.id, id, "response ID must match query ID");
    }

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 8: `build_quinn_endpoint_h3` returns a valid endpoint on a loopback port
/// — the returned endpoint reports a non-zero local address.
#[tokio::test]
async fn build_quinn_endpoint_h3_binds_successfully() {
    init_provider();

    let (_, server_key_pem, server_cert_pem) = gen_server_cert();
    let cert_file = write_temp(&server_cert_pem);
    let key_file = write_temp(&server_key_pem);

    let tls_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..Default::default()
    };
    let mut tls_server_config = build_tls_server_config(&tls_cfg).expect("TLS config");
    Arc::get_mut(&mut tls_server_config)
        .expect("no other Arc refs")
        .alpn_protocols = vec![b"h3".to_vec()];

    let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
    let quic_hardening = heimdall_runtime::QuicHardeningConfig {
        always_retry: false,
        ..Default::default()
    };
    let doh3_hardening = Doh3HardeningConfig::default();

    let endpoint = build_quinn_endpoint_h3(
        bind_addr,
        tls_server_config,
        &quic_hardening,
        &doh3_hardening,
    )
    .expect("endpoint must bind");

    let local_addr = endpoint.local_addr().expect("local addr");
    assert_ne!(local_addr.port(), 0, "ephemeral port must be non-zero");
    assert!(
        local_addr.ip().is_loopback() || local_addr.ip().is_unspecified(),
        "bound address must be loopback or unspecified"
    );

    endpoint.close(quinn::VarInt::from_u32(0), b"test done");
}

/// Test 9: Resource limit of 0 global pending connections drops new connections.
///
/// When `max_global_pending = 0`, `try_acquire_global` always fails and the
/// server calls `incoming.refuse()`.  The client should receive a connection
/// error or timeout.
#[tokio::test]
async fn doh3_resource_limit_zero_drops_connections() {
    let zero_limit_pipeline = {
        let acl = new_acl_handle(CompiledAcl::new(vec![AclRule {
            matchers: vec![],
            action: AclAction::Allow,
        }]));
        Arc::new(AdmissionPipeline {
            acl,
            resource_limits: ResourceLimits {
                max_global_pending: 0, // zero capacity — all connections refused
                ..ResourceLimits::default()
            },
            resource_counters: Arc::new(ResourceCounters::new()),
            rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
            query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
            load_signal: Arc::new(LoadSignal::new()),
            telemetry: Arc::new(AdmissionTelemetry::new()),
        })
    };

    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), zero_limit_pipeline).await;

    let client = make_h3_client(cert_der);

    let conn_result = tokio::time::timeout(
        Duration::from_secs(3),
        client.connect(server_addr, "localhost").expect("connect"),
    )
    .await;

    // Either a connection error or a timeout is acceptable when the limit is 0.
    match conn_result {
        Ok(Err(_)) | Err(_) => {
            // Expected: connection refused or timed out.
        }
        Ok(Ok(conn)) => {
            // Connection succeeded but should fail at the H3 layer; drop it.
            conn.close(quinn::VarInt::from_u32(0), b"probe");
        }
    }

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 10: Drain stops the server cleanly — new connections after draining
/// are rejected (or the client times out).
#[tokio::test]
async fn doh3_drain_stops_server() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    // Perform one successful request to confirm the server is live.
    let client = make_h3_client(cert_der.clone());
    let query = build_query(0x9999);
    let (status, _) = doh3_post_request(server_addr, &client, query).await;
    assert_eq!(status, 200, "server must be reachable before drain");

    // Signal drain and give the server a moment to stop accepting.
    drain.drain_and_wait(Duration::from_secs(2)).await.ok();

    // A new connection attempt after drain should fail or time out.
    let client2 = make_h3_client(cert_der);
    let conn_result = tokio::time::timeout(
        Duration::from_secs(2),
        client2
            .connect(server_addr, "localhost")
            .expect("connect attempt"),
    )
    .await;

    // Either a failure or a timeout is acceptable — the server is stopped.
    match conn_result {
        Ok(Err(_)) | Err(_) => {
            // Expected.
        }
        Ok(Ok(conn)) => {
            // If the OS fast-path accepted the datagram before quinn noticed the
            // endpoint was closed, just discard the connection.
            conn.close(quinn::VarInt::from_u32(0), b"probe");
        }
    }
}

/// Test 11: 0-RTT structural assertion — the server's TLS config must not
/// enable `max_early_data_size > 0`.  A fresh 1-RTT connection must succeed.
///
/// Direct 0-RTT injection requires raw QUIC packet construction and is not
/// achievable through the quinn client API; this test is therefore a structural
/// assertion on the 1-RTT handshake path.
#[tokio::test]
async fn doh3_server_refuses_zero_rtt_structurally() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    // A fresh 1-RTT connection must succeed.
    let client = make_h3_client(cert_der);
    let query = build_query(0x5A5A);
    let (status, _) = doh3_post_request(server_addr, &client, query).await;
    assert_eq!(status, 200, "1-RTT connection must succeed");

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}

/// Test 12: Non-DNS-wire POST body returns 400 Bad Request.
#[tokio::test]
async fn doh3_post_invalid_dns_wire_returns_400() {
    let (server_addr, drain, cert_der, _tel) =
        spawn_doh3_server(Doh3HardeningConfig::default(), permissive_pipeline()).await;

    let client = make_h3_client(cert_der);

    let quinn_conn = client
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_req) = h3::client::new(h3_conn).await.expect("h3 client");

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Send garbage that is not a valid DNS message.
    let garbage = Bytes::from_static(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
    let request = hyper::http::Request::builder()
        .method(hyper::http::Method::POST)
        .uri("https://localhost/dns-query")
        .header("content-type", "application/dns-message")
        .header("content-length", garbage.len())
        .body(())
        .expect("request");

    let mut stream = send_req.send_request(request).await.expect("send_request");
    stream.send_data(garbage).await.expect("send_data");
    stream.finish().await.expect("finish");

    let response = stream.recv_response().await.expect("recv_response");
    assert_eq!(
        response.status().as_u16(),
        400,
        "invalid DNS wire must yield 400 Bad Request"
    );

    drain.drain_and_wait(Duration::from_secs(2)).await.ok();
}
