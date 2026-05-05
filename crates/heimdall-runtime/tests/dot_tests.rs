// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unused_async,
    clippy::undocumented_unsafe_blocks
)]

//! Integration tests for the Sprint 22 `DoT` listener (NET-004, SEC-001..016,
//! SEC-060..068, THREAT-068).
//!
//! Test certificates are generated at test time by `rcgen` (ADR-0046); no
//! pre-baked credential material is committed to the repository.
//!
//! All listener sockets bind to ephemeral OS ports on 127.0.0.1; each test
//! runs an isolated server and stops it via [`Drain::drain_and_wait`].

use std::{
    io::{BufReader, Write as _},
    sync::{Arc, OnceLock},
    time::Duration,
};

use heimdall_core::{
    header::{Header, Qclass, Qtype, Question, Rcode},
    name::Name,
    parser::Message,
    serialiser::Serialiser,
};
use heimdall_runtime::{
    DotListener, Drain, ListenerConfig, TlsServerConfig, TlsTelemetry,
    admission::{
        AclAction, AclRule, AdmissionPipeline, AdmissionTelemetry, CompiledAcl, LoadSignal,
        QueryRlConfig, QueryRlEngine, ResourceCounters, ResourceLimits, RrlConfig, RrlEngine,
    },
    build_tls_server_config,
};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Provider initialisation ───────────────────────────────────────────────────

/// Installs the `ring` crypto provider as the rustls process-level default.
///
/// This is necessary because the test binary may have both `ring` and
/// `aws-lc-rs` features active via transitive deps, preventing rustls from
/// auto-detecting the provider.  `OnceLock` ensures the call is made exactly
/// once across all tests in the binary, regardless of execution order.
static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn init_provider() {
    PROVIDER_INIT.get_or_init(|| {
        // Ignore the error: another test thread may have already installed the
        // provider concurrently.  `install_default` is idempotent on success.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Certificate generation helpers ────────────────────────────────────────────

/// Generates a self-signed Ed25519 server certificate/key pair via `rcgen`.
/// Returns (cert DER bytes, key PEM string, cert PEM string).
fn gen_server_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("keygen");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

/// Generates a self-signed client certificate/key pair for mTLS tests.
fn gen_client_cert() -> (Vec<u8>, String, String) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("client keygen");
    let mut params = CertificateParams::new(vec!["client.localhost".to_owned()]).expect("params");
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).expect("sign");
    (cert.der().to_vec(), key.serialize_pem(), cert.pem())
}

/// Writes a string to a temp file, returns the path.
fn write_temp_pem(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f
}

// ── Admission pipeline helpers ────────────────────────────────────────────────

fn permissive_pipeline() -> Arc<AdmissionPipeline> {
    let allow_all = CompiledAcl::new(vec![AclRule {
        matchers: vec![],
        action: AclAction::Allow,
    }]);
    let acl_handle = heimdall_runtime::admission::new_acl_handle(allow_all);
    Arc::new(AdmissionPipeline {
        acl: acl_handle,
        resource_limits: ResourceLimits::default(),
        resource_counters: Arc::new(ResourceCounters::new()),
        rrl: Arc::new(RrlEngine::new(RrlConfig::default())),
        query_rl: Arc::new(QueryRlEngine::new(QueryRlConfig::default())),
        load_signal: Arc::new(LoadSignal::new()),
        telemetry: Arc::new(AdmissionTelemetry::new()),
    })
}

fn make_resource_counters() -> Arc<ResourceCounters> {
    Arc::new(ResourceCounters::new())
}

// ── Wire-format helpers ───────────────────────────────────────────────────────

fn query_wire(id: u16, name: &str) -> Vec<u8> {
    let mut hdr = Header::default();
    hdr.id = id;
    hdr.qdcount = 1;
    let msg = Message {
        header: hdr,
        questions: vec![Question {
            qname: Name::from_str_unwrap(name),
            qtype: Qtype::A,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut ser = Serialiser::new(true);
    let _ = ser.write_message(&msg);
    ser.finish()
}

fn tcp_frame(wire: &[u8]) -> Vec<u8> {
    let len = wire.len() as u16;
    let mut out = Vec::with_capacity(2 + wire.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(wire);
    out
}

async fn read_framed_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> Message {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("read length prefix");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.expect("read body");
    Message::parse(&body).expect("valid DNS response")
}

async fn stop(drain: Arc<Drain>) {
    drain
        .drain_and_wait(Duration::from_secs(2))
        .await
        .expect("drain");
}

trait NameFromStr {
    fn from_str_unwrap(s: &str) -> Name;
}
impl NameFromStr for Name {
    fn from_str_unwrap(s: &str) -> Name {
        use std::str::FromStr as _;
        Name::from_str(s).expect("valid DNS name")
    }
}

// ── Shared: build a server TlsAcceptor from cert/key temp files ──────────────

fn build_acceptor(cert_pem: &str, key_pem: &str) -> tokio_rustls::TlsAcceptor {
    init_provider();
    let cert_file = write_temp_pem(cert_pem);
    let key_file = write_temp_pem(key_pem);

    let cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    // Keep temp files alive until config is built.
    let server_cfg = build_tls_server_config(&cfg).expect("server config");
    drop(cert_file);
    drop(key_file);
    tokio_rustls::TlsAcceptor::from(server_cfg)
}

/// Builds a rustls `ClientConfig` that trusts the given DER-encoded server
/// certificate as a self-signed trust anchor (no CA chain needed).
fn make_client_config(server_cert_der: Vec<u8>) -> Arc<rustls::ClientConfig> {
    init_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(server_cert_der))
        .expect("add server cert to root store");

    Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Builds a rustls `ClientConfig` that presents a client certificate for mTLS,
/// and trusts the server cert as a self-signed trust anchor.
fn make_mtls_client_config(
    server_cert_der: Vec<u8>,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Arc<rustls::ClientConfig> {
    init_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(server_cert_der))
        .expect("add server cert");

    let client_certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(client_cert_pem.as_bytes()))
            .collect::<Result<_, _>>()
            .expect("parse client cert");

    let client_key = rustls_pemfile::private_key(&mut BufReader::new(client_key_pem.as_bytes()))
        .expect("parse client key")
        .expect("found client key");

    Arc::new(
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .expect("client auth cert"),
    )
}

// ── Test 1: TLS round-trip — REFUSED response ─────────────────────────────────

/// A `DoT` query over a valid TLS connection receives a REFUSED response.
#[tokio::test]
async fn dot_round_trip_returns_refused() {
    let (cert_der, key_pem, cert_pem) = gen_server_cert();
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let acceptor = build_acceptor(&cert_pem, &key_pem);
    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_handshake_timeout_secs: 5,
        ..ListenerConfig::default()
    };
    let tls_cfg = TlsServerConfig::default();
    let drain = Arc::new(Drain::new());

    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        tls_cfg,
        permissive_pipeline(),
        make_resource_counters(),
        Arc::new(TlsTelemetry::new()),
    );

    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect with a TLS client that trusts our self-signed cert.
    let client_cfg = make_client_config(cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS connect");

    let wire = query_wire(0xBEEF, "example.com.");
    tls.write_all(&tcp_frame(&wire)).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(3), read_framed_response(&mut tls))
        .await
        .expect("response within timeout");

    assert_eq!(resp.header.id, 0xBEEF);
    assert!(resp.header.qr(), "QR bit must be set");
    assert_eq!(
        resp.header.flags & 0x000F,
        u16::from(Rcode::Refused.as_u8()),
        "RCODE must be REFUSED"
    );

    stop(drain).await;
}

// ── Test 2: Handshake timeout ─────────────────────────────────────────────────

/// A TCP connection that does not complete the TLS handshake within the timeout
/// is closed; the failure counter is incremented.
#[tokio::test]
async fn dot_handshake_timeout_closes_connection() {
    let (_, key_pem, cert_pem) = gen_server_cert();
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let acceptor = build_acceptor(&cert_pem, &key_pem);
    let telemetry = Arc::new(TlsTelemetry::new());
    let config = ListenerConfig {
        bind_addr: server_addr,
        // Very short timeout so the test completes quickly.
        tcp_handshake_timeout_secs: 1,
        ..ListenerConfig::default()
    };

    let drain = Arc::new(Drain::new());
    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        TlsServerConfig::default(),
        permissive_pipeline(),
        make_resource_counters(),
        Arc::clone(&telemetry),
    );

    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect a raw TCP stream but do not complete a TLS handshake.
    // We just open a TCP connection and send no bytes; the server will
    // time out waiting for the handshake and close the connection.
    let mut tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();

    // Wait for the server to close the connection (after the 1 s handshake timeout).
    let mut buf = vec![0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf))
        .await
        .expect("server closes within 3 s");

    match result {
        Ok(0) | Err(_) => { /* expected: server timed out and closed */ }
        Ok(n) => panic!("unexpected {n} bytes received"),
    }

    // The telemetry must record exactly one timeout failure.
    tokio::time::sleep(Duration::from_millis(50)).await; // allow counter update
    use std::sync::atomic::Ordering;
    assert_eq!(
        telemetry.handshake_failures.load(Ordering::Relaxed),
        1,
        "handshake_failures must be 1"
    );
    assert_eq!(
        telemetry.handshake_failures_timeout.load(Ordering::Relaxed),
        1,
        "handshake_failures_timeout must be 1"
    );
    assert_eq!(
        telemetry.handshake_successes.load(Ordering::Relaxed),
        0,
        "handshake_successes must remain 0"
    );

    stop(drain).await;
}

// ── Test 3: Invalid handshake bytes rejected ──────────────────────────────────

/// A connection that sends garbage bytes instead of a valid TLS handshake is
/// rejected; the handshake failure counter is incremented.
///
/// Note on TLS 1.2: since the `tls12` rustls cargo feature is not activated in
/// this codebase, there is no `&rustls::version::TLS12` constant available to
/// build a TLS-1.2-only `ClientConfig`. This test instead sends a well-formed
/// TLS 1.2 `ClientHello` as raw bytes, which rustls 0.23 (TLS-1.3-only server)
/// rejects with a `protocol_version` alert.
#[tokio::test]
async fn dot_invalid_handshake_is_rejected() {
    let (_, key_pem, cert_pem) = gen_server_cert();
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let acceptor = build_acceptor(&cert_pem, &key_pem);
    let telemetry = Arc::new(TlsTelemetry::new());
    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_handshake_timeout_secs: 5,
        ..ListenerConfig::default()
    };

    let drain = Arc::new(Drain::new());
    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        TlsServerConfig::default(),
        permissive_pipeline(),
        make_resource_counters(),
        Arc::clone(&telemetry),
    );

    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // A TLS 1.2 ClientHello (45 bytes, RFC 5246-compliant structure).
    // HandshakeType(1) + len(3) + version(2) + random(32) + sid_len(1)
    // + cs_len(2) + cs(2) + cm_len(1) + cm(1) = 45 bytes body.
    // Record body = 45. Record total = 5 header + 45 body = 50 bytes.
    #[rustfmt::skip]
    let tls12_client_hello: &[u8] = &[
        // TLS record layer header (5 bytes)
        0x16,       // ContentType: Handshake (22)
        0x03, 0x01, // Legacy record version: TLS 1.0 (as required by RFC 8446 §5.1)
        0x00, 0x2D, // Record length: 45
        // Handshake message (45 bytes)
        0x01,             // HandshakeType: ClientHello
        0x00, 0x00, 0x29, // Handshake length: 41
        // ClientHello body (41 bytes)
        0x03, 0x03,       // client_version: TLS 1.2
        // 32 random bytes (UNIX time + random)
        0x67, 0x4A, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x00,       // session_id length: 0
        0x00, 0x02, // cipher_suites length: 2
        0xC0, 0x2C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x01,       // compression_methods length: 1
        0x00,       // null compression
    ];

    let mut tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    tcp.write_all(tls12_client_hello).await.unwrap();

    // Server sends a TLS alert (protocol_version) and closes.
    let mut buf = vec![0u8; 256];
    let result = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf)).await;

    // Accept: server sent an alert (n > 0), EOF, or connection reset.
    // Reject: timeout (server did not respond at all within 3 s).
    let server_responded = match result {
        Err(_timeout) => false,
        Ok(Ok(_) | Err(_)) => true,
    };
    assert!(
        server_responded,
        "server must respond to (or close) a TLS 1.2 attempt within 3 s"
    );

    // Telemetry must show a failure.
    tokio::time::sleep(Duration::from_millis(100)).await;
    use std::sync::atomic::Ordering;
    assert_eq!(
        telemetry.handshake_failures.load(Ordering::Relaxed),
        1,
        "handshake_failures must be 1 for TLS 1.2 / invalid handshake"
    );
    assert_eq!(
        telemetry.handshake_successes.load(Ordering::Relaxed),
        0,
        "handshake_successes must be 0"
    );

    stop(drain).await;
}

// ── Test 4: mTLS — valid client cert accepted ─────────────────────────────────

/// When mTLS is configured, a client that presents a certificate signed by the
/// trust anchor is accepted and can exchange a DNS query.
#[tokio::test]
async fn dot_mtls_valid_client_cert_accepted() {
    init_provider();
    let (server_cert_der, server_key_pem, server_cert_pem) = gen_server_cert();
    let (client_cert_der, client_key_pem, client_cert_pem) = gen_client_cert();

    // The mTLS trust anchor is the client's own self-signed cert.
    let trust_anchor_file = write_temp_pem(&client_cert_pem);
    let cert_file = write_temp_pem(&server_cert_pem);
    let key_file = write_temp_pem(&server_key_pem);

    let tls_server_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        mtls_trust_anchor: Some(trust_anchor_file.path().to_path_buf()),
        ..TlsServerConfig::default()
    };
    let server_cfg = build_tls_server_config(&tls_server_cfg).expect("server config");
    // Keep temp files alive.
    drop(cert_file);
    drop(key_file);
    drop(trust_anchor_file);

    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let telemetry = Arc::new(TlsTelemetry::new());
    let config = ListenerConfig {
        bind_addr: server_addr,
        ..ListenerConfig::default()
    };
    let drain = Arc::new(Drain::new());

    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        tls_server_cfg,
        permissive_pipeline(),
        make_resource_counters(),
        Arc::clone(&telemetry),
    );
    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client presents its certificate.
    let client_cfg = make_mtls_client_config(server_cert_der, &client_cert_pem, &client_key_pem);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("mTLS connect");

    let wire = query_wire(0x1234, "example.com.");
    tls.write_all(&tcp_frame(&wire)).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(3), read_framed_response(&mut tls))
        .await
        .expect("response within timeout");

    assert_eq!(resp.header.id, 0x1234);
    assert!(resp.header.qr());

    use std::sync::atomic::Ordering;
    assert_eq!(telemetry.handshake_successes.load(Ordering::Relaxed), 1);
    assert_eq!(telemetry.handshake_failures.load(Ordering::Relaxed), 0);

    // Ensure client cert DER was used: just verify mTLS did not fail.
    let _ = client_cert_der; // cert was used in client_cfg above

    stop(drain).await;
}

// ── Test 5: mTLS — missing client cert rejected ───────────────────────────────

/// When mTLS is configured, a client that does not present any certificate is
/// rejected at the TLS handshake layer.
///
/// # Rustls / tokio-rustls handshake-split note
///
/// In TLS 1.3, `CertificateRequest` and the client's empty `Certificate` reply
/// arrive **after** the point where `tokio_rustls::TlsConnector::connect` returns
/// to the caller. The connector resolves once the server's `Finished` is sent;
/// the subsequent certificate-verification round-trip happens asynchronously.
///
/// This test therefore verifies mTLS rejection at the SERVER level: a DNS query
/// sent immediately after `connect()` must fail (the server will have sent a
/// `CertificateRequired` alert and closed the connection), and the server
/// telemetry must reflect exactly one failure.
#[tokio::test]
async fn dot_mtls_missing_client_cert_rejected() {
    init_provider();
    let (server_cert_der, server_key_pem, server_cert_pem) = gen_server_cert();
    let (_, _, client_cert_pem) = gen_client_cert();

    let trust_anchor_file = write_temp_pem(&client_cert_pem);
    let cert_file = write_temp_pem(&server_cert_pem);
    let key_file = write_temp_pem(&server_key_pem);

    let tls_server_cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        mtls_trust_anchor: Some(trust_anchor_file.path().to_path_buf()),
        ..TlsServerConfig::default()
    };
    let server_cfg = build_tls_server_config(&tls_server_cfg).expect("server config");
    drop(cert_file);
    drop(key_file);
    drop(trust_anchor_file);

    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let telemetry = Arc::new(TlsTelemetry::new());
    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_handshake_timeout_secs: 5,
        ..ListenerConfig::default()
    };
    let drain = Arc::new(Drain::new());

    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        tls_server_cfg,
        permissive_pipeline(),
        make_resource_counters(),
        Arc::clone(&telemetry),
    );
    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client connects WITHOUT presenting any client certificate.
    let client_cfg = make_client_config(server_cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();

    // In TLS 1.3, `connect` may return Ok before the server-side
    // CertificateRequired alert is delivered; the rejection manifests as a
    // subsequent read/write error. We therefore verify rejection via telemetry
    // rather than asserting on the connect() result.
    let tls = connector.connect(server_name, tcp_stream).await;

    if let Ok(mut tls_stream) = tls {
        // If connect() returned Ok (TLS 1.3 split), a DNS query must fail.
        let wire = query_wire(0xDEAD, "example.com.");
        let frame = tcp_frame(&wire);
        // Give the server time to process the cert exchange and send an alert.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let write_result = tls_stream.write_all(&frame).await;
        // Either the write fails (server closed), or a subsequent read fails.
        if write_result.is_ok() {
            let read_result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut len_buf = [0u8; 2];
                tls_stream.read_exact(&mut len_buf).await
            })
            .await;
            // read must fail or timeout: server rejected the connection.
            assert!(
                read_result.is_err() || read_result.unwrap().is_err(),
                "server must have closed the connection after mTLS rejection"
            );
        }
        // Either path (write error or read error) is acceptable.
    }
    // If connect() returned Err, the rejection was immediate — also correct.

    // The server telemetry must record exactly one failure.
    tokio::time::sleep(Duration::from_millis(150)).await;
    use std::sync::atomic::Ordering;
    assert_eq!(
        telemetry.handshake_failures.load(Ordering::Relaxed),
        1,
        "handshake_failures must be 1 for missing client cert"
    );
    assert_eq!(
        telemetry.handshake_successes.load(Ordering::Relaxed),
        0,
        "handshake_successes must be 0"
    );

    stop(drain).await;
}

// ── Test 6: TlsTelemetry counters ────────────────────────────────────────────

/// Unit-level smoke-test for `TlsTelemetry` counter increments and `report`.
#[test]
fn tls_telemetry_counters_increment_and_report_without_panic() {
    use std::sync::atomic::Ordering;

    let t = TlsTelemetry::new();
    t.handshake_successes.fetch_add(5, Ordering::Relaxed);
    t.handshake_failures.fetch_add(2, Ordering::Relaxed);
    t.handshake_failures_cert_invalid
        .fetch_add(1, Ordering::Relaxed);
    t.handshake_failures_timeout.fetch_add(1, Ordering::Relaxed);

    assert_eq!(t.handshake_successes.load(Ordering::Relaxed), 5);
    assert_eq!(t.handshake_failures.load(Ordering::Relaxed), 2);
    t.report(); // must not panic
}

// ── Test 7: build_tls_server_config — bad paths → correct errors ──────────────

/// `build_tls_server_config` with a nonexistent cert path returns `TlsError::CertLoad`.
#[test]
fn build_tls_server_config_bad_cert_path_returns_error() {
    use heimdall_runtime::transport::tls::TlsError;
    init_provider();

    let (_, key_pem, _) = gen_server_cert();
    let key_file = write_temp_pem(&key_pem);

    let cfg = TlsServerConfig {
        cert_path: std::path::PathBuf::from("/nonexistent/cert.pem"),
        key_path: key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    let err = build_tls_server_config(&cfg).expect_err("expected error");
    assert!(matches!(err, TlsError::CertLoad { .. }));
}

/// `build_tls_server_config` with a cert file supplied in place of the key
/// returns `TlsError::NoPrivateKey`.
#[test]
fn build_tls_server_config_no_private_key_returns_error() {
    use heimdall_runtime::transport::tls::TlsError;
    init_provider();

    let (_, _, cert_pem) = gen_server_cert();
    let cert_file = write_temp_pem(&cert_pem);
    let fake_key_file = write_temp_pem(&cert_pem);

    let cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: fake_key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    let err = build_tls_server_config(&cfg).expect_err("expected error");
    assert!(matches!(err, TlsError::NoPrivateKey { .. }));
}

// ── Test 8: TLS 1.3-only config ───────────────────────────────────────────────

/// The built `ServerConfig` has its session ticketer enabled, confirming the
/// TLS 1.3 stateless ticket path is active (SEC-001, SEC-003, SEC-008).
/// The TLS 1.3-only invariant is enforced at the `builder_with_protocol_versions`
/// call site in `build_tls_server_config`; the `tls12` cargo feature is
/// deliberately not activated so TLS 1.2 code paths are absent from the binary.
#[test]
fn server_config_ticketer_is_enabled() {
    init_provider();
    let (_, key_pem, cert_pem) = gen_server_cert();
    let cert_file = write_temp_pem(&cert_pem);
    let key_file = write_temp_pem(&key_pem);

    let cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    let sc = build_tls_server_config(&cfg).expect("config built");
    assert!(
        sc.ticketer.enabled(),
        "session ticketer must be enabled (SEC-008)"
    );
}

// ── Test 9: 0-RTT disabled ────────────────────────────────────────────────────

/// The built `ServerConfig` has `max_early_data_size = 0` (SEC-005, SEC-006).
#[test]
fn server_config_has_early_data_disabled() {
    init_provider();
    let (_, key_pem, cert_pem) = gen_server_cert();
    let cert_file = write_temp_pem(&cert_pem);
    let key_file = write_temp_pem(&key_pem);

    let cfg = TlsServerConfig {
        cert_path: cert_file.path().to_path_buf(),
        key_path: key_file.path().to_path_buf(),
        ..TlsServerConfig::default()
    };
    let sc = build_tls_server_config(&cfg).expect("config built");
    assert_eq!(sc.max_early_data_size, 0, "early data must be disabled");
}

// ── Test 10: extract_mtls_identity ───────────────────────────────────────────

/// `extract_mtls_identity` returns a stable 64-char hex fingerprint.
#[test]
fn extract_mtls_identity_fingerprint_is_stable_and_unique() {
    use heimdall_runtime::{MtlsIdentitySource, extract_mtls_identity};

    let cert1 = rustls::pki_types::CertificateDer::from(vec![0x01, 0x02, 0x03]);
    let cert2 = rustls::pki_types::CertificateDer::from(vec![0x04, 0x05, 0x06]);

    let id1a = extract_mtls_identity(&cert1, MtlsIdentitySource::SubjectDn).unwrap();
    let id1b = extract_mtls_identity(&cert1, MtlsIdentitySource::SanDns).unwrap();
    let id2 = extract_mtls_identity(&cert2, MtlsIdentitySource::SubjectDn).unwrap();

    // Same cert, different source → same fingerprint (deferred ASN.1 parsing).
    assert_eq!(id1a, id1b, "identity must be deterministic");
    assert_eq!(id1a.len(), 64, "SHA-256 hex = 64 chars");
    assert!(id1a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(id1a, id2, "different certs must have different identities");
}

// ── Test 11: multiple queries over a single DoT connection ────────────────────

/// Pipelined `DoT` queries on a single connection are correctly demultiplexed.
#[tokio::test]
async fn dot_multiple_pipelined_queries_receive_responses() {
    let (cert_der, key_pem, cert_pem) = gen_server_cert();
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();

    let acceptor = build_acceptor(&cert_pem, &key_pem);
    let config = ListenerConfig {
        bind_addr: server_addr,
        tcp_max_pipelining: 8,
        ..ListenerConfig::default()
    };
    let drain = Arc::new(Drain::new());

    let dot_listener = DotListener::new(
        tcp_listener,
        acceptor,
        config,
        TlsServerConfig::default(),
        permissive_pipeline(),
        make_resource_counters(),
        Arc::new(TlsTelemetry::new()),
    );
    tokio::spawn(dot_listener.run(Arc::clone(&drain)));
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_cfg = make_client_config(cert_der);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS connect");

    for id in [0x1111u16, 0x2222, 0x3333] {
        let wire = query_wire(id, "example.com.");
        tls.write_all(&tcp_frame(&wire)).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(3), read_framed_response(&mut tls))
            .await
            .expect("response within timeout");

        assert_eq!(resp.header.id, id, "response ID must match query ID");
        assert!(resp.header.qr());
    }

    stop(drain).await;
}
