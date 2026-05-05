// SPDX-License-Identifier: MIT

//! DNS-over-QUIC outbound client (NET-022, Task #331, RFC 9250).
//!
//! [`DoqClient`] sends DNS queries over QUIC using the `DoQ` framing defined in
//! RFC 9250 §4.2: each DNS message occupies its own bidirectional QUIC stream,
//! prefixed with a 2-octet length field (same framing as TCP/DoT).
//!
//! Each call opens a fresh QUIC connection; connection reuse is deferred to a
//! dedicated pool sprint.
//!
//! # TLS / ALPN
//!
//! - ALPN: not enforced on the client side (RFC 9250 does not mandate it for
//!   stub resolvers; the server may accept any ALPN).
//! - TLS 1.3 only (QUIC requirement per RFC 9001).
//! - `tls_verify = false` uses a no-op verifier (test environments only).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use rustls::ClientConfig;
use tokio::time::timeout;
use tracing::warn;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

const DOQ_TIMEOUT: Duration = Duration::from_secs(5);

// ── NoVerify cert verifier (tests only) ──────────────────────────────────────

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_rustls_config(tls_verify: bool) -> ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if tls_verify {
        let root_store = rustls::RootCertStore::empty();
        // DoQ (RFC 9250): no ALPN set — the DoQ server does not enforce ALPN.
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    }
}

fn make_quic_endpoint(tls_verify: bool) -> Result<quinn::Endpoint, io::Error> {
    let tls_cfg = build_rustls_config(tls_verify);
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(5))
                .map_err(|e| io::Error::other(e.to_string()))?,
        ));
    client_cfg.transport_config(Arc::new(transport));

    let mut ep = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
    ep.set_default_client_config(client_cfg);
    Ok(ep)
}

// ── DoqClient ─────────────────────────────────────────────────────────────────

/// Outbound DNS-over-QUIC client (RFC 9250).
pub struct DoqClient;

impl DoqClient {
    /// Creates a new [`DoqClient`].
    #[must_use]
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self
    }
}

impl Default for DoqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamClient for DoqClient {
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let result = timeout(DOQ_TIMEOUT, do_doq_query(upstream, msg)).await;
            match result {
                Ok(inner) => inner,
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DoQ query to {}:{} timed out", upstream.host, upstream.port),
                )),
            }
        })
    }
}

async fn do_doq_query(upstream: &UpstreamConfig, msg: &Message) -> Result<Message, io::Error> {
    // ── Serialise DNS query ──────────────────────────────────────────────────
    let mut ser = Serialiser::new(false);
    ser.write_message(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let wire = ser.finish();

    let wire_len = u16::try_from(wire.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "DNS message exceeds 65535 bytes")
    })?;

    // ── Resolve address ──────────────────────────────────────────────────────
    let addr_str = format!("{}:{}", upstream.host, upstream.port);
    let server_addr: SocketAddr = addr_str.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid upstream address: {e}"))
    })?;

    let sni_host = upstream
        .sni
        .as_deref()
        .unwrap_or(upstream.host.as_str())
        .to_string();

    // ── QUIC connection ──────────────────────────────────────────────────────
    let ep = make_quic_endpoint(upstream.tls_verify)?;
    let conn = ep
        .connect(server_addr, &sni_host)
        .map_err(|e| io::Error::other(e.to_string()))?
        .await
        .map_err(|e| {
            warn!(upstream = %upstream.host, "DoQ QUIC handshake failed: {e}");
            io::Error::other(e.to_string())
        })?;

    // ── RFC 9250 §4.2: bidirectional stream with 2-byte length prefix ────────
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
        io::Error::other(e.to_string())
    })?;

    send.write_all(&wire_len.to_be_bytes()).await.map_err(|e| {
        io::Error::other(e.to_string())
    })?;
    send.write_all(&wire).await.map_err(|e| {
        io::Error::other(e.to_string())
    })?;
    send.finish().map_err(|e| io::Error::other(e.to_string()))?;

    // Read 2-byte length prefix.
    let len_buf = recv.read_chunk(2, true).await.map_err(|e| {
        io::Error::other(e.to_string())
    })?;
    let len_chunk = len_buf.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "DoQ: upstream closed stream before length prefix")
    })?;
    if len_chunk.bytes.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoQ: short length prefix"));
    }
    let resp_len = u16::from_be_bytes([len_chunk.bytes[0], len_chunk.bytes[1]]) as usize;

    // Read response body.
    let mut resp_buf = vec![0u8; resp_len];
    let mut received = 0usize;
    while received < resp_len {
        let chunk = recv.read_chunk(resp_len - received, true).await.map_err(|e| {
            io::Error::other(e.to_string())
        })?;
        let c = chunk.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "DoQ: stream closed before full response")
        })?;
        let n = c.bytes.len().min(resp_len - received);
        resp_buf[received..received + n].copy_from_slice(&c.bytes[..n]);
        received += n;
    }

    Message::parse(&resp_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
