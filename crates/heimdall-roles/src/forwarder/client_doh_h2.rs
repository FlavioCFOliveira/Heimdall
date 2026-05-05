// SPDX-License-Identifier: MIT

//! DNS-over-HTTPS/2 outbound client (NET-019, Task #329).
//!
//! [`DohH2Client`] sends DNS queries via HTTP/2 POST to an upstream `DoH` server
//! per RFC 8484.  Uses `hyper` for HTTP/2 and `hyper-rustls` for TLS.
//!
//! Each call opens a fresh HTTP/2 connection; connection reuse is deferred to
//! a dedicated pool sprint.
//!
//! # Wire format (RFC 8484 §4.1)
//!
//! - Method: POST
//! - Path: `/dns-query`
//! - Content-Type: `application/dns-message`
//! - Accept: `application/dns-message`
//! - Body: raw DNS wire message (no length prefix)
//!
//! # TLS policy
//!
//! - TLS 1.2+ (hyper-rustls default); TLS 1.3 preferred.
//! - `tls_verify = true` uses an empty root store (Sprint 38 will wire OS roots).
//! - `tls_verify = false` uses a no-op verifier (test environments only).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::time::timeout;
use tracing::warn;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

const DOH_H2_TIMEOUT: Duration = Duration::from_secs(5);

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
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    }
}

// ── DohH2Client ───────────────────────────────────────────────────────────────

/// Outbound DNS-over-HTTPS/2 client (RFC 8484).
pub struct DohH2Client;

impl DohH2Client {
    /// Creates a new [`DohH2Client`].
    #[must_use]
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self
    }
}

impl Default for DohH2Client {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamClient for DohH2Client {
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let result =
                timeout(DOH_H2_TIMEOUT, do_doh_h2_query(upstream, msg)).await;
            match result {
                Ok(inner) => inner,
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DoH/H2 query to {}:{} timed out", upstream.host, upstream.port),
                )),
            }
        })
    }
}

async fn do_doh_h2_query(upstream: &UpstreamConfig, msg: &Message) -> Result<Message, io::Error> {
    // ── Serialise DNS query ──────────────────────────────────────────────────
    let mut ser = Serialiser::new(false);
    ser.write_message(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let wire = ser.finish();

    // ── Build TLS + HTTP/2 client ────────────────────────────────────────────
    let tls_cfg = build_rustls_config(upstream.tls_verify);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_cfg)
        .https_only()
        .enable_http2()
        .build();
    let client = Client::builder(TokioExecutor::new())
        .build::<_, Full<Bytes>>(https);

    // ── Build POST request ───────────────────────────────────────────────────
    let sni_host = upstream.sni.as_deref().unwrap_or(upstream.host.as_str());
    let uri = format!("https://{}:{}/dns-query", sni_host, upstream.port);

    let req = Request::builder()
        .method("POST")
        .uri(uri.as_str())
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(&wire)))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    // ── Send request ─────────────────────────────────────────────────────────
    let resp = client.request(req).await.map_err(|e| {
        warn!(upstream = %upstream.host, "DoH/H2 request failed: {e}");
        io::Error::other(e.to_string())
    })?;

    let status = resp.status().as_u16();
    if status != 200 {
        return Err(io::Error::other(format!(
            "DoH/H2 upstream returned HTTP {status}"
        )));
    }

    // ── Read response body ───────────────────────────────────────────────────
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let body_bytes = body.to_bytes();

    Message::parse(&body_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}
