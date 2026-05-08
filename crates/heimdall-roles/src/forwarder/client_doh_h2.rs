// SPDX-License-Identifier: MIT

//! DNS-over-HTTPS/2 outbound client (NET-019, Task #329 + Sprint 57 #639).
//!
//! [`DohH2Client`] sends DNS queries via HTTP/2 POST to an upstream `DoH`
//! server per RFC 8484. Uses `hyper-util` for HTTP/2 + connection pooling and
//! `hyper-rustls` for TLS.
//!
//! # Connection reuse (Sprint 57 #639)
//!
//! Each `DohH2Client` caches a `hyper_util::client::legacy::Client` instance
//! per `(host, verify-mode)` pair. The legacy client maintains an internal
//! HTTP/2 connection pool with idle persistence and stream multiplexing
//! (RFC 7540 §5.1.2): subsequent queries to the same upstream reuse the
//! existing TLS+H2 connection until the peer sends GOAWAY or the idle
//! timeout fires.
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

use std::{collections::HashMap, future::Future, io, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use heimdall_core::{parser::Message, serialiser::Serialiser};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rustls::ClientConfig;
use tokio::{sync::Mutex, time::timeout};
use tracing::warn;

use crate::forwarder::{client::UpstreamClient, upstream::UpstreamConfig};

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

/// Type alias for the configured legacy hyper client used by `DohH2Client`.
type H2Client = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

fn build_h2_client(tls_verify: bool) -> H2Client {
    let tls_cfg = build_rustls_config(tls_verify);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_cfg)
        .https_only()
        .enable_http2()
        .build();
    // The legacy hyper-util Client maintains an internal connection pool with
    // idle persistence. Queries to the same upstream reuse the underlying
    // TLS + HTTP/2 connection and multiplex over independent streams
    // (RFC 7540 §5.1.2).
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Some(Duration::from_mins(1)))
        .pool_max_idle_per_host(32)
        .http2_only(true)
        .build::<_, Full<Bytes>>(https)
}

// ── DohH2Client ───────────────────────────────────────────────────────────────

/// Outbound DNS-over-HTTPS/2 client (RFC 8484).
///
/// Holds a pool of `hyper_util::client::legacy::Client` instances keyed by
/// the `tls_verify` flag. Each underlying client manages its own HTTP/2
/// connection pool internally; queries to the same upstream multiplex over
/// the same long-lived connection.
pub struct DohH2Client {
    /// One client per verify-mode. The legacy client itself pools connections
    /// per (scheme, host, port) — we do not need a separate per-upstream
    /// `HashMap` on top.
    clients: Mutex<HashMap<bool, H2Client>>,
}

impl DohH2Client {
    /// Creates a new [`DohH2Client`].
    #[must_use]
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Get-or-create the H2 client for `tls_verify`.
    async fn client_for(&self, tls_verify: bool) -> H2Client {
        let mut clients = self.clients.lock().await;
        if let Some(c) = clients.get(&tls_verify) {
            return c.clone();
        }
        let c = build_h2_client(tls_verify);
        clients.insert(tls_verify, c.clone());
        c
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
            let result = timeout(DOH_H2_TIMEOUT, self.do_doh_h2_query(upstream, msg)).await;
            match result {
                Ok(inner) => inner,
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "DoH/H2 query to {}:{} timed out",
                        upstream.host, upstream.port
                    ),
                )),
            }
        })
    }
}

impl DohH2Client {
    async fn do_doh_h2_query(
        &self,
        upstream: &UpstreamConfig,
        msg: &Message,
    ) -> Result<Message, io::Error> {
        // ── Serialise DNS query ────────────────────────────────────────────
        let mut ser = Serialiser::new(false);
        ser.write_message(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let wire = ser.finish();

        // ── Reuse the cached HTTP/2 client for this verify mode ───────────
        let client = self.client_for(upstream.tls_verify).await;

        // ── Build POST request ────────────────────────────────────────────
        let sni_host = upstream.sni.as_deref().unwrap_or(upstream.host.as_str());
        let uri = format!("https://{}:{}/dns-query", sni_host, upstream.port);

        let req = Request::builder()
            .method("POST")
            .uri(uri.as_str())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(Full::new(Bytes::copy_from_slice(&wire)))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // ── Send request (reuses pooled H2 connection on subsequent calls) ─
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

        // ── Read response body ────────────────────────────────────────────
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let body_bytes = body.to_bytes();

        Message::parse(&body_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_client() {
        let _ = DohH2Client::new();
    }

    #[test]
    fn default_creates_client() {
        let _ = DohH2Client::default();
    }

    #[tokio::test]
    async fn client_for_caches_per_verify_mode() {
        let c = DohH2Client::new();
        let h1 = c.client_for(true).await;
        let h2 = c.client_for(true).await;
        // hyper Clients are clones of an Arc internally; we can't ptr_eq the
        // outer struct, but we can check that the cache holds a single entry
        // by inspecting the map size.
        assert_eq!(
            c.clients.lock().await.len(),
            1,
            "verify=true must produce exactly one cached client"
        );
        // Different verify mode → second cached client.
        let _ = c.client_for(false).await;
        assert_eq!(c.clients.lock().await.len(), 2);
        // Drop bindings to satisfy unused-variable lint.
        drop((h1, h2));
    }
}
