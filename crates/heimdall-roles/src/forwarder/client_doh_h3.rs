// SPDX-License-Identifier: MIT

//! DNS-over-HTTPS/3 outbound client (NET-021, Task #330 + Sprint 57 #640).
//!
//! [`DohH3Client`] sends DNS queries via HTTP/3 POST to an upstream `DoH`
//! server per RFC 8484 over QUIC (RFC 9114 / RFC 9000). Uses `quinn` for
//! QUIC and `h3`/`h3-quinn` for HTTP/3.
//!
//! # Connection reuse (Sprint 57 #640)
//!
//! - `quinn::Endpoint` is cached per `verify-mode` (cheap UDP socket binding).
//! - `quinn::Connection` is cached per `(addr, SNI, verify-mode)`. Subsequent
//!   queries to the same upstream open new bidirectional streams over the
//!   existing connection (RFC 9114 §6.1) — no fresh QUIC + TLS handshake
//!   per query.
//! - Closed/expired connections are evicted on the next `acquire`; the
//!   client transparently reconnects.
//!
//! # Wire format (RFC 8484 §4.1 over HTTP/3)
//!
//! - Method: POST
//! - Path: `/dns-query`
//! - Content-Type: `application/dns-message`
//! - Accept: `application/dns-message`
//! - Body: raw DNS wire message (no length prefix)
//!
//! # TLS / ALPN
//!
//! - ALPN: `"h3"` (required for HTTP/3).
//! - TLS 1.3 only (QUIC requirement per RFC 9001).
//! - `tls_verify = false` uses a no-op verifier (test environments only).

use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use bytes::Buf as _;
use heimdall_core::{parser::Message, serialiser::Serialiser};
use rustls::ClientConfig;
use tokio::{sync::Mutex, time::timeout};
use tracing::{debug, warn};

use crate::forwarder::{client::UpstreamClient, upstream::UpstreamConfig};

const DOH_H3_TIMEOUT: Duration = Duration::from_secs(5);

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
    let mut cfg = if tls_verify {
        let root_store = rustls::RootCertStore::empty();
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };
    // ALPN must be "h3" for HTTP/3.
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg
}

fn make_quic_endpoint(tls_verify: bool) -> Result<quinn::Endpoint, io::Error> {
    let tls_cfg = build_rustls_config(tls_verify);
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30))
            .map_err(|e| io::Error::other(e.to_string()))?,
    ));
    // Allow many concurrent bidi streams for multiplexed DoH/H3 queries.
    transport.max_concurrent_bidi_streams(100u32.into());
    client_cfg.transport_config(Arc::new(transport));

    let mut ep = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
    ep.set_default_client_config(client_cfg);
    Ok(ep)
}

/// Pool key for cached QUIC connections.
#[derive(Clone, Hash, PartialEq, Eq)]
struct H3PoolKey {
    addr: SocketAddr,
    sni: String,
    verify: bool,
}

// ── DohH3Client ───────────────────────────────────────────────────────────────

/// Outbound DNS-over-HTTPS/3 client (RFC 8484 over HTTP/3).
///
/// Caches QUIC endpoints (per verify-mode) and live QUIC connections (per
/// `(addr, SNI, verify)` tuple) so successive queries to the same upstream
/// open new bidi streams instead of paying a fresh QUIC handshake.
pub struct DohH3Client {
    endpoints: Mutex<HashMap<bool, quinn::Endpoint>>,
    connections: Mutex<HashMap<H3PoolKey, quinn::Connection>>,
}

impl DohH3Client {
    /// Creates a new [`DohH3Client`].
    #[must_use]
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self {
            endpoints: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Get-or-create the QUIC endpoint for `tls_verify`.
    async fn endpoint_for(&self, tls_verify: bool) -> Result<quinn::Endpoint, io::Error> {
        let mut eps = self.endpoints.lock().await;
        if let Some(ep) = eps.get(&tls_verify) {
            return Ok(ep.clone());
        }
        let ep = make_quic_endpoint(tls_verify)?;
        eps.insert(tls_verify, ep.clone());
        Ok(ep)
    }

    /// Get-or-create a live QUIC connection to the given upstream.
    ///
    /// Returns the cached connection if it is still alive
    /// (`close_reason()` is None). Otherwise evicts the dead entry and
    /// connects fresh.
    async fn connection_for(&self, key: &H3PoolKey) -> Result<quinn::Connection, io::Error> {
        // Fast-path: probe the cache.
        {
            let conns = self.connections.lock().await;
            if let Some(c) = conns.get(key)
                && c.close_reason().is_none()
            {
                return Ok(c.clone());
            }
        }
        // Slow-path: open a new connection.
        let ep = self.endpoint_for(key.verify).await?;
        let conn = ep
            .connect(key.addr, &key.sni)
            .map_err(|e| io::Error::other(e.to_string()))?
            .await
            .map_err(|e| {
                warn!(addr = %key.addr, "DoH/H3 QUIC handshake failed: {e}");
                io::Error::other(e.to_string())
            })?;

        let mut conns = self.connections.lock().await;
        // Race-replace: only insert if no other task got there first with a
        // live connection.
        match conns.get(key) {
            Some(existing) if existing.close_reason().is_none() => Ok(existing.clone()),
            _ => {
                conns.insert(key.clone(), conn.clone());
                Ok(conn)
            }
        }
    }
}

impl Default for DohH3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamClient for DohH3Client {
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let result = timeout(DOH_H3_TIMEOUT, self.do_doh_h3_query(upstream, msg)).await;
            match result {
                Ok(inner) => inner,
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "DoH/H3 query to {}:{} timed out",
                        upstream.host, upstream.port
                    ),
                )),
            }
        })
    }
}

impl DohH3Client {
    async fn do_doh_h3_query(
        &self,
        upstream: &UpstreamConfig,
        msg: &Message,
    ) -> Result<Message, io::Error> {
        // ── Serialise DNS query ────────────────────────────────────────────
        let mut ser = Serialiser::new(false);
        ser.write_message(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let wire = ser.finish();

        // ── Resolve address ────────────────────────────────────────────────
        let addr_str = format!("{}:{}", upstream.host, upstream.port);
        let server_addr: SocketAddr = addr_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid upstream address: {e}"),
            )
        })?;

        let sni_host = upstream
            .sni
            .as_deref()
            .unwrap_or(upstream.host.as_str())
            .to_string();

        let key = H3PoolKey {
            addr: server_addr,
            sni: sni_host.clone(),
            verify: upstream.tls_verify,
        };

        // ── Up to 2 attempts: a stale connection may pass close_reason()
        // ── but die mid-handshake on the H3 layer; retry once.
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..2u8 {
            let conn = self.connection_for(&key).await?;

            let h3_conn = h3_quinn::Connection::new(conn);
            let h3_setup = h3::client::new(h3_conn).await;
            let (mut driver, mut send_req) = match h3_setup {
                Ok(s) => s,
                Err(e) => {
                    debug!(attempt, "DoH/H3 setup failed: {e}");
                    last_err = Some(io::Error::other(e.to_string()));
                    self.connections.lock().await.remove(&key);
                    if attempt == 1 {
                        break;
                    }
                    continue;
                }
            };

            // Drive the QUIC connection in the background; the future drops
            // when the connection closes.
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            // ── Build POST request ────────────────────────────────────────
            let uri = format!("https://{}:{}/dns-query", sni_host, upstream.port);
            let req = hyper::http::Request::builder()
                .method("POST")
                .uri(uri.as_str())
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", wire.len())
                .body(())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            let exchange = async {
                let mut stream = send_req
                    .send_request(req)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                stream
                    .send_data(bytes::Bytes::from(wire.clone()))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                stream
                    .finish()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;

                let resp = stream
                    .recv_response()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let status = resp.status().as_u16();
                if status != 200 {
                    return Err(io::Error::other(format!(
                        "DoH/H3 upstream returned HTTP {status}"
                    )));
                }
                let mut body_bytes = Vec::new();
                while let Some(chunk) = stream
                    .recv_data()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
                {
                    body_bytes.extend_from_slice(chunk.chunk());
                }
                Ok::<_, io::Error>(body_bytes)
            }
            .await;

            match exchange {
                Ok(body_bytes) => {
                    return Message::parse(&body_bytes)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                Err(e) => {
                    debug!(attempt, error = %e, "DoH/H3 exchange failed; evicting cached conn");
                    self.connections.lock().await.remove(&key);
                    last_err = Some(e);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("DoH/H3 query failed after retry")))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_client() {
        let _ = DohH3Client::new();
    }

    #[test]
    fn default_creates_client() {
        let _ = DohH3Client::default();
    }

    #[tokio::test]
    async fn endpoint_cached_per_verify_mode() {
        let c = DohH3Client::new();
        let _ = c.endpoint_for(true).await.expect("endpoint verify=true");
        let _ = c.endpoint_for(true).await.expect("endpoint verify=true 2");
        assert_eq!(
            c.endpoints.lock().await.len(),
            1,
            "verify=true must produce one cached endpoint"
        );
        let _ = c.endpoint_for(false).await.expect("endpoint verify=false");
        assert_eq!(c.endpoints.lock().await.len(), 2);
    }
}
