// SPDX-License-Identifier: MIT

//! DNS-over-QUIC outbound client (NET-022, Task #331 + Sprint 57 #641, RFC 9250).
//!
//! [`DoqClient`] sends DNS queries over QUIC using the `DoQ` framing defined in
//! RFC 9250 §4.2: each DNS message occupies its own bidirectional QUIC stream,
//! prefixed with a 2-octet length field (same framing as TCP/`DoT`).
//!
//! # Connection reuse (Sprint 57 #641)
//!
//! - `quinn::Endpoint` is cached per `verify-mode`.
//! - `quinn::Connection` is cached per `(addr, SNI, verify-mode)`. Each query
//!   opens a new bidirectional stream on the existing connection (RFC 9250
//!   §5.5: "Connections SHOULD be persistent and multiple queries SHOULD be
//!   sent over the same connection."). Stream-per-query is preserved.
//! - Closed connections are evicted on next acquire.
//!
//! # TLS / ALPN
//!
//! - ALPN: `"doq"` (RFC 9250 §9.1 — both client and server MUST use this token).
//! - TLS 1.3 only (QUIC requirement per RFC 9001).
//! - `tls_verify = false` uses a no-op verifier (test environments only).

use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use heimdall_core::{parser::Message, serialiser::Serialiser};
use rustls::ClientConfig;
use tokio::{sync::Mutex, time::timeout};
use tracing::{debug, warn};

use crate::forwarder::{client::UpstreamClient, upstream::UpstreamConfig};

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
    // RFC 9250 §9.1: ALPN "doq" is mandatory for both client and server.
    cfg.alpn_protocols = vec![b"doq".to_vec()];
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
    transport.max_concurrent_bidi_streams(100u32.into());
    client_cfg.transport_config(Arc::new(transport));

    let mut ep = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
    ep.set_default_client_config(client_cfg);
    Ok(ep)
}

/// Pool key for cached QUIC connections.
#[derive(Clone, Hash, PartialEq, Eq)]
struct DoqPoolKey {
    addr: SocketAddr,
    sni: String,
    verify: bool,
}

// ── DoqClient ─────────────────────────────────────────────────────────────────

/// Outbound DNS-over-QUIC client (RFC 9250).
///
/// Caches QUIC endpoints (per verify-mode) and live QUIC connections (per
/// `(addr, SNI, verify)` tuple) so successive queries to the same upstream
/// open new bidi streams on the existing connection — fulfilling the RFC
/// 9250 §5.5 SHOULD on connection persistence.
pub struct DoqClient {
    endpoints: Mutex<HashMap<bool, quinn::Endpoint>>,
    connections: Mutex<HashMap<DoqPoolKey, quinn::Connection>>,
}

impl DoqClient {
    /// Creates a new [`DoqClient`].
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
    async fn connection_for(&self, key: &DoqPoolKey) -> Result<quinn::Connection, io::Error> {
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
                warn!(addr = %key.addr, "DoQ QUIC handshake failed: {e}");
                io::Error::other(e.to_string())
            })?;

        let mut conns = self.connections.lock().await;
        match conns.get(key) {
            Some(existing) if existing.close_reason().is_none() => Ok(existing.clone()),
            _ => {
                conns.insert(key.clone(), conn.clone());
                Ok(conn)
            }
        }
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
            let result = timeout(DOQ_TIMEOUT, self.do_doq_query(upstream, msg)).await;
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

impl DoqClient {
    async fn do_doq_query(
        &self,
        upstream: &UpstreamConfig,
        msg: &Message,
    ) -> Result<Message, io::Error> {
        // ── Serialise DNS query ────────────────────────────────────────────
        let mut ser = Serialiser::new(false);
        ser.write_message(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let wire = ser.finish();

        let wire_len = u16::try_from(wire.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message exceeds 65535 bytes",
            )
        })?;

        // ── Resolve address + SNI ──────────────────────────────────────────
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

        let key = DoqPoolKey {
            addr: server_addr,
            sni: sni_host,
            verify: upstream.tls_verify,
        };

        // Up to 2 attempts: a stale cached connection may pass close_reason
        // but die when we open the bidi stream; reacquire once.
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..2u8 {
            let conn = self.connection_for(&key).await?;

            // RFC 9250 §4.2: bidi stream with 2-byte length prefix.
            let exchange = async {
                let (mut send, mut recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                send.write_all(&wire_len.to_be_bytes())
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                send.write_all(&wire)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                send.finish().map_err(|e| io::Error::other(e.to_string()))?;

                let len_chunk = recv
                    .read_chunk(2, true)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "DoQ: upstream closed stream before length prefix",
                        )
                    })?;
                if len_chunk.bytes.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "DoQ: short length prefix",
                    ));
                }
                let resp_len =
                    u16::from_be_bytes([len_chunk.bytes[0], len_chunk.bytes[1]]) as usize;

                let mut resp_buf = vec![0u8; resp_len];
                let mut received = 0usize;
                while received < resp_len {
                    let chunk = recv
                        .read_chunk(resp_len - received, true)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))?
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "DoQ: stream closed before full response",
                            )
                        })?;
                    let n = chunk.bytes.len().min(resp_len - received);
                    resp_buf[received..received + n].copy_from_slice(&chunk.bytes[..n]);
                    received += n;
                }
                Ok::<_, io::Error>(resp_buf)
            }
            .await;

            match exchange {
                Ok(resp_buf) => {
                    return Message::parse(&resp_buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                Err(e) => {
                    debug!(attempt, error = %e, "DoQ exchange failed; evicting cached conn");
                    self.connections.lock().await.remove(&key);
                    last_err = Some(e);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("DoQ query failed after retry")))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_client() {
        let _ = DoqClient::new();
    }

    #[test]
    fn default_creates_client() {
        let _ = DoqClient::default();
    }

    #[tokio::test]
    async fn endpoint_cached_per_verify_mode() {
        let c = DoqClient::new();
        let _ = c.endpoint_for(true).await.expect("endpoint verify=true");
        let _ = c.endpoint_for(true).await.expect("endpoint verify=true 2");
        assert_eq!(c.endpoints.lock().await.len(), 1);
        let _ = c.endpoint_for(false).await.expect("endpoint verify=false");
        assert_eq!(c.endpoints.lock().await.len(), 2);
    }
}
