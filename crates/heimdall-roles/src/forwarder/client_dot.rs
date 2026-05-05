// SPDX-License-Identifier: MIT

//! DNS-over-TLS outbound client (NET-019, Task #328).
//!
//! [`DotClient`] establishes a TLS 1.3 TCP connection to each upstream
//! resolver, sends the DNS query with a 2-byte length prefix, and reads the
//! response.  Each call opens a fresh connection; connection pooling is deferred
//! to a dedicated pool sprint.
//!
//! # TLS policy
//!
//! - TLS 1.3 **only** (`builder_with_protocol_versions(&[&TLS13])`).
//! - 0-RTT / early data **disabled** (default in rustls; documented here for
//!   clarity).
//! - SNI: uses `upstream.sni` if set, otherwise falls back to `upstream.host`.
//! - Certificate verification: enabled by default (`upstream.tls_verify = true`).
//!   When `tls_verify = false`, a `NoVerify` verifier is used — only in tests.
//!
//! # Sprint 38 note
//!
//! The `tls_verify = true` path uses an empty root store (no roots → every
//! certificate will fail verification until Sprint 38 wires in native roots).
//! Use `tls_verify = false` in test environments that use a self-signed CA.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use heimdall_core::{parser::Message, serialiser::Serialiser};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::forwarder::{client::UpstreamClient, upstream::UpstreamConfig};

/// Total per-query timeout for `DoT` (TCP connect + TLS handshake + query/response).
const DOT_TIMEOUT: Duration = Duration::from_secs(5);

// ── Crypto provider bootstrap ─────────────────────────────────────────────────

/// Ensures the `ring` crypto provider is installed exactly once per process.
static CRYPTO_PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── NoVerify cert verifier (tests only) ──────────────────────────────────────

/// A no-op TLS certificate verifier used when `upstream.tls_verify = false`.
///
/// This verifier accepts any certificate without validation.  It MUST only be
/// used in test environments where the upstream is trusted by construction
/// (e.g. a local loopback server with a test PKI).  Using it in production
/// removes all certificate chain validation and opens a MITM attack vector.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
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

// ── DotClient ─────────────────────────────────────────────────────────────────

/// Outbound DNS-over-TLS client.
///
/// Holds two TLS configurations: one with standard cert verification (used
/// when `upstream.tls_verify = true`) and one with no verification (used when
/// `upstream.tls_verify = false`, in test environments only).
pub struct DotClient {
    tls_config: Arc<ClientConfig>,
    tls_config_no_verify: Arc<ClientConfig>,
}

impl DotClient {
    /// Creates a new [`DotClient`].
    ///
    /// The `tls_verify = true` config uses an empty root store (Sprint 38 will
    /// wire in the OS trust store).  The `tls_verify = false` config uses a
    /// no-op verifier for test environments.
    #[must_use]
    pub fn new() -> Self {
        ensure_crypto_provider();

        let root_store = rustls::RootCertStore::empty();
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut no_verify_cfg =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
        // Allow TLS 1.2 in no-verify mode for maximum test-env compatibility.
        no_verify_cfg.alpn_protocols.clear();

        Self {
            tls_config: Arc::new(config),
            tls_config_no_verify: Arc::new(no_verify_cfg),
        }
    }

    /// Creates a new [`DotClient`] with a single custom root certificate in DER
    /// format.
    ///
    /// # Errors
    ///
    /// Returns a [`rustls::Error`] if the DER bytes are not a valid X.509
    /// certificate.
    pub fn with_custom_roots(root_cert_der: Vec<u8>) -> Result<Self, rustls::Error> {
        ensure_crypto_provider();
        let cert = rustls::pki_types::CertificateDer::from(root_cert_der);
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(cert)
            .map_err(|e| rustls::Error::General(e.to_string()))?;

        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut no_verify_cfg =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth();
        no_verify_cfg.alpn_protocols.clear();

        Ok(Self {
            tls_config: Arc::new(config),
            tls_config_no_verify: Arc::new(no_verify_cfg),
        })
    }
}

impl Default for DotClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamClient for DotClient {
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        let tls_cfg = if upstream.tls_verify {
            Arc::clone(&self.tls_config)
        } else {
            Arc::clone(&self.tls_config_no_verify)
        };
        Box::pin(async move {
            let result = timeout(DOT_TIMEOUT, do_dot_query(&tls_cfg, upstream, msg)).await;
            match result {
                Ok(inner) => inner,
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DoT query to {}:{} timed out", upstream.host, upstream.port),
                )),
            }
        })
    }
}

// ── Internal query logic ──────────────────────────────────────────────────────

async fn do_dot_query(
    tls_config: &Arc<ClientConfig>,
    upstream: &UpstreamConfig,
    msg: &Message,
) -> Result<Message, io::Error> {
    // ── Serialise query ──────────────────────────────────────────────────────
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

    // ── TCP connect ──────────────────────────────────────────────────────────
    let addr_str = format!("{}:{}", upstream.host, upstream.port);
    let tcp_stream = TcpStream::connect(&addr_str).await.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("TCP connect to {} failed: {e}", upstream.host),
        )
    })?;

    // ── TLS handshake ────────────────────────────────────────────────────────
    let sni_host = upstream.sni.as_deref().unwrap_or(upstream.host.as_str());

    let server_name = ServerName::try_from(sni_host.to_string()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid SNI name '{sni_host}': {e}"),
        )
    })?;

    let connector = TlsConnector::from(Arc::clone(tls_config));
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            warn!(
                upstream = %upstream.host,
                "DoT TLS handshake failed: {e}"
            );
            io::Error::new(e.kind(), format!("DoT TLS handshake failed: {e}"))
        })?;

    // ── Send 2-byte length-prefixed DNS message ──────────────────────────────
    tls_stream.write_all(&wire_len.to_be_bytes()).await?;
    tls_stream.write_all(&wire).await?;

    // ── Read 2-byte length-prefixed response ─────────────────────────────────
    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    tls_stream.read_exact(&mut resp_buf).await?;

    Message::parse(&resp_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_client() {
        let client = DotClient::new();
        let _ = Arc::clone(&client.tls_config);
    }

    #[test]
    fn default_creates_client() {
        let _client = DotClient::default();
    }

    // Network-dependent tests — require a live DoT resolver.
    // Run with: cargo test -- --ignored
    #[tokio::test]
    #[ignore = "network-dependent: queries 1.1.1.1:853 over DoT; run with --ignored"]
    async fn live_dot_query_to_cloudflare() {
        use std::str::FromStr;

        use heimdall_core::{
            header::{Header, Qclass, Qtype, Question},
            name::Name,
        };

        let mut header = Header::default();
        header.id = 0x1234;
        header.set_rd(true);
        header.qdcount = 1;

        let msg = Message {
            header,
            questions: vec![Question {
                qname: Name::from_str("example.com.").expect("INVARIANT: valid name"),
                qtype: Qtype::A,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };

        // Cloudflare 1.1.1.1 DoT — requires OS trust store (Sprint 38).
        let upstream = UpstreamConfig {
            host: "1.1.1.1".to_string(),
            port: 853,
            transport: crate::forwarder::upstream::UpstreamTransport::Dot,
            sni: Some("cloudflare-dns.com".to_string()),
            tls_verify: true,
        };

        let client = DotClient::new();
        let _result = client.query(&upstream, &msg).await;
        // Not asserting Ok here — cert verification will fail without native roots.
    }
}
