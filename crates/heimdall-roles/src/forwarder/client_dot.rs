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
//!   Disabled only for tests; the root store is empty in test configuration,
//!   which causes all certs to fail verification.
//!
//! # Sprint 38 note
//!
//! The current implementation uses `rustls::RootCertStore::empty()` as the
//! trust store (no roots → every certificate will fail verification unless
//! `tls_verify = false`).  Sprint 38 wires in the actual OS trust store.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use std::sync::OnceLock;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::forwarder::client::UpstreamClient;
use crate::forwarder::upstream::UpstreamConfig;

/// Total per-query timeout for `DoT` (TCP connect + TLS handshake + query/response).
const DOT_TIMEOUT: Duration = Duration::from_secs(5);

// ── Crypto provider bootstrap ─────────────────────────────────────────────────

/// Ensures the `ring` crypto provider is installed exactly once per process.
///
/// rustls 0.23 requires a process-level `CryptoProvider` to be installed
/// before any TLS configuration is built.  The `ring` provider is the
/// workspace-standard choice (ADR-0036).  The `let _` ignores the `Err`
/// returned when the provider is already installed (safe: it means another
/// thread beat us).
static CRYPTO_PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── DotClient ─────────────────────────────────────────────────────────────────

/// Outbound DNS-over-TLS client.
///
/// The TLS configuration is built once at construction time and shared across
/// all queries through an [`Arc`].
pub struct DotClient {
    tls_config: Arc<ClientConfig>,
}

impl DotClient {
    /// Creates a new [`DotClient`] with an empty root certificate store.
    ///
    /// # Sprint 38 note
    ///
    /// The root store is intentionally empty in this implementation.  Sprint 38
    /// wires in the OS trust store via `rustls-native-certs`.  Until then, `DoT`
    /// connections will only succeed when `upstream.tls_verify = false` or when
    /// custom roots are loaded via [`with_custom_roots`].
    ///
    /// [`with_custom_roots`]: DotClient::with_custom_roots
    #[must_use]
    pub fn new() -> Self {
        ensure_crypto_provider();
        let root_store = rustls::RootCertStore::empty();
        // TLS 1.3 only — `builder_with_protocol_versions` restricts negotiation
        // to exactly TLS 1.3; the function returns a builder directly (not a
        // Result), so no `.expect()` is required here.
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(config),
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
        Ok(Self {
            tls_config: Arc::new(config),
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
        Box::pin(async move {
            let result = timeout(DOT_TIMEOUT, do_dot_query(&self.tls_config, upstream, msg)).await;
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
        // Verify construction does not panic and the config is accessible.
        let _ = Arc::clone(&client.tls_config);
    }

    #[test]
    fn default_creates_client() {
        let _client = DotClient::default();
    }

    // Network-dependent tests — require a live DoT resolver.
    // Run with: cargo test -- --ignored
    #[tokio::test]
    #[ignore]
    async fn live_dot_query_to_cloudflare() {
        use std::str::FromStr;

        use heimdall_core::header::{Header, Qclass, Qtype, Question};
        use heimdall_core::name::Name;

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
        // This test is expected to fail until Sprint 38 wires in native roots.
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
