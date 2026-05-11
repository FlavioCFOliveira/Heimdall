// SPDX-License-Identifier: MIT

//! DNS-over-TLS outbound client (NET-019, Task #328 + Sprint 57 #638).
//!
//! [`DotClient`] establishes a TLS 1.3 TCP connection to each upstream
//! resolver, sends the DNS query with a 2-byte length prefix, and reads the
//! response. Connections are pooled via
//! [`crate::forwarder::conn_pool::ConnPool`] (RFC 7858 idle persistence) so
//! subsequent queries to the same upstream amortise the TLS handshake cost.
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
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use heimdall_core::{parser::Message, serialiser::Serialiser};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, warn};

use crate::forwarder::{
    client::UpstreamClient,
    conn_pool::{ConnPool, ConnectFn, PoolConfig, PoolError, PooledConn},
    upstream::UpstreamConfig,
};

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

// ── PooledTlsConn ─────────────────────────────────────────────────────────────

/// A pooled `DoT` TLS connection: a `TlsStream<TcpStream>` keyed by the
/// per-upstream pool entry. The peer's underlying TCP socket is probed via
/// `try_read` on the rustls stream's underlying socket — TLS read does not
/// give us a non-blocking probe, but rustls drops the stream on any I/O
/// error during the next exchange, which we handle with the same retry-once
/// path as the classic TCP client.
pub struct PooledTlsConn {
    stream: TlsStream<TcpStream>,
}

impl PooledConn for PooledTlsConn {
    fn is_healthy(&self) -> bool {
        // Probe the underlying TCP socket: WouldBlock means the kernel state
        // is alive and we have no unread bytes; anything else means the peer
        // closed or sent application bytes that would skew the next framing.
        let (tcp, _conn) = self.stream.get_ref();
        let mut buf = [0u8; 1];
        matches!(
            tcp.try_read(&mut buf),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
        )
    }
}

/// Connect factory for the `DoT` pool. Stores the TLS config + SNI so each
/// (config, sni, addr) tuple can have its own pool entry.
struct DotConnect {
    tls_config: Arc<ClientConfig>,
    sni: ServerName<'static>,
}

impl ConnectFn<PooledTlsConn> for DotConnect {
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<PooledTlsConn>> + Send + '_>> {
        let tls_cfg = Arc::clone(&self.tls_config);
        let sni = self.sni.clone();
        Box::pin(async move {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            let connector = TlsConnector::from(tls_cfg);
            let tls_stream = connector
                .connect(sni, tcp)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("DoT TLS handshake failed: {e}")))?;
            Ok(PooledTlsConn { stream: tls_stream })
        })
    }
}

/// Per-upstream pool key: pairs the resolved socket address with the SNI and
/// the `tls_verify` flag, since the TLS endpoint identity is determined by
/// (verify-mode, SNI) — not just the IP.
#[derive(Clone, Hash, PartialEq, Eq)]
struct DotPoolKey {
    addr: SocketAddr,
    sni: String,
    verify: bool,
}

// ── DotClient ─────────────────────────────────────────────────────────────────

/// Outbound DNS-over-TLS client.
///
/// Holds two TLS configurations (verify on / off) and a per-key
/// [`ConnPool<PooledTlsConn>`]. Connections are reused per
/// `(upstream addr, SNI, verify-mode)` tuple.
pub struct DotClient {
    tls_config: Arc<ClientConfig>,
    tls_config_no_verify: Arc<ClientConfig>,
    pools: Mutex<HashMap<DotPoolKey, Arc<ConnPool<PooledTlsConn>>>>,
    pool_config: PoolConfig,
}

impl DotClient {
    /// Creates a new [`DotClient`].
    ///
    /// The `tls_verify = true` config uses an empty root store (Sprint 38 will
    /// wire in the OS trust store).  The `tls_verify = false` config uses a
    /// no-op verifier for test environments.
    #[must_use]
    pub fn new() -> Self {
        Self::with_pool_config(PoolConfig::default())
    }

    /// Creates a new [`DotClient`] with an explicit pool configuration.
    #[must_use]
    pub fn with_pool_config(pool_config: PoolConfig) -> Self {
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
            pools: Mutex::new(HashMap::new()),
            pool_config,
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
            pools: Mutex::new(HashMap::new()),
            pool_config: PoolConfig::default(),
        })
    }

    /// Get-or-create the pool for `(addr, sni, verify)`.
    async fn pool_for(
        &self,
        addr: SocketAddr,
        sni: &ServerName<'static>,
        verify: bool,
    ) -> Arc<ConnPool<PooledTlsConn>> {
        let sni_str = format!("{sni:?}");
        let key = DotPoolKey {
            addr,
            sni: sni_str,
            verify,
        };
        let mut pools = self.pools.lock().await;
        if let Some(p) = pools.get(&key) {
            return Arc::clone(p);
        }
        let tls_cfg = if verify {
            Arc::clone(&self.tls_config)
        } else {
            Arc::clone(&self.tls_config_no_verify)
        };
        let factory = Arc::new(DotConnect {
            tls_config: tls_cfg,
            sni: sni.clone(),
        });
        let pool = ConnPool::new(self.pool_config.clone(), factory);
        pools.insert(key, Arc::clone(&pool));
        pool
    }

    /// Snapshot the aggregate metrics across all per-upstream pools.
    pub async fn pool_metrics(&self) -> [u64; 8] {
        let pools = self.pools.lock().await;
        pools.values().fold([0u64; 8], |mut acc, p| {
            let m = p.metrics().snapshot();
            for i in 0..8 {
                acc[i] = acc[i].saturating_add(m[i]);
            }
            acc
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
            let result = timeout(DOT_TIMEOUT, self.do_dot_query(upstream, msg)).await;
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

impl DotClient {
    async fn do_dot_query(
        &self,
        upstream: &UpstreamConfig,
        msg: &Message,
    ) -> Result<Message, io::Error> {
        // ── Serialise query ────────────────────────────────────────────────
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

        // ── Resolve upstream addr + SNI once per query ────────────────────
        let addr_str = format!("{}:{}", upstream.host, upstream.port);
        let addr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no address for {addr_str}"),
                )
            })?;

        let sni_host = upstream.sni.as_deref().unwrap_or(upstream.host.as_str());
        let sni: ServerName<'static> = ServerName::try_from(sni_host.to_string()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid SNI name '{sni_host}': {e}"),
            )
        })?;

        let pool = self.pool_for(addr, &sni, upstream.tls_verify).await;

        // ── Up to 2 attempts: a stale pool entry may pass the kernel
        // ── probe and die on first write; reacquire once, fail otherwise.
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..2u8 {
            let mut handle = match pool.acquire(addr).await {
                Ok(h) => h,
                Err(PoolError::Overloaded) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "DoT connection pool overloaded",
                    ));
                }
                Err(PoolError::ConnectFailed(e)) => {
                    warn!(upstream = %upstream.host, error = %e, "DoT TLS handshake failed");
                    return Err(e);
                }
            };

            let exchange = async {
                let stream = &mut handle.conn_mut().stream;
                stream.write_all(&wire_len.to_be_bytes()).await?;
                stream.write_all(&wire).await?;
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                let mut resp = vec![0u8; resp_len];
                stream.read_exact(&mut resp).await?;
                Ok::<_, io::Error>(resp)
            }
            .await;

            match exchange {
                Ok(resp) => {
                    handle.release().await;
                    return Message::parse(&resp)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
                Err(e) => {
                    debug!(%addr, attempt, error = %e, "pooled DoT exchange failed; dropping conn");
                    last_err = Some(e);
                    drop(handle);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("DoT query failed after retry")))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
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

    #[tokio::test]
    async fn pool_for_returns_same_arc_for_same_key() {
        let client = DotClient::new();
        let addr: SocketAddr = "127.0.0.1:853".parse().expect("valid addr");
        let sni: ServerName<'static> =
            ServerName::try_from("example.com".to_string()).expect("valid SNI");

        let p1 = client.pool_for(addr, &sni, true).await;
        let p2 = client.pool_for(addr, &sni, true).await;
        assert!(
            Arc::ptr_eq(&p1, &p2),
            "same (addr, sni, verify) must yield the same pool Arc"
        );

        // Different verify mode → different pool.
        let p3 = client.pool_for(addr, &sni, false).await;
        assert!(
            !Arc::ptr_eq(&p1, &p3),
            "different verify mode must yield a separate pool"
        );

        // Different SNI → different pool.
        let sni2: ServerName<'static> =
            ServerName::try_from("other.example".to_string()).expect("valid SNI");
        let p4 = client.pool_for(addr, &sni2, true).await;
        assert!(
            !Arc::ptr_eq(&p1, &p4),
            "different SNI must yield a separate pool"
        );
    }

    #[tokio::test]
    async fn pool_metrics_aggregates_across_pools() {
        let client = DotClient::new();
        let addr1: SocketAddr = "127.0.0.1:853".parse().expect("valid addr");
        let addr2: SocketAddr = "127.0.0.2:853".parse().expect("valid addr");
        let sni: ServerName<'static> =
            ServerName::try_from("example.com".to_string()).expect("valid SNI");

        // Touch two pool entries.
        let _ = client.pool_for(addr1, &sni, true).await;
        let _ = client.pool_for(addr2, &sni, true).await;

        // Metrics start at zero (no acquires yet).
        let m = client.pool_metrics().await;
        assert_eq!(m, [0u64; 8], "metrics must start at zero");
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
