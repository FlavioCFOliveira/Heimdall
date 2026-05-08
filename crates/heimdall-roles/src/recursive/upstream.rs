// SPDX-License-Identifier: MIT

//! Production `UpstreamQuery` implementation: UDP with pooled TCP fallback.
//!
//! [`UdpTcpUpstream`] sends DNS queries over UDP, falling back to TCP when
//! the response carries TC=1 (truncated). Used by [`RecursiveServer`] when
//! wired as a [`QueryDispatcher`].
//!
//! # Connection reuse (Sprint 57 #642)
//!
//! UDP queries open a fresh ephemeral socket per call (the recursive iterator
//! issues queries to many distinct authoritatives so per-target UDP socket
//! caching adds little). TCP fallback queries are pooled via the shared
//! [`ConnPool`] primitive (RFC 7766 idle persistence), so a recursive
//! resolver hitting the same authoritative for multiple cache-cold queries
//! amortises the TCP connect cost across iterations.
//!
//! [`RecursiveServer`]: crate::recursive::RecursiveServer
//! [`QueryDispatcher`]: heimdall_runtime::QueryDispatcher
//! [`ConnPool`]: crate::forwarder::conn_pool::ConnPool

use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use heimdall_core::{parser::Message, serialiser::Serialiser};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

use crate::{
    forwarder::conn_pool::{ConnPool, ConnectFn, PoolConfig, PoolError, PooledConn},
    recursive::follow::UpstreamQuery,
};

const QUERY_TIMEOUT: Duration = Duration::from_millis(2500);
const UDP_BUF: usize = 65535;

// ── Pooled TCP connection (recursive outbound) ───────────────────────────────

/// Pooled TCP connection used by the recursive resolver's TCP fallback path.
///
/// Mirrors `forwarder::client_classic::PooledTcpConn` — kept independent so
/// the recursive iterator's pool sizing and lifecycle are tuned separately
/// from the forwarder pool.
pub struct RecursiveTcpConn {
    stream: TcpStream,
}

impl PooledConn for RecursiveTcpConn {
    fn is_healthy(&self) -> bool {
        let mut buf = [0u8; 1];
        matches!(
            self.stream.try_read(&mut buf),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
        )
    }
}

/// Connect factory for the recursive TCP pool.
struct RecursiveTcpConnect;

impl ConnectFn<RecursiveTcpConn> for RecursiveTcpConnect {
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<RecursiveTcpConn>> + Send + '_>> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            Ok(RecursiveTcpConn { stream })
        })
    }
}

// ── UdpTcpUpstream ───────────────────────────────────────────────────────────

/// Sends DNS queries over UDP, retrying over a pooled TCP connection on TC=1.
pub struct UdpTcpUpstream {
    tcp_pool: Arc<ConnPool<RecursiveTcpConn>>,
}

impl UdpTcpUpstream {
    /// Creates a new [`UdpTcpUpstream`] with the default TCP pool config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_pool_config(PoolConfig::default())
    }

    /// Creates a new [`UdpTcpUpstream`] with an explicit TCP pool config.
    #[must_use]
    pub fn with_pool_config(config: PoolConfig) -> Self {
        Self {
            tcp_pool: ConnPool::new(config, Arc::new(RecursiveTcpConnect)),
        }
    }

    /// Snapshot the underlying TCP pool metrics for telemetry.
    #[must_use]
    pub fn tcp_pool_metrics(&self) -> [u64; 8] {
        self.tcp_pool.metrics().snapshot()
    }
}

impl Default for UdpTcpUpstream {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamQuery for UdpTcpUpstream {
    fn query<'a>(
        &'a self,
        server: std::net::IpAddr,
        port: u16,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let wire = serialise(msg);
            let resp = udp_send(server, port, &wire).await?;
            if resp.header.tc() {
                return self.tcp_send(server, port, &wire).await;
            }
            Ok(resp)
        })
    }
}

impl UdpTcpUpstream {
    async fn tcp_send(
        &self,
        server: std::net::IpAddr,
        port: u16,
        wire: &[u8],
    ) -> Result<Message, io::Error> {
        let target = SocketAddr::new(server, port);

        let len = u16::try_from(wire.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS message too large for TCP framing",
            )
        })?;

        // Up to 2 attempts: a stale pool entry that passes the TCP probe may
        // die on first write; reacquire once.
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..2u8 {
            let mut handle =
                match tokio::time::timeout(QUERY_TIMEOUT, self.tcp_pool.acquire(target)).await {
                    Ok(Ok(h)) => h,
                    Ok(Err(PoolError::Overloaded)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "recursive TCP pool overloaded",
                        ));
                    }
                    Ok(Err(PoolError::ConnectFailed(e))) => return Err(e),
                    Err(_elapsed) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TCP connect timed out",
                        ));
                    }
                };

            let exchange = async {
                let stream = &mut handle.conn_mut().stream;
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(wire).await?;
                let mut len_buf = [0u8; 2];
                tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut len_buf))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "TCP response timed out")
                    })??;
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                let mut resp = vec![0u8; resp_len];
                stream.read_exact(&mut resp).await?;
                Ok::<_, io::Error>(resp)
            }
            .await;

            match exchange {
                Ok(resp) => {
                    handle.release().await;
                    return Message::parse(&resp).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TCP response parse error: {e:?}"),
                        )
                    });
                }
                Err(e) => {
                    debug!(
                        target = %target,
                        attempt,
                        error = %e,
                        "pooled recursive TCP exchange failed; dropping conn"
                    );
                    last_err = Some(e);
                    drop(handle);
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("recursive TCP failed after retry")))
    }
}

fn serialise(msg: &Message) -> Vec<u8> {
    let mut ser = Serialiser::new(false);
    let _ = ser.write_message(msg);
    ser.finish()
}

async fn udp_send(server: std::net::IpAddr, port: u16, wire: &[u8]) -> Result<Message, io::Error> {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    let target = SocketAddr::new(server, port);
    sock.send_to(wire, target).await?;

    let mut buf = vec![0u8; UDP_BUF];
    let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP query timed out"))??;

    Message::parse(&buf[..n]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UDP response parse error: {e:?}"),
        )
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_upstream() {
        let _ = UdpTcpUpstream::new();
    }

    #[test]
    fn default_creates_upstream() {
        let _ = UdpTcpUpstream::default();
    }

    #[test]
    fn metrics_start_at_zero() {
        let u = UdpTcpUpstream::new();
        let m = u.tcp_pool_metrics();
        assert_eq!(m, [0u64; 8]);
    }

    #[tokio::test]
    async fn tcp_send_reuses_connection_across_truncated_replies() {
        // Stand up a TCP echo server that mimics RFC 1035 length-prefixed
        // framing. Two sequential tcp_send() calls must reuse a single
        // accepted TCP connection.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let conns = Arc::new(AtomicUsize::new(0));
        let conns_c = Arc::clone(&conns);
        let _server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                conns_c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    loop {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut payload = vec![0u8; len];
                        if stream.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        // Build a minimal valid DNS response (12-byte header
                        // with QR=1 set in byte 2 bit 7) so Message::parse
                        // succeeds.
                        let mut resp = vec![0u8; 12];
                        resp[2] = 0x80; // QR=1
                        let resp_len = u16::try_from(resp.len()).expect("resp len");
                        let _ = stream.write_all(&resp_len.to_be_bytes()).await;
                        let _ = stream.write_all(&resp).await;
                    }
                });
            }
        });

        let upstream = UdpTcpUpstream::new();
        let wire = b"\x00\x01query".to_vec();
        let _r1 = upstream
            .tcp_send(addr.ip(), addr.port(), &wire)
            .await
            .expect("first tcp_send");
        let _r2 = upstream
            .tcp_send(addr.ip(), addr.port(), &wire)
            .await
            .expect("second tcp_send");

        let m = upstream.tcp_pool_metrics();
        assert_eq!(m[0], 2, "two acquires; metrics: {m:?}");
        assert_eq!(m[1], 1, "second is hit; metrics: {m:?}");
        assert_eq!(m[2], 1, "first is miss; metrics: {m:?}");
        assert_eq!(
            conns.load(Ordering::SeqCst),
            1,
            "exactly one accepted TCP connection — connection reused"
        );
    }
}
