// SPDX-License-Identifier: MIT

//! Classic UDP/TCP outbound DNS client (NET-012/019).
//!
//! Implements the standard DNS query algorithm (RFC 1035 §4.2):
//!
//! 1. Send over UDP; if the response has TC=1, retry over TCP.
//! 2. Prepend a 2-byte length prefix on TCP (RFC 1035 §4.2.2).
//! 3. Timeout: 800 ms for UDP, 5 s for TCP (including retry).
//!
//! The client is stateless: no persistent connections are maintained.
//! Connection pooling for TCP is deferred to a dedicated pool sprint.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use heimdall_core::{parser::Message, serialiser::Serialiser};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tracing::debug;

use crate::forwarder::{client::UpstreamClient, upstream::UpstreamConfig};

/// UDP query timeout (RFC 1034 §5.3.3 recommends ≥ 5 s; 800 ms is the per-attempt budget).
const UDP_TIMEOUT: Duration = Duration::from_millis(800);

/// TCP query timeout (includes connection + send + recv).
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum UDP response size (RFC 1035 §2.3.4 hard limit for plain UDP).
const UDP_RECV_BUF: usize = 512;

/// EDNS(0) UDP payload size advertised in outbound queries (RFC 6891 §6.2.5).
const EDNS_UDP_PAYLOAD: u16 = 4096;

// ── UdpTcpClient ─────────────────────────────────────────────────────────────

/// Outbound DNS client using classic UDP with TCP fallback.
///
/// Each call to [`query`] opens a fresh socket.  No connection state is
/// retained between calls.
///
/// [`query`]: UdpTcpClient::query
pub struct UdpTcpClient;

impl UdpTcpClient {
    /// Creates a new [`UdpTcpClient`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Serialises `msg` to uncompressed wire format with an EDNS OPT record
    /// appended.
    ///
    /// Returns an [`io::Error`] if serialisation fails.
    pub(crate) fn serialise_with_edns(msg: &Message) -> Result<Vec<u8>, io::Error> {
        // Build a copy of the message with an EDNS OPT record in additional.
        let mut wire_msg = msg.clone();
        append_edns_opt(&mut wire_msg);

        let mut ser = Serialiser::new(false);
        ser.write_message(&wire_msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(ser.finish())
    }

    /// Returns `true` if the response wire bytes have the TC (truncated) bit
    /// set in the DNS header.
    ///
    /// The TC bit lives at bit 6 of byte 2 of the 12-byte DNS header
    /// (RFC 1035 §4.1.1).
    #[must_use]
    pub(crate) fn is_truncated(wire: &[u8]) -> bool {
        // Header is 12 bytes; byte index 2 contains: QR|OPCODE(4)|AA|TC|RD
        // TC is bit 1 (0-indexed from LSB) of byte 2.
        if wire.len() < 3 {
            return false;
        }
        (wire[2] & 0x02) != 0
    }
}

impl Default for UdpTcpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamClient for UdpTcpClient {
    fn query<'a>(
        &'a self,
        upstream: &'a UpstreamConfig,
        msg: &'a Message,
    ) -> Pin<Box<dyn Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let wire = Self::serialise_with_edns(msg)?;
            let addr = resolve_addr(&upstream.host, upstream.port).await?;

            // ── UDP attempt ──────────────────────────────────────────────────
            let udp_result = timeout(UDP_TIMEOUT, udp_query(addr, &wire)).await;

            let (response_wire, truncated) = match udp_result {
                Ok(Ok(bytes)) => {
                    let tc = Self::is_truncated(&bytes);
                    (bytes, tc)
                }
                Ok(Err(e)) => {
                    debug!(upstream = %addr, error = %e, "UDP query failed; retrying over TCP");
                    // Fall through to TCP on UDP failure as well.
                    (Vec::new(), true)
                }
                Err(_elapsed) => {
                    debug!(upstream = %addr, "UDP query timed out; retrying over TCP");
                    (Vec::new(), true)
                }
            };

            if !truncated && !response_wire.is_empty() {
                return Message::parse(&response_wire)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }

            // ── TCP fallback ─────────────────────────────────────────────────
            let tcp_result = timeout(TCP_TIMEOUT, tcp_query(addr, &wire)).await;
            match tcp_result {
                Ok(Ok(bytes)) => Message::parse(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
                Ok(Err(e)) => Err(e),
                Err(_elapsed) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("TCP query to {addr} timed out"),
                )),
            }
        })
    }
}

// ── Network helpers ───────────────────────────────────────────────────────────

/// Resolves `host:port` to a [`SocketAddr`].
///
/// If `host` is a valid IP address literal it is used directly; otherwise
/// `tokio::net::lookup_host` is called.
async fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, io::Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addr_str = format!("{host}:{port}");
    tokio::net::lookup_host(addr_str)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}")))
}

/// Sends `wire` to `addr` over UDP and returns the raw response bytes.
async fn udp_query(addr: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(wire, addr).await?;

    let mut buf = vec![0u8; UDP_RECV_BUF];
    let (n, _from) = socket.recv_from(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Sends `wire` to `addr` over TCP with 2-byte length framing (RFC 1035 §4.2.2)
/// and reads the response.
async fn tcp_query(addr: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut stream = TcpStream::connect(addr).await?;

    // Send: 2-byte big-endian length prefix followed by the DNS message.
    let len = u16::try_from(wire.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS message exceeds 65535 bytes",
        )
    })?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(wire).await?;

    // Read: 2-byte length prefix, then payload.
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

// ── EDNS helper ───────────────────────────────────────────────────────────────

/// Appends a minimal EDNS(0) OPT record to `msg.additional`.
///
/// The OPT record advertises a UDP payload size of [`EDNS_UDP_PAYLOAD`] (4096)
/// with no extended RCODE, DNSSEC OK bit cleared, and no options.
fn append_edns_opt(msg: &mut Message) {
    use heimdall_core::{
        header::Qclass,
        rdata::RData,
        record::{Record, Rtype},
    };

    // OPT RR: owner = root (.), type = OPT (41), class = UDP payload size,
    // TTL encodes extended RCODE + flags (0 = no extended RCODE, DO=0).
    msg.additional.push(Record {
        name: heimdall_core::name::Name::root(),
        rtype: Rtype::Opt,
        rclass: Qclass::from_u16(EDNS_UDP_PAYLOAD),
        ttl: 0,
        rdata: RData::Opt(heimdall_core::edns::OptRr {
            udp_payload_size: EDNS_UDP_PAYLOAD,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: vec![],
        }),
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn is_truncated_detects_tc_bit() {
        // Byte 2 of DNS header: bit 1 (0-indexed from MSB right-to-left)
        // Wire: bytes 0..1 = ID, byte 2 = QR|OPCODE|AA|TC|RD
        // TC is bit 1 (value 0x02).
        let mut wire = vec![0u8; 12]; // minimal header
        wire[2] = 0x02; // TC bit set
        assert!(UdpTcpClient::is_truncated(&wire));
    }

    #[test]
    fn is_truncated_clear_when_tc_not_set() {
        let wire = vec![0u8; 12];
        assert!(!UdpTcpClient::is_truncated(&wire));
    }

    #[test]
    fn is_truncated_returns_false_for_short_buffer() {
        assert!(!UdpTcpClient::is_truncated(&[0u8, 0u8]));
    }

    #[test]
    fn serialise_with_edns_produces_non_empty_wire() {
        use heimdall_core::header::Header;

        let msg = Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let wire = UdpTcpClient::serialise_with_edns(&msg)
            .expect("INVARIANT: serialisation of empty message must succeed");
        // At minimum: 12-byte header + OPT RR (11 bytes minimum).
        assert!(wire.len() >= 12, "wire must include DNS header");
    }

    // Network-dependent tests are marked #[ignore]; run with
    //   cargo test -- --ignored
    // against a live resolver.
    #[tokio::test]
    #[ignore]
    async fn live_udp_query_to_google_dns() {
        use std::str::FromStr;

        use heimdall_core::{
            header::{Header, Qclass, Qtype, Question},
            name::Name,
        };

        let mut header = Header::default();
        header.id = 0xABCD;
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

        let upstream = UpstreamConfig {
            host: "8.8.8.8".to_string(),
            port: 53,
            transport: crate::forwarder::upstream::UpstreamTransport::UdpTcp,
            sni: None,
            tls_verify: true,
        };

        let client = UdpTcpClient::new();
        let result = client.query(&upstream, &msg).await;
        assert!(result.is_ok(), "live UDP query failed: {result:?}");
        let response = result.expect("INVARIANT: just checked is_ok");
        assert!(response.header.qr(), "response QR bit must be set");
    }
}
