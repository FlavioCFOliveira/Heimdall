// SPDX-License-Identifier: MIT

//! Production `UpstreamQuery` implementation: UDP with TCP fallback.
//!
//! [`UdpTcpUpstream`] sends DNS queries over UDP, falling back to TCP when
//! the response carries TC=1 (truncated).  Used by [`RecursiveServer`] when
//! wired as a [`QueryDispatcher`].
//!
//! [`RecursiveServer`]: crate::recursive::RecursiveServer
//! [`QueryDispatcher`]: heimdall_runtime::QueryDispatcher

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;

use crate::recursive::follow::UpstreamQuery;

const QUERY_TIMEOUT: Duration = Duration::from_millis(2500);
const UDP_BUF: usize = 65535;

/// Sends DNS queries over UDP, retrying over TCP on TC=1.
pub struct UdpTcpUpstream;

impl UpstreamQuery for UdpTcpUpstream {
    fn query<'a>(
        &'a self,
        server: IpAddr,
        port: u16,
        msg: &'a Message,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let wire = serialise(msg);
            let resp = udp_send(server, port, &wire).await?;
            if resp.header.tc() {
                return tcp_send(server, port, &wire).await;
            }
            Ok(resp)
        })
    }
}

fn serialise(msg: &Message) -> Vec<u8> {
    let mut ser = Serialiser::new(false);
    let _ = ser.write_message(msg);
    ser.finish()
}

async fn udp_send(server: IpAddr, port: u16, wire: &[u8]) -> Result<Message, io::Error> {
    let bind = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    let target = std::net::SocketAddr::new(server, port);
    sock.send_to(wire, target).await?;

    let mut buf = vec![0u8; UDP_BUF];
    let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP query timed out"))??;

    Message::parse(&buf[..n])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("UDP response parse error: {e:?}")))
}

async fn tcp_send(server: IpAddr, port: u16, wire: &[u8]) -> Result<Message, io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = std::net::SocketAddr::new(server, port);
    let mut stream = tokio::time::timeout(QUERY_TIMEOUT, tokio::net::TcpStream::connect(target))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;

    let len = u16::try_from(wire.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS message too large for TCP framing"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(wire).await?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP response timed out"))??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;

    Message::parse(&resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TCP response parse error: {e:?}")))
}
