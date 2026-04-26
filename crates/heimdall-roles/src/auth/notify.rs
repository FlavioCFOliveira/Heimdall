// SPDX-License-Identifier: MIT

//! NOTIFY outbound (RFC 1996) — task #301.
//!
//! Sends a NOTIFY message to a configured secondary on zone update. Retries up
//! to 3 times over TCP if the UDP acknowledgement is not received within 5 s
//! (`PROTO-038`, `PROTO-040`).

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heimdall_core::header::{Header, Opcode, Qclass, Qtype, Question};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use heimdall_core::TsigSigner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{info, warn};

use crate::auth::zone_role::TsigConfig;
use crate::auth::AuthError;

/// Optional TSIG parameters for signing outbound NOTIFY messages.
pub use crate::auth::zone_role::TsigConfig as NotifyTsig;

/// Maximum number of TCP retry attempts if UDP NOTIFY is not acknowledged.
const MAX_RETRIES: u32 = 3;
/// UDP acknowledgement timeout.
const UDP_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends a NOTIFY message for `zone_apex` with `soa_serial` to `target`.
///
/// Procedure (`PROTO-038`):
/// 1. Build NOTIFY message (opcode = NOTIFY, qtype = SOA).
/// 2. TSIG-sign if `tsig` is `Some`.
/// 3. Send over UDP; if no acknowledgement in 5 s → retry up to 3 times via TCP.
///
/// # Errors
///
/// Returns [`AuthError::NotifyFailed`] when all retry attempts are exhausted.
pub async fn send_notify(
    zone_apex: &Name,
    soa_serial: u32,
    target: SocketAddr,
    tsig: Option<&TsigConfig>,
) -> Result<(), AuthError> {
    let wire = build_notify_wire(zone_apex, soa_serial, tsig)?;

    // Attempt UDP first.
    if try_notify_udp(&wire, target).await.is_ok() {
        info!(zone = %zone_apex, serial = soa_serial, %target, "NOTIFY acknowledged (UDP)");
        return Ok(());
    }

    // Retry via TCP up to MAX_RETRIES times.
    for attempt in 1..=MAX_RETRIES {
        match try_notify_tcp(&wire, target).await {
            Ok(()) => {
                info!(
                    zone = %zone_apex,
                    serial = soa_serial,
                    %target,
                    attempt,
                    "NOTIFY acknowledged (TCP)"
                );
                return Ok(());
            }
            Err(e) => {
                warn!(
                    zone = %zone_apex,
                    %target,
                    attempt,
                    error = %e,
                    "NOTIFY TCP attempt failed"
                );
            }
        }
    }

    warn!(zone = %zone_apex, %target, "NOTIFY failed after all retries");
    Err(AuthError::NotifyFailed { target })
}

/// Builds the wire-format NOTIFY message (optionally TSIG-signed).
fn build_notify_wire(
    zone_apex: &Name,
    _soa_serial: u32,
    tsig: Option<&TsigConfig>,
) -> Result<Vec<u8>, AuthError> {
    let mut header = Header {
        id: rand_id(),
        qdcount: 1,
        ..Header::default()
    };
    header.set_opcode(Opcode::Notify);
    header.set_qr(false); // outbound query, not response
    header.set_aa(true);

    let msg = Message {
        header,
        questions: vec![Question {
            qname: zone_apex.clone(),
            qtype: Qtype::Soa,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let mut ser = Serialiser::new(true);
    ser.write_message(&msg).map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();

    if let Some(t) = tsig {
        let key_name = Name::from_str(&t.key_name).map_err(|_| AuthError::InvalidTsigKey)?;
        let signer = TsigSigner::new(key_name, t.algorithm, &t.secret, 300);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let tsig_rec = signer.sign(&wire, now);
        tsig_rec.write_to(&mut wire);
        // Increment arcount.
        let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_add(1);
        wire[10] = (ar >> 8) as u8;
        wire[11] = (ar & 0xFF) as u8;
    }

    Ok(wire)
}

/// Sends NOTIFY via UDP and waits for an acknowledgement.
async fn try_notify_udp(wire: &[u8], target: SocketAddr) -> Result<(), AuthError> {
    let bind_str = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let bind_addr: SocketAddr = bind_str
        .parse()
        .map_err(|e: std::net::AddrParseError| AuthError::Io(e.to_string()))?;
    let sock = UdpSocket::bind(bind_addr).await.map_err(|e| AuthError::Io(e.to_string()))?;
    sock.send_to(wire, target).await.map_err(|e| AuthError::Io(e.to_string()))?;

    let mut buf = [0u8; 512];
    match tokio::time::timeout(UDP_TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _src))) if n >= 2 => {
            if buf[2] & 0x80 != 0 {
                Ok(())
            } else {
                Err(AuthError::NotifyFailed { target })
            }
        }
        _ => Err(AuthError::NotifyFailed { target }),
    }
}

/// Sends NOTIFY via TCP (2-byte length-prefixed) and waits for an ack.
async fn try_notify_tcp(wire: &[u8], target: SocketAddr) -> Result<(), AuthError> {
    let mut stream =
        TcpStream::connect(target).await.map_err(|e| AuthError::Io(e.to_string()))?;

    // 2-byte length prefix.
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (wire.len() as u16).to_be_bytes();
    stream.write_all(&len_bytes).await.map_err(|e| AuthError::Io(e.to_string()))?;
    stream.write_all(wire).await.map_err(|e| AuthError::Io(e.to_string()))?;

    // Read the response length + response.
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(UDP_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| AuthError::NotifyFailed { target })?
        .map_err(|e| AuthError::Io(e.to_string()))?;

    let resp_len = usize::from(u16::from_be_bytes(len_buf));
    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(UDP_TIMEOUT, stream.read_exact(&mut resp_buf))
        .await
        .map_err(|_| AuthError::NotifyFailed { target })?
        .map_err(|e| AuthError::Io(e.to_string()))?;

    if resp_buf.len() < 3 || resp_buf[2] & 0x80 == 0 {
        return Err(AuthError::NotifyFailed { target });
    }
    Ok(())
}

/// Generates a random 16-bit message ID.
///
/// Uses a simple time-based seed; in production this will be replaced by a
/// CSPRNG once the entropy module is integrated.
fn rand_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    #[allow(clippy::cast_possible_truncation)]
    let id = nanos as u16;
    id
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::Opcode;
    use heimdall_core::name::Name;

    use super::*;

    fn test_apex() -> Name {
        Name::from_str("example.com.").expect("INVARIANT: valid test name")
    }

    /// Builds a NOTIFY wire message without TSIG and parses it back for inspection.
    #[test]
    fn notify_message_has_correct_opcode_and_qtype() {
        let wire = build_notify_wire(&test_apex(), 42, None)
            .expect("notify wire must build");

        let msg = heimdall_core::parser::Message::parse(&wire)
            .expect("notify wire must parse");
        assert_eq!(msg.header.opcode(), Opcode::Notify);
        assert!(!msg.questions.is_empty());
        assert_eq!(msg.questions[0].qtype, Qtype::Soa);
        assert_eq!(msg.questions[0].qname.to_string(), "example.com.");
        assert!(msg.header.aa(), "AA must be set in outgoing NOTIFY");
    }

    #[test]
    fn notify_message_with_tsig_has_additional_record() {
        let tsig = TsigConfig {
            key_name: "xfr-key.".to_owned(),
            algorithm: heimdall_core::TsigAlgorithm::HmacSha256,
            secret: b"supersecretkey32bytes-exactly!!".to_vec(),
        };
        let wire = build_notify_wire(&test_apex(), 100, Some(&tsig))
            .expect("notify wire with tsig must build");

        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        assert_eq!(arcount, 1, "TSIG record must be in additional section");
    }

    #[test]
    fn notify_message_no_tsig_arcount_zero() {
        let wire = build_notify_wire(&test_apex(), 1, None)
            .expect("notify wire must build");
        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        assert_eq!(arcount, 0);
    }
}
