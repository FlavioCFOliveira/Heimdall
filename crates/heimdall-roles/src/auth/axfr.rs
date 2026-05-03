// SPDX-License-Identifier: MIT

//! AXFR outbound — full zone transfer server (RFC 5936) — task #299.
//!
//! Serves the zone to an authorised secondary over a TCP (or TLS/XoT) stream.
//! The stream must implement `AsyncRead + AsyncWrite + Unpin`, so the
//! same logic handles plain TCP and TLS without duplication (`PROTO-047`).
//!
//! ## Security
//!
//! Per `PROTO-044`: TSIG is REQUIRED. Per `PROTO-045`: the source-IP ACL is an
//! additional layer, not the sole gate. Both checks run before any zone data is
//! sent (`PROTO-048`).

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use heimdall_core::header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::record::Rtype;
use heimdall_core::serialiser::Serialiser;
use heimdall_core::zone::ZoneFile;
use heimdall_core::{TsigRecord, TsigSigner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::AuthError;
use crate::auth::zone_role::ZoneConfig;

/// Maximum bytes per AXFR TCP message (DNS TCP max = 65535).
const MAX_MSG_BYTES: usize = 65000;

/// Sends the full zone as an AXFR response stream over `stream` (RFC 5936).
///
/// ## Flow
///
/// 1. Verify source IP against `zone_config.axfr_acl` (`PROTO-045`).
/// 2. Verify TSIG on the incoming query if present; reject if absent and TSIG
///    is configured (`PROTO-044`).
/// 3. Stream: `SOA → all RRsets (sorted by owner) → SOA` (RFC 5936 §4.1).
/// 4. Each TCP message is 2-byte length-prefixed and TSIG-signed when in use.
///
/// # Errors
///
/// - [`AuthError::Refused`] — IP not in ACL or TSIG check failed.
/// - [`AuthError::Io`] — I/O error writing to `stream`.
/// - [`AuthError::Serialise`] — message serialisation failure.
pub async fn send_axfr<S>(
    zone: &ZoneFile,
    zone_config: &ZoneConfig,
    query: &Message,
    source_ip: IpAddr,
    stream: &mut S,
) -> Result<(), AuthError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // ── 1. IP ACL check (additional layer; PROTO-045) ─────────────────────────
    if !zone_config.ip_allowed(source_ip) {
        return Err(AuthError::Refused);
    }

    // ── 2. TSIG check (mandatory; PROTO-044) ─────────────────────────────────
    let signer = verify_tsig_on_query(query, zone_config)?;

    // ── 3. Determine zone apex ────────────────────────────────────────────────
    let apex = zone.origin.as_ref().ok_or(AuthError::ZoneHasNoApex)?;

    // Find the SOA record.
    let soa_rec = zone
        .records
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .ok_or(AuthError::ZoneHasNoSoa)?
        .clone();

    // Collect and sort all non-SOA records by owner name then rtype.
    let mut body: Vec<_> = zone
        .records
        .iter()
        .filter(|r| r.rtype != Rtype::Soa)
        .cloned()
        .collect();
    body.sort_by(|a, b| {
        a.name
            .to_string()
            .to_ascii_lowercase()
            .cmp(&b.name.to_string().to_ascii_lowercase())
            .then_with(|| a.rtype.as_u16().cmp(&b.rtype.as_u16()))
    });

    // ── 4. Stream zone: SOA … records … SOA ──────────────────────────────────
    let query_id = query.header.id;

    // First SOA.
    let first_soa_msg = build_axfr_message(query_id, apex, vec![soa_rec.clone()], Rcode::NoError);
    write_dns_tcp_msg(stream, &first_soa_msg, signer.as_ref()).await?;

    // Body records in chunks.
    let mut chunk: Vec<_> = Vec::new();
    for rec in body {
        chunk.push(rec);
        // Flush when the chunk is large enough.
        if chunk.len() >= 50 {
            let msg = build_axfr_message(query_id, apex, chunk, Rcode::NoError);
            write_dns_tcp_msg(stream, &msg, signer.as_ref()).await?;
            chunk = Vec::new();
        }
    }
    if !chunk.is_empty() {
        let msg = build_axfr_message(query_id, apex, chunk, Rcode::NoError);
        write_dns_tcp_msg(stream, &msg, signer.as_ref()).await?;
    }

    // Final SOA.
    let final_soa_msg = build_axfr_message(query_id, apex, vec![soa_rec], Rcode::NoError);
    write_dns_tcp_msg(stream, &final_soa_msg, signer.as_ref()).await?;

    Ok(())
}

// ── TSIG helpers ──────────────────────────────────────────────────────────────

/// If the zone config has a TSIG key, verify that the query is signed with it.
/// Returns the `TsigSigner` for signing outbound messages, or `None` if no TSIG.
fn verify_tsig_on_query(
    query: &Message,
    zone_config: &ZoneConfig,
) -> Result<Option<TsigSigner>, AuthError> {
    use std::str::FromStr;

    // No TSIG configured → must still check whether the query carries
    // one we don't know about (PROTO-044: reject any unsigned request
    // when TSIG is required). Since we have no key, we cannot verify, so refuse.
    let Some(tsig_cfg) = &zone_config.tsig_key else {
        return Err(AuthError::Refused);
    };

    let key_name =
        heimdall_core::Name::from_str(&tsig_cfg.key_name).map_err(|_| AuthError::InvalidTsigKey)?;
    let signer = TsigSigner::new(key_name, tsig_cfg.algorithm, &tsig_cfg.secret, 300);

    // Find the TSIG record in the query's additional section.
    let tsig_rec = query
        .additional
        .iter()
        .find(|r| r.rtype == heimdall_core::record::Rtype::Unknown(250))
        .and_then(|r| {
            if let heimdall_core::rdata::RData::Unknown { data, .. } = &r.rdata {
                TsigRecord::parse_rdata(r.name.clone(), data).ok()
            } else {
                None
            }
        });

    let tsig_rec = tsig_rec.ok_or(AuthError::Refused)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Serialize the query to verify against.
    let mut ser = Serialiser::new(false);
    ser.write_message(query)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let query_wire = ser.finish();

    signer
        .verify(&query_wire, &tsig_rec, now)
        .map_err(|_| AuthError::TsigVerifyFailed)?;

    Ok(Some(signer))
}

// ── Message building ──────────────────────────────────────────────────────────

fn build_axfr_message(
    id: u16,
    apex: &Name,
    records: Vec<heimdall_core::record::Record>,
    rcode: Rcode,
) -> Message {
    #[allow(clippy::cast_possible_truncation)]
    let ancount = records.len() as u16;
    let mut header = Header {
        id,
        qdcount: 1,
        ancount,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_opcode(Opcode::Query);
    header.set_aa(true);
    header.set_rcode(rcode);

    Message {
        header,
        questions: vec![Question {
            qname: apex.clone(),
            qtype: Qtype::Axfr,
            qclass: Qclass::In,
        }],
        answers: records,
        authority: vec![],
        additional: vec![],
    }
}

/// Serialise `msg`, optionally TSIG-sign it, and write with 2-byte TCP framing.
async fn write_dns_tcp_msg<S>(
    stream: &mut S,
    msg: &Message,
    signer: Option<&TsigSigner>,
) -> Result<(), AuthError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut ser = Serialiser::new(true);
    ser.write_message(msg)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();

    // TSIG-sign if configured.
    if let Some(sig) = signer {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let tsig_rec = sig.sign(&wire, now);
        tsig_rec.write_to(&mut wire);
        // Increment arcount.
        let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_add(1);
        wire[10] = (ar >> 8) as u8;
        wire[11] = (ar & 0xFF) as u8;
    }

    // TCP 2-byte length prefix.
    if wire.len() > MAX_MSG_BYTES {
        return Err(AuthError::Serialise(
            "AXFR message exceeds 65000 bytes".to_owned(),
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (wire.len() as u16).to_be_bytes();
    stream
        .write_all(&len_bytes)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;
    stream
        .write_all(&wire)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::name::Name;
    use heimdall_core::zone::{ZoneFile, ZoneLimits};

    use super::*;
    use crate::auth::zone_role::{TsigConfig, ZoneConfig, ZoneRole};

    const ZONE_TEXT: &str = "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
www IN A 192.0.2.2\n\
";

    fn parse_zone() -> ZoneFile {
        ZoneFile::parse(ZONE_TEXT, None, ZoneLimits::default())
            .expect("INVARIANT: test zone must parse")
    }

    fn tsig_config() -> TsigConfig {
        TsigConfig {
            key_name: "xfr-key.".to_owned(),
            algorithm: heimdall_core::TsigAlgorithm::HmacSha256,
            secret: b"supersecretkey32bytes-exactly!!".to_vec(),
        }
    }

    #[tokio::test]
    async fn axfr_refused_when_ip_not_in_acl() {
        let zone = parse_zone();
        let cfg = ZoneConfig {
            apex: Name::from_str("example.com.").expect("INVARIANT: valid name"),
            role: ZoneRole::Primary,
            upstream_primary: None,
            notify_secondaries: vec![],
            tsig_key: Some(tsig_config()),
            axfr_acl: vec!["10.0.0.1".parse().expect("INVARIANT: valid ip")],
            zone_file: None,
        };
        let query = make_minimal_axfr_query();
        let source_ip: std::net::IpAddr = "192.0.2.99".parse().expect("INVARIANT: valid ip");
        let mut stream = tokio::io::duplex(65536).0;

        let result = send_axfr(&zone, &cfg, &query, source_ip, &mut stream).await;
        assert!(matches!(result, Err(AuthError::Refused)));
    }

    fn make_minimal_axfr_query() -> Message {
        let header = Header {
            id: 1,
            qdcount: 1,
            ..Header::default()
        };
        Message {
            header,
            questions: vec![heimdall_core::header::Question {
                qname: Name::from_str("example.com.").expect("INVARIANT: valid name"),
                qtype: Qtype::Axfr,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }
}
