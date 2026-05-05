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

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use heimdall_core::{
    TsigRecord, TsigSigner,
    header::{Header, Opcode, Qclass, Qtype, Question, Rcode},
    name::Name,
    parser::Message,
    record::Rtype,
    serialiser::Serialiser,
    zone::ZoneFile,
};
use tokio::io::AsyncWriteExt;

use crate::auth::{AuthError, zone_role::ZoneConfig};

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
    raw: &[u8],
    source_ip: IpAddr,
    stream: &mut S,
) -> Result<(), AuthError>
where
    S: AsyncWriteExt + Unpin,
{
    // ── 1. IP ACL check (additional layer; PROTO-045) ─────────────────────────
    if !zone_config.ip_allowed(source_ip) {
        return Err(AuthError::Refused);
    }

    // ── 2. TSIG check (mandatory; PROTO-044) ─────────────────────────────────
    let signer = verify_tsig_on_query(query, raw, zone_config)?;

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

// ── Synchronous frame builder ─────────────────────────────────────────────────

/// Builds the full AXFR response as a list of pre-framed wire messages
/// (each entry includes the 2-byte TCP length prefix).
///
/// Performs the same ACL + TSIG checks as [`send_axfr`], but returns the
/// frames instead of writing them to a stream.  Used by the TCP transport
/// layer to write zone transfer responses without `async` overhead at the
/// dispatch point.
///
/// # Errors
///
/// - [`AuthError::Refused`] — IP not in ACL or TSIG check failed.
/// - [`AuthError::ZoneHasNoApex`] / [`AuthError::ZoneHasNoSoa`] — zone incomplete.
/// - [`AuthError::Serialise`] — message serialisation failure.
pub fn build_axfr_frames(
    zone: &ZoneFile,
    zone_config: &ZoneConfig,
    query: &Message,
    raw: &[u8],
    source_ip: IpAddr,
) -> Result<Vec<Vec<u8>>, AuthError> {
    if !zone_config.ip_allowed(source_ip) {
        return Err(AuthError::Refused);
    }
    let signer = verify_tsig_on_query(query, raw, zone_config)?;

    let apex = zone.origin.as_ref().ok_or(AuthError::ZoneHasNoApex)?;
    let soa_rec = zone
        .records
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .ok_or(AuthError::ZoneHasNoSoa)?
        .clone();

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

    let id = query.header.id;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut frames = Vec::new();

    frames.push(make_axfr_frame(
        &build_axfr_message(id, apex, vec![soa_rec.clone()], Rcode::NoError),
        signer.as_ref(),
        now,
    )?);

    for chunk in body.chunks(50) {
        frames.push(make_axfr_frame(
            &build_axfr_message(id, apex, chunk.to_vec(), Rcode::NoError),
            signer.as_ref(),
            now,
        )?);
    }

    frames.push(make_axfr_frame(
        &build_axfr_message(id, apex, vec![soa_rec], Rcode::NoError),
        signer.as_ref(),
        now,
    )?);

    Ok(frames)
}

/// Serialises `msg`, optionally TSIG-signs it, and returns a 2-byte-length-prefixed frame.
fn make_axfr_frame(
    msg: &Message,
    signer: Option<&TsigSigner>,
    now: u64,
) -> Result<Vec<u8>, AuthError> {
    let mut ser = Serialiser::new(true);
    ser.write_message(msg)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();

    if let Some(sig) = signer {
        let tsig_rec = sig.sign(&wire, now);
        tsig_rec.write_to(&mut wire);
        let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_add(1);
        wire[10] = (ar >> 8) as u8;
        wire[11] = (ar & 0xFF) as u8;
    }

    if wire.len() > MAX_MSG_BYTES {
        return Err(AuthError::Serialise(
            "AXFR message exceeds 65000 bytes".to_owned(),
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (wire.len() as u16).to_be_bytes();
    let mut frame = Vec::with_capacity(2 + wire.len());
    frame.extend_from_slice(&len_bytes);
    frame.extend_from_slice(&wire);
    Ok(frame)
}

// ── TSIG helpers ──────────────────────────────────────────────────────────────

/// If the zone config has a TSIG key, verify that the query is signed with it.
/// Returns the `TsigSigner` for signing outbound messages, or `None` if no TSIG.
///
/// `raw` must be the original wire bytes of the received query (with the TSIG
/// record still present in the additional section).  TSIG MAC verification MUST
/// use the original bytes, not a re-serialized representation, because even
/// semantically equivalent re-encodings differ byte-for-byte from the signed data.
fn verify_tsig_on_query(
    query: &Message,
    raw: &[u8],
    zone_config: &ZoneConfig,
) -> Result<Option<TsigSigner>, AuthError> {
    use std::str::FromStr;

    // PROTO-048: zone transfers MUST be authenticated.  Refuse unauthenticated
    // AXFR when no TSIG key is configured on this zone.
    let Some(tsig_cfg) = &zone_config.tsig_key else {
        return Err(AuthError::Refused);
    };

    let key_name =
        heimdall_core::Name::from_str(&tsig_cfg.key_name).map_err(|_| AuthError::InvalidTsigKey)?;
    let signer = TsigSigner::new(key_name, tsig_cfg.algorithm, &tsig_cfg.secret, 300);

    // Find the TSIG record in the query's additional section.
    // Rtype::Tsig is the distinct variant for TYPE 250 (not Rtype::Unknown(250)).
    let tsig_rr = query
        .additional
        .iter()
        .find(|r| r.rtype == heimdall_core::record::Rtype::Tsig);

    // No TSIG RR present: reject as unauthenticated (REFUSED).
    let tsig_rr = tsig_rr.ok_or(AuthError::Refused)?;

    // TSIG RR present but RDATA is malformed: reject with FORMERR (RFC 8945 §4.5.1).
    let tsig_rec = if let heimdall_core::rdata::RData::Unknown { data, .. } = &tsig_rr.rdata {
        TsigRecord::parse_rdata(tsig_rr.name.clone(), data).map_err(|_| AuthError::FormErr)?
    } else {
        return Err(AuthError::FormErr);
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Verify against the original wire bytes so the HMAC is checked over exactly
    // the bytes the client signed, not over a re-serialized representation.
    signer
        .verify(raw, &tsig_rec, now)
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

    use heimdall_core::{
        name::Name,
        zone::{ZoneFile, ZoneLimits},
    };

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

        let result = send_axfr(&zone, &cfg, &query, &[], source_ip, &mut stream).await;
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
