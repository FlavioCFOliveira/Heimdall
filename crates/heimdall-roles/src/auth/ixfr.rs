// SPDX-License-Identifier: MIT

//! IXFR outbound — incremental zone transfer server (RFC 1995) — task #300.
//!
//! Serves incremental zone deltas to authorised secondaries over TCP.  Falls
//! back to a full AXFR-format response when the journal gap is too large or
//! the requested serial is not present (`PROTO-037`).

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use heimdall_core::TsigSigner;
use heimdall_core::header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::record::{Record, Rtype};
use heimdall_core::serialiser::Serialiser;
use heimdall_core::zone::ZoneFile;
use tokio::io::AsyncWriteExt;

use crate::auth::AuthError;
use crate::auth::zone_role::ZoneConfig;

/// A single serial transition in the IXFR journal.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// The previous (old) SOA serial.
    pub from_serial: u32,
    /// The new SOA serial after this transition.
    pub to_serial: u32,
    /// Records deleted in this transition.
    pub deleted: Vec<Record>,
    /// Records added in this transition.
    pub added: Vec<Record>,
}

/// Serves an IXFR response over `stream` (RFC 1995, `PROTO-037`).
///
/// ## Flow
///
/// 1. Extract client serial from the authority SOA in `query`.
/// 2. If client serial >= current zone serial → send empty response (no change).
/// 3. If `journal` has a complete chain → send condensed IXFR deltas.
/// 4. If journal gap → fall back to AXFR format.
/// 5. TSIG-sign each message if configured.
///
/// # Errors
///
/// Returns [`AuthError::Refused`] on TSIG/ACL failure,
/// or [`AuthError::Io`] / [`AuthError::Serialise`] on stream errors.
pub async fn send_ixfr<S>(
    zone: &ZoneFile,
    zone_config: &ZoneConfig,
    query: &Message,
    journal: &[JournalEntry],
    source_ip: IpAddr,
    stream: &mut S,
) -> Result<(), AuthError>
where
    S: AsyncWriteExt + Unpin,
{
    // ── IP ACL check ──────────────────────────────────────────────────────────
    if !zone_config.ip_allowed(source_ip) {
        return Err(AuthError::Refused);
    }

    // ── TSIG check ────────────────────────────────────────────────────────────
    let signer = require_tsig_signer(zone_config)?;

    // ── Extract zone SOA ──────────────────────────────────────────────────────
    let apex = zone.origin.as_ref().ok_or(AuthError::ZoneHasNoApex)?;
    let soa_rec = zone
        .records
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .ok_or(AuthError::ZoneHasNoSoa)?
        .clone();

    let current_serial = soa_serial(&soa_rec);

    // ── Extract client serial from authority section ───────────────────────────
    let client_serial = extract_client_serial(query);

    // ── RFC 1982 serial comparison: nothing to do ─────────────────────────────
    if let Some(cs) = client_serial {
        if serial_ge(cs, current_serial) {
            // Client is up to date — send empty IXFR response (just the SOA).
            let msg = build_ixfr_message(query.header.id, apex, vec![soa_rec]);
            write_dns_tcp_msg(stream, &msg, signer.as_ref()).await?;
            return Ok(());
        }

        // Check whether the journal covers the gap.
        if has_complete_chain(journal, cs, current_serial) {
            return send_ixfr_deltas(
                stream,
                query.header.id,
                apex,
                &soa_rec,
                journal,
                cs,
                current_serial,
                signer.as_ref(),
            )
            .await;
        }
    }

    // ── Fallback: AXFR format inside IXFR envelope ───────────────────────────
    send_axfr_fallback(
        stream,
        zone,
        query.header.id,
        apex,
        &soa_rec,
        signer.as_ref(),
    )
    .await
}

// ── Serial helpers (RFC 1982) ─────────────────────────────────────────────────

/// Returns `true` if `a >= b` in RFC 1982 serial arithmetic.
fn serial_ge(a: u32, b: u32) -> bool {
    a == b || serial_gt(a, b)
}

/// Returns `true` if `a > b` in RFC 1982 serial arithmetic.
fn serial_gt(a: u32, b: u32) -> bool {
    let half: u32 = 1u32 << 31;
    (a != b) && ((a < b && b.wrapping_sub(a) > half) || (a > b && a.wrapping_sub(b) < half))
}

fn soa_serial(rec: &Record) -> u32 {
    if let heimdall_core::rdata::RData::Soa { serial, .. } = &rec.rdata {
        *serial
    } else {
        0
    }
}

fn extract_client_serial(msg: &Message) -> Option<u32> {
    msg.authority
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .and_then(|r| {
            if let heimdall_core::rdata::RData::Soa { serial, .. } = &r.rdata {
                Some(*serial)
            } else {
                None
            }
        })
}

fn has_complete_chain(journal: &[JournalEntry], from: u32, to: u32) -> bool {
    if from == to {
        return true;
    }
    // Walk the journal looking for a continuous chain from `from` to `to`.
    let mut current = from;
    loop {
        if let Some(entry) = journal.iter().find(|e| e.from_serial == current) {
            current = entry.to_serial;
            if current == to {
                return true;
            }
        } else {
            return false;
        }
        if current == from {
            // Cycle guard.
            return false;
        }
    }
}

// ── Delta streaming ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn send_ixfr_deltas<S>(
    stream: &mut S,
    id: u16,
    apex: &Name,
    current_soa: &Record,
    journal: &[JournalEntry],
    from_serial: u32,
    to_serial: u32,
    signer: Option<&TsigSigner>,
) -> Result<(), AuthError>
where
    S: AsyncWriteExt + Unpin,
{
    // RFC 1995 §4: current SOA → (old SOA, deleted, new SOA, added) × N transitions
    let header_msg = build_ixfr_message(id, apex, vec![current_soa.clone()]);
    write_dns_tcp_msg(stream, &header_msg, signer).await?;

    // Collect the ordered chain of transitions.
    let mut transitions: Vec<&JournalEntry> = Vec::new();
    let mut current = from_serial;
    while let Some(entry) = journal.iter().find(|e| e.from_serial == current) {
        transitions.push(entry);
        current = entry.to_serial;
        if current == to_serial {
            break;
        }
    }

    for entry in transitions {
        // Build a fake old-SOA record with the old serial.
        let old_soa = make_soa_with_serial(current_soa, entry.from_serial);
        let new_soa = make_soa_with_serial(current_soa, entry.to_serial);

        // old_soa + deleted records.
        let mut del_recs = vec![old_soa];
        del_recs.extend_from_slice(&entry.deleted);
        let del_msg = build_ixfr_message(id, apex, del_recs);
        write_dns_tcp_msg(stream, &del_msg, signer).await?;

        // new_soa + added records.
        let mut add_recs = vec![new_soa];
        add_recs.extend_from_slice(&entry.added);
        let add_msg = build_ixfr_message(id, apex, add_recs);
        write_dns_tcp_msg(stream, &add_msg, signer).await?;
    }

    // Closing SOA.
    let closing = build_ixfr_message(id, apex, vec![current_soa.clone()]);
    write_dns_tcp_msg(stream, &closing, signer).await?;

    Ok(())
}

/// Fall back to a full AXFR response within the IXFR envelope.
async fn send_axfr_fallback<S>(
    stream: &mut S,
    zone: &ZoneFile,
    id: u16,
    apex: &Name,
    soa_rec: &Record,
    signer: Option<&TsigSigner>,
) -> Result<(), AuthError>
where
    S: AsyncWriteExt + Unpin,
{
    // First SOA.
    write_dns_tcp_msg(
        stream,
        &build_ixfr_message(id, apex, vec![soa_rec.clone()]),
        signer,
    )
    .await?;

    // All non-SOA records.
    let body: Vec<_> = zone
        .records
        .iter()
        .filter(|r| r.rtype != Rtype::Soa)
        .cloned()
        .collect();
    for chunk in body.chunks(50) {
        let msg = build_ixfr_message(id, apex, chunk.to_vec());
        write_dns_tcp_msg(stream, &msg, signer).await?;
    }

    // Final SOA.
    write_dns_tcp_msg(
        stream,
        &build_ixfr_message(id, apex, vec![soa_rec.clone()]),
        signer,
    )
    .await?;

    Ok(())
}

// ── Message / wire helpers ────────────────────────────────────────────────────

fn make_soa_with_serial(template: &Record, serial: u32) -> Record {
    let rdata = if let heimdall_core::rdata::RData::Soa {
        ref mname,
        ref rname,
        refresh,
        retry,
        expire,
        minimum,
        ..
    } = template.rdata
    {
        heimdall_core::rdata::RData::Soa {
            mname: mname.clone(),
            rname: rname.clone(),
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    } else {
        template.rdata.clone()
    };
    Record {
        rdata,
        ..template.clone()
    }
}

fn build_ixfr_message(id: u16, apex: &Name, records: Vec<Record>) -> Message {
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
    header.set_rcode(Rcode::NoError);

    Message {
        header,
        questions: vec![Question {
            qname: apex.clone(),
            qtype: Qtype::Ixfr,
            qclass: Qclass::In,
        }],
        answers: records,
        authority: vec![],
        additional: vec![],
    }
}

fn require_tsig_signer(zone_config: &ZoneConfig) -> Result<Option<TsigSigner>, AuthError> {
    use std::str::FromStr;

    // PROTO-048: zone transfers MUST be authenticated.  Refuse unauthenticated
    // IXFR when no TSIG key is configured on this zone.
    let Some(tsig_cfg) = &zone_config.tsig_key else {
        return Err(AuthError::Refused);
    };
    let key_name =
        heimdall_core::Name::from_str(&tsig_cfg.key_name).map_err(|_| AuthError::InvalidTsigKey)?;
    Ok(Some(TsigSigner::new(
        key_name,
        tsig_cfg.algorithm,
        &tsig_cfg.secret,
        300,
    )))
}

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

    if let Some(sig) = signer {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let tsig_rec = sig.sign(&wire, now);
        tsig_rec.write_to(&mut wire);
        let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_add(1);
        wire[10] = (ar >> 8) as u8;
        wire[11] = (ar & 0xFF) as u8;
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

// ── Synchronous frame builder ─────────────────────────────────────────────────

/// Builds the IXFR response as a list of pre-framed wire messages
/// (each entry includes the 2-byte TCP length prefix).
///
/// Follows the same flow as [`send_ixfr`]:
/// - Client serial >= current → single SOA frame (client up to date).
/// - Journal has a complete chain → incremental delta frames.
/// - Otherwise → AXFR-format fallback.
///
/// # Errors
///
/// - [`AuthError::Refused`] — IP not in ACL or TSIG not configured.
/// - [`AuthError::ZoneHasNoApex`] / [`AuthError::ZoneHasNoSoa`] — zone incomplete.
/// - [`AuthError::Serialise`] — message serialisation failure.
pub fn build_ixfr_frames(
    zone: &ZoneFile,
    zone_config: &ZoneConfig,
    query: &Message,
    _raw: &[u8],
    journal: &[JournalEntry],
    source_ip: IpAddr,
) -> Result<Vec<Vec<u8>>, AuthError> {
    if !zone_config.ip_allowed(source_ip) {
        return Err(AuthError::Refused);
    }
    let signer = require_tsig_signer(zone_config)?;

    let apex = zone.origin.as_ref().ok_or(AuthError::ZoneHasNoApex)?;
    let soa_rec = zone
        .records
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .ok_or(AuthError::ZoneHasNoSoa)?
        .clone();
    let current_serial = soa_serial(&soa_rec);
    let client_serial = extract_client_serial(query);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if let Some(cs) = client_serial {
        if serial_ge(cs, current_serial) {
            let msg = build_ixfr_message(query.header.id, apex, vec![soa_rec]);
            return Ok(vec![make_ixfr_frame(&msg, signer.as_ref(), now)?]);
        }

        if has_complete_chain(journal, cs, current_serial) {
            return build_ixfr_delta_frames(
                query.header.id,
                apex,
                &soa_rec,
                journal,
                cs,
                current_serial,
                signer.as_ref(),
                now,
            );
        }
    }

    build_ixfr_axfr_fallback_frames(zone, query.header.id, apex, &soa_rec, signer.as_ref(), now)
}

#[allow(clippy::too_many_arguments)]
fn build_ixfr_delta_frames(
    id: u16,
    apex: &heimdall_core::name::Name,
    current_soa: &Record,
    journal: &[JournalEntry],
    from_serial: u32,
    to_serial: u32,
    signer: Option<&TsigSigner>,
    now: u64,
) -> Result<Vec<Vec<u8>>, AuthError> {
    let mut frames = Vec::new();

    let header_msg = build_ixfr_message(id, apex, vec![current_soa.clone()]);
    frames.push(make_ixfr_frame(&header_msg, signer, now)?);

    let mut transitions: Vec<&JournalEntry> = Vec::new();
    let mut current = from_serial;
    while let Some(entry) = journal.iter().find(|e| e.from_serial == current) {
        transitions.push(entry);
        current = entry.to_serial;
        if current == to_serial {
            break;
        }
    }

    for entry in transitions {
        let old_soa = make_soa_with_serial(current_soa, entry.from_serial);
        let new_soa = make_soa_with_serial(current_soa, entry.to_serial);

        let mut del_recs = vec![old_soa];
        del_recs.extend_from_slice(&entry.deleted);
        frames.push(make_ixfr_frame(&build_ixfr_message(id, apex, del_recs), signer, now)?);

        let mut add_recs = vec![new_soa];
        add_recs.extend_from_slice(&entry.added);
        frames.push(make_ixfr_frame(&build_ixfr_message(id, apex, add_recs), signer, now)?);
    }

    let closing = build_ixfr_message(id, apex, vec![current_soa.clone()]);
    frames.push(make_ixfr_frame(&closing, signer, now)?);
    Ok(frames)
}

fn build_ixfr_axfr_fallback_frames(
    zone: &ZoneFile,
    id: u16,
    apex: &heimdall_core::name::Name,
    soa_rec: &Record,
    signer: Option<&TsigSigner>,
    now: u64,
) -> Result<Vec<Vec<u8>>, AuthError> {
    let mut frames = Vec::new();

    frames.push(make_ixfr_frame(
        &build_ixfr_message(id, apex, vec![soa_rec.clone()]),
        signer,
        now,
    )?);

    let body: Vec<_> = zone
        .records
        .iter()
        .filter(|r| r.rtype != Rtype::Soa)
        .cloned()
        .collect();
    for chunk in body.chunks(50) {
        frames.push(make_ixfr_frame(
            &build_ixfr_message(id, apex, chunk.to_vec()),
            signer,
            now,
        )?);
    }

    frames.push(make_ixfr_frame(
        &build_ixfr_message(id, apex, vec![soa_rec.clone()]),
        signer,
        now,
    )?);
    Ok(frames)
}

fn make_ixfr_frame(
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

    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (wire.len() as u16).to_be_bytes();
    let mut frame = Vec::with_capacity(2 + wire.len());
    frame.extend_from_slice(&len_bytes);
    frame.extend_from_slice(&wire);
    Ok(frame)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn serial_ge_basic() {
        assert!(serial_ge(5, 5));
        assert!(serial_ge(6, 5));
        assert!(!serial_ge(4, 5));
    }

    #[test]
    fn serial_gt_wraparound() {
        // RFC 1982: 0xFFFF_FFFE < 1 (wraps)
        assert!(serial_gt(1, 0xFFFF_FFFE));
        assert!(!serial_gt(0xFFFF_FFFE, 1));
    }

    #[test]
    fn has_complete_chain_single_hop() {
        let entries = vec![JournalEntry {
            from_serial: 1,
            to_serial: 2,
            deleted: vec![],
            added: vec![],
        }];
        assert!(has_complete_chain(&entries, 1, 2));
        assert!(!has_complete_chain(&entries, 1, 3));
    }

    #[test]
    fn has_complete_chain_multi_hop() {
        let entries = vec![
            JournalEntry {
                from_serial: 1,
                to_serial: 2,
                deleted: vec![],
                added: vec![],
            },
            JournalEntry {
                from_serial: 2,
                to_serial: 3,
                deleted: vec![],
                added: vec![],
            },
        ];
        assert!(has_complete_chain(&entries, 1, 3));
    }

    #[test]
    fn has_complete_chain_same_serial() {
        // Client is already current.
        assert!(has_complete_chain(&[], 5, 5));
    }
}
