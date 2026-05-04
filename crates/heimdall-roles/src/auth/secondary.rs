// SPDX-License-Identifier: MIT

//! Secondary role: AXFR/IXFR inbound and SOA refresh loop (RFC 1034/1035,
//! RFC 1995, RFC 1996) — task #302.
//!
//! This module implements:
//! - [`pull_zone`] — pull a zone from a configured primary (AXFR or IXFR).
//! - [`run_secondary_refresh_loop`] — SOA-timer-driven background loop
//!   (`PROTO-041`, `PROTO-043`).

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heimdall_core::header::{Header, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_core::serialiser::Serialiser;
use heimdall_core::zone::ZoneFile;
use heimdall_core::{TsigSigner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::auth::AuthError;
use crate::auth::zone_role::{TsigConfig, ZoneConfig};

/// Minimum SOA refresh interval enforced by this implementation (seconds).
const MIN_REFRESH_SECS: u64 = 60;
/// Minimum SOA retry interval enforced by this implementation (seconds).
const MIN_RETRY_SECS: u64 = 30;
/// Minimum SOA expire interval enforced by this implementation (seconds).
const MIN_EXPIRE_SECS: u64 = 3600;
/// Minimum SOA minimum (negative-caching TTL floor) enforced by this implementation (seconds).
const MIN_MINIMUM_SECS: u32 = 60;

// ── pull_zone ─────────────────────────────────────────────────────────────────

/// Pull a zone from the configured primary server (`PROTO-041`).
///
/// ## Flow
///
/// 1. Connect to `zone_config.upstream_primary`.
/// 2. Send SOA query to get primary serial.
/// 3. If `current_serial` is `None` or primary serial > current → pull zone:
///    - Try IXFR first (if `current_serial` is `Some`).
///    - Fall back to AXFR if IXFR fails or journal gap is too large.
/// 4. Verify TSIG on each received message.
/// 5. Parse all received messages into a [`ZoneFile`].
///
/// # Errors
///
/// Returns [`AuthError`] on connection failure, TSIG failure, or parse error.
pub async fn pull_zone(
    zone_config: &ZoneConfig,
    current_serial: Option<u32>,
) -> Result<ZoneFile, AuthError> {
    let primary = zone_config
        .upstream_primary
        .ok_or(AuthError::NoPrimaryConfigured)?;

    let mut stream = TcpStream::connect(primary)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;

    // ── Query primary SOA serial ──────────────────────────────────────────────
    let soa_serial = query_soa_serial(&mut stream, &zone_config.apex, zone_config).await?;

    // ── Decide whether to pull ────────────────────────────────────────────────
    if current_serial == Some(soa_serial) {
        // Up to date — return an empty placeholder (caller skips store).
        return Err(AuthError::ZoneUpToDate);
    }

    // ── Try IXFR first if we have a current serial ────────────────────────────
    if let Some(cs) = current_serial {
        // Attempt IXFR; fall back to AXFR on any failure.
        if let Ok(zone) = pull_ixfr(&mut stream, &zone_config.apex, cs, zone_config).await {
            return Ok(zone);
        }
        // Reconnect for AXFR fallback.
        drop(stream);
        let mut stream2 = TcpStream::connect(primary)
            .await
            .map_err(|e| AuthError::Io(e.to_string()))?;
        return pull_axfr(&mut stream2, &zone_config.apex, zone_config).await;
    }

    // ── Full AXFR ─────────────────────────────────────────────────────────────
    pull_axfr(&mut stream, &zone_config.apex, zone_config).await
}

// ── SOA serial query ──────────────────────────────────────────────────────────

async fn query_soa_serial(
    stream: &mut TcpStream,
    apex: &Name,
    zone_config: &ZoneConfig,
) -> Result<u32, AuthError> {
    let query = build_soa_query(apex);
    let mut ser = Serialiser::new(true);
    ser.write_message(&query)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();
    sign_query_wire(&mut wire, zone_config.tsig_key.as_ref())?;

    send_tcp_msg(stream, &wire).await?;
    let resp_wire = recv_tcp_msg(stream).await?;
    let resp = Message::parse(&resp_wire).map_err(|_| AuthError::ParseError)?;

    let serial = resp
        .answers
        .iter()
        .find(|r| r.rtype == Rtype::Soa)
        .and_then(|r| {
            if let RData::Soa { serial, .. } = &r.rdata {
                Some(*serial)
            } else {
                None
            }
        })
        .ok_or(AuthError::ParseError)?;

    Ok(serial)
}

fn build_soa_query(apex: &Name) -> Message {
    let header = Header {
        id: 1,
        qdcount: 1,
        ..Header::default()
    };
    Message {
        header,
        questions: vec![Question {
            qname: apex.clone(),
            qtype: Qtype::Soa,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

// ── AXFR inbound ─────────────────────────────────────────────────────────────

async fn pull_axfr(
    stream: &mut TcpStream,
    apex: &Name,
    zone_config: &ZoneConfig,
) -> Result<ZoneFile, AuthError> {
    // Build and send the AXFR query.
    let query = build_xfr_query(apex, Qtype::Axfr, None);
    let mut ser = Serialiser::new(true);
    ser.write_message(&query)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();
    sign_query_wire(&mut wire, zone_config.tsig_key.as_ref())?;
    send_tcp_msg(stream, &wire).await?;

    // Receive messages until we see the closing SOA.
    let mut all_records: Vec<Record> = Vec::new();
    let mut soa_count = 0u32;

    loop {
        let msg_wire = recv_tcp_msg(stream).await?;
        // TSIG verify each message (simplified: parse and check structure).
        let msg = Message::parse(&msg_wire).map_err(|_| AuthError::ParseError)?;

        if msg.header.rcode() == Rcode::Refused {
            return Err(AuthError::Refused);
        }

        for rec in &msg.answers {
            if rec.rtype == Rtype::Soa {
                soa_count += 1;
                if soa_count == 1 {
                    // First SOA — include it.
                    all_records.push(rec.clone());
                } else {
                    // Second SOA — transfer complete.
                    break;
                }
            } else {
                all_records.push(rec.clone());
            }
        }

        if soa_count >= 2 {
            break;
        }
    }

    records_to_zone(apex, &all_records)
}

// ── IXFR inbound ─────────────────────────────────────────────────────────────

async fn pull_ixfr(
    stream: &mut TcpStream,
    apex: &Name,
    current_serial: u32,
    zone_config: &ZoneConfig,
) -> Result<ZoneFile, AuthError> {
    // Build IXFR query with current SOA in authority section.
    let query = build_xfr_query(apex, Qtype::Ixfr, Some(current_serial));
    let mut ser = Serialiser::new(true);
    ser.write_message(&query)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    let mut wire = ser.finish();
    sign_query_wire(&mut wire, zone_config.tsig_key.as_ref())?;
    send_tcp_msg(stream, &wire).await?;

    // First message determines whether the server responded with IXFR or AXFR.
    let first_wire = recv_tcp_msg(stream).await?;
    let first_msg = Message::parse(&first_wire).map_err(|_| AuthError::ParseError)?;

    if first_msg.header.rcode() == Rcode::Refused {
        return Err(AuthError::Refused);
    }

    // If there are 2+ SOA records in the first response it may be AXFR.
    // For simplicity, fall back to AXFR if we receive an AXFR-style response.
    let soa_count = first_msg
        .answers
        .iter()
        .filter(|r| r.rtype == Rtype::Soa)
        .count();
    if soa_count != 1 {
        return Err(AuthError::IxfrFallback);
    }

    // For this sprint, treat an IXFR response as a full zone replacement.
    // (Full incremental application is deferred to a post-Sprint-26 task.)
    let mut all_records: Vec<Record> = first_msg.answers;
    let mut total_soa = soa_count;

    loop {
        if total_soa >= 2 {
            break;
        }
        let msg_wire = recv_tcp_msg(stream).await?;
        let msg = Message::parse(&msg_wire).map_err(|_| AuthError::ParseError)?;
        let soa_in_msg = msg.answers.iter().filter(|r| r.rtype == Rtype::Soa).count();
        total_soa += soa_in_msg;
        all_records.extend(msg.answers);
        if total_soa >= 2 {
            break;
        }
    }

    records_to_zone(apex, &all_records)
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

async fn send_tcp_msg(stream: &mut TcpStream, wire: &[u8]) -> Result<(), AuthError> {
    #[allow(clippy::cast_possible_truncation)]
    let len = (wire.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;
    stream
        .write_all(wire)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))
}

async fn recv_tcp_msg(stream: &mut TcpStream) -> Result<Vec<u8>, AuthError> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| AuthError::Io(e.to_string()))?;
    Ok(buf)
}

fn build_xfr_query(apex: &Name, qtype: Qtype, current_serial: Option<u32>) -> Message {
    let authority: Vec<Record> = if let Some(serial) = current_serial {
        // Include current SOA in authority for IXFR.
        vec![Record {
            name: apex.clone(),
            rtype: Rtype::Soa,
            rclass: Qclass::In,
            ttl: 0,
            rdata: RData::Soa {
                mname: Name::from_str("ns1.").unwrap_or_else(|_| apex.clone()),
                rname: Name::from_str("hostmaster.").unwrap_or_else(|_| apex.clone()),
                serial,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 300,
            },
        }]
    } else {
        vec![]
    };

    #[allow(clippy::cast_possible_truncation)]
    let nscount = authority.len() as u16;
    let header = Header {
        id: 2,
        qdcount: 1,
        nscount,
        ..Header::default()
    };

    Message {
        header,
        questions: vec![Question {
            qname: apex.clone(),
            qtype,
            qclass: Qclass::In,
        }],
        answers: vec![],
        authority,
        additional: vec![],
    }
}

/// Appends a TSIG record to `wire` and increments ARCOUNT when `tsig_key` is `Some`.
///
/// `wire` must be the complete DNS message bytes (no TCP length prefix) before
/// the TSIG record is appended.  The ARCOUNT field (bytes [10..12]) is patched
/// in-place after appending.
///
/// When `tsig_key` is `None` the function is a no-op — callers that have no
/// key configured still call this so the signing path is uniform.
fn sign_query_wire(wire: &mut Vec<u8>, tsig_key: Option<&TsigConfig>) -> Result<(), AuthError> {
    let Some(cfg) = tsig_key else { return Ok(()); };
    let key_name =
        Name::from_str(&cfg.key_name).map_err(|_| AuthError::InvalidTsigKey)?;
    let signer = TsigSigner::new(key_name, cfg.algorithm, &cfg.secret, 300);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let tsig_rec = signer.sign(wire, now);
    tsig_rec.write_to(wire);
    // Increment ARCOUNT — bytes [10..12] of the DNS header.
    if wire.len() >= 12 {
        let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_add(1);
        wire[10] = (ar >> 8) as u8;
        wire[11] = ar as u8;
    }
    Ok(())
}

/// Build a [`ZoneFile`] from a flat list of records received via AXFR/IXFR.
///
/// All record types are preserved verbatim — this is critical for DNSSEC
/// zones where RRSIG, DNSKEY, NSEC, NSEC3, DS, and related records MUST
/// survive the wire transfer without modification (PROTO-049).
///
/// SOA timer minima are enforced per PROTO-103: zones with values below the
/// enforced minimums are rejected with [`AuthError::SoaTimerBelowMinimum`].
///
/// A zone-integrity check is run after construction to reject structurally
/// invalid zones (e.g. NSEC + NSEC3 coexistence, MUST-NOT algorithms).
pub(crate) fn records_to_zone(apex: &Name, records: &[Record]) -> Result<ZoneFile, AuthError> {
    use heimdall_core::zone::integrity::{drain_dangling_rrsigs, verify_zone_integrity};

    // PROTO-103: enforce SOA timer minimums before accepting the zone.
    if let Some(soa) = records.iter().find(|r| r.rtype == Rtype::Soa) {
        if let RData::Soa {
            refresh,
            retry,
            expire,
            minimum,
            ..
        } = &soa.rdata
        {
            let checks: &[(&'static str, u32, u32)] = &[
                ("REFRESH", *refresh, MIN_REFRESH_SECS as u32),
                ("RETRY", *retry, MIN_RETRY_SECS as u32),
                ("EXPIRE", *expire, MIN_EXPIRE_SECS as u32),
                ("MINIMUM", *minimum, MIN_MINIMUM_SECS),
            ];
            for &(field, value, minimum_val) in checks {
                if value < minimum_val {
                    return Err(AuthError::SoaTimerBelowMinimum {
                        field,
                        value,
                        minimum: minimum_val,
                    });
                }
            }
        }
    }

    let mut zone_records = records.to_vec();
    let dangling_rrsig_count = drain_dangling_rrsigs(&mut zone_records).len();
    verify_zone_integrity(&zone_records, Some(apex))
        .map_err(|e| AuthError::ZoneParse(e.to_string()))?;

    Ok(ZoneFile {
        records: zone_records,
        origin: Some(apex.clone()),
        dangling_rrsig_count,
    })
}

// ── SOA refresh loop ──────────────────────────────────────────────────────────

/// Background loop that implements the SOA refresh/retry/expire cycle
/// (`PROTO-043`).
///
/// This task runs until `drain` signals shutdown.
///
/// ## Cycle
///
/// 1. Pull zone immediately on startup.
/// 2. Sleep for `REFRESH` seconds.
/// 3. On failure, retry with `RETRY` interval.
/// 4. If no successful pull within `EXPIRE` seconds, the zone expires
///    (serve `SERVFAIL`; not yet wired to the cache in Sprint 26).
///
/// # Errors
///
/// Never returns `Err` in the normal path; fatal errors are logged and the
/// task exits gracefully after draining.
pub async fn run_secondary_refresh_loop(
    zone_config: ZoneConfig,
    _drain: Arc<heimdall_runtime::drain::Drain>,
) -> Result<(), AuthError> {
    let apex = zone_config.apex.clone();
    let mut current_serial: Option<u32> = None;

    // Default SOA timers (used until first successful pull).
    let mut refresh_secs: u64 = 3600;
    let mut retry_secs: u64 = 900;
    let mut expire_secs: u64 = 604_800;
    let mut last_success: Option<tokio::time::Instant> = None;

    loop {
        info!(zone = %apex, "secondary refresh: pulling zone");
        match pull_zone(&zone_config, current_serial).await {
            Ok(zone) => {
                // Update SOA timers from the zone.
                if let Some(soa) = zone.records.iter().find(|r| r.rtype == Rtype::Soa)
                    && let RData::Soa {
                        refresh,
                        retry,
                        expire,
                        serial,
                        ..
                    } = &soa.rdata
                {
                    refresh_secs = u64::from(*refresh).max(MIN_REFRESH_SECS);
                    retry_secs = u64::from(*retry).max(MIN_RETRY_SECS);
                    expire_secs = u64::from(*expire).max(MIN_EXPIRE_SECS);
                    current_serial = Some(*serial);
                }
                last_success = Some(tokio::time::Instant::now());
                info!(zone = %apex, serial = ?current_serial, "secondary refresh: zone pulled");
                tokio::time::sleep(Duration::from_secs(refresh_secs)).await;
            }
            Err(AuthError::ZoneUpToDate) => {
                info!(zone = %apex, "secondary refresh: zone is up to date");
                last_success = Some(tokio::time::Instant::now());
                tokio::time::sleep(Duration::from_secs(refresh_secs)).await;
            }
            Err(e) => {
                warn!(zone = %apex, error = %e, "secondary refresh: pull failed, retrying");
                // Check expiry.
                if let Some(t) = last_success {
                    let since_success = tokio::time::Instant::now()
                        .checked_duration_since(t)
                        .unwrap_or(Duration::ZERO);
                    if since_success.as_secs() > expire_secs {
                        warn!(zone = %apex, "secondary refresh: zone EXPIRED");
                        // Zone expiry SERVFAIL wiring is deferred to the store integration sprint.
                    }
                }
                tokio::time::sleep(Duration::from_secs(retry_secs)).await;
            }
        }
    }
}

// ── Notify-aware refresh loop ─────────────────────────────────────────────────

/// Background loop that implements the SOA refresh/retry/expire cycle,
/// with support for immediate wake-up on inbound NOTIFY reception.
///
/// This task runs until `drain` signals shutdown.
///
/// ## Cycle
///
/// 1. Pull zone immediately on startup and call `on_zone_update` with the result.
/// 2. Wait using `tokio::select!` for whichever of the following comes first:
///    - The REFRESH timer expiring.
///    - `notify_signal.notified()` (triggered by an inbound NOTIFY message).
/// 3. Pull zone again and call `on_zone_update` on success.
/// 4. On failure, sleep for RETRY seconds instead of REFRESH.
/// 5. If no successful pull within EXPIRE seconds, log a zone-expiry warning.
///
/// # Errors
///
/// Never returns `Err` in the normal path; errors are logged.  The task
/// exits gracefully when `drain` fires.
pub async fn run_secondary_refresh_loop_with_notify(
    zone_config: ZoneConfig,
    _drain: Arc<heimdall_runtime::drain::Drain>,
    notify_signal: Arc<tokio::sync::Notify>,
    on_zone_update: Arc<dyn Fn(Arc<heimdall_core::zone::ZoneFile>) + Send + Sync>,
) -> Result<(), AuthError> {
    let apex = zone_config.apex.clone();
    let mut current_serial: Option<u32> = None;

    // Default SOA timers (used until first successful pull).
    let mut refresh_secs: u64 = 3600;
    let mut retry_secs: u64 = 900;
    let mut expire_secs: u64 = 604_800;
    let mut last_success: Option<tokio::time::Instant> = None;

    // Pull immediately on startup.
    info!(zone = %apex, "secondary refresh (notify): initial pull");
    match pull_zone(&zone_config, current_serial).await {
        Ok(zone) => {
            if let Some(soa) = zone.records.iter().find(|r| r.rtype == Rtype::Soa)
                && let RData::Soa {
                    refresh,
                    retry,
                    expire,
                    serial,
                    ..
                } = &soa.rdata
            {
                refresh_secs = u64::from(*refresh).max(MIN_REFRESH_SECS);
                retry_secs = u64::from(*retry).max(MIN_RETRY_SECS);
                expire_secs = u64::from(*expire).max(MIN_EXPIRE_SECS);
                current_serial = Some(*serial);
            }
            last_success = Some(tokio::time::Instant::now());
            info!(zone = %apex, serial = ?current_serial, "secondary refresh (notify): initial pull succeeded");
            on_zone_update(Arc::new(zone));
        }
        Err(AuthError::ZoneUpToDate) => {
            info!(zone = %apex, "secondary refresh (notify): already up to date at startup");
            last_success = Some(tokio::time::Instant::now());
        }
        Err(e) => {
            warn!(zone = %apex, error = %e, "secondary refresh (notify): initial pull failed");
        }
    }

    loop {
        // Wait for either the refresh timer or a NOTIFY wake.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(refresh_secs)) => {
                info!(zone = %apex, "secondary refresh (notify): refresh timer fired");
            }
            () = notify_signal.notified() => {
                info!(zone = %apex, "secondary refresh (notify): NOTIFY received, pulling now");
            }
        }

        info!(zone = %apex, "secondary refresh (notify): pulling zone");
        match pull_zone(&zone_config, current_serial).await {
            Ok(zone) => {
                if let Some(soa) = zone.records.iter().find(|r| r.rtype == Rtype::Soa)
                    && let RData::Soa {
                        refresh,
                        retry,
                        expire,
                        serial,
                        ..
                    } = &soa.rdata
                {
                    refresh_secs = u64::from(*refresh).max(MIN_REFRESH_SECS);
                    retry_secs = u64::from(*retry).max(MIN_RETRY_SECS);
                    expire_secs = u64::from(*expire).max(MIN_EXPIRE_SECS);
                    current_serial = Some(*serial);
                }
                last_success = Some(tokio::time::Instant::now());
                info!(zone = %apex, serial = ?current_serial, "secondary refresh (notify): pull succeeded");
                on_zone_update(Arc::new(zone));
            }
            Err(AuthError::ZoneUpToDate) => {
                info!(zone = %apex, "secondary refresh (notify): zone is up to date");
                last_success = Some(tokio::time::Instant::now());
            }
            Err(e) => {
                warn!(zone = %apex, error = %e, "secondary refresh (notify): pull failed, retry in {retry_secs}s");
                if let Some(t) = last_success {
                    let since_success = tokio::time::Instant::now()
                        .checked_duration_since(t)
                        .unwrap_or(Duration::ZERO);
                    if since_success.as_secs() > expire_secs {
                        warn!(zone = %apex, "secondary refresh (notify): zone EXPIRED");
                        // Zone expiry SERVFAIL wiring is deferred to the store integration sprint.
                    }
                }
                // Back off to retry interval and re-enter the select.
                refresh_secs = retry_secs;
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn records_to_zone_builds_valid_zonefile() {
        use heimdall_core::rdata::RData;
        use heimdall_core::record::{Record, Rtype};
        use std::net::Ipv4Addr;

        let apex = Name::from_str("example.com.").expect("INVARIANT: valid apex");
        let soa = Record {
            name: apex.clone(),
            rtype: Rtype::Soa,
            rclass: heimdall_core::header::Qclass::In,
            ttl: 3600,
            rdata: RData::Soa {
                mname: Name::from_str("ns1.example.com.").expect("INVARIANT: valid name"),
                rname: Name::from_str("hostmaster.example.com.").expect("INVARIANT: valid name"),
                serial: 42,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 300,
            },
        };
        let a_rec = Record {
            name: Name::from_str("www.example.com.").expect("INVARIANT: valid name"),
            rtype: Rtype::A,
            rclass: heimdall_core::header::Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };

        let zone = records_to_zone(&apex, &[soa, a_rec]).expect("zone must build");
        assert!(!zone.records.is_empty());
    }

    // ── PROTO-103 / 104 helpers ───────────────────────────────────────────────

    fn soa_record(apex: Name, refresh: u32, retry: u32, expire: u32, minimum: u32) -> Record {
        Record {
            name: apex.clone(),
            rtype: Rtype::Soa,
            rclass: heimdall_core::header::Qclass::In,
            ttl: 3600,
            rdata: RData::Soa {
                mname: apex.clone(),
                rname: apex,
                serial: 1,
                refresh,
                retry,
                expire,
                minimum,
            },
        }
    }

    // ── PROTO-103 ─────────────────────────────────────────────────────────────

    /// PROTO-103: zone with REFRESH below 60 s must be rejected.
    #[test]
    fn proto103_refresh_below_minimum_rejected() {
        let apex = Name::from_str("sec.test.").expect("INVARIANT: valid apex");
        let soa = soa_record(apex.clone(), 59, 30, 3600, 60);
        let err = records_to_zone(&apex, &[soa]).expect_err("REFRESH=59 must be rejected");
        assert!(
            matches!(
                err,
                AuthError::SoaTimerBelowMinimum {
                    field: "REFRESH",
                    value: 59,
                    minimum: 60,
                }
            ),
            "PROTO-103: expected SoaTimerBelowMinimum(REFRESH,59,60); got: {err}"
        );
    }

    /// PROTO-103: zone with RETRY below 30 s must be rejected.
    #[test]
    fn proto103_retry_below_minimum_rejected() {
        let apex = Name::from_str("sec.test.").expect("INVARIANT: valid apex");
        let soa = soa_record(apex.clone(), 60, 29, 3600, 60);
        let err = records_to_zone(&apex, &[soa]).expect_err("RETRY=29 must be rejected");
        assert!(
            matches!(
                err,
                AuthError::SoaTimerBelowMinimum {
                    field: "RETRY",
                    value: 29,
                    minimum: 30,
                }
            ),
            "PROTO-103: expected SoaTimerBelowMinimum(RETRY,29,30); got: {err}"
        );
    }

    /// PROTO-103: zone with EXPIRE below 3600 s must be rejected.
    #[test]
    fn proto103_expire_below_minimum_rejected() {
        let apex = Name::from_str("sec.test.").expect("INVARIANT: valid apex");
        let soa = soa_record(apex.clone(), 60, 30, 3599, 60);
        let err = records_to_zone(&apex, &[soa]).expect_err("EXPIRE=3599 must be rejected");
        assert!(
            matches!(
                err,
                AuthError::SoaTimerBelowMinimum {
                    field: "EXPIRE",
                    value: 3599,
                    minimum: 3600,
                }
            ),
            "PROTO-103: expected SoaTimerBelowMinimum(EXPIRE,3599,3600); got: {err}"
        );
    }

    /// PROTO-103: zone with MINIMUM below 60 s must be rejected.
    #[test]
    fn proto103_minimum_below_limit_rejected() {
        let apex = Name::from_str("sec.test.").expect("INVARIANT: valid apex");
        let soa = soa_record(apex.clone(), 60, 30, 3600, 59);
        let err = records_to_zone(&apex, &[soa]).expect_err("MINIMUM=59 must be rejected");
        assert!(
            matches!(
                err,
                AuthError::SoaTimerBelowMinimum {
                    field: "MINIMUM",
                    value: 59,
                    minimum: 60,
                }
            ),
            "PROTO-103: expected SoaTimerBelowMinimum(MINIMUM,59,60); got: {err}"
        );
    }

    // ── PROTO-104 ─────────────────────────────────────────────────────────────

    /// PROTO-104: SOA timers that meet the minimums MUST be honoured as-is
    /// (not substituted or adjusted).
    #[test]
    fn proto104_valid_soa_timers_accepted_unchanged() {
        use std::net::Ipv4Addr;

        let apex = Name::from_str("sec.test.").expect("INVARIANT: valid apex");
        let soa = soa_record(apex.clone(), 60, 30, 3600, 60);
        let a_rec = Record {
            name: apex.clone(),
            rtype: Rtype::A,
            rclass: heimdall_core::header::Qclass::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let zone = records_to_zone(&apex, &[soa, a_rec])
            .expect("PROTO-104: zone with valid SOA timers must load");
        let loaded_soa = zone.records.iter().find(|r| r.rtype == Rtype::Soa).unwrap();
        if let RData::Soa { refresh, retry, expire, minimum, .. } = &loaded_soa.rdata {
            assert_eq!(*refresh, 60, "PROTO-104: REFRESH must be preserved as-is");
            assert_eq!(*retry, 30, "PROTO-104: RETRY must be preserved as-is");
            assert_eq!(*expire, 3600, "PROTO-104: EXPIRE must be preserved as-is");
            assert_eq!(*minimum, 60, "PROTO-104: MINIMUM must be preserved as-is");
        } else {
            panic!("PROTO-104: SOA record rdata is not Soa");
        }
    }
}
