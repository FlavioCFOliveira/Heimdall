// SPDX-License-Identifier: MIT

//! Authoritative server role for the Heimdall DNS server.
//!
//! This module provides the complete authoritative DNS server implementation:
//!
//! - **Query serving** ([`query`]) — RFC 1034/1035 standard query processing with
//!   CNAME/DNAME, DNSSEC pass-through, glue, and truncation.
//! - **AXFR outbound** ([`axfr`]) — RFC 5936 full zone transfer to secondaries.
//! - **IXFR outbound** ([`ixfr`]) — RFC 1995 incremental zone transfer.
//! - **NOTIFY outbound** ([`notify`]) — RFC 1996 change notification to secondaries.
//! - **Secondary inbound** ([`secondary`]) — AXFR/IXFR pull and SOA refresh loop.
//! - **UPDATE → NOTIMP** ([`update`]) — RFC 2136 UPDATE rejection (`PROTO-032..035`).
//! - **Zone lifecycle** ([`lifecycle`]) — add/remove/reload zones.
//! - **Zone role config** ([`zone_role`]) — per-zone primary/secondary configuration.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use arc_swap::ArcSwap;
use heimdall_core::header::{Opcode, Qtype, Rcode};
use heimdall_core::parser::Message;
use heimdall_core::serialiser::Serialiser;
use heimdall_core::zone::ZoneFile;
use heimdall_runtime::{QueryDispatcher, ZoneTransferHandler};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::warn;

pub mod axfr;
pub mod ixfr;
pub mod lifecycle;
pub mod notify;
pub mod query;
pub mod secondary;
pub mod update;
pub mod zone_role;

pub use lifecycle::ZoneLifecycle;
pub use zone_role::{TsigConfig, ZoneConfig, ZoneRole};

// ── AuthError ─────────────────────────────────────────────────────────────────

/// Errors produced by the authoritative server role.
#[derive(Debug)]
pub enum AuthError {
    /// The incoming DNS message carried no question.
    NoQuestion,
    /// The source IP is not in the configured ACL.
    Refused,
    /// TSIG signature verification failed.
    TsigVerifyFailed,
    /// TSIG key name is invalid or malformed.
    InvalidTsigKey,
    /// DNS message serialisation failure.
    Serialise(String),
    /// DNS message parse failure.
    ParseError,
    /// I/O error (network or file).
    Io(String),
    /// Zone file has no apex (`$ORIGIN`).
    ZoneHasNoApex,
    /// Zone file has no SOA record.
    ZoneHasNoSoa,
    /// Zone parse error.
    ZoneParse(String),
    /// Zone is already up to date (secondary pull returned no new data).
    ZoneUpToDate,
    /// No primary server configured for secondary pull.
    NoPrimaryConfigured,
    /// IXFR journal gap requires fallback to AXFR.
    IxfrFallback,
    /// NOTIFY failed after all retry attempts.
    NotifyFailed {
        /// The target address that could not be reached.
        target: std::net::SocketAddr,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoQuestion => write!(f, "DNS message has no question"),
            Self::Refused => write!(f, "request refused (ACL or TSIG failure)"),
            Self::TsigVerifyFailed => write!(f, "TSIG signature verification failed"),
            Self::InvalidTsigKey => write!(f, "invalid TSIG key name"),
            Self::Serialise(e) => write!(f, "serialisation error: {e}"),
            Self::ParseError => write!(f, "DNS message parse error"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ZoneHasNoApex => write!(f, "zone has no apex ($ORIGIN)"),
            Self::ZoneHasNoSoa => write!(f, "zone has no SOA record"),
            Self::ZoneParse(e) => write!(f, "zone parse error: {e}"),
            Self::ZoneUpToDate => write!(f, "zone is already up to date"),
            Self::NoPrimaryConfigured => {
                write!(f, "no upstream primary configured for secondary pull")
            }
            Self::IxfrFallback => write!(f, "IXFR requires AXFR fallback"),
            Self::NotifyFailed { target } => {
                write!(f, "NOTIFY to {target} failed after all retries")
            }
        }
    }
}

impl std::error::Error for AuthError {}

// ── AuthServer ────────────────────────────────────────────────────────────────

/// Authoritative DNS server.
///
/// Holds the per-zone configuration map (swappable at runtime via
/// [`arc_swap::ArcSwap`]) and routes incoming DNS messages to the appropriate
/// handler.
///
/// Zone data is stored in Redis (Sprint 18); `AuthServer` coordinates zone
/// operations by holding the per-zone config and delegating lookups to the
/// runtime store layer.
pub struct AuthServer {
    /// Per-zone configuration indexed by zone apex wire bytes (lower-cased).
    zones: ArcSwap<HashMap<Vec<u8>, ZoneConfig>>,
    /// Per-zone wakeup notify for triggering an immediate secondary refresh on
    /// inbound NOTIFY reception.  Only populated for `Secondary` / `Both` zones.
    ///
    /// Keyed by zone apex wire bytes (lower-cased), same as `zones`.
    notify_channels: std::sync::Mutex<HashMap<Vec<u8>, Arc<Notify>>>,
}

impl AuthServer {
    /// Creates a new [`AuthServer`] pre-populated with the given zones.
    #[must_use]
    pub fn new(zones: Vec<ZoneConfig>) -> Self {
        let map: HashMap<Vec<u8>, ZoneConfig> = zones
            .into_iter()
            .map(|cfg| (cfg.apex.as_wire_bytes().to_ascii_lowercase(), cfg))
            .collect();
        Self {
            zones: ArcSwap::new(Arc::new(map)),
            notify_channels: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Hot-swaps the zone configuration atomically.
    pub fn update_zones(&self, zones: Vec<ZoneConfig>) {
        let map: HashMap<Vec<u8>, ZoneConfig> = zones
            .into_iter()
            .map(|cfg| (cfg.apex.as_wire_bytes().to_ascii_lowercase(), cfg))
            .collect();
        self.zones.store(Arc::new(map));
    }

    /// Register a `tokio::sync::Notify` for a secondary zone so that inbound
    /// NOTIFY messages can wake the refresh loop immediately.
    ///
    /// `apex_wire` must be the zone apex as lower-cased wire bytes (as returned
    /// by `Name::as_wire_bytes().to_ascii_lowercase()`).
    pub fn register_notify_signal(&self, apex_wire: &[u8], signal: Arc<Notify>) {
        self.notify_channels
            .lock()
            .expect("INVARIANT: notify_channels mutex is not poisoned")
            .insert(apex_wire.to_vec(), signal);
    }

    /// Return the wakeup channel for `apex_wire`, if this zone is a secondary.
    #[must_use]
    pub fn notify_channel(&self, apex_wire: &[u8]) -> Option<Arc<Notify>> {
        self.notify_channels
            .lock()
            .expect("INVARIANT: notify_channels mutex is not poisoned")
            .get(apex_wire)
            .cloned()
    }

    /// Atomically replace the in-memory zone file for `apex_wire` with `new_zone`.
    ///
    /// Called by the secondary refresh loop after a successful AXFR/IXFR pull to
    /// make the new zone data visible to query serving.
    pub fn update_zone_file(&self, apex_wire: &[u8], new_zone: Arc<ZoneFile>) {
        let old = self.zones.load();
        let mut map = (**old).clone();
        if let Some(cfg) = map.get_mut(apex_wire) {
            cfg.zone_file = Some(new_zone);
        }
        self.zones.store(Arc::new(map));
    }

    /// Serves a single inbound DNS message.
    ///
    /// Returns the serialised response wire bytes.
    ///
    /// ## Routing
    ///
    /// - `Opcode::Update` → `NOTIMP` immediately (`PROTO-032..035`).
    /// - `Opcode::Notify` → ACKed for zones where this instance is `Secondary`
    ///   or `Both`; the associated refresh loop is woken via its notify channel.
    ///   Returns `REFUSED` for `Primary`-only zones (RFC 1996 §3.10).
    /// - `Opcode::Query` → dispatched to [`query::serve_query`] against the
    ///   matching zone.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Serialise`] if the response cannot be serialised
    /// (e.g. an impossible oversized message), or [`AuthError::NoQuestion`]
    /// if the message has no question (except for UPDATE, which is handled
    /// before question parsing).
    pub fn handle(&self, msg: &Message, _source_ip: IpAddr) -> Result<Vec<u8>, AuthError> {
        let opcode = msg.header.opcode();

        // RFC 2136 UPDATE → NOTIMP immediately (PROTO-033).
        if opcode == Opcode::Update {
            let resp = update::handle_update(msg);
            return serialise(&resp);
        }

        // Standard query: find the zone and serve.
        let q = msg.questions.first().ok_or(AuthError::NoQuestion)?;

        // Longest-suffix zone match.
        let zones_snap = self.zones.load();
        let zone_cfg = longest_suffix_match(&zones_snap, &q.qname);

        // Inbound NOTIFY (RFC 1996): ACK for secondary/both zones, REFUSED for primary-only.
        if opcode == Opcode::Notify {
            if let Some(cfg) = zone_cfg {
                if matches!(cfg.role, ZoneRole::Secondary | ZoneRole::Both) {
                    // Wake the secondary refresh loop for an immediate pull.
                    let apex_wire = cfg.apex.as_wire_bytes().to_ascii_lowercase();
                    if let Some(sig) = self.notify_channel(&apex_wire) {
                        sig.notify_one();
                    }
                    // Build NOTIFY ACK: QR=1, opcode=NOTIFY, AA=1, RCODE=NOERROR.
                    let ack = make_notify_ack(msg);
                    return serialise(&ack);
                }
            }
            // No matching secondary zone → REFUSED (RFC 1996 §3.10).
            let resp = make_error_response(msg, Rcode::Refused);
            return serialise(&resp);
        }

        if zone_cfg.is_none() {
            // No zone found → REFUSED.
            let resp = make_error_response(msg, Rcode::Refused);
            return serialise(&resp);
        }

        // For AXFR/IXFR, return REFUSED here (transport layer handles them).
        if matches!(q.qtype, Qtype::Axfr | Qtype::Ixfr) {
            let resp = make_error_response(msg, Rcode::Refused);
            return serialise(&resp);
        }

        // Standard query — serve from the in-memory zone file if available.
        let zone_cfg = zone_cfg.expect("INVARIANT: zone_cfg is Some when we reach this point");
        if let Some(zone_file) = zone_cfg.zone_file.as_deref() {
            let dnssec_ok = extract_do_bit(msg);
            let max_udp_payload = 0; // use default
            match query::serve_query(zone_file, &zone_cfg.apex, msg, dnssec_ok, max_udp_payload) {
                Ok(resp) => return serialise(&resp),
                Err(e) => {
                    warn!(error = ?e, "AuthServer::handle: serve_query error");
                    let resp = make_error_response(msg, Rcode::ServFail);
                    return serialise(&resp);
                }
            }
        }

        // No in-memory zone attached — Redis path not yet implemented.
        let resp = make_error_response(msg, Rcode::Refused);
        warn!(
            qname = %q.qname,
            "AuthServer::handle: in-memory zone not available (deferred to Redis sprint)"
        );
        serialise(&resp)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the DO (DNSSEC OK) bit is set in the query's OPT record.
fn extract_do_bit(msg: &Message) -> bool {
    msg.additional.iter().any(|r| {
        if let heimdall_core::rdata::RData::Opt(opt) = &r.rdata {
            opt.dnssec_ok
        } else {
            false
        }
    })
}

/// Perform longest-suffix match of `qname` against the zone map.
fn longest_suffix_match<'a>(
    zones: &'a HashMap<Vec<u8>, ZoneConfig>,
    qname: &heimdall_core::Name,
) -> Option<&'a ZoneConfig> {
    let qname_lower = qname.as_wire_bytes().to_ascii_lowercase();
    let wire = &qname_lower;
    let mut pos = 0;
    let mut best: Option<(&'a ZoneConfig, usize)> = None;

    while pos < wire.len() {
        let label_len = usize::from(wire[pos]);
        let suffix = wire.get(pos..)?;
        let suffix_len = wire.len() - pos;

        if let Some(cfg) = zones.get(suffix)
            && best.is_none_or(|(_, prev_len)| suffix_len > prev_len)
        {
            best = Some((cfg, suffix_len));
        }

        if label_len == 0 {
            break;
        }
        pos += 1 + label_len;
    }
    best.map(|(cfg, _)| cfg)
}

fn make_error_response(query: &Message, rcode: Rcode) -> Message {
    use heimdall_core::header::Header;
    let mut header = Header {
        id: query.header.id,
        qdcount: query.header.qdcount,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_opcode(Opcode::Query);
    header.set_rcode(rcode);
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// Build a NOTIFY ACK per RFC 1996 §3.8:
/// QR=1, opcode=NOTIFY, AA=1, RCODE=NOERROR.
fn make_notify_ack(query: &Message) -> Message {
    use heimdall_core::header::Header;
    let mut header = Header {
        id: query.header.id,
        qdcount: query.header.qdcount,
        ..Header::default()
    };
    header.set_qr(true);
    header.set_opcode(Opcode::Notify);
    header.set_aa(true);
    header.set_rcode(Rcode::NoError);
    Message {
        header,
        questions: query.questions.clone(),
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn serialise(msg: &Message) -> Result<Vec<u8>, AuthError> {
    let mut ser = Serialiser::new(true);
    ser.write_message(msg)
        .map_err(|e| AuthError::Serialise(e.to_string()))?;
    Ok(ser.finish())
}

// ── QueryDispatcher impl ──────────────────────────────────────────────────────

impl QueryDispatcher for AuthServer {
    fn dispatch(&self, msg: &Message, src: std::net::IpAddr) -> Vec<u8> {
        match self.handle(msg, src) {
            Ok(wire) => wire,
            Err(e) => {
                warn!(error = ?e, "AuthServer::dispatch: handle error");
                let resp = make_error_response(msg, Rcode::ServFail);
                serialise(&resp).unwrap_or_default()
            }
        }
    }
}

// ── ZoneTransferHandler impl ──────────────────────────────────────────────────

impl ZoneTransferHandler for AuthServer {
    fn build_xfr_frames(
        &self,
        msg: &Message,
        raw: &[u8],
        src: std::net::IpAddr,
    ) -> Option<Vec<Vec<u8>>> {
        let q = msg.questions.first()?;
        let zones_snap = self.zones.load();
        let zone_cfg = longest_suffix_match(&zones_snap, &q.qname)?;
        let zone_file = zone_cfg.zone_file.as_deref()?;

        match q.qtype {
            Qtype::Axfr => match axfr::build_axfr_frames(zone_file, zone_cfg, msg, raw, src) {
                Ok(frames) => Some(frames),
                Err(e) => {
                    warn!(error = ?e, "AuthServer: AXFR build failed");
                    None
                }
            },
            Qtype::Ixfr => {
                match ixfr::build_ixfr_frames(zone_file, zone_cfg, msg, raw, &[], src) {
                    Ok(frames) => Some(frames),
                    Err(e) => {
                        warn!(error = ?e, "AuthServer: IXFR build failed");
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
    use heimdall_core::name::Name;

    use super::*;

    fn make_query(opcode: Opcode, qname: &str, qtype: Qtype) -> Message {
        let mut header = Header {
            id: 42,
            qdcount: 1,
            ..Header::default()
        };
        header.set_opcode(opcode);
        Message {
            header,
            questions: vec![Question {
                qname: Name::from_str(qname).expect("INVARIANT: valid test name"),
                qtype,
                qclass: Qclass::In,
            }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn empty_server() -> AuthServer {
        AuthServer::new(vec![])
    }

    #[test]
    fn handle_update_returns_notimp() {
        let server = empty_server();
        let msg = make_query(Opcode::Update, "example.com.", Qtype::Soa);
        let wire = server
            .handle(&msg, "127.0.0.1".parse().expect("INVARIANT: valid ip"))
            .expect("handle must not error");

        let resp = Message::parse(&wire).expect("response must parse");
        assert_eq!(resp.header.rcode(), Rcode::NotImp);
    }

    #[test]
    fn handle_no_question_returns_error_for_non_update() {
        let server = empty_server();
        let header = Header {
            id: 99,
            ..Header::default()
        };
        let msg = Message {
            header,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let result = server.handle(&msg, "127.0.0.1".parse().expect("INVARIANT: valid ip"));
        assert!(result.is_err());
    }

    #[test]
    fn auth_error_display_coverage() {
        let errs = [
            AuthError::NoQuestion,
            AuthError::Refused,
            AuthError::TsigVerifyFailed,
            AuthError::InvalidTsigKey,
            AuthError::Serialise("x".into()),
            AuthError::ParseError,
            AuthError::Io("y".into()),
            AuthError::ZoneHasNoApex,
            AuthError::ZoneHasNoSoa,
            AuthError::ZoneParse("z".into()),
            AuthError::ZoneUpToDate,
            AuthError::NoPrimaryConfigured,
            AuthError::IxfrFallback,
            AuthError::NotifyFailed {
                target: "127.0.0.1:53".parse().expect("INVARIANT: valid addr"),
            },
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }
}
