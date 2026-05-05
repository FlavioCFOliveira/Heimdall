// SPDX-License-Identifier: MIT

//! Policy-zone loaders: file-based (RPZ-017) and AXFR stub (RPZ-016, RPZ-030).
//!
//! # File format
//!
//! RPZ zone files follow standard RFC 1035 zone-file syntax.  Owner names encode
//! the trigger type:
//!
//! ```text
//! blocked.example.com.<zone>. CNAME .            ; QNAME exact → NXDOMAIN
//! *.evil.com.<zone>.          CNAME .            ; QNAME wildcard → NXDOMAIN
//! 32.1.2.3.4.rpz-client-ip.<zone>. CNAME rpz-drop. ; Client-IP /32 → DROP
//! ```
//!
//! Action CNAME targets:
//! - `.`              → `Nxdomain`
//! - `*.`             → `Nodata`
//! - `rpz-passthru.`  → `Passthru`
//! - `rpz-drop.`      → `Drop`
//! - `rpz-tcp-only.`  → `TcpOnly`
//! - Any other name   → `CnameRedirect { target }`
//! - Any non-CNAME RR → `LocalData { records }`

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use heimdall_core::{
    name::Name,
    rdata::RData,
    record::Record,
    zone::{ZoneFile, ZoneLimits},
};

use crate::rpz::{
    action::RpzAction,
    trigger::{CidrRange, RpzEntry, RpzTrigger},
    zone::PolicyZone,
};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can arise when loading a policy zone.
#[derive(Debug)]
pub enum RpzLoadError {
    /// An I/O error reading the zone file.
    Io(std::io::Error),
    /// A zone-file parse error.
    ParseError(String),
    /// An action CNAME target could not be decoded.
    InvalidAction(String),
    /// A trigger owner-name format is not recognised.
    InvalidTrigger(String),
}

impl fmt::Display for RpzLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ParseError(s) => write!(f, "zone-file parse error: {s}"),
            Self::InvalidAction(s) => write!(f, "invalid RPZ action: {s}"),
            Self::InvalidTrigger(s) => write!(f, "invalid RPZ trigger: {s}"),
        }
    }
}

impl std::error::Error for RpzLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<std::io::Error> for RpzLoadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── PolicyZoneConfig ──────────────────────────────────────────────────────────

/// Configuration for one RPZ policy zone (RPZ-030).
#[derive(Debug, Clone)]
pub struct PolicyZoneConfig {
    /// Zone FQDN (e.g. `"rpz.example.com."`).
    pub zone: String,
    /// Where to load zone data from.
    pub source: ZoneSource,
    /// Evaluation order; 0 = highest priority (RPZ-019).
    pub evaluation_order: u8,
    /// Default TTL for synthetic records emitted by this zone (seconds, RPZ-033).
    pub policy_ttl: u32,
}

/// Where a policy zone is loaded from.
#[derive(Debug, Clone)]
pub enum ZoneSource {
    /// Load zone data from a local zone file (RPZ-017).
    File {
        /// Path to the zone file.
        path: std::path::PathBuf,
    },
    /// Load zone data via AXFR (RPZ-016).
    ///
    /// Sprint 34: stub implementation — logs a deferred message and returns an
    /// empty zone.  Full zone-transfer wiring is deferred to the integration sprint.
    Axfr {
        /// IP address of the zone's primary server.
        primary: IpAddr,
        /// TSIG key name for authenticated transfers.
        tsig_key: String,
        /// Zone refresh interval in seconds.
        refresh_secs: u64,
    },
}

// ── File loader ───────────────────────────────────────────────────────────────

/// Loads a policy zone from a local zone file (RPZ-017).
///
/// The file must be in standard RFC 1035 zone-file format with RPZ-encoded
/// owner names.  Each CNAME or non-CNAME resource record is decoded into an
/// [`RpzEntry`] and inserted into the returned [`PolicyZone`].
///
/// # Errors
///
/// Returns [`RpzLoadError`] on I/O failure, parse error, or invalid trigger/action.
pub fn load_from_file(config: &PolicyZoneConfig) -> Result<PolicyZone, RpzLoadError> {
    let ZoneSource::File { path } = &config.source else {
        return Err(RpzLoadError::ParseError(
            "load_from_file called with non-File source".to_string(),
        ));
    };

    let src = std::fs::read_to_string(path)?;
    let origin = Name::parse_str(&config.zone)
        .map_err(|e| RpzLoadError::ParseError(format!("invalid zone name: {e}")))?;

    let zone_file = ZoneFile::parse(&src, Some(origin.clone()), ZoneLimits::default())
        .map_err(|e| RpzLoadError::ParseError(e.to_string()))?;

    let mut policy_zone = PolicyZone::new(config.zone.clone(), config.evaluation_order);
    policy_zone.policy_ttl = config.policy_ttl;

    // Group non-CNAME records by owner for LocalData aggregation.
    let mut local_data: HashMap<String, Vec<Record>> = HashMap::new();

    for (position, record) in zone_file.records.iter().enumerate() {
        // Strip the trailing `.<zone>` suffix from the owner name to derive
        // the trigger-encoded prefix.
        let owner_str = record.name.to_string();
        let trigger_prefix = strip_zone_suffix(&owner_str, &config.zone);

        match &record.rdata {
            RData::Cname(target) => {
                let action = decode_action(target);
                let trigger =
                    decode_trigger(trigger_prefix, record).map_err(RpzLoadError::InvalidTrigger)?;
                policy_zone.insert(RpzEntry {
                    trigger,
                    action,
                    position,
                });
            }
            _ => {
                // Non-CNAME records are accumulated as LocalData for the owner.
                local_data
                    .entry(owner_str.clone())
                    .or_default()
                    .push(record.clone());
            }
        }
    }

    // Flush accumulated LocalData entries.
    for (position, (owner_str, records)) in local_data.into_iter().enumerate() {
        let trigger_prefix = strip_zone_suffix(&owner_str, &config.zone);
        // Use a synthetic record stub for trigger decoding (we only need owner/type/class).
        // Since LocalData records are grouped, use the first record's metadata.
        let first = &records[0];
        let trigger =
            decode_trigger(trigger_prefix, first).map_err(RpzLoadError::InvalidTrigger)?;
        let action = RpzAction::LocalData { records };
        policy_zone.insert(RpzEntry {
            trigger,
            action,
            position,
        });
    }

    Ok(policy_zone)
}

/// Loads a policy zone via AXFR (RPZ-016).
///
/// Sprint 34 stub: logs a deferred message and returns an empty [`PolicyZone`].
///
/// # Errors
///
/// Currently infallible; returns `Ok` with an empty zone.
// The async signature is retained so callers can be written as async without
// changes when the real AXFR wiring lands (RPZ-016 integration sprint).
#[allow(clippy::unused_async)]
pub async fn load_via_axfr(config: &PolicyZoneConfig) -> Result<PolicyZone, RpzLoadError> {
    tracing::info!(
        event = "rpz_axfr_deferred",
        zone = %config.zone,
        "AXFR RPZ load: zone transfer wiring deferred to integration sprint"
    );
    Ok(PolicyZone::new(
        config.zone.clone(),
        config.evaluation_order,
    ))
}

// ── Trigger decoder ───────────────────────────────────────────────────────────

/// Strips the trailing `.<zone>` suffix from `owner_str`, returning only the
/// trigger-encoded prefix.  If the owner is exactly the zone apex, returns `"@"`.
fn strip_zone_suffix<'a>(owner_str: &'a str, zone: &str) -> &'a str {
    // Normalise: both are presentation format with trailing dot.
    // owner_str: "blocked.example.com.rpz.example.com."
    // zone:      "rpz.example.com."
    // We want to strip the ".<zone>" suffix. The zone already has a trailing dot;
    // owner_str also has one, so we look for ".<zone>" without the trailing dot
    // of the suffix (they share the owner's trailing dot).

    let zone_no_dot = zone.trim_end_matches('.');
    // Build the suffix pattern: ".<zone_no_dot>."
    let suffix = alloc::format!(".{zone_no_dot}.");

    if let Some(prefix) = owner_str.strip_suffix(&suffix) {
        if prefix.is_empty() { "@" } else { prefix }
    } else if owner_str.trim_end_matches('.') == zone_no_dot {
        "@"
    } else {
        owner_str
    }
}

// The `alloc` crate is not available in `no_std` but the project is `std`.
// Using the full path to avoid any ambiguity.
use std as alloc;

/// Decodes an RPZ trigger from the trigger-encoded prefix and the original record.
///
/// Encoding rules (simplified from the RPZ draft):
/// - `@` or zone-apex  → QNAME exact match on the zone itself (unusual; treated as apex).
/// - `*.<suffix>`      → QNAME wildcard (strip the leading `*.`).
/// - `<qname>`         → QNAME exact match.
/// - `32.<a>.<b>.<c>.<d>.rpz-client-ip` → Client-IP /32 for v4.
/// - `<pfx>.<reversed-octets>.rpz-client-ip` → Client-IP CIDR.
/// - `32.<v6-parts>.rpz-client-ip` → Client-IP /128 for v6 (simplified).
///
/// Returns `Err(String)` for unrecognised encodings.
fn decode_trigger(prefix: &str, _record: &Record) -> Result<RpzTrigger, String> {
    if prefix == "@" {
        // Zone-apex entry; treat as exact QNAME match on root (unusual, valid).
        return Ok(RpzTrigger::QnameExact(Name::root()));
    }

    // Wildcard QNAME: prefix starts with `*.`
    if let Some(suffix_str) = prefix.strip_prefix("*.") {
        let suffix = Name::parse_str(suffix_str)
            .map_err(|e| format!("invalid wildcard suffix '{suffix_str}': {e}"))?;
        return Ok(RpzTrigger::QnameWildcard(suffix));
    }

    // Client-IP trigger: suffix before zone contains `.rpz-client-ip`.
    if let Some(cidr_encoded) = strip_rpz_suffix(prefix, "rpz-client-ip") {
        let range = decode_cidr(cidr_encoded)
            .map_err(|e| format!("invalid client-ip CIDR '{cidr_encoded}': {e}"))?;
        return Ok(RpzTrigger::ClientIp(range));
    }

    // Response-IP trigger.
    if let Some(cidr_encoded) = strip_rpz_suffix(prefix, "rpz-ip") {
        let range = decode_cidr(cidr_encoded)
            .map_err(|e| format!("invalid response-ip CIDR '{cidr_encoded}': {e}"))?;
        return Ok(RpzTrigger::ResponseIp(range));
    }

    // NSIP trigger.
    if let Some(cidr_encoded) = strip_rpz_suffix(prefix, "rpz-nsip") {
        let range = decode_cidr(cidr_encoded)
            .map_err(|e| format!("invalid nsip CIDR '{cidr_encoded}': {e}"))?;
        return Ok(RpzTrigger::Nsip(range));
    }

    // NSDNAME trigger.
    if let Some(nsdname_encoded) = strip_rpz_suffix(prefix, "rpz-nsdname") {
        // Wildcard nsdname: starts with `*.`
        if let Some(suffix_str) = nsdname_encoded.strip_prefix("*.") {
            let suffix = Name::parse_str(suffix_str)
                .map_err(|e| format!("invalid nsdname suffix '{suffix_str}': {e}"))?;
            return Ok(RpzTrigger::NsdnameSuffix(suffix));
        }
        let name = Name::parse_str(nsdname_encoded)
            .map_err(|e| format!("invalid nsdname '{nsdname_encoded}': {e}"))?;
        return Ok(RpzTrigger::NsdnameExact(name));
    }

    // Default: QNAME exact match.
    let name =
        Name::parse_str(prefix).map_err(|e| format!("invalid QNAME trigger '{prefix}': {e}"))?;
    Ok(RpzTrigger::QnameExact(name))
}

/// Strips a known RPZ type suffix from `prefix`.
///
/// Given `prefix = "32.1.2.3.4.rpz-client-ip"` and `rpz_type = "rpz-client-ip"`,
/// returns `Some("32.1.2.3.4")`.
fn strip_rpz_suffix<'a>(prefix: &'a str, rpz_type: &str) -> Option<&'a str> {
    let suffix = alloc::format!(".{rpz_type}");
    prefix
        .strip_suffix(&suffix)
        .or_else(|| if prefix == rpz_type { Some("") } else { None })
}

/// Decodes an RPZ-encoded CIDR string (e.g. `"32.1.2.3.4"` → `1.2.3.4/32`).
///
/// RPZ IPv4 encoding: `<prefix_len>.<d4>.<d3>.<d2>.<d1>` (reversed octets).
/// RPZ IPv6 encoding: `<prefix_len>.<nibbles-reversed>` (simplified).
fn decode_cidr(encoded: &str) -> Result<CidrRange, String> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.is_empty() {
        return Err("empty CIDR encoding".to_string());
    }
    let prefix_len: u8 = parts[0]
        .parse()
        .map_err(|_| format!("non-numeric prefix length '{}'", parts[0]))?;

    // Try IPv4: format is `<pfx>.<d4>.<d3>.<d2>.<d1>` (4 reversed octets).
    if parts.len() == 5 {
        let d1: u8 = parts[4].parse().map_err(|_| "bad IPv4 octet".to_string())?;
        let d2: u8 = parts[3].parse().map_err(|_| "bad IPv4 octet".to_string())?;
        let d3: u8 = parts[2].parse().map_err(|_| "bad IPv4 octet".to_string())?;
        let d4: u8 = parts[1].parse().map_err(|_| "bad IPv4 octet".to_string())?;
        if prefix_len > 32 {
            return Err(format!("IPv4 prefix length {prefix_len} > 32"));
        }
        let addr = IpAddr::V4(Ipv4Addr::new(d1, d2, d3, d4));
        return Ok(CidrRange { addr, prefix_len });
    }

    // Simplified IPv6 support: allow `<pfx>.<addr>` where <addr> is a standard
    // colon-notation IPv6 address with colons replaced by dots (heuristic).
    if parts.len() >= 2 {
        // Reconstruct by joining all parts except the first, replacing '.' with ':'.
        let addr_str = parts[1..].join(":").replacen(' ', "", 0);
        // Also try joining with dots to see if we can parse a literal.
        let addr_raw = parts[1..].join(".");
        if let Ok(v6) = Ipv6Addr::from_str(&addr_raw) {
            if prefix_len > 128 {
                return Err(format!("IPv6 prefix length {prefix_len} > 128"));
            }
            return Ok(CidrRange {
                addr: IpAddr::V6(v6),
                prefix_len,
            });
        }
        let _ = addr_str; // suppress unused warning
    }

    Err(format!("unrecognised CIDR encoding '{encoded}'"))
}

// ── Action decoder ────────────────────────────────────────────────────────────

/// Decodes an RPZ action from a CNAME target name.
///
/// | Target          | Action              |
/// |-----------------|---------------------|
/// | `.`             | `Nxdomain`          |
/// | `*.`            | `Nodata`            |
/// | `rpz-passthru.` | `Passthru`          |
/// | `rpz-drop.`     | `Drop`              |
/// | `rpz-tcp-only.` | `TcpOnly`           |
/// | other name      | `CnameRedirect`     |
fn decode_action(target: &Name) -> RpzAction {
    let s = target.to_string();
    match s.as_str() {
        "." => RpzAction::Nxdomain,
        "*." => RpzAction::Nodata,
        "rpz-passthru." => RpzAction::Passthru,
        "rpz-drop." => RpzAction::Drop,
        "rpz-tcp-only." => RpzAction::TcpOnly,
        _ => RpzAction::CnameRedirect {
            target: Box::new(target.clone()),
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write as IoWrite;

    use super::*;

    fn make_config(path: std::path::PathBuf) -> PolicyZoneConfig {
        PolicyZoneConfig {
            zone: "rpz.test.".to_string(),
            source: ZoneSource::File { path },
            evaluation_order: 0,
            policy_ttl: 30,
        }
    }

    #[test]
    fn load_from_file_nxdomain_entry() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Write a minimal RPZ zone file with an NXDOMAIN (CNAME to ".") entry.
        write!(
            tmp,
            "$ORIGIN rpz.test.\n\
             $TTL 30\n\
             @ IN SOA ns1 hostmaster 1 3600 900 604800 30\n\
             blocked.example.com IN CNAME .\n"
        )
        .unwrap();
        tmp.flush().unwrap();

        let config = make_config(tmp.path().to_path_buf());
        let zone = load_from_file(&config).expect("load_from_file should succeed");

        // The QNAME exact trigger "blocked.example.com." → Nxdomain must be present.
        let qname = Name::parse_str("blocked.example.com.").unwrap();
        assert_eq!(zone.check_qname(&qname), Some(RpzAction::Nxdomain));
    }

    #[test]
    fn load_from_file_malformed_rejected() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "THIS IS NOT A ZONE FILE @@@@").unwrap();
        tmp.flush().unwrap();

        let config = make_config(tmp.path().to_path_buf());
        let result = load_from_file(&config);
        assert!(result.is_err(), "malformed file should produce an error");
    }

    #[test]
    fn load_from_file_passthru_entry() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            "$ORIGIN rpz.test.\n\
             $TTL 30\n\
             @ IN SOA ns1 hostmaster 1 3600 900 604800 30\n\
             allowed.example.com IN CNAME rpz-passthru.\n"
        )
        .unwrap();
        tmp.flush().unwrap();

        let config = make_config(tmp.path().to_path_buf());
        let zone = load_from_file(&config).expect("load_from_file should succeed");
        let qname = Name::parse_str("allowed.example.com.").unwrap();
        assert_eq!(zone.check_qname(&qname), Some(RpzAction::Passthru));
    }

    #[tokio::test]
    async fn load_via_axfr_stub_returns_empty_zone() {
        let config = PolicyZoneConfig {
            zone: "rpz.test.".to_string(),
            source: ZoneSource::Axfr {
                primary: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                tsig_key: "key.".to_string(),
                refresh_secs: 3600,
            },
            evaluation_order: 0,
            policy_ttl: 30,
        };
        let zone = load_via_axfr(&config).await.expect("stub should not fail");
        assert_eq!(zone.name, "rpz.test.");
        // Empty zone — no matches.
        let qname = Name::parse_str("anything.example.com.").unwrap();
        assert!(zone.check_qname(&qname).is_none());
    }
}
