// SPDX-License-Identifier: MIT

//! Binary encoding and key-generation for the Redis persistence layer.
//!
//! This module provides:
//!
//! - **Key generators** — [`zone_key`], [`zone_staging_key`], [`zone_journal_key`],
//!   [`cache_key`], [`field_name`] — implement the key namespace defined in
//!   `STORE-019`, `STORE-023`, `STORE-028`, `STORE-037..042`, `STORE-045`.
//! - **[`RrsetPayload`]** — encode/decode the compact binary `RRset` format
//!   (`STORE-043`).
//! - **[`CacheEntry`]** — encode/decode the cache entry format which prepends a
//!   9-byte header to an [`RrsetPayload`] (`STORE-044`).
//! - **[`DnssecOutcome`]** — four-variant enum matching `DNSSEC-010` discriminants.

use std::time::{SystemTime, UNIX_EPOCH};

use super::StoreError;

// ── Key namespace constants ───────────────────────────────────────────────────

/// Global Heimdall namespace prefix required by `STORE-037`.
const PREFIX: &str = "heimdall";

/// Authoritative zone namespace segment (`STORE-038`).
const NS_ZONE_AUTH: &str = "zone:auth";

/// Recursive resolver cache namespace segment (`STORE-038`).
const NS_CACHE_RECURSIVE: &str = "cache:recursive";

/// Forwarder cache namespace segment (`STORE-038`).
const NS_CACHE_FORWARDER: &str = "cache:forwarder";

/// IXFR journal namespace segment (`STORE-045`).
const NS_JOURNAL_AUTH: &str = "journal:auth";

/// Staging key suffix appended for atomic zone replacement (`STORE-023`).
const STAGING_SUFFIX: &str = ":staging";

// ── Key generators ────────────────────────────────────────────────────────────

/// Produce the live zone key for `fqdn` (`STORE-019`).
///
/// Pattern: `heimdall:zone:auth:{<fqdn>}` — the hash tag `{…}` ensures that the
/// live key and staging key hash to the same Redis Cluster slot (`STORE-039/040`).
///
/// `fqdn` is normalised to lowercase ASCII by this function.
///
/// # Examples
///
/// ```
/// # use heimdall_runtime::store::encoding::zone_key;
/// assert_eq!(zone_key("Example.COM."), "heimdall:zone:auth:{example.com.}");
/// ```
#[must_use]
pub fn zone_key(fqdn: &str) -> String {
    format!("{PREFIX}:{NS_ZONE_AUTH}:{{{}}}", fqdn.to_lowercase())
}

/// Produce the staging key for `fqdn` used during atomic zone replacement
/// (`STORE-023`).
///
/// Pattern: `heimdall:zone:auth:{<fqdn>}:staging`
///
/// # Examples
///
/// ```
/// # use heimdall_runtime::store::encoding::zone_staging_key;
/// assert_eq!(
///     zone_staging_key("example.com."),
///     "heimdall:zone:auth:{example.com.}:staging",
/// );
/// ```
#[must_use]
pub fn zone_staging_key(fqdn: &str) -> String {
    format!(
        "{PREFIX}:{NS_ZONE_AUTH}:{{{}}}{}",
        fqdn.to_lowercase(),
        STAGING_SUFFIX
    )
}

/// Produce the IXFR journal key for `fqdn` (`STORE-045`).
///
/// Pattern: `heimdall:journal:auth:{fqdn}`
///
/// # Examples
///
/// ```
/// # use heimdall_runtime::store::encoding::zone_journal_key;
/// assert_eq!(
///     zone_journal_key("example.com."),
///     "heimdall:journal:auth:{example.com.}",
/// );
/// ```
#[must_use]
pub fn zone_journal_key(fqdn: &str) -> String {
    format!("{PREFIX}:{NS_JOURNAL_AUTH}:{{{}}}", fqdn.to_lowercase())
}

/// Cache namespace selector (`STORE-027`, `STORE-028`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheNamespace {
    /// Recursive resolver cache (`heimdall:cache:recursive:…`).
    Recursive,
    /// Forwarder cache (`heimdall:cache:forwarder:…`).
    Forwarder,
}

impl CacheNamespace {
    fn segment(self) -> &'static str {
        match self {
            Self::Recursive => NS_CACHE_RECURSIVE,
            Self::Forwarder => NS_CACHE_FORWARDER,
        }
    }
}

/// Produce a cache key for the given `(namespace, owner, qtype, qclass)` tuple
/// (`STORE-028`, `STORE-042`).
///
/// Pattern: `heimdall:cache:{recursive|forwarder}:{owner}|{qtype}|{qclass}`
///
/// `owner` is normalised to lowercase ASCII. `qtype` and `qclass` are the
/// decimal representations of their respective 16-bit values.
///
/// # Examples
///
/// ```
/// # use heimdall_runtime::store::encoding::{cache_key, CacheNamespace};
/// let key = cache_key(CacheNamespace::Recursive, "Example.COM.", 1, 1);
/// assert_eq!(key, "heimdall:cache:recursive:example.com.|1|1");
/// ```
#[must_use]
pub fn cache_key(ns: CacheNamespace, owner: &str, qtype: u16, qclass: u16) -> String {
    format!(
        "{PREFIX}:{}:{}|{}|{}",
        ns.segment(),
        owner.to_lowercase(),
        qtype,
        qclass,
    )
}

/// Produce the field name for a Hash entry given `(owner, qtype, qclass)`
/// (`STORE-042`).
///
/// Format: `<lowercase_fqdn>|<qtype_u16_decimal>|<qclass_u16_decimal>`
///
/// # Examples
///
/// ```
/// # use heimdall_runtime::store::encoding::field_name;
/// assert_eq!(field_name("Example.COM.", 1, 1), "example.com.|1|1");
/// ```
#[must_use]
pub fn field_name(owner: &str, qtype: u16, qclass: u16) -> String {
    format!("{}|{}|{}", owner.to_lowercase(), qtype, qclass)
}

// ── RRset binary payload (STORE-043) ─────────────────────────────────────────

/// Current `RRset` payload format version byte.
const RRSET_VERSION: u8 = 0x01;

/// Compact binary `RRset` representation used as Hash field values for zone data
/// and as the embedded payload inside [`CacheEntry`] values.
///
/// Wire format (`STORE-043`):
/// ```text
/// [version: u8 = 0x01]
/// [ttl: u32 big-endian]
/// [rdata_count: u16 big-endian]
/// for each RDATA:
///   [length: u16 big-endian]
///   [wire_bytes: [u8; length]]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetPayload {
    /// DNS TTL in seconds.
    pub ttl: u32,
    /// Wire-encoded RDATA records; each element is one record's bytes.
    pub rdata: Vec<Vec<u8>>,
}

impl RrsetPayload {
    /// Encode this payload into a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::EncodingError`] if any individual RDATA record
    /// exceeds 65535 bytes, or if `rdata` contains more than 65535 records.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let rdata_count = u16::try_from(self.rdata.len())
            .map_err(|_| StoreError::encoding("RRset RDATA count exceeds u16::MAX"))?;

        // Pre-compute capacity: 1 (version) + 4 (ttl) + 2 (count) + sum of (2 + len) each.
        let payload_len: usize = self
            .rdata
            .iter()
            .try_fold(7usize, |acc, r| {
                if r.len() > usize::from(u16::MAX) {
                    None
                } else {
                    Some(acc + 2 + r.len())
                }
            })
            .ok_or_else(|| StoreError::encoding("RDATA record length exceeds u16::MAX"))?;

        let mut buf = Vec::with_capacity(payload_len);
        buf.push(RRSET_VERSION);
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&rdata_count.to_be_bytes());
        for r in &self.rdata {
            // Length already checked above via try_fold.
            #[allow(clippy::cast_possible_truncation)]
            let len = r.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(r);
        }
        Ok(buf)
    }

    /// Decode a payload previously produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DecodingError`] if the buffer is malformed,
    /// truncated, or uses an unknown version byte.
    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0usize;

        // version
        let version = read_u8(buf, &mut pos)?;
        if version != RRSET_VERSION {
            return Err(StoreError::decoding(format!(
                "unsupported RRset payload version: {version:#04x}"
            )));
        }

        // ttl
        let ttl = read_u32_be(buf, &mut pos)?;

        // rdata_count
        let count = usize::from(read_u16_be(buf, &mut pos)?);

        let mut rdata = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(read_u16_be(buf, &mut pos)?);
            let bytes = read_bytes(buf, &mut pos, len)?;
            rdata.push(bytes.to_vec());
        }

        if pos != buf.len() {
            return Err(StoreError::decoding("trailing bytes after RRset payload"));
        }

        Ok(Self { ttl, rdata })
    }
}

// ── Cache entry format (STORE-044) ────────────────────────────────────────────

/// DNSSEC validation outcome (`DNSSEC-010`), encoded as the first byte of a
/// cache entry.
///
/// | Variant        | Wire byte |
/// |----------------|-----------|
/// | `Secure`       | `0x00`    |
/// | `Insecure`     | `0x01`    |
/// | `Bogus`        | `0x02`    |
/// | `Indeterminate`| `0x03`    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecOutcome {
    /// The `RRset` was validated successfully by a chain of trust.
    Secure,
    /// Validation succeeded, but there is no chain of trust.
    Insecure,
    /// Validation was attempted and failed.
    Bogus,
    /// Validation was not attempted.
    Indeterminate,
}

impl DnssecOutcome {
    fn to_byte(self) -> u8 {
        match self {
            Self::Secure => 0x00,
            Self::Insecure => 0x01,
            Self::Bogus => 0x02,
            Self::Indeterminate => 0x03,
        }
    }

    fn from_byte(b: u8) -> Result<Self, StoreError> {
        match b {
            0x00 => Ok(Self::Secure),
            0x01 => Ok(Self::Insecure),
            0x02 => Ok(Self::Bogus),
            0x03 => Ok(Self::Indeterminate),
            other => Err(StoreError::decoding(format!(
                "unknown DNSSEC outcome byte: {other:#04x}"
            ))),
        }
    }
}

/// Cache entry stored as a Redis String value (`STORE-044`).
///
/// Wire format — 9-byte header followed by an [`RrsetPayload`]:
/// ```text
/// [dnssec_outcome: u8]
/// [inserted_at: u32 big-endian UNIX timestamp]
/// [stale_until: u32 big-endian UNIX timestamp]
/// [... RrsetPayload (STORE-043) ...]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// DNSSEC validation outcome for this entry.
    pub dnssec_outcome: DnssecOutcome,
    /// UNIX timestamp (seconds) when this entry was inserted.
    pub inserted_at: u32,
    /// UNIX timestamp (seconds) after which stale-serving may begin.
    pub stale_until: u32,
    /// The `RRset` payload.
    pub rrset: RrsetPayload,
}

impl CacheEntry {
    /// Build a new cache entry for `rrset`, inserting it at `now`.
    ///
    /// `stale_until` is computed as `inserted_at + rrset.ttl`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::EncodingError`] if the current system time is
    /// before the Unix epoch or if it overflows a `u32`.
    pub fn new(rrset: RrsetPayload, dnssec_outcome: DnssecOutcome) -> Result<Self, StoreError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::encoding("system clock is before the Unix epoch"))?
            .as_secs();
        let inserted_at = u32::try_from(now_secs)
            .map_err(|_| StoreError::encoding("current UNIX timestamp overflows u32"))?;
        let stale_until = inserted_at.saturating_add(rrset.ttl);
        Ok(Self {
            dnssec_outcome,
            inserted_at,
            stale_until,
            rrset,
        })
    }

    /// Encode this entry into a byte vector.
    ///
    /// # Errors
    ///
    /// Propagates [`StoreError::EncodingError`] from the inner
    /// [`RrsetPayload::encode`] call.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let rrset_bytes = self.rrset.encode()?;
        let mut buf = Vec::with_capacity(9 + rrset_bytes.len());
        buf.push(self.dnssec_outcome.to_byte());
        buf.extend_from_slice(&self.inserted_at.to_be_bytes());
        buf.extend_from_slice(&self.stale_until.to_be_bytes());
        buf.extend_from_slice(&rrset_bytes);
        Ok(buf)
    }

    /// Decode a buffer previously produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DecodingError`] if the buffer is malformed.
    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0usize;
        let dnssec_outcome = DnssecOutcome::from_byte(read_u8(buf, &mut pos)?)?;
        let inserted_at = read_u32_be(buf, &mut pos)?;
        let stale_until = read_u32_be(buf, &mut pos)?;
        let rrset = RrsetPayload::decode(&buf[pos..])?;
        Ok(Self {
            dnssec_outcome,
            inserted_at,
            stale_until,
            rrset,
        })
    }
}

// ── Buffer reading helpers ────────────────────────────────────────────────────

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, StoreError> {
    buf.get(*pos)
        .copied()
        .ok_or_else(|| StoreError::decoding("unexpected end of buffer reading u8"))
        .inspect(|_| *pos += 1)
}

fn read_u16_be(buf: &[u8], pos: &mut usize) -> Result<u16, StoreError> {
    let end = pos
        .checked_add(2)
        .ok_or_else(|| StoreError::decoding("position overflow"))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| StoreError::decoding("unexpected end of buffer reading u16"))?;
    let val = u16::from_be_bytes([slice[0], slice[1]]);
    *pos = end;
    Ok(val)
}

fn read_u32_be(buf: &[u8], pos: &mut usize) -> Result<u32, StoreError> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| StoreError::decoding("position overflow"))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| StoreError::decoding("unexpected end of buffer reading u32"))?;
    let val = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
    *pos = end;
    Ok(val)
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], StoreError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| StoreError::decoding("position overflow"))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| StoreError::decoding("unexpected end of buffer reading bytes"))?;
    *pos = end;
    Ok(slice)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Key generation ──────────────────────────────────────────────────────

    #[test]
    fn zone_key_lowercase_and_hash_tag() {
        assert_eq!(
            zone_key("Example.COM."),
            "heimdall:zone:auth:{example.com.}"
        );
    }

    #[test]
    fn zone_staging_key_has_staging_suffix() {
        assert_eq!(
            zone_staging_key("example.com."),
            "heimdall:zone:auth:{example.com.}:staging"
        );
    }

    #[test]
    fn zone_journal_key_format() {
        assert_eq!(
            zone_journal_key("example.com."),
            "heimdall:journal:auth:{example.com.}"
        );
    }

    #[test]
    fn cache_key_recursive_namespace() {
        assert_eq!(
            cache_key(CacheNamespace::Recursive, "Example.COM.", 1, 1),
            "heimdall:cache:recursive:example.com.|1|1"
        );
    }

    #[test]
    fn cache_key_forwarder_namespace() {
        assert_eq!(
            cache_key(CacheNamespace::Forwarder, "example.com.", 28, 1),
            "heimdall:cache:forwarder:example.com.|28|1"
        );
    }

    #[test]
    fn field_name_pipe_separator() {
        assert_eq!(field_name("Example.COM.", 1, 1), "example.com.|1|1");
        assert_eq!(
            field_name("mail.example.com.", 15, 1),
            "mail.example.com.|15|1"
        );
    }

    #[test]
    fn cache_namespaces_are_distinct() {
        let rec = cache_key(CacheNamespace::Recursive, "x.com.", 1, 1);
        let fwd = cache_key(CacheNamespace::Forwarder, "x.com.", 1, 1);
        assert_ne!(rec, fwd);
    }

    // ── RrsetPayload round-trip ─────────────────────────────────────────────

    #[test]
    fn rrset_payload_empty_rdata_round_trip() {
        let payload = RrsetPayload {
            ttl: 300,
            rdata: vec![],
        };
        let encoded = payload.encode().expect("encode succeeds");
        let decoded = RrsetPayload::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rrset_payload_single_record_round_trip() {
        let payload = RrsetPayload {
            ttl: 3600,
            rdata: vec![vec![1u8, 2, 3, 4]], // A record: 4 bytes
        };
        let encoded = payload.encode().expect("encode succeeds");
        let decoded = RrsetPayload::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rrset_payload_multiple_records_round_trip() {
        let payload = RrsetPayload {
            ttl: 86_400,
            rdata: vec![vec![192, 168, 1, 1], vec![10, 0, 0, 1], vec![172, 16, 0, 1]],
        };
        let encoded = payload.encode().expect("encode succeeds");
        let decoded = RrsetPayload::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rrset_payload_version_byte_is_0x01() {
        let payload = RrsetPayload {
            ttl: 60,
            rdata: vec![],
        };
        let encoded = payload.encode().expect("encode succeeds");
        assert_eq!(encoded[0], 0x01);
    }

    #[test]
    fn rrset_payload_ttl_is_big_endian() {
        let payload = RrsetPayload {
            ttl: 0x0102_0304,
            rdata: vec![],
        };
        let encoded = payload.encode().expect("encode succeeds");
        assert_eq!(&encoded[1..5], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn rrset_payload_wrong_version_rejected() {
        let payload = RrsetPayload {
            ttl: 300,
            rdata: vec![],
        };
        let mut encoded = payload.encode().expect("encode succeeds");
        encoded[0] = 0xFF; // corrupt version
        let err = RrsetPayload::decode(&encoded).expect_err("should reject bad version");
        assert!(matches!(err, StoreError::DecodingError(_)));
    }

    #[test]
    fn rrset_payload_truncated_buffer_rejected() {
        let err = RrsetPayload::decode(&[0x01]).expect_err("should reject truncated");
        assert!(matches!(err, StoreError::DecodingError(_)));
    }

    // ── CacheEntry round-trip ───────────────────────────────────────────────

    #[test]
    fn cache_entry_round_trip() {
        let rrset = RrsetPayload {
            ttl: 300,
            rdata: vec![vec![1, 2, 3, 4]],
        };
        // Build with explicit timestamps to make the test deterministic.
        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Secure,
            inserted_at: 1_700_000_000,
            stale_until: 1_700_000_300,
            rrset,
        };
        let encoded = entry.encode().expect("encode succeeds");
        let decoded = CacheEntry::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn cache_entry_dnssec_outcome_bytes() {
        for (outcome, byte) in [
            (DnssecOutcome::Secure, 0x00u8),
            (DnssecOutcome::Insecure, 0x01),
            (DnssecOutcome::Bogus, 0x02),
            (DnssecOutcome::Indeterminate, 0x03),
        ] {
            let entry = CacheEntry {
                dnssec_outcome: outcome,
                inserted_at: 0,
                stale_until: 0,
                rrset: RrsetPayload {
                    ttl: 0,
                    rdata: vec![],
                },
            };
            let encoded = entry.encode().expect("encode");
            assert_eq!(
                encoded[0], byte,
                "outcome {outcome:?} should encode to {byte:#04x}"
            );
        }
    }

    #[test]
    fn cache_entry_unknown_dnssec_byte_rejected() {
        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Secure,
            inserted_at: 0,
            stale_until: 0,
            rrset: RrsetPayload {
                ttl: 0,
                rdata: vec![],
            },
        };
        let mut encoded = entry.encode().expect("encode");
        encoded[0] = 0xFF;
        let err = CacheEntry::decode(&encoded).expect_err("unknown byte rejected");
        assert!(matches!(err, StoreError::DecodingError(_)));
    }

    #[test]
    fn cache_entry_header_layout() {
        // Verify inserted_at and stale_until occupy bytes 1..5 and 5..9.
        let entry = CacheEntry {
            dnssec_outcome: DnssecOutcome::Indeterminate,
            inserted_at: 0xDEAD_BEEF,
            stale_until: 0xCAFE_BABE,
            rrset: RrsetPayload {
                ttl: 0,
                rdata: vec![],
            },
        };
        let encoded = entry.encode().expect("encode");
        assert_eq!(&encoded[1..5], &0xDEAD_BEEFu32.to_be_bytes());
        assert_eq!(&encoded[5..9], &0xCAFE_BABEu32.to_be_bytes());
    }
}
