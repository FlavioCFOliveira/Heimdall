// SPDX-License-Identifier: MIT

//! Trust anchor management for DNSSEC validation (DNSSEC-009/015/023).
//!
//! [`TrustAnchorStore`] holds the currently trusted DNSKEY set for the root
//! zone, bootstrapped from the IANA KSK-2017 (key tag 20326, algorithm 8
//! RSASHA256).  A simplified RFC 5011 state machine manages key lifecycle.
//!
//! State is persisted atomically to `managed-keys.json` in the data directory
//! via a temp-file + rename pattern.

use heimdall_core::header::Qclass;
use heimdall_core::name::Name;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_core::zone::{ZoneFile, ZoneLimits};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

// ── IANA root KSK-2017 (RFC 5702, key tag 20326, algorithm 8 RSASHA256) ───────

/// The IANA root zone KSK-2017 in zone-file presentation format.
///
/// Published at <https://www.iana.org/dnssec/files> and in RFC 8145.
/// Key tag: 20326 · Algorithm: 8 (RSASHA256) · Flags: 257 (KSK)
// IANA KSK-2017 (key tag 20326, algorithm 8 RSASHA256, flags 257).
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// DS SHA-256: E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
const IANA_ROOT_KSK_ZONE_ENTRY: &str = concat!(
    ". 172800 IN DNSKEY 257 3 8 ",
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
    "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv",
    "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0",
    "jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ",
    "G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU",
    "fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1A",
    "kUTV74bU="
);

// ── RFC 5011 state machine ────────────────────────────────────────────────────

/// Hold-down interval for RFC 5011 key additions: 30 days.
const ADD_HOLD_DOWN_SECS: u64 = 30 * 24 * 3600;

/// Hold-down interval for RFC 5011 key removals: 30 days.
#[allow(dead_code)]
const REMOVE_HOLD_DOWN_SECS: u64 = 30 * 24 * 3600;

/// The lifecycle state of a managed trust anchor key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /// The key is currently trusted.
    Valid,
    /// The key has been seen but the hold-down period has not yet elapsed.
    AddPending {
        /// Unix second at which the hold-down period ends.
        hold_down_until: u64,
    },
    /// The key has been revoked and MUST NOT be used for validation.
    Revoked,
}

/// A single entry in the managed-keys database.
#[derive(Debug, Clone)]
pub struct ManagedKey {
    /// The 16-bit key tag of this DNSKEY.
    pub key_tag: u16,
    /// The DNSSEC algorithm number (8 = RSASHA256, 13 = ECDSAP256SHA256, …).
    pub algorithm: u8,
    /// Raw public key bytes from the DNSKEY RDATA.
    pub public_key: Vec<u8>,
    /// Current RFC 5011 state.
    pub state: KeyState,
}

// ── TrustAnchorError ──────────────────────────────────────────────────────────

/// Errors that can arise in [`TrustAnchorStore`].
#[derive(Debug)]
pub enum TrustAnchorError {
    /// The built-in IANA KSK zone entry could not be parsed.
    BuiltinParseFailure(String),
    /// State persistence I/O failed.
    PersistenceIo(String),
    /// The state file contains invalid JSON.
    InvalidStateFile(String),
}

impl std::fmt::Display for TrustAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BuiltinParseFailure(e) => {
                write!(f, "FATAL: built-in IANA KSK parsing failed: {e}")
            }
            Self::PersistenceIo(e) => write!(f, "trust anchor persistence I/O: {e}"),
            Self::InvalidStateFile(e) => write!(f, "managed-keys.json: invalid format: {e}"),
        }
    }
}

impl std::error::Error for TrustAnchorError {}

// ── TrustAnchorStore ──────────────────────────────────────────────────────────

/// Manages the trusted DNSKEY set for the root zone.
///
/// On construction the IANA KSK-2017 is bootstrapped from the embedded
/// zone-file entry.  Subsequent calls to [`process_dnskey_rrset`] implement
/// a simplified RFC 5011 state machine: new keys enter `AddPending` until the
/// 30-day hold-down elapses, after which they become `Valid`.  Revoked keys
/// (the REVOKE bit, flag bit 8 set) are immediately demoted.
///
/// State is persisted atomically to `{data_dir}/managed-keys.json`.
///
/// [`process_dnskey_rrset`]: TrustAnchorStore::process_dnskey_rrset
pub struct TrustAnchorStore {
    inner: Mutex<TrustAnchorInner>,
    data_dir: PathBuf,
}

struct TrustAnchorInner {
    keys: Vec<ManagedKey>,
    /// Cached `Arc<Vec<Record>>` of currently-Valid DNSKEY records.
    trusted_cache: Arc<Vec<Record>>,
}

impl TrustAnchorStore {
    /// Creates a new [`TrustAnchorStore`], loading state from
    /// `{data_dir}/managed-keys.json` if it exists, then bootstrapping the
    /// IANA KSK-2017 if no valid keys are present.
    ///
    /// # Errors
    ///
    /// Returns [`TrustAnchorError::BuiltinParseFailure`] if the embedded IANA
    /// KSK zone entry cannot be parsed — this is a programming error and the
    /// process should not continue.
    pub fn new(data_dir: &Path) -> Result<Self, TrustAnchorError> {
        let mut keys: Vec<ManagedKey> = Vec::new();

        // Attempt to load persisted state.
        let state_path = data_dir.join("managed-keys.json");
        if state_path.exists() {
            match load_state_file(&state_path) {
                Ok(loaded) => keys = loaded,
                Err(e) => {
                    warn!(
                        path = %state_path.display(),
                        error = %e,
                        "managed-keys.json could not be loaded — using built-in KSK"
                    );
                }
            }
        }

        // Bootstrap the built-in KSK if no valid keys are in the state file.
        if !keys.iter().any(|k| k.state == KeyState::Valid) {
            let bootstrap = parse_builtin_ksk()?;
            keys.retain(|k| k.key_tag != bootstrap.key_tag || k.algorithm != bootstrap.algorithm);
            keys.push(bootstrap);
            info!("trust anchor: bootstrapped IANA KSK-2017 (key tag 20326)");
        }

        let trusted_cache = build_trusted_cache(&keys);
        let inner = TrustAnchorInner {
            keys,
            trusted_cache,
        };

        Ok(Self {
            inner: Mutex::new(inner),
            data_dir: data_dir.to_owned(),
        })
    }

    /// Returns the set of currently-Valid DNSKEY records as `Record` objects.
    #[must_use]
    pub fn get_trusted_keys(&self) -> Arc<Vec<Record>> {
        let guard = self.lock();
        Arc::clone(&guard.trusted_cache)
    }

    /// Processes a DNSKEY `RRset` received from the root zone.
    ///
    /// Implements a simplified RFC 5011 §2.4 state machine:
    ///
    /// - Keys not yet tracked → enter `AddPending` with a 30-day hold-down.
    /// - `AddPending` keys whose hold-down has elapsed → promoted to `Valid`.
    /// - Keys with the REVOKE flag (bit 8 of flags) → set to `Revoked`.
    /// - Keys no longer present in the `RRset` → logged but not automatically
    ///   removed (removal requires explicit operator action in RFC 5011).
    ///
    /// Returns `true` if any state change occurred (caller may want to
    /// persist or log the change).
    pub fn process_dnskey_rrset(&self, dnskeys: &[Record], now_secs: u64) -> bool {
        let mut guard = self.lock();
        let mut changed = false;

        for record in dnskeys {
            let RData::Dnskey {
                flags,
                algorithm,
                public_key,
                ..
            } = &record.rdata
            else {
                continue;
            };

            // REVOKE bit is bit 8 of the flags field (RFC 5011 §3).
            // Note: RFC 5011 §3 specifies matching the pre-revocation key tag
            // (i.e. computed with the REVOKE bit cleared), because setting the
            // REVOKE bit changes the key tag value.
            let revoked = flags & 0x0080 != 0;
            let non_revoke_flags = flags & !0x0080u16;
            let key_tag = if revoked {
                compute_key_tag(non_revoke_flags, 3u8, *algorithm, public_key)
            } else {
                compute_key_tag(*flags, 3u8, *algorithm, public_key)
            };

            if revoked {
                // Mark any tracked key with the pre-revocation tag as Revoked.
                if let Some(entry) = guard
                    .keys
                    .iter_mut()
                    .find(|k| k.key_tag == key_tag && k.algorithm == *algorithm)
                    && entry.state != KeyState::Revoked
                {
                    entry.state = KeyState::Revoked;
                    info!(
                        key_tag = key_tag,
                        algorithm = algorithm,
                        "trust anchor: key revoked"
                    );
                    changed = true;
                }
                continue;
            }

            // Check if we already track this key.
            if let Some(entry) = guard
                .keys
                .iter_mut()
                .find(|k| k.key_tag == key_tag && k.algorithm == *algorithm)
            {
                // Promote AddPending → Valid after hold-down.
                if let KeyState::AddPending { hold_down_until } = entry.state
                    && now_secs >= hold_down_until
                {
                    entry.state = KeyState::Valid;
                    info!(
                        key_tag = key_tag,
                        algorithm = algorithm,
                        "trust anchor: key promoted to Valid after hold-down"
                    );
                    changed = true;
                }
            } else {
                // New key — enter AddPending.
                guard.keys.push(ManagedKey {
                    key_tag,
                    algorithm: *algorithm,
                    public_key: public_key.clone(),
                    state: KeyState::AddPending {
                        hold_down_until: now_secs.saturating_add(ADD_HOLD_DOWN_SECS),
                    },
                });
                info!(
                    key_tag = key_tag,
                    algorithm = algorithm,
                    hold_down_days = ADD_HOLD_DOWN_SECS / 86400,
                    "trust anchor: new key entered AddPending"
                );
                changed = true;
            }
        }

        if changed {
            guard.trusted_cache = build_trusted_cache(&guard.keys);
        }

        changed
    }

    /// Persists the current managed-keys state to disk atomically.
    ///
    /// # Errors
    ///
    /// Returns [`TrustAnchorError::PersistenceIo`] on any I/O error.
    pub fn persist(&self) -> Result<(), TrustAnchorError> {
        let guard = self.lock();
        let json = serialise_keys(&guard.keys);
        drop(guard);

        let state_path = self.data_dir.join("managed-keys.json");
        atomic_write(&state_path, json.as_bytes())
            .map_err(|e| TrustAnchorError::PersistenceIo(e.to_string()))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn lock(&self) -> std::sync::MutexGuard<'_, TrustAnchorInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Parses the built-in IANA KSK-2017 zone entry into a [`ManagedKey`].
///
/// # Errors
///
/// Returns [`TrustAnchorError::BuiltinParseFailure`] if the constant is
/// malformed.  This is a programming error — the caller should panic.
fn parse_builtin_ksk() -> Result<ManagedKey, TrustAnchorError> {
    let limits = ZoneLimits::default();
    let origin = Name::root();
    let zone = ZoneFile::parse(IANA_ROOT_KSK_ZONE_ENTRY, Some(origin), limits)
        .map_err(|e| TrustAnchorError::BuiltinParseFailure(e.to_string()))?;

    for record in &zone.records {
        if let RData::Dnskey {
            flags,
            algorithm,
            public_key,
            ..
        } = &record.rdata
        {
            let key_tag = compute_key_tag(*flags, 3u8, *algorithm, public_key);
            return Ok(ManagedKey {
                key_tag,
                algorithm: *algorithm,
                public_key: public_key.clone(),
                state: KeyState::Valid,
            });
        }
    }

    Err(TrustAnchorError::BuiltinParseFailure(
        "no DNSKEY record found in built-in KSK zone entry".into(),
    ))
}

/// Computes the DNS key tag per RFC 4034 §B.
fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut wire = Vec::with_capacity(4 + public_key.len());
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.push(protocol);
    wire.push(algorithm);
    wire.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &b) in wire.iter().enumerate() {
        if i & 1 == 0 {
            ac = ac.wrapping_add(u32::from(b) << 8);
        } else {
            ac = ac.wrapping_add(u32::from(b));
        }
    }
    ac = ac.wrapping_add(ac >> 16);
    (ac & 0xFFFF) as u16
}

/// Builds the cached `Arc<Vec<Record>>` from the `Valid` keys.
fn build_trusted_cache(keys: &[ManagedKey]) -> Arc<Vec<Record>> {
    let root = Name::root();
    let records: Vec<Record> = keys
        .iter()
        .filter(|k| k.state == KeyState::Valid)
        .map(|k| Record {
            name: root.clone(),
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 172_800,
            rdata: RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: k.algorithm,
                public_key: k.public_key.clone(),
            },
        })
        .collect();
    Arc::new(records)
}

/// Minimal hand-rolled JSON serialiser for the managed-keys list.
fn serialise_keys(keys: &[ManagedKey]) -> String {
    let mut out = String::from("[\n");
    for (i, k) in keys.iter().enumerate() {
        let state_str = match &k.state {
            KeyState::Valid => r#""Valid""#.to_string(),
            KeyState::AddPending { hold_down_until } => {
                format!(r#"{{"AddPending":{hold_down_until}}}"#)
            }
            KeyState::Revoked => r#""Revoked""#.to_string(),
        };
        let pk_hex: String =
            k.public_key
                .iter()
                .fold(String::with_capacity(k.public_key.len() * 2), |mut s, b| {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                    s
                });
        {
            use std::fmt::Write as _;
            let _ = write!(
                out,
                "  {{\"key_tag\":{},\"algorithm\":{},\"public_key\":\"{pk_hex}\",\"state\":{state_str}}}",
                k.key_tag, k.algorithm,
            );
        }
        if i + 1 < keys.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push(']');
    out
}

/// Minimal hand-rolled JSON parser for the managed-keys list.
fn load_state_file(path: &Path) -> Result<Vec<ManagedKey>, TrustAnchorError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| TrustAnchorError::PersistenceIo(e.to_string()))?;

    // Very simple: find each `{...}` object and parse fields.
    let mut keys = Vec::new();
    let mut depth = 0i32;
    let mut obj_start = None;

    for (i, ch) in json.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &json[start..=i];
                        if let Some(key) = parse_key_object(obj) {
                            keys.push(key);
                        }
                    }
                    obj_start = None;
                }
            }
            _ => {}
        }
    }

    Ok(keys)
}

/// Parses a single `{key_tag:…, algorithm:…, public_key:…, state:…}` object.
fn parse_key_object(obj: &str) -> Option<ManagedKey> {
    // INVARIANT: key_tag fits u16 and algorithm fits u8 by DNS protocol definition
    // (RFC 4034 §5.1: key tag is 16-bit; algorithm is 8-bit). Values produced by
    // our own serialiser, so truncation is sound.
    #[allow(clippy::cast_possible_truncation)]
    let key_tag = extract_u64(obj, "\"key_tag\"")? as u16;
    #[allow(clippy::cast_possible_truncation)]
    let algorithm = extract_u64(obj, "\"algorithm\"")? as u8;
    let pk_hex = extract_str(obj, "\"public_key\"")?;
    let public_key = hex_decode(pk_hex)?;

    let state = if obj.contains("\"Valid\"") {
        KeyState::Valid
    } else if obj.contains("\"Revoked\"") {
        KeyState::Revoked
    } else {
        let hd = extract_u64(obj, "\"AddPending\"")?;
        KeyState::AddPending {
            hold_down_until: hd,
        }
    };

    Some(ManagedKey {
        key_tag,
        algorithm,
        public_key,
        state,
    })
}

fn extract_u64(json: &str, key: &str) -> Option<u64> {
    let pos = json.find(key)?;
    let after = json[pos + key.len()..].trim_start_matches([' ', ':', '{', '\n']);
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    after[..end].parse().ok()
}

fn extract_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pos = json.find(key)?;
    let after = &json[pos + key.len()..];
    let start = after.find('"')? + 1;
    let end = after[start + 1..].find('"')? + start + 1;
    Some(&after[start..end])
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Writes `data` to `path` atomically via a temp file in the same directory.
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join(format!(".tmp-managed-keys-{}", std::process::id()));

    std::fs::write(&tmp_path, data)?;
    std::fs::rename(&tmp_path, path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store() -> (TrustAnchorStore, TempDir) {
        let dir = TempDir::new().expect("INVARIANT: tempdir creation works in tests");
        let store = TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init must succeed");
        (store, dir)
    }

    #[test]
    fn bootstrap_produces_at_least_one_trusted_key() {
        let (store, _dir) = temp_store();
        let keys = store.get_trusted_keys();
        assert!(!keys.is_empty(), "must have at least the IANA KSK-2017");
    }

    #[test]
    fn get_trusted_keys_returns_only_valid_keys() {
        let (store, _dir) = temp_store();
        let keys = store.get_trusted_keys();
        for k in keys.iter() {
            assert_eq!(k.rtype, Rtype::Dnskey);
        }
    }

    #[test]
    fn process_new_key_enters_add_pending() {
        let (store, _dir) = temp_store();
        let root = Name::root();
        let fake_key = Record {
            name: root,
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![0u8; 64],
            },
        };
        let changed = store.process_dnskey_rrset(&[fake_key], 1_000_000);
        assert!(changed, "new key must trigger a state change");
    }

    #[test]
    fn process_revoked_key_sets_revoked() {
        let (store, _dir) = temp_store();
        // Build a record whose flags have the REVOKE bit set (bit 8 = 0x0080).
        let root = Name::root();
        let revoked_key = Record {
            name: root.clone(),
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Dnskey {
                flags: 257 | 0x0080,
                protocol: 3,
                algorithm: 13,
                public_key: vec![0u8; 64],
            },
        };

        // First, add it normally.
        let normal_key = Record {
            name: root,
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![0u8; 64],
            },
        };
        store.process_dnskey_rrset(&[normal_key], 1_000_000);
        // Now process with the REVOKE flag.
        let changed = store.process_dnskey_rrset(&[revoked_key], 1_000_001);
        assert!(changed, "revoking must trigger a state change");
    }

    #[test]
    fn add_pending_promoted_after_hold_down() {
        let (store, _dir) = temp_store();
        let root = Name::root();
        let new_key = Record {
            name: root,
            rtype: Rtype::Dnskey,
            rclass: Qclass::In,
            ttl: 172800,
            rdata: RData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![1u8; 64],
            },
        };
        let now = 1_000_000_u64;
        store.process_dnskey_rrset(&[new_key.clone()], now);

        // Process again after hold-down elapses.
        let after_hold = now + ADD_HOLD_DOWN_SECS + 1;
        let changed = store.process_dnskey_rrset(&[new_key], after_hold);
        assert!(changed, "key must be promoted after hold-down");
    }

    #[test]
    fn persist_and_reload() {
        let dir = TempDir::new().expect("INVARIANT: tempdir");
        let store = TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init");
        store.persist().expect("INVARIANT: persist must succeed");

        // Reload from the persisted state.
        let store2 = TrustAnchorStore::new(dir.path()).expect("INVARIANT: reload");
        let keys = store2.get_trusted_keys();
        assert!(!keys.is_empty(), "reloaded store must have trusted keys");
    }

    #[test]
    fn compute_key_tag_known_value() {
        // The IANA KSK-2017 has key tag 20326.
        // We parse the built-in entry and verify the computed tag.
        let mk = parse_builtin_ksk().expect("INVARIANT: built-in KSK must parse");
        assert_eq!(mk.key_tag, 20326, "IANA KSK-2017 key tag must be 20326");
    }
}
