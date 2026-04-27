// SPDX-License-Identifier: MIT

//! Zone lifecycle admin hooks — task #304.
//!
//! Provides structured operations for adding, removing, and hot-reloading
//! authoritative zones.  Each operation parses/validates the zone file and
//! emits a structured [`tracing`] audit event.
//!
//! Redis integration (write-to-staging + RENAME) is the canonical zone-store
//! path (`STORE-023`).  In Sprint 26, the lifecycle operations work on
//! in-memory [`ZoneFile`]s.  The `RedisStore` write path is wired in the next
//! sprint when the role ↔ store API is finalised.

use std::path::{Path, PathBuf};

use heimdall_core::name::Name;
use heimdall_core::zone::{ZoneFile, ZoneLimits};
use tracing::info;

use crate::auth::AuthError;
use crate::auth::zone_role::ZoneRole;

// ── ZoneLifecycle ─────────────────────────────────────────────────────────────

/// Admin interface for zone lifecycle operations.
///
/// Each operation parses the zone file from `zone_file_base_path / <apex>.zone`,
/// validates it against `limits`, and emits a structured audit event.
#[derive(Debug, Clone)]
pub struct ZoneLifecycle {
    /// Base directory where zone files live (`<apex>.zone` naming convention).
    pub zone_file_base_path: PathBuf,
    /// Zone-size and record-count limits applied on every parse.
    pub limits: ZoneLimits,
}

impl ZoneLifecycle {
    /// Creates a new [`ZoneLifecycle`] with the given base path and limits.
    #[must_use]
    pub fn new(zone_file_base_path: impl Into<PathBuf>, limits: ZoneLimits) -> Self {
        Self {
            zone_file_base_path: zone_file_base_path.into(),
            limits,
        }
    }

    /// Adds a new zone.
    ///
    /// Parses `file`, validates it, and emits an audit event.  In Sprint 26
    /// the parsed zone is returned for the caller to store in Redis.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ZoneParse`] on parse failure or
    /// [`AuthError::Io`] on file-read error.
    pub fn add_zone(
        &self,
        apex: &Name,
        file: &Path,
        role: &ZoneRole,
    ) -> Result<ZoneFile, AuthError> {
        let zone = self.parse_zone_file(apex, file)?;
        info!(
            zone = %apex,
            ?role,
            records = zone.records.len(),
            path = %file.display(),
            "lifecycle: zone added"
        );
        Ok(zone)
    }

    /// Removes a zone.
    ///
    /// In Sprint 26, emits an audit event; Redis `DEL` is wired later.
    ///
    /// # Errors
    ///
    /// Never returns an error in Sprint 26 (no store wired yet).
    pub fn remove_zone(&self, apex: &Name) -> Result<(), AuthError> {
        info!(zone = %apex, "lifecycle: zone removed");
        Ok(())
    }

    /// Hot-reloads a zone.
    ///
    /// Re-parses the zone file from `zone_file_base_path / <apex_filename>.zone`
    /// and emits an audit event.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ZoneParse`] on parse failure or
    /// [`AuthError::Io`] on file-read error.
    pub fn reload_zone(&self, apex: &Name) -> Result<ZoneFile, AuthError> {
        let filename = apex_to_filename(apex);
        let file = self.zone_file_base_path.join(&filename);
        let zone = self.parse_zone_file(apex, &file)?;
        info!(
            zone = %apex,
            records = zone.records.len(),
            path = %file.display(),
            "lifecycle: zone reloaded"
        );
        Ok(zone)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn parse_zone_file(&self, apex: &Name, file: &Path) -> Result<ZoneFile, AuthError> {
        let src = std::fs::read_to_string(file).map_err(|e| AuthError::Io(e.to_string()))?;
        ZoneFile::parse(&src, Some(apex.clone()), self.limits.clone())
            .map_err(|e| AuthError::ZoneParse(e.to_string()))
    }
}

/// Converts a zone apex to a safe filename fragment.
///
/// `example.com.` → `example.com.zone`
fn apex_to_filename(apex: &Name) -> String {
    let s = apex.to_string();
    let trimmed = s.trim_end_matches('.');
    format!("{trimmed}.zone")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn test_apex() -> Name {
        Name::from_str("example.com.").expect("INVARIANT: valid test name")
    }

    #[test]
    fn apex_to_filename_strips_trailing_dot() {
        let name = test_apex();
        assert_eq!(apex_to_filename(&name), "example.com.zone");
    }

    #[test]
    fn add_zone_parses_file() {
        let tmp = tempfile_with_content(
            "\
$ORIGIN example.com.\n\
$TTL 3600\n\
@ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
@ IN NS ns1\n\
ns1 IN A 192.0.2.1\n\
",
        );
        let apex = test_apex();
        let lc = ZoneLifecycle::new(
            tmp.parent().expect("INVARIANT: parent exists"),
            ZoneLimits::default(),
        );
        let zone = lc
            .add_zone(&apex, &tmp, &ZoneRole::Primary)
            .expect("add_zone must succeed");
        assert_eq!(zone.records.len(), 3);
    }

    #[test]
    fn add_zone_fails_on_parse_error() {
        let tmp = tempfile_with_content("NOT VALID ZONE DATA\n");
        let apex = test_apex();
        let lc = ZoneLifecycle::new(
            tmp.parent().expect("INVARIANT: parent exists"),
            ZoneLimits::default(),
        );
        let result = lc.add_zone(&apex, &tmp, &ZoneRole::Primary);
        assert!(result.is_err());
    }

    #[test]
    fn remove_zone_emits_no_error() {
        let lc = ZoneLifecycle::new("/tmp", ZoneLimits::default());
        let result = lc.remove_zone(&test_apex());
        assert!(result.is_ok());
    }

    /// Create a temporary file with the given content.  Caller must keep the
    /// `NamedTempFile` alive for the duration of the test.
    fn tempfile_with_content(content: &str) -> PathBuf {
        use std::io::Write;
        let mut tmp = tempfile::Builder::new()
            .suffix(".zone")
            .tempfile()
            .expect("INVARIANT: temp file must be creatable");
        tmp.write_all(content.as_bytes())
            .expect("INVARIANT: write must succeed");
        tmp.into_temp_path()
            .keep()
            .expect("INVARIANT: keep must succeed")
    }
}
