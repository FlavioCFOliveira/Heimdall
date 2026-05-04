// SPDX-License-Identifier: MIT

//! THREAT-143 structured anomaly event base-envelope helpers.
//!
//! Every anomaly event emitted by Heimdall MUST carry the base-envelope fields
//! defined in THREAT-143: `schema_version`, `event_type`, `correlation_id`, and
//! `instance.*` sub-fields (`instance_node`, `instance_version`).  This module
//! provides the non-event-specific fields so each call site does not repeat
//! them.
//!
//! Call-site pattern:
//!
//! ```ignore
//! use crate::ops::anomaly;
//!
//! let cid = anomaly::next_correlation_id();
//! tracing::warn!(
//!     schema_version = anomaly::SCHEMA_VERSION,
//!     event_type     = "acl-deny",
//!     correlation_id = %cid,
//!     instance_node  = anomaly::instance_node(),
//!     instance_version = anomaly::INSTANCE_VERSION,
//!     // event-specific fields …
//!     "ACL deny",
//! );
//! ```

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// THREAT-143 schema version.  Increment this string when the base envelope
/// changes in a backward-incompatible way.
pub const SCHEMA_VERSION: &str = "1.0";

/// Heimdall release version, embedded at compile time from `Cargo.toml`.
pub const INSTANCE_VERSION: &str = env!("CARGO_PKG_VERSION");

static COUNTER: AtomicU64 = AtomicU64::new(0);
static NODE: OnceLock<String> = OnceLock::new();

/// Returns the next per-process monotonic correlation ID (THREAT-143).
///
/// The ID is 24 lower-case hexadecimal characters: the current millisecond
/// timestamp (16 hex digits) concatenated with a monotonically increasing
/// per-process counter (8 hex digits).  This satisfies the "ULID or equivalent
/// monotonic identifier" requirement of THREAT-143 without adding an external
/// crate dependency.
#[must_use]
pub fn next_correlation_id() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{ms:016x}{n:08x}")
}

/// Returns the OS hostname of this instance (fetched once and cached).
///
/// Reads from the `HOSTNAME` environment variable first (set automatically
/// in most container environments); falls back to reading `/etc/hostname`;
/// returns `"unknown"` if both fail.
#[must_use]
pub fn instance_node() -> &'static str {
    NODE.get_or_init(|| {
        if let Ok(h) = std::env::var("HOSTNAME") {
            if !h.is_empty() {
                return h;
            }
        }
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = h.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
        "unknown".to_owned()
    })
}
