// SPDX-License-Identifier: MIT

//! Zone-size enforcement limits (Task #218).
//!
//! [`ZoneLimits`] carries all configurable upper bounds for zone-file parsing.
//! Every limit is checked incrementally as records are produced; none are
//! evaluated only at the end.

use std::fmt;

// ── LimitKind ─────────────────────────────────────────────────────────────────

/// Identifies which limit was exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitKind {
    /// Total resource record count exceeded [`ZoneLimits::max_records`].
    RecordCount,
    /// RRSIG record count exceeded [`ZoneLimits::max_rrsig_records`].
    RrsigCount,
    /// NS record count exceeded [`ZoneLimits::max_ns_records`].
    NsCount,
    /// Nested `$INCLUDE` depth exceeded [`ZoneLimits::max_include_depth`].
    IncludeDepth,
    /// `$GENERATE` expansion would exceed [`ZoneLimits::max_generate_records`].
    GenerateRecords,
    /// Source text length exceeds [`ZoneLimits::max_zone_size_bytes`].
    ZoneSizeBytes,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordCount => write!(f, "record count limit exceeded"),
            Self::RrsigCount => write!(f, "RRSIG record count limit exceeded"),
            Self::NsCount => write!(f, "NS record count limit exceeded"),
            Self::IncludeDepth => write!(f, "$INCLUDE nesting depth limit exceeded"),
            Self::GenerateRecords => write!(f, "$GENERATE expansion record limit exceeded"),
            Self::ZoneSizeBytes => write!(f, "zone source text size limit exceeded"),
        }
    }
}

// ── ZoneLimits ────────────────────────────────────────────────────────────────

/// Configurable upper bounds for zone-file parsing.
///
/// All defaults are conservative but suitable for large production zones.
/// Callers that need stricter or looser limits can construct this directly.
///
/// # Security note
///
/// These limits guard against resource-exhaustion attacks (THREAT-067 and
/// related threats): a maliciously crafted zone file could otherwise consume
/// unbounded memory or CPU.
#[derive(Debug, Clone)]
pub struct ZoneLimits {
    /// Maximum total resource record count.  Default: 5,000,000.
    pub max_records: usize,
    /// Maximum RRSIG record count.  Default: 10,000,000.
    pub max_rrsig_records: usize,
    /// Maximum NS record count.  Default: 1,000.
    pub max_ns_records: usize,
    /// Maximum `$INCLUDE` nesting depth.  Default: 8.
    pub max_include_depth: usize,
    /// Maximum records produced by a single `$GENERATE` directive.  Default: 10,000.
    pub max_generate_records: u32,
    /// Maximum zone source text length in bytes.  Default: 100,000,000 (100 MiB).
    pub max_zone_size_bytes: usize,
}

impl Default for ZoneLimits {
    fn default() -> Self {
        Self {
            max_records: 5_000_000,
            max_rrsig_records: 10_000_000,
            max_ns_records: 1_000,
            max_include_depth: 8,
            max_generate_records: 10_000,
            max_zone_size_bytes: 100_000_000,
        }
    }
}
