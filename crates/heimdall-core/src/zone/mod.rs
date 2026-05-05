// SPDX-License-Identifier: MIT

//! RFC 1035 §5 zone-file parser for the Heimdall DNS server (Sprint 15).
//!
//! # Modules
//!
//! - [`tokenizer`] — hand-rolled tokenizer producing [`tokenizer::Token`]s.
//! - [`parser`] — directive and RR parser producing [`crate::record::Record`]s.
//! - [`directives`] — `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE` handlers.
//! - [`limits`] — [`ZoneLimits`] and [`LimitKind`] for zone-size enforcement.
//! - [`integrity`] — load-time DNSSEC signature verification.
//!
//! # Example
//!
//! ```rust
//! use heimdall_core::zone::{ZoneFile, ZoneLimits};
//!
//! let src = "\
//! $ORIGIN example.com.\n\
//! $TTL 3600\n\
//! @ IN SOA ns1 hostmaster 1 3600 900 604800 300\n\
//! @ IN NS ns1\n\
//! ns1 IN A 192.0.2.1\n\
//! ";
//! let zone = ZoneFile::parse(src, None, ZoneLimits::default()).unwrap();
//! assert_eq!(zone.records.len(), 3);
//! ```

pub mod directives;
pub mod integrity;
pub mod limits;
pub mod parser;
pub mod tokenizer;

use std::{
    fmt,
    path::{Path, PathBuf},
};

pub use integrity::{IntegrityError, verify_zone_signatures};
use integrity::{drain_dangling_rrsigs, verify_zone_integrity};
pub use limits::{LimitKind, ZoneLimits};

use crate::{name::Name, record::Record};

// ── ZoneError ─────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a zone file.
#[derive(Debug, Clone)]
pub enum ZoneError {
    /// A tokenizer error (unterminated string, bad escape, unmatched paren).
    Tokenize {
        /// The physical line number where the error occurred.
        line: usize,
        /// A static description of the error.
        msg: &'static str,
    },
    /// A directive that is not recognised.
    UnknownDirective {
        /// Line number.
        line: usize,
        /// The unrecognised directive string.
        directive: String,
    },
    /// A resource record type that is not recognised.
    UnknownType {
        /// Line number.
        line: usize,
        /// The unrecognised type string.
        rtype: String,
    },
    /// RDATA could not be parsed for the given type.
    ParseRdata {
        /// Line number.
        line: usize,
        /// The record type name.
        rtype: String,
        /// Human-readable explanation.
        reason: String,
    },
    /// A `$INCLUDE` file forms a cycle with an ancestor.
    IncludeCycle {
        /// The path that was already open.
        path: PathBuf,
    },
    /// `$INCLUDE` nesting exceeded the configured maximum.
    IncludeDepthExceeded,
    /// A zone-size limit was exceeded.
    ZoneSizeLimit(LimitKind),
    /// A domain name could not be constructed.
    InvalidName {
        /// Line number.
        line: usize,
        /// Human-readable explanation.
        reason: String,
    },
    /// A relative name appeared but no `$ORIGIN` is in effect.
    MissingOrigin {
        /// Line number.
        line: usize,
    },
    /// A blank-owner line appeared before any owner was established.
    MissingOwner {
        /// Line number.
        line: usize,
    },
    /// A `$GENERATE` directive would produce more records than the limit allows.
    GenerateOverflow {
        /// Line number.
        line: usize,
    },
    /// A filesystem I/O error (from `$INCLUDE` file reads).
    Io(String),
    /// A DNSSEC integrity check failed after zone load.
    IntegrityError(IntegrityError),
    /// Zone file has an unsupported format (PROTO-101).
    UnsupportedFormat {
        /// The file extension that triggered the rejection.
        extension: String,
    },
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tokenize { line, msg } => write!(f, "line {line}: tokenizer error: {msg}"),
            Self::UnknownDirective { line, directive } => {
                write!(f, "line {line}: unknown directive: {directive}")
            }
            Self::UnknownType { line, rtype } => {
                write!(f, "line {line}: unknown RR type: {rtype}")
            }
            Self::ParseRdata {
                line,
                rtype,
                reason,
            } => {
                write!(f, "line {line}: failed to parse {rtype} RDATA: {reason}")
            }
            Self::IncludeCycle { path } => {
                write!(f, "$INCLUDE cycle detected: {}", path.display())
            }
            Self::IncludeDepthExceeded => write!(f, "$INCLUDE nesting depth limit exceeded"),
            Self::ZoneSizeLimit(k) => write!(f, "zone size limit: {k}"),
            Self::InvalidName { line, reason } => {
                write!(f, "line {line}: invalid domain name: {reason}")
            }
            Self::MissingOrigin { line } => {
                write!(f, "line {line}: relative name used but $ORIGIN is not set")
            }
            Self::MissingOwner { line } => {
                write!(
                    f,
                    "line {line}: blank-owner line before any owner was established"
                )
            }
            Self::GenerateOverflow { line } => {
                write!(
                    f,
                    "line {line}: $GENERATE expansion would exceed record limit"
                )
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::IntegrityError(e) => write!(f, "DNSSEC integrity error: {e}"),
            Self::UnsupportedFormat { extension } => {
                write!(
                    f,
                    "zone file format '.{extension}' is not supported (PROTO-101): only RFC 1035 zone files are accepted"
                )
            }
        }
    }
}

impl std::error::Error for ZoneError {}

impl From<std::io::Error> for ZoneError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<IntegrityError> for ZoneError {
    fn from(e: IntegrityError) -> Self {
        Self::IntegrityError(e)
    }
}

// ── ZoneFile ──────────────────────────────────────────────────────────────────

/// A parsed DNS zone file.
///
/// Contains the flat list of resource records and the effective `$ORIGIN`
/// (if one was established by a directive or passed as `origin` to [`parse`]).
///
/// [`parse`]: ZoneFile::parse
#[derive(Debug, Clone)]
pub struct ZoneFile {
    /// All resource records in file order.
    pub records: Vec<Record>,
    /// The final effective `$ORIGIN` after parsing, if any was established.
    pub origin: Option<Name>,
    /// Number of RRSIG records that were silently dropped at load time because
    /// they covered a type absent from the zone (DNSSEC-076).  Non-zero values
    /// should be logged as warnings by the caller.
    pub dangling_rrsig_count: usize,
}

impl ZoneFile {
    /// Parses zone-file text.
    ///
    /// `origin` is the default `$ORIGIN` used for relative names if no
    /// `$ORIGIN` directive appears first.  `limits` controls resource-
    /// exhaustion guards.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError`] on any tokenizer, parser, directive, or size-limit
    /// error encountered during parsing.
    pub fn parse(src: &str, origin: Option<Name>, limits: ZoneLimits) -> Result<Self, ZoneError> {
        // Zone-size guard: check the raw byte length before any allocation.
        if src.len() > limits.max_zone_size_bytes {
            return Err(ZoneError::ZoneSizeLimit(LimitKind::ZoneSizeBytes));
        }

        let mut zp = parser::ZoneParser::new(src, origin, limits, vec![]);
        let mut records = zp.parse_all()?;
        let origin = zp.origin().cloned();
        let dangling_rrsig_count = drain_dangling_rrsigs(&mut records).len();
        verify_zone_integrity(&records, origin.as_ref())?;
        Ok(Self {
            records,
            origin,
            dangling_rrsig_count,
        })
    }

    /// Parses a zone file from a filesystem path.
    ///
    /// Rejects files whose extension is `.json`, `.yaml`, or `.yml` per
    /// PROTO-101 before attempting to parse the content.
    ///
    /// # Errors
    ///
    /// Returns [`ZoneError::UnsupportedFormat`] for JSON/YAML extensions,
    /// [`ZoneError::Io`] if the file cannot be read, or any parse or
    /// integrity error encountered while processing the file's contents.
    pub fn parse_file(
        path: &Path,
        origin: Option<Name>,
        limits: ZoneLimits,
    ) -> Result<Self, ZoneError> {
        // PROTO-101: JSON, YAML, and other structured-data formats are not
        // supported as zone file sources.
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_ascii_lowercase();
            if matches!(ext_lower.as_str(), "json" | "yaml" | "yml") {
                return Err(ZoneError::UnsupportedFormat {
                    extension: ext_lower,
                });
            }
        }

        let src = std::fs::read_to_string(path)?;
        // Canonicalise the path so the cycle-detection set works reliably.
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let include_stack = vec![canonical];

        if src.len() > limits.max_zone_size_bytes {
            return Err(ZoneError::ZoneSizeLimit(LimitKind::ZoneSizeBytes));
        }

        let mut zp = parser::ZoneParser::new(&src, origin, limits, include_stack);
        let mut records = zp.parse_all()?;
        let origin = zp.origin().cloned();
        let dangling_rrsig_count = drain_dangling_rrsigs(&mut records).len();
        verify_zone_integrity(&records, origin.as_ref())?;
        Ok(Self {
            records,
            origin,
            dangling_rrsig_count,
        })
    }
}
