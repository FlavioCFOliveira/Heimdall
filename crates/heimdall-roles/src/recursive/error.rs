// SPDX-License-Identifier: MIT

//! Error mapping for the recursive resolver role.
//!
//! [`RecursiveError`] captures all failure modes that can arise during iterative
//! resolution and maps each to the appropriate DNS RCODE and optional Extended
//! DNS Error (EDE) info-code (RFC 8914).

use heimdall_core::{edns::ede_code, header::Rcode};

// ── RecursiveError ─────────────────────────────────────────────────────────────

/// Errors that can arise during recursive query resolution.
///
/// Each variant maps to a DNS RCODE and, where appropriate, an Extended DNS
/// Error info-code (RFC 8914 §5.2).
#[derive(Debug)]
#[non_exhaustive]
pub enum RecursiveError {
    /// The query was denied by the ACL policy.
    ///
    /// Maps to `REFUSED`. No EDE code is included to avoid leaking policy.
    AclDeny,

    /// DNSSEC validation returned a `Bogus` result.
    ///
    /// Maps to `SERVFAIL` + EDE 6 (DNSSEC Bogus).
    BogusValidation {
        /// Human-readable reason for the bogus outcome.
        reason: String,
    },

    /// An upstream query timed out and the budget was exhausted.
    ///
    /// Maps to `SERVFAIL` + EDE 22 (No Reachable Authority).
    QueryTimeout {
        /// Elapsed milliseconds at the point of exhaustion.
        elapsed_ms: u64,
    },

    /// Every reachable upstream returned `REFUSED`.
    ///
    /// Maps to `SERVFAIL` + EDE 20 (Not Authoritative).
    UpstreamRefused,

    /// Every reachable upstream returned `SERVFAIL`.
    ///
    /// Maps to `SERVFAIL` + EDE 2 (SERVFAIL).
    UpstreamServFail,

    /// The queried name does not exist (NXDOMAIN).
    ///
    /// Maps to `NXDOMAIN`. No EDE code.
    NxDomain,

    /// The name exists but has no data of the requested type (NODATA).
    ///
    /// Maps to `NOERROR`. No EDE code.
    NoData,

    /// The delegation chain exceeded [`MAX_DELEGATION_DEPTH`].
    ///
    /// Maps to `SERVFAIL` + EDE 22 (No Reachable Authority).
    ///
    /// [`MAX_DELEGATION_DEPTH`]: crate::recursive::follow::MAX_DELEGATION_DEPTH
    MaxDelegationsExceeded,

    /// The CNAME chain exceeded [`MAX_CNAME_HOPS`].
    ///
    /// Maps to `SERVFAIL` + EDE 22 (No Reachable Authority).
    ///
    /// [`MAX_CNAME_HOPS`]: crate::recursive::follow::MAX_CNAME_HOPS
    MaxCnameHopsExceeded,

    /// No trust anchor DNSKEY was found for validation.
    ///
    /// Maps to `SERVFAIL` + EDE 9 (DNSKEY Missing).
    TrustAnchorNotFound,

    /// A cache read or write operation failed.
    ///
    /// Maps to `SERVFAIL`.
    CacheError(String),
}

impl RecursiveError {
    /// Returns the DNS RCODE appropriate for this error.
    #[must_use]
    pub fn to_rcode(&self) -> Rcode {
        match self {
            Self::AclDeny => Rcode::Refused,
            Self::NxDomain => Rcode::NxDomain,
            Self::NoData => Rcode::NoError,
            Self::BogusValidation { .. }
            | Self::QueryTimeout { .. }
            | Self::UpstreamRefused
            | Self::UpstreamServFail
            | Self::MaxDelegationsExceeded
            | Self::MaxCnameHopsExceeded
            | Self::TrustAnchorNotFound
            | Self::CacheError(_) => Rcode::ServFail,
        }
    }

    /// Returns the RFC 8914 Extended DNS Error info-code for this error, if any.
    ///
    /// `AclDeny` returns `None` deliberately to avoid leaking internal policy
    /// information to external clients.
    #[must_use]
    pub fn to_ede_code(&self) -> Option<u16> {
        match self {
            // AclDeny intentionally returns None — avoid leaking policy details.
            Self::AclDeny | Self::NxDomain | Self::NoData | Self::CacheError(_) => None,
            Self::BogusValidation { .. } => Some(ede_code::DNSSEC_BOGUS),
            Self::QueryTimeout { .. } => Some(ede_code::NO_REACHABLE_AUTHORITY),
            Self::UpstreamRefused => Some(ede_code::NOT_AUTHORITATIVE),
            Self::UpstreamServFail => Some(ede_code::UNSUPPORTED_DS_DIGEST_TYPE), // EDE 2
            Self::MaxDelegationsExceeded | Self::MaxCnameHopsExceeded => {
                Some(ede_code::NO_REACHABLE_AUTHORITY)
            }
            Self::TrustAnchorNotFound => Some(ede_code::DNSKEY_MISSING),
        }
    }

    /// Returns `false` unconditionally: errors never set the AD (Authentic Data) bit.
    ///
    /// Per DNSSEC-008, the AD bit MUST NOT be set on any error response.
    #[must_use]
    pub fn should_set_ad(&self) -> bool {
        false
    }
}

impl std::fmt::Display for RecursiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AclDeny => write!(f, "query denied by ACL"),
            Self::BogusValidation { reason } => {
                write!(f, "DNSSEC validation failed (bogus): {reason}")
            }
            Self::QueryTimeout { elapsed_ms } => {
                write!(f, "query timed out after {elapsed_ms} ms")
            }
            Self::UpstreamRefused => write!(f, "all upstream servers refused the query"),
            Self::UpstreamServFail => write!(f, "all upstream servers returned SERVFAIL"),
            Self::NxDomain => write!(f, "non-existent domain"),
            Self::NoData => write!(f, "no data of requested type"),
            Self::MaxDelegationsExceeded => write!(f, "maximum delegation depth exceeded"),
            Self::MaxCnameHopsExceeded => write!(f, "maximum CNAME hop count exceeded"),
            Self::TrustAnchorNotFound => write!(f, "no trust anchor DNSKEY found"),
            Self::CacheError(msg) => write!(f, "cache error: {msg}"),
        }
    }
}

impl std::error::Error for RecursiveError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_deny_maps_to_refused_no_ede() {
        let err = RecursiveError::AclDeny;
        assert_eq!(err.to_rcode(), Rcode::Refused);
        assert_eq!(err.to_ede_code(), None);
        assert!(!err.should_set_ad());
    }

    #[test]
    fn bogus_validation_maps_to_servfail_ede6() {
        let err = RecursiveError::BogusValidation {
            reason: "expired".into(),
        };
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::DNSSEC_BOGUS));
    }

    #[test]
    fn query_timeout_maps_to_servfail_ede22() {
        let err = RecursiveError::QueryTimeout { elapsed_ms: 5000 };
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::NO_REACHABLE_AUTHORITY));
    }

    #[test]
    fn upstream_refused_maps_to_servfail_ede20() {
        let err = RecursiveError::UpstreamRefused;
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::NOT_AUTHORITATIVE));
    }

    #[test]
    fn upstream_servfail_maps_to_servfail_ede2() {
        let err = RecursiveError::UpstreamServFail;
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        // EDE code 2 (UNSUPPORTED_DS_DIGEST_TYPE constant value = 2)
        assert_eq!(err.to_ede_code(), Some(2));
    }

    #[test]
    fn nxdomain_maps_to_nxdomain_no_ede() {
        let err = RecursiveError::NxDomain;
        assert_eq!(err.to_rcode(), Rcode::NxDomain);
        assert_eq!(err.to_ede_code(), None);
    }

    #[test]
    fn nodata_maps_to_noerror_no_ede() {
        let err = RecursiveError::NoData;
        assert_eq!(err.to_rcode(), Rcode::NoError);
        assert_eq!(err.to_ede_code(), None);
    }

    #[test]
    fn max_delegations_exceeded_maps_to_servfail_ede22() {
        let err = RecursiveError::MaxDelegationsExceeded;
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::NO_REACHABLE_AUTHORITY));
    }

    #[test]
    fn max_cname_hops_exceeded_maps_to_servfail_ede22() {
        let err = RecursiveError::MaxCnameHopsExceeded;
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::NO_REACHABLE_AUTHORITY));
    }

    #[test]
    fn trust_anchor_not_found_maps_to_servfail_ede9() {
        let err = RecursiveError::TrustAnchorNotFound;
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), Some(ede_code::DNSKEY_MISSING));
    }

    #[test]
    fn cache_error_maps_to_servfail_no_ede() {
        let err = RecursiveError::CacheError("disk full".into());
        assert_eq!(err.to_rcode(), Rcode::ServFail);
        assert_eq!(err.to_ede_code(), None);
    }

    #[test]
    fn display_not_empty_for_all_variants() {
        let errs: Vec<RecursiveError> = vec![
            RecursiveError::AclDeny,
            RecursiveError::BogusValidation { reason: "x".into() },
            RecursiveError::QueryTimeout { elapsed_ms: 1000 },
            RecursiveError::UpstreamRefused,
            RecursiveError::UpstreamServFail,
            RecursiveError::NxDomain,
            RecursiveError::NoData,
            RecursiveError::MaxDelegationsExceeded,
            RecursiveError::MaxCnameHopsExceeded,
            RecursiveError::TrustAnchorNotFound,
            RecursiveError::CacheError("y".into()),
        ];
        for e in &errs {
            assert!(
                !e.to_string().is_empty(),
                "Display must not be empty for {e:?}"
            );
        }
    }
}
