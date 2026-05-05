// SPDX-License-Identifier: MIT

//! DNSSEC validator for the forwarder role (DNSSEC-019..024, Task #333).
//!
//! [`ForwarderValidator`] wraps the [`ResponseValidator`] from the recursive
//! role and applies the same trust-anchor + NTA state (DNSSEC-023).
//!
//! # Key rule (DNSSEC-019)
//!
//! The upstream's AD bit is **never** trusted.  The local DNSSEC validation
//! result is the sole determinant of whether the response's AD flag is set.
//! A response with `AD=1` from an upstream resolver is treated identically to
//! one with `AD=0`; only the RRSIG records in the message body matter.

use std::sync::Arc;

use heimdall_core::{dnssec::verify::ValidationOutcome, name::Name, parser::Message};

use crate::{
    dnssec_roles::{NtaStore, TrustAnchorStore},
    recursive::validate::ResponseValidator,
};

// ── ForwarderValidator ────────────────────────────────────────────────────────

/// DNSSEC validator for the forwarder role.
///
/// Wraps [`ResponseValidator`] (shared trust-anchor + NTA state per
/// DNSSEC-023).  The forwarder validates independently of any upstream DNSSEC
/// claim.
pub struct ForwarderValidator {
    inner: ResponseValidator,
}

impl ForwarderValidator {
    /// Creates a new [`ForwarderValidator`].
    #[must_use]
    pub fn new(trust_anchor: Arc<TrustAnchorStore>, nta_store: Arc<NtaStore>) -> Self {
        Self {
            inner: ResponseValidator::new(trust_anchor, nta_store),
        }
    }

    /// Validates DNSSEC signatures in `msg` against the trust anchor and NTAs.
    ///
    /// DNSSEC-019: the upstream's AD bit is ignored.  `msg` is validated
    /// entirely from its RRSIG records.
    ///
    /// `zone_apex` is used for NTA checking.
    /// `now_secs` is the current Unix timestamp for validity-period checks.
    #[must_use]
    pub fn validate(&self, msg: &Message, zone_apex: &Name, now_secs: u32) -> ValidationOutcome {
        self.inner.validate(msg, zone_apex, now_secs)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::Header;

    use super::*;
    use crate::dnssec_roles::{NtaStore, TrustAnchorStore};

    fn make_validator() -> ForwarderValidator {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        let nta_store = Arc::new(NtaStore::new(100));
        std::mem::forget(dir);
        ForwarderValidator::new(trust_anchor, nta_store)
    }

    fn empty_msg_with_ad() -> Message {
        let mut header = Header::default();
        // Set AD bit as if an upstream claimed the response is secure.
        header.set_ad(true);
        Message {
            header,
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn upstream_ad_bit_not_trusted_returns_insecure() {
        let validator = make_validator();
        let msg = empty_msg_with_ad();
        let zone = Name::from_str("example.com.").expect("INVARIANT: valid name");

        // Message has AD=1 but no RRSIG records — must return Insecure, not Secure.
        let outcome = validator.validate(&msg, &zone, 1_000_000);
        assert_eq!(
            outcome,
            ValidationOutcome::Insecure,
            "upstream AD bit must not be trusted — validation must be Insecure without RRSIGs"
        );
    }

    #[test]
    fn unsigned_response_returns_insecure() {
        let validator = make_validator();
        let msg = Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        };
        let zone = Name::root();
        let outcome = validator.validate(&msg, &zone, 1_000_000);
        assert_eq!(outcome, ValidationOutcome::Insecure);
    }
}
