// SPDX-License-Identifier: MIT

//! DNSSEC validator wiring for the recursive resolver role.
//!
//! [`ResponseValidator`] connects the DNSSEC validation primitives from
//! `heimdall-core` with the trust anchor and NTA stores to produce a
//! [`ValidationOutcome`] for each response message.

use std::sync::Arc;

use heimdall_core::dnssec::algorithms::DnsAlgorithm;
use heimdall_core::dnssec::budget::ValidationBudget;
use heimdall_core::dnssec::verify::{
    BogusReason, KEY_LIMIT, SIG_LIMIT, ValidationOutcome, verify_rrsig_with_budget,
};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use tracing::warn;

use crate::dnssec_roles::{NtaStore, TrustAnchorStore};

// ── ResponseValidator ─────────────────────────────────────────────────────────

/// Validates a DNS response message using DNSSEC trust anchors and NTAs.
///
/// The validation algorithm:
///
/// 1. If the queried name has an active NTA → return `Insecure`.
/// 2. Retrieve trusted DNSKEYs from the `TrustAnchorStore`.
/// 3. If no DNSKEY and no RRSIG records are present → `Insecure` (unsigned).
/// 4. Enforce RRSIG count ≤ [`SIG_LIMIT`] (8); excess → `Bogus(KeyTrapLimit)`.
/// 5. Run `verify_rrsig` on each RRSIG with a bounded [`ValidationBudget`]
///    (100 ms wall time, [`KEY_LIMIT`] = 4 key attempts per RRSIG).
/// 6. Aggregate: any `Bogus` → return `Bogus`; all `Secure` → `Secure`;
///    otherwise `Insecure`.
pub struct ResponseValidator {
    trust_anchor: Arc<TrustAnchorStore>,
    nta_store: Arc<NtaStore>,
}

impl ResponseValidator {
    /// Creates a new [`ResponseValidator`].
    #[must_use]
    pub fn new(trust_anchor: Arc<TrustAnchorStore>, nta_store: Arc<NtaStore>) -> Self {
        Self {
            trust_anchor,
            nta_store,
        }
    }

    /// Validates all signatures in `msg` against the trust anchor.
    ///
    /// `zone_apex` is used for NTA checking.
    /// `now_secs` is the current Unix timestamp for validity-period checks.
    #[must_use]
    pub fn validate(&self, msg: &Message, zone_apex: &Name, now_secs: u32) -> ValidationOutcome {
        // Step 1: NTA check — if the zone apex has an active NTA, skip validation.
        if self.nta_store.is_active_nta(zone_apex, u64::from(now_secs)) {
            return ValidationOutcome::Insecure;
        }

        let trusted_keys = self.trust_anchor.get_trusted_keys();

        // Collect all RRSIG records from answers and authority (not additional — OPT is there).
        let rrsigs: Vec<&Record> = msg
            .answers
            .iter()
            .chain(msg.authority.iter())
            .filter(|r| r.rtype == Rtype::Rrsig)
            .collect();

        // Collect DNSKEY records from the response (answers, authority, and additional).
        let dnskeys_in_msg: Vec<&Record> = msg
            .answers
            .iter()
            .chain(msg.authority.iter())
            .chain(msg.additional.iter())
            .filter(|r| r.rtype == Rtype::Dnskey)
            .collect();

        // Step 3: No signatures and no DNSKEY records → unsigned zone.
        if rrsigs.is_empty() && dnskeys_in_msg.is_empty() {
            return ValidationOutcome::Insecure;
        }

        if rrsigs.is_empty() {
            // DNSKEY present but no signatures covering them → Insecure.
            return ValidationOutcome::Insecure;
        }

        // DNSSEC-086: sig limit — reject zones presenting more RRSIGs than the
        // allowed cap.  Processing a huge RRSIG set is a KeyTrap amplification
        // vector; exceeding SIG_LIMIT is treated as a bogus outcome.
        if rrsigs.len() > SIG_LIMIT {
            return ValidationOutcome::Bogus(BogusReason::KeyTrapLimit);
        }

        // Build the combined DNSKEY set (trusted + any in the message).
        let mut all_dnskeys: Vec<Record> = trusted_keys.as_ref().clone();
        for r in &dnskeys_in_msg {
            all_dnskeys.push((*r).clone());
        }

        // Collect the covered RRsets for each RRSIG (answers + authority only; additional has OPT).
        let rrset_all: Vec<&Record> = msg.answers.iter().chain(msg.authority.iter()).collect();

        // Step 4: Validate each RRSIG.
        let budget = ValidationBudget::new(std::time::Duration::from_millis(100));
        let mut any_secure = false;
        let mut any_bogus: Option<ValidationOutcome> = None;
        let mut deprecated_alg_used: Option<u8> = None;

        for rrsig in &rrsigs {
            // Find the covered records (those matching the type covered and owner).
            let RData::Rrsig {
                type_covered: covered_type,
                algorithm: rrsig_alg,
                signer_name: signer,
                ..
            } = &rrsig.rdata
            else {
                continue;
            };
            let covered_type = *covered_type;

            let rrset: Vec<Record> = rrset_all
                .iter()
                .filter(|r| r.rtype == covered_type && r.name == rrsig.name)
                .map(|r| (*r).clone())
                .collect();

            if rrset.is_empty() {
                continue;
            }

            // Find DNSKEYs matching the signer name.
            let candidate_keys: Vec<Record> = all_dnskeys
                .iter()
                .filter(|k| k.name == *signer)
                .cloned()
                .collect();

            let outcome = verify_rrsig_with_budget(
                &rrset,
                &rrsig.rdata,
                &candidate_keys,
                u64::from(now_secs),
                KEY_LIMIT,
                Some(&budget),
            );

            match outcome {
                ValidationOutcome::Secure => {
                    // Track if the successful validation used a deprecated algorithm
                    // (DNSSEC-038, DNSSEC-039).
                    let alg = DnsAlgorithm::from_u8(*rrsig_alg);
                    if alg.is_deprecated() {
                        deprecated_alg_used = Some(*rrsig_alg);
                    }
                    any_secure = true;
                }
                ValidationOutcome::Bogus(_) => {
                    any_bogus = Some(outcome);
                }
                _ => {}
            }
        }

        // Emit structured log event for deprecated-algorithm use (DNSSEC-039).
        if let Some(alg) = deprecated_alg_used {
            warn!(
                algorithm = alg,
                zone = %zone_apex,
                "DNSSEC validation closed via deprecated algorithm (DNSSEC-039)"
            );
        }

        // Step 5: Aggregate.
        if let Some(bogus) = any_bogus {
            return bogus;
        }
        if any_secure {
            ValidationOutcome::Secure
        } else {
            ValidationOutcome::Insecure
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;

    use heimdall_core::header::Header;

    use super::*;

    fn make_validator() -> ResponseValidator {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        let nta_store = Arc::new(NtaStore::new(100));
        // Keep dir alive by leaking (acceptable in tests).
        std::mem::forget(dir);
        ResponseValidator::new(trust_anchor, nta_store)
    }

    fn empty_msg() -> Message {
        Message {
            header: Header::default(),
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn root() -> Name {
        Name::root()
    }

    #[test]
    fn unsigned_response_returns_insecure() {
        let validator = make_validator();
        let msg = empty_msg();
        let outcome = validator.validate(&msg, &root(), 1_000_000);
        assert_eq!(outcome, ValidationOutcome::Insecure);
    }

    #[test]
    fn nta_bypasses_validation() {
        let dir = tempfile::TempDir::new().expect("INVARIANT: tempdir");
        let trust_anchor =
            Arc::new(TrustAnchorStore::new(dir.path()).expect("INVARIANT: store init"));
        let nta_store = Arc::new(NtaStore::new(100));

        let broken_zone = Name::from_str("broken.example.com.").expect("INVARIANT: valid name");
        nta_store
            .add(broken_zone.clone(), 9_999_999, "test")
            .expect("INVARIANT: add NTA");

        let validator = ResponseValidator::new(trust_anchor, nta_store);
        let msg = empty_msg();

        // Even if a signature is present (which it isn't here), the NTA
        // must cause the result to be Insecure.
        let outcome = validator.validate(&msg, &broken_zone, 1_000_000);
        assert_eq!(outcome, ValidationOutcome::Insecure);
    }

    // ── DNSSEC-086 KeyTrap sig-limit tests (task #602) ────────────────────────

    fn dummy_rrsig(name: &Name, n: u8) -> Record {
        use heimdall_core::rdata::RData;
        use heimdall_core::record::Rtype;
        use heimdall_core::header::Qclass;
        Record {
            name: name.clone(),
            rtype: Rtype::Rrsig,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Rrsig {
                type_covered: Rtype::A,
                algorithm: 15,
                labels: 2,
                original_ttl: 300,
                sig_expiration: u32::MAX,
                sig_inception: 0,
                key_tag: u16::from(n),
                signer_name: name.clone(),
                signature: vec![0u8; 64],
            },
        }
    }

    fn make_msg_with_rrsigs(zone: &Name, count: usize) -> Message {
        use heimdall_core::header::Header;
        let answers: Vec<Record> = (0..count)
            .map(|i| dummy_rrsig(zone, i as u8))
            .collect();
        #[allow(clippy::cast_possible_truncation)]
        let ancount = answers.len() as u16;
        Message {
            header: Header { ancount, ..Header::default() },
            questions: vec![],
            answers,
            authority: vec![],
            additional: vec![],
        }
    }

    /// (i) Boundary: SIG_LIMIT=8 RRSIGs → no sig-limit KeyTrapLimit.
    #[test]
    fn keytrap_boundary_8_rrsigs_does_not_fire_sig_limit() {
        let validator = make_validator();
        let zone = Name::from_str("example.com.").expect("INVARIANT");
        let msg = make_msg_with_rrsigs(&zone, SIG_LIMIT);

        let outcome = validator.validate(&msg, &zone, 1_000_000);
        assert_ne!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::KeyTrapLimit),
            "(i) boundary: SIG_LIMIT RRSIGs must not fire sig-limit KeyTrapLimit"
        );
    }

    /// (iii) Sig-limit cap: SIG_LIMIT+1 = 9 RRSIGs → KeyTrapLimit fires.
    #[test]
    fn keytrap_9_rrsigs_fires_sig_limit() {
        let validator = make_validator();
        let zone = Name::from_str("example.com.").expect("INVARIANT");
        let msg = make_msg_with_rrsigs(&zone, SIG_LIMIT + 1);

        let outcome = validator.validate(&msg, &zone, 1_000_000);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::KeyTrapLimit),
            "(iii) 9 RRSIGs must fire sig-limit KeyTrapLimit"
        );
    }

    /// (iv) Product-cap: 4 keys × 9 RRSIGs → sig-limit (9 > SIG_LIMIT=8) fires KeyTrapLimit.
    ///
    /// The sig-limit check (RRSIG count > SIG_LIMIT) fires before any key-candidate
    /// processing, making both the sig-limit and the product-cap enforcement equivalent
    /// at the SIG_LIMIT boundary.
    #[test]
    fn keytrap_4_keys_9_rrsigs_fires_cap() {
        let validator = make_validator();
        let zone = Name::from_str("example.com.").expect("INVARIANT");
        // 9 RRSIGs (> SIG_LIMIT=8) → sig-limit check fires.
        // 4 DNSKEY records do not affect the outcome since the limit fires first.
        let mut msg = make_msg_with_rrsigs(&zone, SIG_LIMIT + 1);

        use heimdall_core::rdata::RData;
        use heimdall_core::record::Rtype;
        use heimdall_core::header::Qclass;
        for _ in 0..KEY_LIMIT {
            msg.answers.push(Record {
                name: zone.clone(),
                rtype: Rtype::Dnskey,
                rclass: Qclass::In,
                ttl: 300,
                rdata: RData::Dnskey {
                    flags: 0x0101,
                    protocol: 3,
                    algorithm: 15,
                    public_key: vec![0u8; 32],
                },
            });
        }
        // ancount update is informational only; validate() iterates the vec.
        let outcome = validator.validate(&msg, &zone, 1_000_000);
        assert_eq!(
            outcome,
            ValidationOutcome::Bogus(BogusReason::KeyTrapLimit),
            "(iv) 4 keys × 9 RRSIGs must fire KeyTrapLimit"
        );
    }
}
