// SPDX-License-Identifier: MIT

//! DNSSEC validation primitives for Heimdall (Sprint 16).
//!
//! This module implements the DNSSEC validation pipeline as specified in
//! RFC 4034, RFC 4035, RFC 5155, RFC 8198, and RFC 8624.
//!
//! # Modules
//!
//! - [`canonical`] — RFC 4034 §6 canonical name ordering and signing-input construction.
//! - [`algorithms`] — Algorithm support table and RFC 8624 policy.
//! - [`verify`] — RRSIG verification pipeline (RFC 4035 §5).
//! - [`nsec`] — NSEC and NSEC3 type-bitmap encoding and existence proofs.
//! - [`synthesis`] — Aggressive NSEC/NSEC3 synthesis (RFC 8198).
//! - [`budget`] — Per-query wall-clock CPU budget enforcement.
//!
//! # DNSSEC validation flow
//!
//! ```text
//! 1. Build canonical signing input  →  canonical::rrset_signing_input
//! 2. Select algorithm               →  algorithms::DnsAlgorithm
//! 3. Verify RRSIG                   →  verify::verify_rrsig
//! 4. Prove non-existence            →  nsec::nsec_proves_nxdomain
//!                                      nsec::nsec3_proves_nxdomain
//! 5. Synthesise negative responses  →  synthesis::synthesise_negative
//! 6. Enforce CPU budget             →  budget::ValidationBudget
//! ```
//!
//! # Security requirements
//!
//! - All `unsafe` is prohibited in this module (`#![deny(unsafe_code)]` at crate root).
//! - NSEC3 iteration count is bounded to [`nsec::MAX_NSEC3_ITERATIONS`] = 150
//!   (DNSSEC-044, RFC 9276 §3.1).
//! - DNSKEY candidate attempts per RRSIG are bounded by `max_attempts`
//!   (DNSSEC-040, RFC 9276 `KeyTrap` mitigation).
//! - Per-query wall-clock budget is enforced via [`budget::ValidationBudget`]
//!   (DNSSEC-045).

pub mod algorithms;
pub mod budget;
pub mod canonical;
pub mod nsec;
pub mod synthesis;
pub mod verify;

// Re-export the primary validation types at the dnssec module level.
pub use algorithms::{DigestType, DnsAlgorithm, DsAcceptance, dnskey_matches_ds, select_ds_records};
pub use budget::ValidationBudget;
pub use canonical::{RsigFields, canonical_name_wire, canonical_rdata_wire, rrset_signing_input};
pub use nsec::{
    MAX_NSEC3_ITERATIONS, NsecProofType, Nsec3ProofType, encode_type_bitmap,
    nsec3_excess_iterations_ede, nsec3_hash, nsec3_hash_with_budget,
    nsec_proves_nxdomain, nsec3_proves_nxdomain, type_in_bitmap,
};
pub use synthesis::{NsecOrNsec3Proof, SynthesisResult, synthesise_negative};
pub use verify::{BogusReason, ValidationOutcome, verify_rrsig, verify_rrsig_with_budget};
