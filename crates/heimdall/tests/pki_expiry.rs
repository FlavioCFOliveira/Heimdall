// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! CI gate: generated test PKI certificates must have ≥ 30 days until expiry.
//! (Sprint 47 task #467 AC)
//!
//! Since certs are generated fresh each test run (not checked in), this test
//! verifies that the `TestPki` generator always produces certs with at least 30
//! days of validity remaining and never accidentally produces short-lived certs.

use heimdall_e2e_harness::pki::TestPki;

#[test]
fn server_cert_has_at_least_30_days_to_expiry() {
    let pki = TestPki::generate();
    let days = pki.server_cert_days_to_expiry();
    assert!(
        days >= 30,
        "server cert must have ≥ 30 days to expiry, got {days} days"
    );
}

#[test]
fn ca_cert_has_at_least_30_days_to_expiry() {
    let pki = TestPki::generate();
    let days = pki.ca_cert_days_to_expiry();
    assert!(
        days >= 30,
        "CA cert must have ≥ 30 days to expiry, got {days} days"
    );
}

#[test]
fn client_cert_has_at_least_30_days_to_expiry() {
    let pki = TestPki::generate();
    let days = pki.client_cert_days_to_expiry();
    assert!(
        days >= 30,
        "client cert must have ≥ 30 days to expiry, got {days} days"
    );
}

#[test]
fn pki_files_written_to_tempdir() {
    let pki = TestPki::generate();
    assert!(pki.ca_cert_path.exists(), "ca-cert.pem not written");
    assert!(pki.server_cert_path.exists(), "server-cert.pem not written");
    assert!(pki.server_key_path.exists(), "server-key.pem not written");
    assert!(pki.client_cert_path.exists(), "client-cert.pem not written");
    assert!(pki.client_key_path.exists(), "client-key.pem not written");
}
