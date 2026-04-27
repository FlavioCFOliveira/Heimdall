// SPDX-License-Identifier: MIT

//! Heimdall protocol-conformance and interop integration test suite (Sprint 36).
//!
//! Each sub-module contains a focused set of integration tests that exercise
//! `heimdall-core` primitives against published IETF test vectors and reference
//! implementation golden outputs.
//!
//! # Modules
//!
//! - [`dnssec_vectors`] — IETF DNSSEC test vectors (RFC 5702, RFC 6605, RFC 8080, RFC 5155).

pub mod dnssec_vectors;
pub mod validator_e2e;
