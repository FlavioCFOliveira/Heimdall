// SPDX-License-Identifier: MIT

//! Heimdall protocol-conformance and interop integration test suite (Sprint 36).
//!
//! Each sub-module contains a focused set of integration tests that exercise
//! `heimdall-core` primitives against published IETF test vectors and reference
//! implementation golden outputs.
//!
//! # Modules
//!
//! - [`dnssec_vectors`]  — IETF DNSSEC test vectors (RFC 5702, RFC 6605, RFC 8080, RFC 5155).
//! - [`validator_e2e`]   — End-to-end DNSSEC validation pipeline (task #364).
//! - [`golden_unbound`]  — Golden comparison against Unbound recursive resolver (task #365).
//! - [`golden_nsd`]      — Golden comparison against NSD authoritative server (task #366).
//! - [`golden_knot`]     — Golden comparison against Knot DNS and Knot Resolver (task #367).
//! - [`interop_dot`]     — DoT interoperability suite (task #368).
//! - [`interop_doh`]     — DoH H2/H3 interoperability suite (task #369).
//! - [`interop_doq`]     — DoQ interoperability suite (task #370).
//! - [`rfc4034`]         — RFC 4034 + RFC 6840 canonical-form golden vectors (task #370).

pub mod dnssec_vectors;
pub mod golden_knot;
pub mod golden_nsd;
pub mod golden_unbound;
pub mod interop_doh;
pub mod interop_doq;
pub mod interop_dot;
pub mod rfc4034;
pub mod validator_e2e;
