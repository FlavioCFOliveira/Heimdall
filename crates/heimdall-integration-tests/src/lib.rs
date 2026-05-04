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
//! - [`ecs_strip`]       — ECS strip integration tests (PROTO-015/017/018/019, task #599).
//! - [`validator_e2e`]   — End-to-end DNSSEC validation pipeline (task #364).
//! - [`golden_unbound`]  — Golden comparison against Unbound recursive resolver (task #365).
//! - [`golden_nsd`]      — Golden comparison against NSD authoritative server (task #366).
//! - [`golden_knot`]     — Golden comparison against Knot DNS and Knot Resolver (task #367).
//! - [`interop_dot`]     — `DoT` interoperability suite (task #368).
//! - [`interop_doh`]     — `DoH` H2/H3 interoperability suite (task #369).
//! - [`interop_doq`]     — `DoQ` interoperability suite (task #370).
//! - [`rfc4034`]         — RFC 4034 + RFC 6840 canonical-form golden vectors (task #370).
//! - [`step4_ede20`]         — Step-4 REFUSED + EDE INFO-CODE 20 dispatcher tests (ROLE-024/025, task #600).
//! - [`nsec_synthesis_e2e`]  — Aggressive NSEC/NSEC3 synthesis E2E (DNSSEC-025..030, task #601).
//!
//! ## Sprint 37: Runtime hardening validation
//!
//! - [`hardening_seccomp`]    — Seccomp-BPF allow-list validation (task #371).
//! - [`hardening_openbsd`]    — OpenBSD pledge+unveil validation (task #372).
//! - [`hardening_macos`]      — macOS sandbox-profile validation (task #373).
//! - [`hardening_wx`]         — W^X enforcement validation (task #374).
//! - [`hardening_privdrop`]   — Privilege-drop validation (task #375).
//! - [`hardening_fs`]         — Filesystem isolation validation (task #376).
//! - [`hardening_nopriv`]     — No-privsep assertion (task #377).
//! - [`hardening_drift_check`] — CI drift gate: spec ↔ profile consistency (task #378).

pub mod dnssec_vectors;
pub mod ecs_strip;
pub mod golden_knot;
pub mod golden_nsd;
pub mod golden_unbound;
pub mod hardening_drift_check;
pub mod hardening_fs;
pub mod hardening_macos;
pub mod hardening_nopriv;
pub mod hardening_privdrop;
pub mod hardening_seccomp;
pub mod hardening_wx;
pub mod interop_doh;
pub mod interop_doq;
pub mod interop_dot;
pub mod nsec_synthesis_e2e;
pub mod rfc4034;
pub mod step4_ede20;
pub mod validator_e2e;

#[cfg(target_os = "openbsd")]
pub mod hardening_openbsd;
