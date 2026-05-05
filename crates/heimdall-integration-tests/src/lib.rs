// SPDX-License-Identifier: MIT

// This crate exists solely to host integration test modules; production-code
// invariants (unwrap/expect denial, cast hardness, doc-comment completeness)
// do not apply. Allowing these lints crate-wide avoids repeating the
// attribute on every module and matches the convention already established
// in `heimdall-e2e-harness`.
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
    clippy::unused_async,
    clippy::many_single_char_names,
    clippy::float_cmp,
    clippy::needless_for_each,
    dead_code
)]

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
//! - [`conformance`]     — Docker container harness for reference implementations (task #492).
//! - [`golden_nsd`]      — Golden comparison against NSD authoritative server (task #366).
//! - [`golden_knot`]     — Golden comparison against Knot DNS and Knot Resolver (task #367).
//! - [`golden_powerdns`] — Golden comparison against `PowerDNS` auth + recursor (task #564).
//! - [`golden_coredns`]  — Golden comparison against `CoreDNS` forwarder (task #565).
//! - [`interop_dot`]     — `DoT` interoperability suite (task #368).
//! - [`interop_doh`]     — `DoH` H2/H3 interoperability suite (task #369).
//! - [`interop_doq`]     — `DoQ` interoperability suite (task #370).
//! - [`rfc4034`]         — RFC 4034 + RFC 6840 canonical-form golden vectors (task #370, #496).
//! - [`step4_ede20`]         — Step-4 REFUSED + EDE INFO-CODE 20 dispatcher tests (ROLE-024/025, task #600).
//! - [`nsec_synthesis_e2e`]  — Aggressive NSEC/NSEC3 synthesis E2E (DNSSEC-025..030, task #601).
//! - [`cache_admission_e2e`] — Cache admission integration tests (CACHE-012/013/015/016, task #603).
//!
//! ## Sprint 37: Runtime hardening validation
//!
//! - `hardening_seccomp`    — Seccomp-BPF allow-list validation (task #371).
//! - `hardening_openbsd`    — OpenBSD pledge+unveil validation (task #372).
//! - [`hardening_macos`]      — macOS sandbox-profile validation (task #373).
//! - [`hardening_wx`]         — W^X enforcement validation (task #374).
//! - [`hardening_privdrop`]   — Privilege-drop validation (task #375).
//! - [`hardening_fs`]         — Filesystem isolation validation (task #376).
//! - [`hardening_nopriv`]     — No-privsep assertion (task #377).
//! - [`hardening_drift_check`] — CI drift gate: spec ↔ profile consistency (task #378).
//!
//! ## Sprint 53: Stability and soak testing
//!
//! - [`soak_sustained_load`]    — 24h QPS stability + measurement infrastructure (task #525).
//! - [`soak_memory_leak`]       — `VmRSS` / heaptrack memory-leak detection (task #526).
//! - [`soak_fd_leak`]           — FD/socket leak across reload + admin-RPC churn (task #527).
//! - [`soak_cache_eviction`]    — Cache eviction under 4× capacity pressure (task #528).
//! - [`soak_tek_rotation`]      — TEK/token-key rotation safety under concurrent load (task #529).
//! - [`soak_crash_recovery`]    — SIGKILL + restart cache survival via Redis (task #530).
//! - [`soak_ddos`]              — `DDoS` profiles: UDP flood, NXDOMAIN flood, `NXNSAttack` (task #550).
//! - [`soak_reload_under_load`] — SIGHUP during sustained load — 144-reload correctness (task #551).

pub mod cache_admission_e2e;
pub mod conformance;
pub mod dnssec_vectors;
pub mod ecs_strip;
pub mod golden_coredns;
pub mod golden_knot;
pub mod golden_nsd;
pub mod golden_powerdns;
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
pub mod perf_iouring;
pub mod perf_reuseport;
pub mod rfc4034;
pub mod soak_cache_eviction;
pub mod soak_crash_recovery;
pub mod soak_ddos;
pub mod soak_fd_leak;
pub mod soak_memory_leak;
pub mod soak_reload_under_load;
pub mod soak_sustained_load;
pub mod soak_tek_rotation;
pub mod step4_ede20;
pub mod validator_e2e;

#[cfg(target_os = "openbsd")]
pub mod hardening_openbsd;
