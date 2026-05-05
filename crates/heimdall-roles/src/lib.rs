// SPDX-License-Identifier: MIT

//! # heimdall-roles
//!
//! Authoritative zone management, recursive resolver, forwarder, and
//! query-resolution precedence logic for the Heimdall DNS server.
//!
//! ## Modules
//!
//! - [`auth`] — Authoritative server role: query serving, AXFR/IXFR outbound,
//!   NOTIFY, secondary refresh loop, UPDATE→NOTIMP, zone lifecycle.
//! - [`recursive`] — Recursive resolver role: iterative delegation following,
//!   DNSSEC validation wiring, cache integration, and root hints.
//! - [`dnssec_roles`] — DNSSEC management: trust anchor store (RFC 5011) and
//!   Negative Trust Anchor store.
//! - [`forwarder`] — Forwarder role: rule-based upstream dispatch, transport
//!   fallback, independent DNSSEC validation, cache integration, and
//!   per-client rate limiting.
//!
//! ## Modules
//!
//! - [`auth`] — Authoritative server role: query serving, AXFR/IXFR outbound,
//!   NOTIFY, secondary refresh loop, UPDATE→NOTIMP, zone lifecycle.
//! - [`recursive`] — Recursive resolver role: iterative delegation following,
//!   DNSSEC validation wiring, cache integration, and root hints.
//! - [`dnssec_roles`] — DNSSEC management: trust anchor store (RFC 5011) and
//!   Negative Trust Anchor store.
//! - [`forwarder`] — Forwarder role: rule-based upstream dispatch, transport
//!   fallback, independent DNSSEC validation, cache integration, and
//!   per-client rate limiting.
//! - [`rpz`] — Response Policy Zones (RPZ): multi-zone policy enforcement for
//!   the recursive resolver (RPZ-001..003).
//! - [`multi_role`] — Composite auth+recursive dispatcher for coexistence
//!   deployments.
//!
//! ## Re-exports
//!
//! Key types are re-exported at the crate root for ergonomic use:
//! - [`AuthServer`]
//! - [`AuthError`]
//! - [`ZoneConfig`]
//! - [`ZoneRole`]
//! - [`ZoneLifecycle`]
//! - [`RecursiveServer`]
//! - [`RecursiveError`]
//! - [`ForwarderServer`]
//! - [`ForwarderError`]
//! - [`MultiRoleDispatcher`]

#![deny(unsafe_code)]
#![deny(missing_docs)]
// See `crates/heimdall-core/src/lib.rs` for the rationale: production code
// keeps the workspace lint posture intact, while test code gets a
// pragmatic relaxation matching `heimdall-e2e-harness`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreadable_literal,
        clippy::items_after_statements,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
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
        dead_code,
    )
)]

pub mod auth;
pub mod dnssec_roles;
pub mod forwarder;
pub mod multi_role;
pub mod recursive;
pub mod rpz;

pub use auth::{AuthError, AuthServer, ZoneConfig, ZoneLifecycle, ZoneRole};
pub use forwarder::{ForwarderError, ForwarderServer};
pub use multi_role::MultiRoleDispatcher;
pub use recursive::{QnameMinError, QnameMinMode, RecursiveError, RecursiveServer, UdpTcpUpstream};
