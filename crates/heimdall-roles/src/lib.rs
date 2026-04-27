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

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod dnssec_roles;
pub mod forwarder;
pub mod recursive;

pub use auth::{AuthError, AuthServer, ZoneConfig, ZoneLifecycle, ZoneRole};
pub use forwarder::{ForwarderError, ForwarderServer};
pub use recursive::{RecursiveError, RecursiveServer};
