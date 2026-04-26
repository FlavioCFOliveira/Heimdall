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
//!
//! ## Re-exports
//!
//! Key types are re-exported at the crate root for ergonomic use:
//! - [`AuthServer`]
//! - [`AuthError`]
//! - [`ZoneConfig`]
//! - [`ZoneRole`]
//! - [`ZoneLifecycle`]

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;

pub use auth::{AuthError, AuthServer, ZoneConfig, ZoneLifecycle, ZoneRole};
