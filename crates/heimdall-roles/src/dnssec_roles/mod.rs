// SPDX-License-Identifier: MIT

//! DNSSEC management modules for the recursive resolver role.
//!
//! This module is named `dnssec_roles` to avoid a name collision with
//! `heimdall_core::dnssec`.
//!
//! # Modules
//!
//! - [`trust_anchor`] — [`TrustAnchorStore`]: bootstraps the IANA KSK-2017,
//!   implements a simplified RFC 5011 state machine, and persists managed-key
//!   state to disk.
//! - [`nta`] — [`NtaStore`]: bounded Negative Trust Anchor store with
//!   time-limited entries and structured tracing events.

pub mod nta;
pub mod trust_anchor;

pub use nta::{NtaEntry, NtaError, NtaStore};
pub use trust_anchor::{KeyState, ManagedKey, TrustAnchorError, TrustAnchorStore};
