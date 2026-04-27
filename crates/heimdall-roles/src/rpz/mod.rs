// SPDX-License-Identifier: MIT

//! Response Policy Zones (RPZ) for the recursive resolver role (RPZ-001..003).
//!
//! # Overview
//!
//! RPZ allows a DNS operator to define policy zones that intercept queries and
//! modify responses according to configurable actions.  This module implements
//! the RPZ draft specification for the Heimdall recursive resolver.
//!
//! # Modules
//!
//! - [`action`] — [`RpzAction`]: the seven RPZ response policy actions.
//! - [`trigger`] — [`RpzTrigger`], [`RpzEntry`], [`CidrRange`]: trigger types
//!   and the entry pairing a trigger with an action.
//! - [`trie`] — [`QnameTrie`], [`CidrTrie`], [`NsdnameMatcher`]: sub-linear
//!   matching data structures.
//! - [`zone`] — [`PolicyZone`]: a compiled zone holding all matching structures.
//! - [`engine`] — [`RpzEngine`], [`RpzContext`], [`RpzDecision`]: multi-zone
//!   evaluation engine with first-match-wins semantics.
//! - [`loader`] — [`PolicyZoneConfig`], [`ZoneSource`], [`load_from_file`],
//!   [`load_via_axfr`], [`RpzLoadError`]: loaders for file-based and AXFR zones.
//! - [`redis`] — [`RpzRedisStore`]: Redis persistence stub (STORE-031..034).

pub mod action;
pub mod engine;
pub mod loader;
pub mod redis;
pub mod trigger;
pub mod trie;
pub mod zone;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use action::RpzAction;
pub use engine::{RpzContext, RpzDecision, RpzEngine};
pub use loader::{
    PolicyZoneConfig, RpzLoadError, ZoneSource, load_from_file, load_via_axfr,
};
pub use redis::RpzRedisStore;
pub use trigger::{CidrRange, RpzEntry, RpzTrigger};
pub use trie::{CidrTrie, NsdnameMatcher, QnameTrie};
pub use zone::{DEFAULT_POLICY_TTL, PolicyZone};
