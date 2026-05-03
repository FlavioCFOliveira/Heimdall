// SPDX-License-Identifier: MIT

//! Redis persistence layer for Heimdall.
//!
//! This module implements the three data domains defined in
//! `013-persistence.md`:
//!
//! - **Authoritative zone data** — one HSET per zone, RENAME-based atomic swap
//!   (`STORE-018..025`).
//! - **Query-response cache** — individual String keys with `SET … EX`
//!   (`STORE-026..030`).
//! - **IXFR journal** — one Sorted Set per zone, score = serial number
//!   (`STORE-045..046`).
//!
//! ## Module layout
//!
//! - [`mod@client`]       — [`RedisStore`] struct, [`RedisTopology`], pool wiring.
//! - [`mod@encoding`]     — binary encoders/decoders for key fields and values.
//! - [`mod@zone_store`]   — authoritative-zone HSET operations.
//! - [`mod@cache_store`]  — cache SET…EX operations.
//! - [`mod@ixfr_journal`] — IXFR Sorted Set operations.
//! - [`mod@backoff`]      — exponential backoff with ±20 % jitter.
//! - [`mod@metrics`]      — per-operation counters and latency stubs.

pub mod backoff;
pub mod cache_store;
pub mod client;
pub mod encoding;
pub mod ixfr_journal;
pub mod metrics;
pub mod zone_store;

pub use client::{CacheNamespace, RedisAuth, RedisConfig, RedisStore, RedisTopology, StoreDrainStats, StoreError, TrackedConn};
pub use encoding::{
    CacheEntry, DnssecOutcome, RrsetPayload, cache_key, field_name, zone_journal_key, zone_key,
    zone_staging_key,
};
pub use metrics::StoreMetrics;
