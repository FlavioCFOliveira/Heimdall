// SPDX-License-Identifier: MIT

//! RPZ Redis persistence stub (STORE-031..034).
//!
//! Sprint 34 implements a logging stub.  Full Redis wiring is deferred to the
//! integration sprint.
//!
//! # Redis key design (for future implementation)
//!
//! All entries for a zone are stored in a Redis hash:
//!
//! ```text
//! KEY:   heimdall:rpz:zone:<zone_name>
//! FIELD: "<trigger_type>:<trigger_value>"
//! VALUE: JSON-serialised action
//! ```
//!
//! This allows atomic `HSET`/`HDEL` mutations and bulk `HGETALL` on cold start.

use crate::rpz::{
    action::RpzAction,
    trigger::{RpzEntry, RpzTrigger},
};

// ── RpzRedisStore ─────────────────────────────────────────────────────────────

/// Redis persistence adapter for RPZ policy entries (STORE-031..034).
///
/// Sprint 34: in-memory stub that emits structured log events on every
/// operation.  The full Redis wiring (deadpool-redis connection pool,
/// HSET/HDEL/HGETALL commands) is deferred to the integration sprint.
pub struct RpzRedisStore {
    _private: (),
}

impl RpzRedisStore {
    /// Creates a new (stub) `RpzRedisStore`.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Persists an RPZ entry to Redis (stub: emits a structured log event).
    // The async signature is intentional: the real Redis implementation will await
    // the connection pool and command pipeline (STORE-031).
    #[allow(clippy::unused_async)]
    pub async fn store_entry(&self, zone: &str, trigger: &RpzTrigger, action: &RpzAction) {
        tracing::info!(
            event = "rpz_redis_write",
            zone = zone,
            trigger_type = trigger.type_label(),
            action = ?action,
            "stub: Redis persistence deferred"
        );
    }

    /// Removes an RPZ entry from Redis (stub: emits a structured log event).
    #[allow(clippy::unused_async)]
    pub async fn remove_entry(&self, zone: &str, trigger: &RpzTrigger) {
        tracing::info!(
            event = "rpz_redis_remove",
            zone = zone,
            trigger_type = trigger.type_label(),
            "stub: Redis persistence deferred"
        );
    }

    /// Loads all RPZ entries for a zone from Redis on cold start (stub: returns empty vec).
    #[allow(clippy::unused_async)]
    pub async fn load_zone(&self, zone: &str) -> Vec<RpzEntry> {
        tracing::info!(
            event = "rpz_redis_load",
            zone = zone,
            "stub: Redis persistence deferred"
        );
        vec![]
    }
}

impl Default for RpzRedisStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use heimdall_core::name::Name;

    use super::*;
    use crate::rpz::{
        action::RpzAction,
        trigger::{CidrRange, RpzTrigger},
    };

    #[tokio::test]
    async fn store_entry_does_not_panic() {
        let store = RpzRedisStore::new();
        let trigger = RpzTrigger::ClientIp(CidrRange {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            prefix_len: 32,
        });
        store
            .store_entry("rpz.test.", &trigger, &RpzAction::Drop)
            .await;
    }

    #[tokio::test]
    async fn remove_entry_does_not_panic() {
        let store = RpzRedisStore::new();
        let trigger = RpzTrigger::QnameExact(Name::from_str("blocked.example.com.").unwrap());
        store.remove_entry("rpz.test.", &trigger).await;
    }

    #[tokio::test]
    async fn load_zone_returns_empty() {
        let store = RpzRedisStore::new();
        let entries = store.load_zone("rpz.test.").await;
        assert!(entries.is_empty());
    }
}
