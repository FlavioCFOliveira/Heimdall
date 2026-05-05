// SPDX-License-Identifier: MIT

//! Authoritative zone HSET operations (`STORE-018..025`).
//!
//! Each authoritative zone is stored as a single Redis Hash:
//! - **Live key**: `heimdall:zone:auth:{<fqdn>}` (`STORE-019`).
//! - **Staging key**: `heimdall:zone:auth:{<fqdn>}:staging` (`STORE-023`).
//!
//! The hash tag `{…}` ensures both keys slot to the same Redis Cluster node
//! so that `RENAME` is atomic under Cluster topology (`STORE-039/040`).
//!
//! ## Field encoding
//!
//! Hash fields are `<lowercase_owner>|<qtype>|<qclass>` (`STORE-042`).
//! Values are the STORE-043 binary `RRset` encoding (via [`RrsetPayload`]).
//!
//! ## Zone replacement
//!
//! [`write_zone`] writes all fields to the staging key then issues a single
//! `RENAME` command, providing atomicity per `STORE-023`.

use redis::AsyncCommands;

use super::{
    client::{RedisStore, StoreError},
    encoding::{RrsetPayload, field_name, zone_key, zone_staging_key},
};

/// A single `RRset` entry to be written into a zone Hash.
#[derive(Debug, Clone)]
pub struct ZoneRrset {
    /// Owner name, fully-qualified.
    pub owner: String,
    /// QTYPE numeric value.
    pub qtype: u16,
    /// QCLASS numeric value.
    pub qclass: u16,
    /// The `RRset` payload to encode and store.
    pub rrset: RrsetPayload,
}

/// Write (or atomically replace) an entire zone in Redis (`STORE-018..023`).
///
/// Steps:
/// 1. Encode all `rrsets` using the STORE-043 binary format.
/// 2. `HSET` all fields into the staging key in one command.
/// 3. `RENAME` staging key → live key (atomic at Redis level).
///
/// On any error the staging key may be left behind — it will be overwritten on
/// the next write attempt (staging is always written in full before RENAME).
///
/// # Errors
///
/// Returns [`StoreError`] on encoding failures or Redis command errors.
pub async fn write_zone(
    store: &RedisStore,
    fqdn: &str,
    rrsets: &[ZoneRrset],
) -> Result<(), StoreError> {
    let staging = zone_staging_key(fqdn);
    let live = zone_key(fqdn);

    // Build the flat list of (field, value) pairs required by HSET.
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::with_capacity(rrsets.len());
    for entry in rrsets {
        let field = field_name(&entry.owner, entry.qtype, entry.qclass);
        let value = entry.rrset.encode()?;
        pairs.push((field, value));
    }

    let mut conn = store.connection().await?;

    if pairs.is_empty() {
        // Empty zone: DEL both keys.  RENAME requires source to exist, so for
        // an empty zone we simply DEL the live key directly.
        redis::cmd("DEL")
            .arg(&staging)
            .query_async::<()>(&mut conn)
            .await
            .map_err(StoreError::Redis)?;
        redis::cmd("DEL")
            .arg(&live)
            .query_async::<()>(&mut conn)
            .await
            .map_err(StoreError::Redis)?;
    } else {
        // Build the HSET argument list: HSET key field value [field value …]
        let mut hset_cmd = redis::cmd("HSET");
        hset_cmd.arg(&staging);
        for (field, value) in &pairs {
            hset_cmd.arg(field).arg(value.as_slice());
        }
        hset_cmd
            .query_async::<()>(&mut conn)
            .await
            .map_err(StoreError::Redis)?;

        // Atomic swap: staging → live.
        redis::cmd("RENAME")
            .arg(&staging)
            .arg(&live)
            .query_async::<()>(&mut conn)
            .await
            .map_err(StoreError::Redis)?;
    }

    store.record_success();
    store.metrics.record_zone_write_ok();
    Ok(())
}

/// Retrieve a single `RRset` from the zone Hash (`STORE-024`).
///
/// Issues a single `HGET` command — O(1) average complexity at the Redis level.
///
/// Returns `None` if the key or field does not exist.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors or decoding failures.
pub async fn get_rrset(
    store: &RedisStore,
    fqdn: &str,
    owner: &str,
    qtype: u16,
    qclass: u16,
) -> Result<Option<RrsetPayload>, StoreError> {
    let key = zone_key(fqdn);
    let field = field_name(owner, qtype, qclass);

    let mut conn = store.connection().await?;

    let bytes: Option<Vec<u8>> = conn.hget(&key, &field).await.map_err(StoreError::Redis)?;

    match bytes {
        None => Ok(None),
        Some(b) => Ok(Some(RrsetPayload::decode(&b)?)),
    }
}

/// Delete an entire zone from Redis (`STORE-022`).
///
/// Issues a single `DEL` command — O(1) from Heimdall's perspective.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors.
pub async fn delete_zone(store: &RedisStore, fqdn: &str) -> Result<(), StoreError> {
    let key = zone_key(fqdn);
    let mut conn = store.connection().await?;
    conn.del::<_, ()>(&key).await.map_err(StoreError::Redis)?;
    store.record_success();
    Ok(())
}

/// Enumerate all `RRset`s in a zone via `HSCAN` (`STORE-025`).
///
/// Uses the `COUNT` hint from `store.config().hscan_count` (default 1024,
/// `STORE-048`). Each iteration yields `(field_string, RrsetPayload)`.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors or decoding failures.
pub async fn scan_zone(
    store: &RedisStore,
    fqdn: &str,
) -> Result<Vec<(String, RrsetPayload)>, StoreError> {
    let key = zone_key(fqdn);
    let count = store.config().hscan_count;

    let mut conn = store.connection().await?;
    let mut cursor: u64 = 0;
    let mut results = Vec::new();

    loop {
        let reply: (u64, Vec<(String, Vec<u8>)>) = redis::cmd("HSCAN")
            .arg(&key)
            .arg(cursor)
            .arg("COUNT")
            .arg(count)
            .query_async(&mut conn)
            .await
            .map_err(StoreError::Redis)?;

        cursor = reply.0;
        for (field, bytes) in reply.1 {
            let payload = RrsetPayload::decode(&bytes)?;
            results.push((field, payload));
        }

        if cursor == 0 {
            break;
        }
    }

    Ok(results)
}
