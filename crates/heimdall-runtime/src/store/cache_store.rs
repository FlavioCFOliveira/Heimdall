// SPDX-License-Identifier: MIT

//! Cache `SET … EX` operations (`STORE-026..030`).
//!
//! Each cached `RRset` is stored as an individual Redis String value whose TTL
//! is set in the same `SET` command that writes the value (`STORE-026`).
//!
//! ## Key pattern (`STORE-028`)
//!
//! - Recursive: `heimdall:cache:recursive:{owner}|{qtype}|{qclass}`
//! - Forwarder: `heimdall:cache:forwarder:{owner}|{qtype}|{qclass}`
//!
//! ## Value format (`STORE-044`)
//!
//! 9-byte header (`dnssec_outcome` + `inserted_at` + `stale_until`) followed
//! by the STORE-043 `RRset` binary payload.

use redis::AsyncCommands;

use super::client::{RedisStore, StoreError};
use super::encoding::{CacheEntry, CacheNamespace, cache_key};

/// Write a cache entry with the given `ttl_seconds` expiry (`STORE-026`).
///
/// Uses `SET key value EX seconds` — a single atomic command. A separate
/// `EXPIRE` is never issued.
///
/// If `ttl_seconds` is 0 the entry is not written (a zero-TTL entry would
/// expire immediately and serve no purpose).
///
/// # Errors
///
/// Returns [`StoreError`] on encoding failures or Redis command errors.
pub async fn write_cache(
    store: &RedisStore,
    ns: CacheNamespace,
    owner: &str,
    qtype: u16,
    qclass: u16,
    entry: &CacheEntry,
    ttl_seconds: u64,
) -> Result<(), StoreError> {
    if ttl_seconds == 0 {
        return Ok(());
    }

    let key = cache_key(ns, owner, qtype, qclass);
    let bytes = entry.encode()?;

    let mut conn = store.connection().await?;

    // SET key value EX seconds — single command per STORE-026.
    conn.set_ex::<_, _, ()>(&key, bytes.as_slice(), ttl_seconds)
        .await
        .map_err(|e| {
            store.metrics.record_cache_write_err();
            StoreError::Redis(e)
        })?;

    store.record_success();
    store.metrics.record_cache_write_ok();
    Ok(())
}

/// Read a cache entry by `(namespace, owner, qtype, qclass)`.
///
/// Returns `None` when the key does not exist or has expired.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors or decoding failures.
pub async fn read_cache(
    store: &RedisStore,
    ns: CacheNamespace,
    owner: &str,
    qtype: u16,
    qclass: u16,
) -> Result<Option<CacheEntry>, StoreError> {
    let key = cache_key(ns, owner, qtype, qclass);

    let mut conn = store.connection().await?;

    let bytes: Option<Vec<u8>> = conn.get(&key).await.map_err(StoreError::Redis)?;

    match bytes {
        None => {
            store.metrics.record_cache_miss();
            Ok(None)
        }
        Some(b) => {
            store.metrics.record_cache_hit();
            Ok(Some(CacheEntry::decode(&b)?))
        }
    }
}

/// Delete a cache entry.
///
/// Returns the number of keys deleted (0 if not found, 1 if deleted).
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors.
pub async fn delete_cache(
    store: &RedisStore,
    ns: CacheNamespace,
    owner: &str,
    qtype: u16,
    qclass: u16,
) -> Result<u64, StoreError> {
    let key = cache_key(ns, owner, qtype, qclass);

    let mut conn = store.connection().await?;

    let deleted: u64 = conn.del(&key).await.map_err(StoreError::Redis)?;
    Ok(deleted)
}
