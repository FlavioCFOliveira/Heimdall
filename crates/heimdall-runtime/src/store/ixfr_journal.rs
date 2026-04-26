// SPDX-License-Identifier: MIT

//! IXFR journal Sorted Set operations (`STORE-045..046`).
//!
//! Each authoritative zone has a Redis Sorted Set at key:
//! `heimdall:journal:auth:{fqdn}` (`STORE-045`)
//!
//! - **Score** = zone serial number (as `f64`).
//! - **Member** = binary-encoded changeset for that serial transition.
//!
//! ## Pruning (`STORE-046`)
//!
//! The journal retains at most 7 days (604 800 seconds) or 1000 entries,
//! whichever limit is reached first. Pruning is performed atomically inside a
//! Redis `MULTI`/`EXEC` transaction so that concurrent IXFR consumers never
//! observe a partially-pruned journal.

use super::client::{RedisStore, StoreError};
use super::encoding::zone_journal_key;

/// Maximum number of journal entries to retain (`STORE-046`).
pub const MAX_JOURNAL_ENTRIES: usize = 1000;

/// Maximum journal retention in seconds: 7 days (`STORE-046`).
pub const MAX_JOURNAL_AGE_SECS: u64 = 7 * 24 * 3600; // 604 800

/// Append a changeset for `serial` to the IXFR journal (`STORE-045`).
///
/// `changeset` is the caller-provided binary representation of the changed
/// `RRset`s for the serial transition. The format is defined by the IXFR
/// implementation (outside the scope of this module).
///
/// After a successful append, count-based pruning is triggered atomically
/// (`STORE-046`).
///
/// `now_unix_secs` is passed for future time-based pruning; currently unused
/// in the count-based prune path.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors.
pub async fn append(
    store: &RedisStore,
    fqdn: &str,
    serial: u32,
    changeset: &[u8],
    _now_unix_secs: u64,
) -> Result<(), StoreError> {
    let key = zone_journal_key(fqdn);

    let mut conn = store.connection().await?;

    // ZADD key score member
    redis::cmd("ZADD")
        .arg(&key)
        .arg(f64::from(serial))
        .arg(changeset)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|e| {
            store.metrics.record_journal_append_err();
            StoreError::Redis(e)
        })?;

    // Prune atomically under MULTI/EXEC (`STORE-046`).
    prune_by_count(&key, &mut conn).await?;

    store.record_success();
    store.metrics.record_journal_append_ok();
    Ok(())
}

/// Retrieve all journal entries with serial strictly greater than `since_serial`.
///
/// Returns a vector of `(serial, changeset_bytes)` pairs ordered by serial
/// (ascending). Used to serve IXFR responses for `PROTO-039`.
///
/// # Errors
///
/// Returns [`StoreError`] on Redis command errors.
pub async fn query_since(
    store: &RedisStore,
    fqdn: &str,
    since_serial: u32,
) -> Result<Vec<(u32, Vec<u8>)>, StoreError> {
    let key = zone_journal_key(fqdn);

    let mut conn = store.connection().await?;

    // ZRANGEBYSCORE key (since_serial +inf WITHSCORES
    // The "(" prefix in Redis score notation means exclusive lower bound.
    let raw: Vec<(Vec<u8>, f64)> = redis::cmd("ZRANGEBYSCORE")
        .arg(&key)
        .arg(format!("({since_serial}"))
        .arg("+inf")
        .arg("WITHSCORES")
        .query_async(&mut conn)
        .await
        .map_err(StoreError::Redis)?;

    let entries = raw
        .into_iter()
        .map(|(member, score)| {
            // Scores are stored as f64; serial numbers are u32. Truncate safely.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let serial = score as u32;
            (serial, member)
        })
        .collect();

    Ok(entries)
}

/// Prune the journal to at most [`MAX_JOURNAL_ENTRIES`] inside a MULTI/EXEC
/// transaction (`STORE-046`).
///
/// The count-based limit is applied by removing the lowest-scoring entries.
/// Time-based pruning (7-day window) requires per-entry insertion timestamps
/// and is deferred to the IXFR implementation sprint.
async fn prune_by_count(key: &str, conn: &mut super::client::PooledConn) -> Result<(), StoreError> {
    // Get the current count (outside the transaction — needed to decide whether
    // to prune at all).
    let count: usize = redis::cmd("ZCARD")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StoreError::Redis)?;

    if count <= MAX_JOURNAL_ENTRIES {
        return Ok(());
    }

    let excess = count - MAX_JOURNAL_ENTRIES;

    // MULTI / EXEC wrapping the prune so no concurrent reader sees a partial
    // journal during the remove (`STORE-046`).
    redis::cmd("MULTI")
        .query_async::<()>(conn)
        .await
        .map_err(StoreError::Redis)?;

    // `excess` ≤ `count` ≤ 2^53 in practice (Redis enforces memory limits),
    // so the cast to i64 is safe — excess would never approach i64::MAX.
    #[allow(clippy::cast_possible_wrap)]
    let stop_index = (excess as i64) - 1;
    let prune_result = redis::cmd("ZREMRANGEBYRANK")
        .arg(key)
        .arg(0i64)
        .arg(stop_index)
        .query_async::<()>(conn)
        .await;

    if let Err(e) = prune_result {
        // If the queued command fails, discard the transaction (best-effort).
        let _ = redis::cmd("DISCARD").query_async::<()>(conn).await;
        return Err(StoreError::Redis(e));
    }

    redis::cmd("EXEC")
        .query_async::<()>(conn)
        .await
        .map_err(StoreError::Redis)?;

    Ok(())
}
