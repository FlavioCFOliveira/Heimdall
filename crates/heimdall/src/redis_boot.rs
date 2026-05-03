// SPDX-License-Identifier: MIT

//! Redis pool bootstrap and liveness probe at boot (BIN-050, STORE-005..016).
//!
//! Called from `main()` during the async boot sequence.  If `[persistence]` is
//! not configured in the TOML file (neither `uds_path` nor `host` is set), this
//! module is a no-op and returns `None`.
//!
//! When persistence is configured, startup is **fail-closed**: any failure to
//! reach Redis (pool creation, PING, schema version mismatch) logs a structured
//! `ERROR` event and exits with code 1.

use heimdall_runtime::{
    RedisAuth, RedisConfig, RedisStore, RedisTopology,
    config::PersistenceConfig,
};

/// Schema version marker stored in Redis under `heimdall:schema_version`.
///
/// Bump this constant whenever a breaking change to the Redis key schema is
/// made (migration required).  On startup, Heimdall reads the key; if it
/// exists and holds a different value, the process exits with code 1.
const SCHEMA_VERSION: &str = "1";

/// Bootstrap the Redis connection pool from the given `PersistenceConfig`.
///
/// Returns `None` when persistence is not configured.  On any error, logs a
/// structured event at `ERROR` level and calls `std::process::exit(1)`.
pub async fn connect(cfg: &PersistenceConfig) -> Option<RedisStore> {
    if !cfg.is_configured() {
        return None;
    }

    let redis_cfg = build_redis_config(cfg);

    let store = match RedisStore::connect(redis_cfg) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "heimdall::boot",
                error = %e,
                addr = persistence_addr(cfg),
                "Redis pool creation failed; aborting boot (BIN-050)"
            );
            std::process::exit(1);
        }
    };

    // Obtain a connection and verify liveness with PING.
    let mut conn = match store.connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                target: "heimdall::boot",
                error = %e,
                addr = persistence_addr(cfg),
                "Redis pool connection failed; aborting boot (BIN-050)"
            );
            std::process::exit(1);
        }
    };

    // PING to confirm the server is reachable.
    if let Err(e) = redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
    {
        tracing::error!(
            target: "heimdall::boot",
            error = %e,
            addr = persistence_addr(cfg),
            "Redis PING failed; aborting boot (BIN-050)"
        );
        std::process::exit(1);
    }

    // Check the namespace schema version marker.
    match redis::cmd("GET")
        .arg("heimdall:schema_version")
        .query_async::<Option<String>>(&mut conn)
        .await
    {
        Ok(None) => {
            // Fresh Redis instance — write the marker.
            if let Err(e) = redis::cmd("SET")
                .arg("heimdall:schema_version")
                .arg(SCHEMA_VERSION)
                .query_async::<()>(&mut conn)
                .await
            {
                tracing::warn!(
                    target: "heimdall::boot",
                    error = %e,
                    "Failed to write Redis schema version marker; continuing"
                );
            }
        }
        Ok(Some(ref v)) if v == SCHEMA_VERSION => {
            // Version matches — OK.
        }
        Ok(Some(found)) => {
            tracing::error!(
                target: "heimdall::boot",
                expected = SCHEMA_VERSION,
                found = %found,
                "Redis schema version mismatch; namespace incompatible — aborting boot"
            );
            std::process::exit(1);
        }
        Err(e) => {
            tracing::error!(
                target: "heimdall::boot",
                error = %e,
                "Failed to read Redis schema version marker; aborting boot"
            );
            std::process::exit(1);
        }
    }

    tracing::info!(
        target: "heimdall::boot",
        addr = persistence_addr(cfg),
        schema_version = SCHEMA_VERSION,
        "Redis connection pool ready"
    );

    Some(store)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_redis_config(cfg: &PersistenceConfig) -> RedisConfig {
    let topology = if let Some(path) = &cfg.uds_path {
        RedisTopology::UnixSocket { path: path.clone() }
    } else {
        let host = cfg.host.clone().unwrap_or_default();
        RedisTopology::Tcp {
            host,
            port: cfg.port,
            tls: cfg.tls,
        }
    };

    RedisConfig {
        topology,
        auth: RedisAuth {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        },
        pool_max_size: cfg.pool_max_size,
        pool_min_size: cfg.pool_min_size,
        pool_acquisition_timeout_ms: cfg.pool_acquisition_timeout_ms,
        hscan_count: 1024,
    }
}

fn persistence_addr(cfg: &PersistenceConfig) -> String {
    if let Some(path) = &cfg.uds_path {
        format!("unix://{}", path.display())
    } else {
        let host = cfg.host.as_deref().unwrap_or("?");
        format!("redis://{}:{}", host, cfg.port)
    }
}
