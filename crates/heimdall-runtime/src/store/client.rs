// SPDX-License-Identifier: MIT

//! Redis client wrapper: topology, pool, error types, and availability flag.
//!
//! ## Topology
//!
//! [`RedisTopology`] represents the four supported connection modes:
//! - [`RedisTopology::UnixSocket`] — default (`STORE-005`).
//! - [`RedisTopology::Tcp`] — optional; TLS mandatory on non-loopback (`STORE-009`).
//! - [`RedisTopology::Cluster`] — Redis Cluster via `deadpool_redis::cluster::Pool`
//!   (`STORE-040`).
//! - [`RedisTopology::Sentinel`] — Redis Sentinel via `deadpool_redis::sentinel::Pool`
//!   (`STORE-041`).
//!
//! ## Pool
//!
//! All four topologies use `deadpool-redis` pools (ADR-0043):
//! - Standalone and Sentinel: [`deadpool_redis::Pool`].
//! - Cluster: [`deadpool_redis::cluster::Pool`].
//!
//! ## Availability flag
//!
//! [`RedisStore::is_available`] reflects whether the last command succeeded.
//! [`RedisStore::record_error`] marks unavailable and emits a structured
//! `tracing::warn!` event per `STORE-017`.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use deadpool_redis::{Config as StandalonePoolConfig, Runtime};

// Re-export for convenience in other store modules.
pub use super::encoding::CacheNamespace;
use super::metrics::StoreMetrics;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the store layer.
#[derive(Debug)]
pub enum StoreError {
    /// A Redis command failed.
    Redis(redis::RedisError),
    /// Connection pool acquisition failed.
    ///
    /// Covers both standalone/sentinel and cluster pool errors; deadpool
    /// exposes the same underlying type (`deadpool::managed::PoolError<RedisError>`)
    /// for all topology variants so a single variant is used here.
    Pool(deadpool_redis::PoolError),
    /// Binary encoding failed.
    EncodingError(String),
    /// Binary decoding failed.
    DecodingError(String),
    /// Configuration error (invalid topology, missing credentials, etc.).
    Config(String),
}

impl StoreError {
    /// Construct an encoding error with a human-readable message.
    pub(crate) fn encoding(msg: impl Into<String>) -> Self {
        Self::EncodingError(msg.into())
    }

    /// Construct a decoding error with a human-readable message.
    pub(crate) fn decoding(msg: impl Into<String>) -> Self {
        Self::DecodingError(msg.into())
    }

    /// Convert a cluster pool error into a `StoreError`.
    ///
    /// Cluster and standalone pool errors have the same underlying type in
    /// deadpool-redis, so this conversion is infallible.
    pub(crate) fn from_cluster_pool(e: &deadpool_redis::cluster::PoolError) -> Self {
        // `deadpool_redis::cluster::PoolError` = `deadpool::managed::PoolError<RedisError>`
        // which is the same underlying type as `deadpool_redis::PoolError`.
        // We format the error rather than transmuting to avoid unsound casting.
        Self::Config(format!("cluster pool error: {e}"))
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redis(e) => write!(f, "redis error: {e}"),
            Self::Pool(e) => write!(f, "connection pool error: {e}"),
            Self::EncodingError(s) => write!(f, "encoding error: {s}"),
            Self::DecodingError(s) => write!(f, "decoding error: {s}"),
            Self::Config(s) => write!(f, "store configuration error: {s}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Redis(e) => Some(e),
            Self::Pool(e) => Some(e),
            _ => None,
        }
    }
}

impl From<redis::RedisError> for StoreError {
    fn from(e: redis::RedisError) -> Self {
        Self::Redis(e)
    }
}

impl From<deadpool_redis::PoolError> for StoreError {
    fn from(e: deadpool_redis::PoolError) -> Self {
        Self::Pool(e)
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/// Redis ACL credentials (`STORE-012`).
///
/// Anonymous connections are prohibited; both `username` and `password` must
/// be operator-supplied.
#[derive(Debug, Clone)]
pub struct RedisAuth {
    /// ACL username.
    pub username: String,
    /// ACL password.
    pub password: String,
}

// ── Topology ──────────────────────────────────────────────────────────────────

/// Connection topology for the Redis backend.
///
/// UDS is the default and preferred mode (`STORE-005`). TCP with TLS is
/// required for non-loopback hosts (`STORE-009`). Cluster and Sentinel
/// topologies are optional deployment modes (`STORE-040`, `STORE-041`).
#[derive(Debug, Clone)]
pub enum RedisTopology {
    /// Unix domain socket (default, `STORE-005`).
    UnixSocket {
        /// Filesystem path of the Redis socket.
        path: PathBuf,
    },
    /// TCP connection, optionally with TLS 1.3 (`STORE-008..011`, `STORE-050`).
    Tcp {
        /// Hostname or IP address of the Redis server.
        host: String,
        /// TCP port.
        port: u16,
        /// Whether TLS 1.3 is enabled. Mandatory for non-loopback hosts.
        tls: bool,
    },
    /// Redis Cluster (`STORE-040`).
    Cluster {
        /// Seed node addresses, each in `"redis://host:port"` URL form.
        nodes: Vec<String>,
    },
    /// Redis Sentinel (`STORE-041`).
    Sentinel {
        /// Sentinel node addresses, each in `"redis://host:port"` URL form.
        sentinels: Vec<String>,
        /// The service name (master group name) to query.
        service_name: String,
    },
}

// ── Redis config ──────────────────────────────────────────────────────────────

/// Redis client configuration.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// Connection topology.
    pub topology: RedisTopology,
    /// ACL credentials (mandatory, `STORE-012`).
    pub auth: RedisAuth,
    /// Maximum connection pool size (`STORE-047`).
    pub pool_max_size: usize,
    /// Minimum connection pool size (pre-warmed at startup, `STORE-047`).
    pub pool_min_size: usize,
    /// Pool acquisition timeout in milliseconds (`STORE-047`).
    pub pool_acquisition_timeout_ms: u64,
    /// `COUNT` hint for `HSCAN` during zone enumeration (`STORE-048`).
    pub hscan_count: usize,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            topology: RedisTopology::UnixSocket {
                path: PathBuf::from("/var/run/redis/redis.sock"),
            },
            auth: RedisAuth {
                username: String::new(),
                password: String::new(),
            },
            pool_max_size: 64,
            pool_min_size: 5,
            pool_acquisition_timeout_ms: 100,
            hscan_count: 1024,
        }
    }
}

// ── Inner connection handle ───────────────────────────────────────────────────

/// Internal connection variant — one per topology.
enum ConnectionHandle {
    /// Pooled standalone connection (UDS or TCP).
    Standalone(deadpool_redis::Pool),
    /// Pooled sentinel connection.
    Sentinel(deadpool_redis::sentinel::Pool),
    /// Pooled cluster connection.
    Cluster(deadpool_redis::cluster::Pool),
}

// ── Pooled connection wrapper ─────────────────────────────────────────────────

/// A pooled connection obtained from the store.
///
/// Implements [`redis::aio::ConnectionLike`] so that it can be passed directly
/// to `redis::cmd(...).query_async(&mut conn)`.
pub enum PooledConn {
    /// Connection from a standalone (UDS or TCP) pool.
    Standalone(deadpool_redis::Connection),
    /// Connection from a sentinel pool.
    Sentinel(deadpool_redis::sentinel::Connection),
    /// Connection from a cluster pool.
    Cluster(deadpool_redis::cluster::Connection),
}

impl redis::aio::ConnectionLike for PooledConn {
    fn req_packed_command<'a>(
        &'a mut self,
        cmd: &'a redis::Cmd,
    ) -> redis::RedisFuture<'a, redis::Value> {
        match self {
            Self::Standalone(c) => c.req_packed_command(cmd),
            Self::Sentinel(c) => c.req_packed_command(cmd),
            Self::Cluster(c) => c.req_packed_command(cmd),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
        match self {
            Self::Standalone(c) => c.req_packed_commands(cmd, offset, count),
            Self::Sentinel(c) => c.req_packed_commands(cmd, offset, count),
            Self::Cluster(c) => c.req_packed_commands(cmd, offset, count),
        }
    }

    fn get_db(&self) -> i64 {
        match self {
            Self::Standalone(c) => c.get_db(),
            Self::Sentinel(c) => c.get_db(),
            Self::Cluster(c) => c.get_db(),
        }
    }
}

// ── Drain stats ──────────────────────────────────────────────────────────────

/// Statistics returned by [`RedisStore::drain`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreDrainStats {
    /// Number of connections in flight at the moment drain was initiated.
    pub commands_in_flight_at_drain: usize,
    /// Number of in-flight connections that completed before the grace timeout.
    pub commands_completed_during_drain: usize,
    /// Number of in-flight connections that were still outstanding when the
    /// grace timeout elapsed (0 on clean drain).
    pub commands_force_cancelled: usize,
}

// ── TrackedConn ───────────────────────────────────────────────────────────────

/// A pooled connection that decrements the store's `in_flight` counter on drop.
pub struct TrackedConn {
    inner: PooledConn,
    in_flight: Arc<AtomicUsize>,
}

impl Drop for TrackedConn {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl redis::aio::ConnectionLike for TrackedConn {
    fn req_packed_command<'a>(
        &'a mut self,
        cmd: &'a redis::Cmd,
    ) -> redis::RedisFuture<'a, redis::Value> {
        self.inner.req_packed_command(cmd)
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
        self.inner.req_packed_commands(cmd, offset, count)
    }

    fn get_db(&self) -> i64 {
        self.inner.get_db()
    }
}

// ── RedisStore ────────────────────────────────────────────────────────────────

/// Redis connection wrapper providing availability tracking and metrics.
///
/// Connections are obtained via [`RedisStore::connection`]. Higher-level
/// operations are implemented in [`super::zone_store`], [`super::cache_store`],
/// and [`super::ixfr_journal`].
///
/// # Availability
///
/// [`RedisStore::is_available`] reflects whether the last command succeeded.
/// On any command failure, call [`RedisStore::record_error`] to update the flag
/// and emit a `tracing::warn!` event per `STORE-017`.
pub struct RedisStore {
    config: RedisConfig,
    handle: ConnectionHandle,
    available: Arc<AtomicBool>,
    /// Number of connections currently checked out (in-flight).
    in_flight: Arc<AtomicUsize>,
    /// Set to `true` once [`RedisStore::drain`] is called; new connection
    /// requests are rejected while draining.
    draining: Arc<AtomicBool>,
    /// Shared metrics instance.
    pub metrics: StoreMetrics,
}

impl RedisStore {
    /// Open a connection pool based on `config`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Config`] if the topology configuration is invalid
    /// or if pool creation fails.
    #[must_use = "the RedisStore must be used; dropping it closes the pool"]
    pub fn connect(config: RedisConfig) -> Result<Self, StoreError> {
        let handle = build_handle(&config)?;
        Ok(Self {
            config,
            handle,
            available: Arc::new(AtomicBool::new(true)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            draining: Arc::new(AtomicBool::new(false)),
            metrics: StoreMetrics::new(),
        })
    }

    /// Whether Redis is currently reachable.
    ///
    /// Updated by [`Self::record_error`] and [`Self::record_success`].
    /// Callers serving from in-process state during an outage should check this
    /// flag before attempting a Redis command (`STORE-017`).
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Mark the store as unavailable after a command failure and emit a
    /// structured warning event (`STORE-017`).
    pub fn record_error(&self, err: &StoreError) {
        self.available.store(false, Ordering::Release);
        tracing::warn!(
            event = "redis_operation_failed",
            error = %err,
            available = false,
            "Redis operation failed; serving from in-process state"
        );
    }

    /// Mark the store as available after a successful command.
    pub fn record_success(&self) {
        self.available.store(true, Ordering::Release);
    }

    /// Obtain a connection from the pool.
    ///
    /// Returns a [`TrackedConn`] that decrements the in-flight counter when
    /// dropped. Fails with [`StoreError::Config`] if drain has been initiated.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Pool`] (standalone/sentinel) or
    /// [`StoreError::Config`] (cluster or draining) if the pool cannot provide
    /// a connection within the configured acquisition timeout.
    pub async fn connection(&self) -> Result<TrackedConn, StoreError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(StoreError::Config(
                "Redis pool is draining; new connections are refused".into(),
            ));
        }

        let inner = match &self.handle {
            ConnectionHandle::Standalone(pool) => pool
                .get()
                .await
                .map(PooledConn::Standalone)
                .map_err(StoreError::Pool)?,
            ConnectionHandle::Sentinel(pool) => pool
                .get()
                .await
                .map(PooledConn::Sentinel)
                .map_err(StoreError::Pool)?,
            ConnectionHandle::Cluster(pool) => pool
                .get()
                .await
                .map(PooledConn::Cluster)
                .map_err(|e| StoreError::from_cluster_pool(&e))?,
        };

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        Ok(TrackedConn {
            inner,
            in_flight: Arc::clone(&self.in_flight),
        })
    }

    /// Initiate a graceful pool drain.
    ///
    /// 1. Sets the draining flag so no new connections are accepted.
    /// 2. Waits up to `grace` for all in-flight connections to be returned.
    /// 3. Returns [`StoreDrainStats`] with counters for observability.
    ///
    /// Drain failures (e.g. Redis unavailable mid-drain) do NOT block process
    /// exit — they are captured in `commands_force_cancelled`.
    pub async fn drain(&self, grace: Duration) -> StoreDrainStats {
        let in_flight_at_drain = self.in_flight.load(Ordering::Acquire);
        self.draining.store(true, Ordering::Release);

        if in_flight_at_drain > 0 {
            let deadline = tokio::time::Instant::now() + grace;
            loop {
                if self.in_flight.load(Ordering::Acquire) == 0 {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        let remaining = self.in_flight.load(Ordering::Acquire);
        let completed = in_flight_at_drain.saturating_sub(remaining);

        StoreDrainStats {
            commands_in_flight_at_drain: in_flight_at_drain,
            commands_completed_during_drain: completed,
            commands_force_cancelled: remaining,
        }
    }

    /// Active [`RedisConfig`].
    #[must_use]
    pub fn config(&self) -> &RedisConfig {
        &self.config
    }
}

// ── Handle construction ───────────────────────────────────────────────────────

fn build_handle(config: &RedisConfig) -> Result<ConnectionHandle, StoreError> {
    match &config.topology {
        RedisTopology::UnixSocket { path } => {
            // Redis URL for UDS: redis+unix:///path/to/socket?user=…&password=…
            let url = format!(
                "redis+unix://{}?user={}&password={}",
                path.display(),
                url_encode(&config.auth.username),
                url_encode(&config.auth.password),
            );
            let pool_cfg = StandalonePoolConfig::from_url(url);
            let pool = pool_cfg
                .create_pool(Some(Runtime::Tokio1))
                .map_err(|e| StoreError::Config(format!("UDS pool creation failed: {e}")))?;
            Ok(ConnectionHandle::Standalone(pool))
        }

        RedisTopology::Tcp { host, port, tls } => {
            let scheme = if *tls { "rediss" } else { "redis" };
            let url = format!(
                "{scheme}://{}:{}@{host}:{port}/0",
                url_encode(&config.auth.username),
                url_encode(&config.auth.password),
            );
            let pool_cfg = StandalonePoolConfig::from_url(url);
            let pool = pool_cfg
                .create_pool(Some(Runtime::Tokio1))
                .map_err(|e| StoreError::Config(format!("TCP pool creation failed: {e}")))?;
            Ok(ConnectionHandle::Standalone(pool))
        }

        RedisTopology::Cluster { nodes } => {
            let sentinel_cfg = deadpool_redis::cluster::Config {
                urls: Some(nodes.clone()),
                connections: None,
                pool: None,
                read_from_replicas: false,
            };
            let pool = sentinel_cfg
                .create_pool(Some(Runtime::Tokio1))
                .map_err(|e| StoreError::Config(format!("cluster pool creation failed: {e}")))?;
            Ok(ConnectionHandle::Cluster(pool))
        }

        RedisTopology::Sentinel {
            sentinels,
            service_name,
        } => {
            let sentinel_cfg = deadpool_redis::sentinel::Config::from_urls(
                sentinels.clone(),
                service_name.clone(),
                deadpool_redis::sentinel::SentinelServerType::Master,
            );
            let pool = sentinel_cfg
                .create_pool(Some(Runtime::Tokio1))
                .map_err(|e| StoreError::Config(format!("sentinel pool creation failed: {e}")))?;
            Ok(ConnectionHandle::Sentinel(pool))
        }
    }
}

/// Percent-encode a string for inclusion in a Redis URL.
///
/// Encodes characters that would break URL parsing. Alphanumerics and `-_~.`
/// are left as-is; all others are percent-encoded.
fn url_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}
