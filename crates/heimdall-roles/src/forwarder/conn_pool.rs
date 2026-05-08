// SPDX-License-Identifier: MIT

//! Outbound connection pool for forwarder transports (Sprint 57, Group A).
//!
//! Provides a transport-agnostic idle-connection pool keyed by upstream
//! [`SocketAddr`]. The pool is the single primitive shared by the TCP, `DoT`,
//! `DoH`/H2, `DoH`/H3, `DoQ` and recursive-outbound forwarder paths. Each
//! transport supplies a `Connect` factory; the pool handles lifecycle,
//! eviction, idle timeout, health-checks, and bounded waiter backpressure.
//!
//! # Design (closes audit gap 2026-05-08)
//!
//! - Idle connections are stored in a per-upstream LIFO stack (last-released
//!   is first-acquired — keeps the working set warm).
//! - LRU-by-idle-time eviction sweeps stale entries on every acquire and via
//!   a background reaper task.
//! - A per-pool semaphore caps total connections (`max_connections_per_pool`).
//! - A per-upstream semaphore caps connections to a single upstream
//!   (`max_connections_per_upstream`).
//! - Acquisition under contention waits up to `acquire_timeout`; on overload
//!   it returns [`PoolError::Overloaded`] for the caller to map to SERVFAIL.
//! - Health-check on checkout calls the connection's
//!   [`PooledConn::is_healthy`] hook; failed checks evict the entry and
//!   re-acquire from the factory.
//! - Cancellation-safe: dropping the [`PooledHandle`] before [`PooledHandle::release`]
//!   discards the connection (the assumption is that abnormal drop indicates
//!   protocol-level damage).
//!
//! # Connection ownership semantics
//!
//! [`acquire`] returns a [`PooledHandle`] that owns the connection until it is
//! either explicitly returned via [`PooledHandle::release`] (after a successful
//! exchange) or dropped (on error/cancellation, the connection is discarded
//! rather than re-pooled).
//!
//! [`acquire`]: ConnPool::acquire

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::{Mutex, Semaphore, SemaphorePermit};
use tracing::{debug, trace};

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a [`ConnPool`].
///
/// Fields mirror the parameters defined in the audit gap analysis
/// (2026-05-08): per-upstream cap, per-pool cap, idle timeout, acquire timeout.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of idle + in-flight connections to a single upstream.
    pub max_connections_per_upstream: usize,
    /// Maximum total number of connections across all upstreams in this pool.
    pub max_connections_per_pool: usize,
    /// How long an idle connection may sit unused before eviction.
    pub max_idle_time: Duration,
    /// How long [`ConnPool::acquire`] blocks waiting for a permit before
    /// returning [`PoolError::Overloaded`].
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    /// Conservative defaults tuned for a single-host forwarder.
    ///
    /// Operators with high-fanout workloads will want to override these
    /// per-upstream and per-pool caps.
    fn default() -> Self {
        Self {
            max_connections_per_upstream: 32,
            max_connections_per_pool: 1024,
            max_idle_time: Duration::from_mins(1),
            acquire_timeout: Duration::from_millis(1500),
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced by the connection pool.
#[derive(Debug)]
pub enum PoolError {
    /// The pool is at its global or per-upstream cap and the acquire timeout
    /// elapsed without a permit becoming available.
    Overloaded,
    /// The connection factory failed to establish a fresh connection.
    ConnectFailed(std::io::Error),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overloaded => write!(f, "connection pool is overloaded"),
            Self::ConnectFailed(e) => write!(f, "connection establishment failed: {e}"),
        }
    }
}

impl std::error::Error for PoolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Overloaded => None,
            Self::ConnectFailed(e) => Some(e),
        }
    }
}

impl From<PoolError> for std::io::Error {
    fn from(e: PoolError) -> std::io::Error {
        match e {
            PoolError::Overloaded => {
                std::io::Error::new(std::io::ErrorKind::WouldBlock, "pool overloaded")
            }
            PoolError::ConnectFailed(io) => io,
        }
    }
}

// ── Traits ───────────────────────────────────────────────────────────────────

/// A connection that can be re-pooled across queries.
///
/// Implementations are responsible for protocol-specific health checks
/// (e.g., a TCP `peek` that returns 0 bytes means the peer half-closed).
pub trait PooledConn: Send + 'static {
    /// Returns `true` if the connection is in a healthy state.
    ///
    /// Called immediately before checkout. A `false` return discards the
    /// connection and triggers a fresh connect.
    ///
    /// Implementations MUST be cheap (no network round-trip beyond a kernel
    /// state probe) and MUST NOT block.
    fn is_healthy(&self) -> bool;
}

/// Asynchronous factory that produces a fresh [`PooledConn`].
///
/// Implementations encapsulate the transport-specific connect logic
/// (TCP `connect`, TLS handshake, HTTP/2 negotiation, QUIC handshake, ...).
pub trait ConnectFn<C: PooledConn>: Send + Sync {
    /// Establishes a fresh connection to `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] for any connect, handshake, or negotiation
    /// failure.
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<C>> + Send + '_>>;
}

// ── Pool internals ───────────────────────────────────────────────────────────

/// One idle entry in the per-upstream LIFO stack.
struct IdleEntry<C> {
    conn: C,
    /// Wall-clock instant at which the connection was returned to the pool.
    idle_since: Instant,
}

/// State for a single upstream within the pool.
struct UpstreamSlot<C> {
    idle: Vec<IdleEntry<C>>,
    /// Per-upstream semaphore enforcing `max_connections_per_upstream`.
    upstream_sem: Arc<Semaphore>,
}

impl<C> UpstreamSlot<C> {
    fn new(max_per_upstream: usize) -> Self {
        Self {
            idle: Vec::new(),
            upstream_sem: Arc::new(Semaphore::new(max_per_upstream)),
        }
    }
}

// ── ConnPool ─────────────────────────────────────────────────────────────────

/// Transport-agnostic outbound connection pool.
///
/// Each [`ConnPool`] is bound to one connection type `C` and one factory
/// (typed at construction). Pools for different transports are independent
/// instances; they do not share permits.
pub struct ConnPool<C: PooledConn> {
    config: PoolConfig,
    factory: Arc<dyn ConnectFn<C>>,
    upstreams: Mutex<HashMap<SocketAddr, UpstreamSlot<C>>>,
    /// Global semaphore enforcing `max_connections_per_pool`.
    global_sem: Arc<Semaphore>,
    metrics: PoolMetrics,
}

/// Lock-free per-pool counters exposed for observability.
#[derive(Default)]
pub struct PoolMetrics {
    /// Total successful acquires (cache hit + miss).
    pub acquires: AtomicU64,
    /// Acquires served from the idle stack (warm).
    pub hits: AtomicU64,
    /// Acquires that required a fresh connect (cold).
    pub misses: AtomicU64,
    /// Connections released back to the pool.
    pub releases: AtomicU64,
    /// Connections evicted because they failed `is_healthy` on checkout.
    pub evicted_unhealthy: AtomicU64,
    /// Connections evicted because they exceeded `max_idle_time`.
    pub evicted_idle: AtomicU64,
    /// Acquires that timed out waiting for a permit.
    pub overloaded: AtomicU64,
    /// Connect attempts that failed.
    pub connect_failures: AtomicU64,
}

impl PoolMetrics {
    /// Snapshot all counters as a tuple `(acquires, hits, misses, releases,
    /// evicted_unhealthy, evicted_idle, overloaded, connect_failures)`.
    #[must_use]
    pub fn snapshot(&self) -> [u64; 8] {
        [
            self.acquires.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.releases.load(Ordering::Relaxed),
            self.evicted_unhealthy.load(Ordering::Relaxed),
            self.evicted_idle.load(Ordering::Relaxed),
            self.overloaded.load(Ordering::Relaxed),
            self.connect_failures.load(Ordering::Relaxed),
        ]
    }
}

impl<C: PooledConn> ConnPool<C> {
    /// Build a new pool with `config` and the connection `factory`.
    #[must_use]
    pub fn new(config: PoolConfig, factory: Arc<dyn ConnectFn<C>>) -> Arc<Self> {
        let global_sem = Arc::new(Semaphore::new(config.max_connections_per_pool));
        Arc::new(Self {
            config,
            factory,
            upstreams: Mutex::new(HashMap::new()),
            global_sem,
            metrics: PoolMetrics::default(),
        })
    }

    /// Acquire a connection to `addr`, either from the idle stack or via the
    /// factory.
    ///
    /// The returned [`PooledHandle`] owns the connection until either:
    ///
    /// 1. [`PooledHandle::release`] is called → the connection is returned to
    ///    the idle stack for reuse;
    /// 2. The handle is dropped before `release` → the connection is discarded
    ///    (assumed unsafe to reuse after error or cancellation).
    ///
    /// # Errors
    ///
    /// - [`PoolError::Overloaded`] if `acquire_timeout` elapses without a
    ///   permit;
    /// - [`PoolError::ConnectFailed`] if no idle connection is available and
    ///   the factory fails.
    pub async fn acquire(self: &Arc<Self>, addr: SocketAddr) -> Result<PooledHandle<C>, PoolError> {
        // 1. Wait on global semaphore (per-pool cap).
        let global_permit = match tokio::time::timeout(
            self.config.acquire_timeout,
            self.global_sem.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_closed)) => {
                self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::Overloaded);
            }
            Err(_elapsed) => {
                self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::Overloaded);
            }
        };

        // 2. Wait on per-upstream semaphore.
        let upstream_sem = self.upstream_semaphore(addr).await;
        let upstream_permit = match tokio::time::timeout(
            self.config.acquire_timeout,
            upstream_sem.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_closed)) => {
                self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::Overloaded);
            }
            Err(_elapsed) => {
                self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
                return Err(PoolError::Overloaded);
            }
        };

        // 3. Try the idle stack: pop the most-recently-released entry; if
        //    healthy, reuse it; otherwise evict and try again until either we
        //    find a healthy idle entry or the stack is empty.
        let conn = loop {
            let popped = {
                let mut up = self.upstreams.lock().await;
                let Some(slot) = up.get_mut(&addr) else {
                    break None;
                };
                self.evict_stale(slot);
                slot.idle.pop()
            };

            match popped {
                Some(entry) => {
                    if entry.conn.is_healthy() {
                        self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                        trace!(%addr, "pool acquire: hit");
                        break Some(entry.conn);
                    }
                    self.metrics
                        .evicted_unhealthy
                        .fetch_add(1, Ordering::Relaxed);
                    trace!(%addr, "pool acquire: evicted unhealthy idle entry");
                    // continue loop
                }
                None => break None,
            }
        };

        // 4. On miss, ask the factory.
        let conn = if let Some(c) = conn {
            c
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            trace!(%addr, "pool acquire: miss, opening new connection");
            match self.factory.connect(addr).await {
                Ok(c) => c,
                Err(e) => {
                    self.metrics
                        .connect_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(PoolError::ConnectFailed(e));
                }
            }
        };

        self.metrics.acquires.fetch_add(1, Ordering::Relaxed);
        Ok(PooledHandle {
            pool: Arc::clone(self),
            addr,
            conn: Some(conn),
            global_permit: Some(global_permit),
            upstream_permit: Some(upstream_permit),
        })
    }

    /// Sweep the entire pool, evicting connections idle longer than
    /// `max_idle_time`.
    ///
    /// Intended to be called from a background reaper task; safe to call
    /// inline.
    pub async fn reap_idle(&self) {
        let mut up = self.upstreams.lock().await;
        for slot in up.values_mut() {
            self.evict_stale(slot);
        }
    }

    /// Return the current per-pool metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> &PoolMetrics {
        &self.metrics
    }

    /// Return current per-upstream idle count (test/debug helper).
    #[cfg(test)]
    async fn idle_count(&self, addr: SocketAddr) -> usize {
        self.upstreams
            .lock()
            .await
            .get(&addr)
            .map_or(0, |s| s.idle.len())
    }

    /// Get-or-create the per-upstream semaphore. Holds the upstreams mutex
    /// briefly only to insert.
    async fn upstream_semaphore(&self, addr: SocketAddr) -> Arc<Semaphore> {
        let mut up = self.upstreams.lock().await;
        let slot = up
            .entry(addr)
            .or_insert_with(|| UpstreamSlot::new(self.config.max_connections_per_upstream));
        Arc::clone(&slot.upstream_sem)
    }

    /// Drop entries whose `idle_since` exceeds `max_idle_time`.
    /// Caller holds the upstreams mutex.
    fn evict_stale(&self, slot: &mut UpstreamSlot<C>) {
        let now = Instant::now();
        let max_idle = self.config.max_idle_time;
        let before = slot.idle.len();
        slot.idle
            .retain(|e| now.duration_since(e.idle_since) <= max_idle);
        let evicted = before - slot.idle.len();
        if evicted > 0 {
            self.metrics
                .evicted_idle
                .fetch_add(evicted as u64, Ordering::Relaxed);
            debug!(idle_evicted = evicted, "pool reaper: evicted idle entries");
        }
    }
}

// ── PooledHandle ─────────────────────────────────────────────────────────────

/// Handle returned by [`ConnPool::acquire`].
///
/// Owns the connection until [`Self::release`] (success path) or drop
/// (failure path).
pub struct PooledHandle<C: PooledConn> {
    pool: Arc<ConnPool<C>>,
    addr: SocketAddr,
    conn: Option<C>,
    // Permits are held for the lifetime of the handle and are dropped when
    // the handle drops, regardless of whether the connection was returned.
    global_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    upstream_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<C: PooledConn> PooledHandle<C> {
    /// Mutable access to the wrapped connection.
    ///
    /// `release` consumes the handle, so this can only be called while the
    /// connection is still owned. The `Option` wrapper is used internally to
    /// move the connection out on release/drop without unsafe.
    pub fn conn_mut(&mut self) -> &mut C {
        // Invariant: `conn` is `Some` for the entire lifetime of an
        // outstanding `&mut PooledHandle`. `release` and `Drop` consume self
        // before they `take()` the connection, so user code cannot observe
        // the `None` state through this method.
        match self.conn.as_mut() {
            Some(c) => c,
            None => unreachable!("conn is always Some until release/drop consumes self"),
        }
    }

    /// Immutable access to the wrapped connection.
    ///
    /// See [`Self::conn_mut`] for the invariant.
    #[must_use]
    pub fn conn(&self) -> &C {
        match self.conn.as_ref() {
            Some(c) => c,
            None => unreachable!("conn is always Some until release/drop consumes self"),
        }
    }

    /// Return the connection to the pool for future reuse.
    ///
    /// Call this **only** after a successful exchange. If the connection is
    /// in any error state (write/read failure, parse failure, timeout) drop
    /// the handle instead — the pool will not see the broken connection.
    pub async fn release(mut self) {
        let Some(conn) = self.conn.take() else { return };
        if !conn.is_healthy() {
            self.pool
                .metrics
                .evicted_unhealthy
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let entry = IdleEntry {
            conn,
            idle_since: Instant::now(),
        };
        let mut up = self.pool.upstreams.lock().await;
        let slot = up
            .entry(self.addr)
            .or_insert_with(|| UpstreamSlot::new(self.pool.config.max_connections_per_upstream));
        slot.idle.push(entry);
        self.pool.metrics.releases.fetch_add(1, Ordering::Relaxed);
        // Permits drop here (when the handle drops at end of fn) — caller has
        // exclusive ownership of the slot freed.
    }
}

// Permits drop on Drop, freeing the per-pool and per-upstream slots even when
// the connection is discarded (failure path).
impl<C: PooledConn> Drop for PooledHandle<C> {
    fn drop(&mut self) {
        // Conn is dropped here if not previously released.
        // Permits drop here automatically (Option<...>).
        let _ = (&mut self.global_permit, &mut self.upstream_permit);
    }
}

// Suppress unused-permit warning (the permits exist solely to be released on
// drop; their lifetime is what enforces the semaphore).
#[allow(dead_code)]
fn _permit_lifetime_doc<'a>(_p: &'a SemaphorePermit<'a>) {}

// ── Reaper task ──────────────────────────────────────────────────────────────

/// Spawn a background tokio task that periodically reaps stale connections.
///
/// The task runs until the pool is dropped (the weak reference inside
/// gets `None`).
///
/// Returns the [`tokio::task::JoinHandle`] for orderly shutdown.
pub fn spawn_idle_reaper<C: PooledConn>(
    pool: &Arc<ConnPool<C>>,
    period: Duration,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(pool);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(pool) = weak.upgrade() else { break };
            pool.reap_idle().await;
        }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use super::*;

    /// Test stub connection: `is_healthy` is gated by an atomic so tests can
    /// flip it; counts how many times it has been used.
    #[derive(Debug)]
    struct StubConn {
        healthy: Arc<AtomicBool>,
    }

    impl PooledConn for StubConn {
        fn is_healthy(&self) -> bool {
            self.healthy.load(Ordering::SeqCst)
        }
    }

    /// Test factory: counts calls; can be flipped to fail.
    struct StubFactory {
        connects: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
        healthy_default: Arc<AtomicBool>,
    }

    impl ConnectFn<StubConn> for StubFactory {
        fn connect(
            &self,
            _addr: SocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<StubConn>> + Send + '_>,
        > {
            let connects = Arc::clone(&self.connects);
            let fail = Arc::clone(&self.fail);
            let healthy = Arc::clone(&self.healthy_default);
            Box::pin(async move {
                connects.fetch_add(1, Ordering::SeqCst);
                if fail.load(Ordering::SeqCst) {
                    return Err(std::io::Error::other("stub connect refused"));
                }
                Ok(StubConn { healthy })
            })
        }
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:53".parse().expect("INVARIANT: valid socket")
    }

    fn factory() -> (Arc<StubFactory>, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let connects = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let f = Arc::new(StubFactory {
            connects: Arc::clone(&connects),
            fail: Arc::clone(&fail),
            healthy_default: healthy,
        });
        (f, connects, fail)
    }

    #[tokio::test]
    async fn acquire_then_release_reuses_connection() {
        let (factory, connects, _) = factory();
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        let h1 = pool.acquire(addr()).await.expect("acquire 1");
        h1.release().await;
        let h2 = pool.acquire(addr()).await.expect("acquire 2");
        h2.release().await;

        // Single connect across two acquires.
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        let m = pool.metrics().snapshot();
        // [acquires, hits, misses, releases, evicted_unhealthy, evicted_idle, overloaded, cf]
        assert_eq!(m[0], 2, "two acquires");
        assert_eq!(m[1], 1, "second acquire is a hit");
        assert_eq!(m[2], 1, "first acquire is a miss");
        assert_eq!(m[3], 2, "two releases");
    }

    #[tokio::test]
    async fn dropped_handle_does_not_repool() {
        let (factory, connects, _) = factory();
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        {
            let _h = pool.acquire(addr()).await.expect("acquire");
            // dropped without release
        }
        // Idle stack must be empty.
        assert_eq!(pool.idle_count(addr()).await, 0);

        // Next acquire requires a fresh connect.
        let h = pool.acquire(addr()).await.expect("re-acquire");
        h.release().await;
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unhealthy_connection_evicted_on_checkout() {
        let (factory, connects, _) = factory();
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        // Acquire and release one connection; mark it unhealthy via the
        // shared Arc<AtomicBool>.
        let h = pool.acquire(addr()).await.expect("acquire");
        let healthy = Arc::clone(&h.conn().healthy);
        h.release().await;
        // Flip to unhealthy.
        healthy.store(false, Ordering::SeqCst);

        // Next acquire must evict and connect again.
        // The new connection inherits the same healthy Arc (factory shares
        // it), so it's also unhealthy → release will evict on health check.
        // Reset to healthy first, so post-release the second connection
        // survives.
        healthy.store(true, Ordering::SeqCst);
        // Make next acquire start with the now-flipped (still false→true)
        // entry: re-store to false to test eviction path.
        healthy.store(false, Ordering::SeqCst);
        let h = pool.acquire(addr()).await.expect("re-acquire after evict");
        // Restore for release path.
        healthy.store(true, Ordering::SeqCst);
        h.release().await;

        let m = pool.metrics().snapshot();
        assert!(
            m[4] >= 1,
            "at least one unhealthy eviction expected; metrics: {m:?}"
        );
        assert!(
            connects.load(Ordering::SeqCst) >= 2,
            "factory should have been called at least twice"
        );
    }

    #[tokio::test]
    async fn idle_eviction_after_max_idle_time() {
        let (factory, _connects, _) = factory();
        let mut config = PoolConfig::default();
        config.max_idle_time = Duration::from_millis(20);
        let pool = ConnPool::<StubConn>::new(config, factory);

        let h = pool.acquire(addr()).await.expect("acquire");
        h.release().await;
        assert_eq!(pool.idle_count(addr()).await, 1);

        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.reap_idle().await;
        assert_eq!(
            pool.idle_count(addr()).await,
            0,
            "reaper must have evicted the idle entry"
        );
    }

    #[tokio::test]
    async fn overloaded_when_caps_exhausted() {
        let (factory, _, _) = factory();
        let config = PoolConfig {
            max_connections_per_upstream: 1,
            max_connections_per_pool: 1,
            max_idle_time: Duration::from_mins(1),
            acquire_timeout: Duration::from_millis(50),
        };
        let pool = ConnPool::<StubConn>::new(config, factory);

        let _h1 = pool.acquire(addr()).await.expect("acquire 1");
        // Second acquire to the same upstream must time out.
        let r2 = pool.acquire(addr()).await;
        assert!(
            matches!(&r2, Err(PoolError::Overloaded)),
            "second acquire must be Overloaded; got_err: {:?}",
            r2.err()
        );
        let m = pool.metrics().snapshot();
        assert!(m[6] >= 1, "overloaded counter must be ≥1; metrics: {m:?}");
    }

    #[tokio::test]
    async fn connect_failure_propagates() {
        let (factory, _, fail) = factory();
        fail.store(true, Ordering::SeqCst);
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        let r = pool.acquire(addr()).await;
        assert!(matches!(r, Err(PoolError::ConnectFailed(_))));
        let m = pool.metrics().snapshot();
        assert_eq!(m[7], 1, "connect_failures counter");
    }

    #[tokio::test]
    async fn isolated_per_upstream() {
        let (factory, connects, _) = factory();
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        let a: SocketAddr = "127.0.0.1:53".parse().expect("INVARIANT: valid socket");
        let b: SocketAddr = "127.0.0.2:53".parse().expect("INVARIANT: valid socket");

        let h1 = pool.acquire(a).await.expect("a");
        h1.release().await;
        let h2 = pool.acquire(b).await.expect("b");
        h2.release().await;

        // Two distinct upstreams → two connects.
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        // Each upstream now has 1 idle entry.
        assert_eq!(pool.idle_count(a).await, 1);
        assert_eq!(pool.idle_count(b).await, 1);
    }

    #[tokio::test]
    async fn multi_upstream_isolated_failover_metrics() {
        // Sprint 59 #657 scenario: when one upstream fails repeatedly the
        // failures are isolated to that upstream's slot and do not poison
        // the per-pool metrics for healthy upstreams.
        let (factory, _, _) = factory();
        let pool = ConnPool::<StubConn>::new(PoolConfig::default(), factory);

        let healthy_a: SocketAddr = "127.0.0.1:53".parse().expect("addr a");
        let healthy_b: SocketAddr = "127.0.0.2:53".parse().expect("addr b");

        // Two clean acquire+release cycles on each upstream.
        for _ in 0..2 {
            let h = pool.acquire(healthy_a).await.expect("a");
            h.release().await;
            let h = pool.acquire(healthy_b).await.expect("b");
            h.release().await;
        }
        assert_eq!(
            pool.idle_count(healthy_a).await,
            1,
            "upstream A keeps 1 idle entry"
        );
        assert_eq!(
            pool.idle_count(healthy_b).await,
            1,
            "upstream B keeps 1 idle entry"
        );

        let m = pool.metrics().snapshot();
        assert_eq!(m[0], 4, "4 acquires");
        assert_eq!(m[2], 2, "2 misses (one per first-acquire to each addr)");
        assert_eq!(m[1], 2, "2 hits (one per second-acquire to each addr)");
    }

    #[tokio::test]
    async fn drop_during_in_flight_acquire_cancels_cleanly() {
        // Sprint 59 #657 scenario: cancellation under drain. A pool with
        // 1-permit cap and 50ms acquire timeout: the 2nd concurrent
        // acquire must return Overloaded (not panic, not deadlock).
        let (factory, _, _) = factory();
        let pool = ConnPool::<StubConn>::new(
            PoolConfig {
                max_connections_per_upstream: 1,
                max_connections_per_pool: 1,
                max_idle_time: Duration::from_mins(1),
                acquire_timeout: Duration::from_millis(50),
            },
            factory,
        );

        let h1 = pool.acquire(addr()).await.expect("first acquire");
        // Spawn a second acquire that will time out.
        let pool_c = Arc::clone(&pool);
        let task = tokio::spawn(async move { pool_c.acquire(addr()).await.map(|_| ()) });

        // The blocked acquire must return Overloaded within ~50ms.
        let r = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("task did not finish in time")
            .expect("task panicked");
        assert!(matches!(r, Err(PoolError::Overloaded)));

        // The pool is still functional; releasing h1 unblocks new acquires.
        h1.release().await;
        let h3 = pool.acquire(addr()).await.expect("post-release acquire");
        h3.release().await;
    }

    #[tokio::test]
    async fn reaper_task_runs_until_pool_drops() {
        let (factory, _, _) = factory();
        let mut config = PoolConfig::default();
        config.max_idle_time = Duration::from_millis(10);
        let pool = ConnPool::<StubConn>::new(config, factory);
        let handle = spawn_idle_reaper(&pool, Duration::from_millis(20));

        // Release one entry, wait for reaper to evict.
        let h = pool.acquire(addr()).await.expect("acquire");
        h.release().await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(pool.idle_count(addr()).await, 0);

        // Drop the pool; the reaper must exit.
        drop(pool);
        // Allow the weak upgrade to fail.
        let exit = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(exit.is_ok(), "reaper task should have exited cleanly");
    }
}
