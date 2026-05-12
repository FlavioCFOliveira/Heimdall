// SPDX-License-Identifier: MIT

//! Poll-until-condition helpers for integration tests (Sprint 68 task #684).
//!
//! Heimdall's integration tests historically interleaved [`std::thread::sleep`]
//! and [`tokio::time::sleep`] calls between "did action" and "check result" to
//! give the daemon time to publish the side-effect (metric increment, log line,
//! socket state, persisted record, …).  Two failure modes are inherent to that
//! pattern:
//!
//! 1. **Wall-clock waste.** Every test pays the full sleep budget even when the
//!    side-effect lands in microseconds — the most common case on a developer
//!    laptop and on cold caches.
//! 2. **Flake floor.** When the runner is overloaded (CI, ASAN, soak) the
//!    side-effect takes longer than the sleep and the test fails non-deterministically.
//!
//! The helpers in this module convert *sleep-then-assert* into
//! *poll-until-condition*: the body re-evaluates a probe closure on a tight
//! interval (5 ms by default) until it returns `Some(T)` or a per-test
//! deadline elapses.
//!
//! ## Pattern
//!
//! Sync (in a synchronous test that spawns a `TestServer` subprocess):
//!
//! ```no_run
//! # use heimdall_e2e_harness::poll_until;
//! # use std::time::Duration;
//! # fn fetch_metric() -> Option<u64> { Some(1) }
//! let val = poll_until(
//!     "heimdall_cache_hits_total reaches 1",
//!     Duration::from_secs(5),
//!     Duration::from_millis(5),
//!     || fetch_metric().filter(|v| *v >= 1),
//! );
//! assert_eq!(val, 1);
//! ```
//!
//! Async (inside a `#[tokio::test]` that drives a listener via `Drain`):
//!
//! ```no_run
//! # use heimdall_e2e_harness::poll_until_async;
//! # use std::time::Duration;
//! # async fn probe() -> Option<()> { Some(()) }
//! # async fn example() {
//! poll_until_async(
//!     "listener task is polling",
//!     Duration::from_secs(2),
//!     Duration::from_millis(5),
//!     || async { probe().await },
//! )
//! .await;
//! # }
//! ```
//!
//! ## Scope
//!
//! These helpers are *only* a coordination mechanism for tests that wait on
//! **eventual consistency** (a metric will be incremented soon, a counter will
//! settle).  Tests that assert **time-bounded behaviour** — e.g. "the TTL=1 s
//! record must be evicted after 1 s" — must keep the deliberate `sleep`, with
//! an `// INVARIANT:` comment cross-referencing the spec requirement under
//! test.  See [`docs/process/test-conventions.md`] for the full taxonomy.

use std::{
    future::Future,
    time::{Duration, Instant},
};

// ── Defaults ─────────────────────────────────────────────────────────────────

/// Default polling interval used when callers do not supply one.  Chosen so
/// the fast path (condition already true) converges in a single iteration on
/// any modern host.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Default per-test deadline.  Five seconds is the same budget used by
/// `TestServer::wait_ready` and is comfortably above any side-effect this
/// project legitimately waits on outside soak/perf paths.
pub const DEFAULT_POLL_DEADLINE: Duration = Duration::from_secs(5);

// ── Sync helper ──────────────────────────────────────────────────────────────

/// Polls `check` every `interval` until it returns `Some(T)` or until
/// `deadline` elapses.
///
/// Returns the value on success.  Panics with a message that includes `descr`
/// and the elapsed wall-clock on timeout — the panic message is the only
/// information the test author sees when CI fails, so be specific.
///
/// `interval` is enforced as a **minimum** between probe attempts; on fast
/// hosts the first probe usually succeeds and `interval` is never observed.
///
/// # Panics
///
/// Panics if `check` has not returned `Some` by the time `deadline` elapses.
///
/// # Examples
///
/// ```no_run
/// use heimdall_e2e_harness::poll_until;
/// use std::time::Duration;
///
/// # fn metric_value() -> u64 { 1 }
/// let value = poll_until(
///     "metric must increment",
///     Duration::from_secs(5),
///     Duration::from_millis(5),
///     || {
///         let v = metric_value();
///         if v >= 1 { Some(v) } else { None }
///     },
/// );
/// assert_eq!(value, 1);
/// ```
#[track_caller]
#[allow(
    clippy::manual_assert,
    reason = "explicit if-panic keeps the timeout check separate from the success-return arm, preserving #[track_caller] panic location"
)]
pub fn poll_until<T, F>(descr: &str, deadline: Duration, interval: Duration, mut check: F) -> T
where
    F: FnMut() -> Option<T>,
{
    let started = Instant::now();
    let absolute_deadline = started + deadline;
    loop {
        if let Some(value) = check() {
            return value;
        }
        if Instant::now() >= absolute_deadline {
            panic!(
                "poll_until: timed out waiting for `{descr}` after {:.3?} (deadline {:.3?})",
                started.elapsed(),
                deadline,
            );
        }
        std::thread::sleep(interval);
    }
}

/// Like [`poll_until`] but returns `Option<T>` rather than panicking on
/// timeout.  Use this when the caller needs to assert on the timeout itself
/// (typical pattern: a `wait_for_*` helper that exposes a boolean to its
/// caller).
///
/// `Some(value)` is returned when `check` first yields `Some`; `None` is
/// returned if the deadline elapses first.
pub fn poll_until_or_timeout<T, F>(
    deadline: Duration,
    interval: Duration,
    mut check: F,
) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    let absolute_deadline = Instant::now() + deadline;
    loop {
        if let Some(value) = check() {
            return Some(value);
        }
        if Instant::now() >= absolute_deadline {
            return None;
        }
        std::thread::sleep(interval);
    }
}

// ── Bounded-wait helpers for tests that have no observable readiness signal ──

/// Sleeps for `dur` synchronously.  Use this for tests where:
///
/// 1. The thing being awaited has **no observable signal** (no metric, no
///    socket, no log line) — for example, waiting for tokio signal handlers
///    to be installed on a daemon spawned without an observability port, or
///    waiting for stderr to flush before SIGTERM.
/// 2. The assertion that follows is **negative** ("counter must NOT have
///    incremented", "daemon must NOT have exited") — a poll-until-condition
///    would terminate at the first sample and miss a delayed change.
///
/// This helper exists purely to consolidate the rationale at a single
/// site.  Every call passes a `reason: &'static str` that is **discarded at
/// runtime** but kept in source as documentation; the compiler enforces
/// that the reason is supplied.  Equivalent to `std::thread::sleep(dur)`.
///
/// # Examples
///
/// ```
/// use heimdall_e2e_harness::wait_bounded;
/// use std::time::Duration;
///
/// // Time-bounded negative assertion — POLL would defeat the design.
/// wait_bounded(
///     "ROLE-005: over 100 ms the disabled-role counter must NOT increment",
///     Duration::from_millis(100),
/// );
/// ```
pub fn wait_bounded(_reason: &'static str, dur: Duration) {
    std::thread::sleep(dur);
}

/// Async sister of [`wait_bounded`].  Same semantics: deliberate fixed-time
/// wait when no readiness signal exists.
pub async fn wait_bounded_async(_reason: &'static str, dur: Duration) {
    tokio::time::sleep(dur).await;
}

// ── Async helper ─────────────────────────────────────────────────────────────

/// Async sister of [`poll_until`]: polls `check` every `interval` until the
/// returned future yields `Some(T)` or `deadline` elapses.
///
/// Uses [`tokio::time::sleep`] for the inter-probe wait so the runtime is not
/// blocked during the wait window.  Therefore this helper must be invoked
/// from inside a tokio runtime with the `time` driver enabled (the standard
/// `#[tokio::test]` macro enables it).
///
/// # Panics
///
/// Panics if `check` has not yielded `Some` by the time `deadline` elapses.
///
/// # Examples
///
/// ```no_run
/// use heimdall_e2e_harness::poll_until_async;
/// use std::time::Duration;
///
/// # async fn example() {
/// # async fn probe() -> Option<u64> { Some(1) }
/// let value = poll_until_async(
///     "background task has emitted at least one event",
///     Duration::from_secs(5),
///     Duration::from_millis(5),
///     || async { probe().await },
/// )
/// .await;
/// assert_eq!(value, 1);
/// # }
/// ```
//
// Note: `#[track_caller]` cannot be applied to `async fn` on stable Rust
// (rust-lang/rust#110011). The panic message itself names the helper and the
// `descr` argument, which is sufficient to locate the call site.
#[allow(
    clippy::manual_assert,
    reason = "explicit if-panic keeps the timeout check separate from the success-return arm; assert! would interfere with future cancellation-safety changes"
)]
pub async fn poll_until_async<T, F, Fut>(
    descr: &str,
    deadline: Duration,
    interval: Duration,
    mut check: F,
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let started = Instant::now();
    let absolute_deadline = started + deadline;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        if Instant::now() >= absolute_deadline {
            panic!(
                "poll_until_async: timed out waiting for `{descr}` after {:.3?} (deadline {:.3?})",
                started.elapsed(),
                deadline,
            );
        }
        tokio::time::sleep(interval).await;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn poll_until_returns_immediately_when_condition_is_true() {
        let started = Instant::now();
        let v = poll_until(
            "trivially true",
            Duration::from_secs(5),
            Duration::from_millis(50),
            || Some(42u32),
        );
        assert_eq!(v, 42);
        // First probe is synchronous; should converge in well under the interval.
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "first-iteration convergence must not pay the interval cost"
        );
    }

    #[test]
    fn poll_until_converges_after_n_iterations() {
        let counter = AtomicU32::new(0);
        let v = poll_until(
            "counter reaches 3",
            Duration::from_secs(5),
            Duration::from_millis(1),
            || {
                let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= 3 { Some(n) } else { None }
            },
        );
        assert_eq!(v, 3);
    }

    #[test]
    #[should_panic(expected = "poll_until: timed out waiting for `never settles`")]
    fn poll_until_panics_on_timeout() {
        let _: () = poll_until(
            "never settles",
            Duration::from_millis(30),
            Duration::from_millis(5),
            || None::<()>,
        );
    }

    #[tokio::test]
    async fn poll_until_async_returns_immediately_when_condition_is_true() {
        let started = Instant::now();
        let v = poll_until_async(
            "trivially true",
            Duration::from_secs(5),
            Duration::from_millis(50),
            || async { Some(7u32) },
        )
        .await;
        assert_eq!(v, 7);
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn poll_until_async_converges_after_n_iterations() {
        let counter = AtomicU32::new(0);
        let v = poll_until_async(
            "async counter reaches 3",
            Duration::from_secs(5),
            Duration::from_millis(1),
            || async {
                let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= 3 { Some(n) } else { None }
            },
        )
        .await;
        assert_eq!(v, 3);
    }

    #[tokio::test]
    #[should_panic(expected = "poll_until_async: timed out waiting for `never settles`")]
    async fn poll_until_async_panics_on_timeout() {
        let _: () = poll_until_async(
            "never settles",
            Duration::from_millis(30),
            Duration::from_millis(5),
            || async { None::<()> },
        )
        .await;
    }
}
