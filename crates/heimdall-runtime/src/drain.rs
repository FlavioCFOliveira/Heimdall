// SPDX-License-Identifier: MIT

//! Controlled drain primitive.
//!
//! The [`Drain`] primitive signals the server to stop accepting new work and
//! waits for all in-flight operations to complete (or a timeout to elapse).
//!
//! # Usage pattern
//!
//! Each query handler calls [`Drain::acquire`] on entry. If the server is already
//! draining, `acquire` returns `None` and the handler should reject the request.
//! Otherwise it returns a [`DrainGuard`] that the handler holds for the duration
//! of its work. When the guard is dropped (on success, error, or panic), the
//! in-flight counter is decremented.
//!
//! To initiate a clean shutdown, call [`Drain::drain_and_wait`]. It atomically
//! sets the draining flag and waits until all outstanding guards are dropped.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::Notify;

/// Shared inner state for the drain primitive.
struct DrainInner {
    /// Set to `true` once [`Drain::drain_and_wait`] is called.
    draining: AtomicBool,
    /// Number of outstanding [`DrainGuard`] instances.
    in_flight: AtomicUsize,
    /// Notified by the last dropping guard while draining.
    notify: Notify,
}

/// Drain primitive — signals the server to stop accepting new work and waits
/// for all in-flight operations to complete.
///
/// Cheaply cloneable; all clones share the same drain state.
#[derive(Clone)]
pub struct Drain {
    inner: Arc<DrainInner>,
}

/// RAII guard held by each in-flight operation.
///
/// Dropping this guard decrements the in-flight counter. When the last guard is
/// dropped after drain has been initiated, [`Drain::drain_and_wait`] is unblocked.
pub struct DrainGuard {
    inner: Arc<DrainInner>,
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        // Decrement the in-flight counter.
        // AcqRel: synchronise with the load in drain_and_wait so that the
        // draining flag read below sees the latest store.
        let prev = self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
        // If we were the last in-flight operation and drain has started,
        // wake the waiter in drain_and_wait.
        if prev == 1 && self.inner.draining.load(Ordering::Acquire) {
            self.inner.notify.notify_one();
        }
    }
}

/// Error returned by [`Drain::drain_and_wait`].
#[derive(Debug, PartialEq, Eq)]
pub enum DrainError {
    /// The drain timeout elapsed before all in-flight operations completed.
    Timeout,
}

impl std::fmt::Display for DrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("drain timed out: in-flight operations did not complete in time")
    }
}

impl std::error::Error for DrainError {}

impl Drain {
    /// Create a new drain primitive in the non-draining state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DrainInner {
                draining: AtomicBool::new(false),
                in_flight: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
        }
    }

    /// Acquire a guard for an in-flight operation.
    ///
    /// Returns `None` if the server is already draining (the caller should reject
    /// the request). Otherwise returns a [`DrainGuard`] that must be held for the
    /// duration of the operation.
    ///
    /// # Ordering
    ///
    /// Uses `Acquire` for the draining check so that the guard increment is
    /// sequenced after any prior `Release` store to the draining flag.
    #[must_use]
    pub fn acquire(&self) -> Option<DrainGuard> {
        // Acquire ordering: see the most recent Release store to `draining`.
        if self.inner.draining.load(Ordering::Acquire) {
            return None;
        }
        // Increment before the second draining check to avoid a race where
        // drain_and_wait observes zero in-flight between our check and increment.
        self.inner.in_flight.fetch_add(1, Ordering::AcqRel);

        // Double-check: drain might have been initiated between our first check and
        // the increment. If so, decrement and return None.
        if self.inner.draining.load(Ordering::Acquire) {
            let prev = self.inner.in_flight.fetch_sub(1, Ordering::AcqRel);
            // Notify in case drain_and_wait is already waiting and we were at 1.
            if prev == 1 {
                self.inner.notify.notify_one();
            }
            return None;
        }

        Some(DrainGuard {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Signal drain start and wait for all in-flight operations to complete, or
    /// until `timeout` elapses.
    ///
    /// After this method returns (regardless of outcome), [`Drain::acquire`] will
    /// return `None` on all subsequent calls.
    ///
    /// # Errors
    ///
    /// Returns [`DrainError::Timeout`] if `timeout` elapses before all in-flight
    /// guards are dropped.
    pub async fn drain_and_wait(&self, timeout: Duration) -> Result<(), DrainError> {
        // Set draining flag. Release ordering: any acquire of the flag by a
        // concurrent acquire() call will observe this store.
        self.inner.draining.store(true, Ordering::Release);

        // If there are already zero in-flight operations, we are done immediately.
        // Acquire ordering: synchronise with the AcqRel decrement in DrainGuard::drop.
        if self.inner.in_flight.load(Ordering::Acquire) == 0 {
            return Ok(());
        }

        // Wait until the last DrainGuard notifies us, with a timeout.
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);

        let result = tokio::time::timeout(timeout, async {
            loop {
                // Re-check before awaiting to handle the case where the counter
                // reached zero between our initial check and pinning the future.
                if self.inner.in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.as_mut().await;
                // After being notified, check again — spurious wakeups are possible.
                if self.inner.in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
            }
        })
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(_elapsed) => Err(DrainError::Timeout),
        }
    }

    /// Returns `true` if drain has been initiated.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Acquire)
    }

    /// Returns the number of outstanding [`DrainGuard`] instances.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.inner.in_flight.load(Ordering::Acquire)
    }
}

impl Default for Drain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn acquire_and_drop_with_no_drain() {
        let drain = Drain::new();
        let guard = drain.acquire().expect("acquire before drain");
        assert!(!drain.is_draining());
        drop(guard);
    }

    #[tokio::test]
    async fn drain_with_no_in_flight_completes_immediately() {
        let drain = Drain::new();
        drain
            .drain_and_wait(Duration::from_millis(100))
            .await
            .expect("drain with no in-flight");
        assert!(drain.is_draining());
    }

    #[tokio::test]
    async fn acquire_returns_none_after_drain() {
        let drain = Drain::new();
        drain
            .drain_and_wait(Duration::from_millis(50))
            .await
            .expect("drain");
        assert!(drain.acquire().is_none());
    }

    #[tokio::test]
    async fn drain_waits_for_guard_drop() {
        let drain = Drain::new();
        let guard = drain.acquire().expect("acquire");

        let drain_clone = drain.clone();
        let task = tokio::spawn(async move {
            drain_clone
                .drain_and_wait(Duration::from_millis(500))
                .await
                .expect("drain should succeed")
        });

        // Give the task time to begin waiting.
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(guard);

        task.await.expect("task panicked");
        assert_eq!(drain.inner.in_flight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn drain_times_out_when_guards_held() {
        let drain = Drain::new();
        let _guard = drain.acquire().expect("acquire");

        let result = drain.drain_and_wait(Duration::from_millis(20)).await;
        assert_eq!(result, Err(DrainError::Timeout));
    }

    #[tokio::test]
    async fn multiple_guards_all_must_drop() {
        let drain = Drain::new();
        let g1 = drain.acquire().expect("g1");
        let g2 = drain.acquire().expect("g2");
        let g3 = drain.acquire().expect("g3");

        let drain_clone = drain.clone();
        let task = tokio::spawn(async move {
            drain_clone
                .drain_and_wait(Duration::from_millis(500))
                .await
                .expect("drain")
        });

        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(g1);
        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(g2);
        tokio::time::sleep(Duration::from_millis(5)).await;
        drop(g3);

        task.await.expect("task panicked");
    }
}
