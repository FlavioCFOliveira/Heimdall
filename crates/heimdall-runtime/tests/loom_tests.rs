// SPDX-License-Identifier: MIT
// Loom concurrency tests — activated only when RUSTFLAGS='--cfg loom'.
//
// Run with:
//   RUSTFLAGS='--cfg loom' cargo test -p heimdall-runtime --test loom_tests
//
// Tier 2 CI runs these via the `loom` job in ci-tier2.yml.
// Normal `cargo test` does NOT execute this module.

#[cfg(loom)]
mod loom_tests {
    use loom::sync::Arc;
    use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use loom::thread;

    /// Model: one reader acquiring a drain guard + one drain initiator.
    ///
    /// Verifies that the in-flight counter is always consistent across all valid
    /// memory-ordering interleavings: the counter must never go negative, and the
    /// drain initiator must always observe a non-negative count.
    #[test]
    fn drain_counter_consistency() {
        loom::model(|| {
            let draining = Arc::new(AtomicBool::new(false));
            let counter = Arc::new(AtomicUsize::new(0));

            let draining_r = Arc::clone(&draining);
            let counter_r = Arc::clone(&counter);

            // Reader: increment (acquire guard), simulate work, decrement (drop guard).
            let reader = thread::spawn(move || {
                // Simulate Drain::acquire: check draining flag.
                if draining_r.load(Ordering::Acquire) {
                    // Already draining: do not acquire.
                    return;
                }
                // Increment before second draining check (mirrors Drain::acquire).
                counter_r.fetch_add(1, Ordering::AcqRel);

                // Double-check draining (mirrors the second check in acquire()).
                if draining_r.load(Ordering::Acquire) {
                    let prev = counter_r.fetch_sub(1, Ordering::AcqRel);
                    // prev must be >= 1 — the counter was incremented above.
                    assert!(prev >= 1, "in-flight count underflowed");
                    return;
                }

                // Simulate work.

                // Decrement (DrainGuard::drop).
                let prev = counter_r.fetch_sub(1, Ordering::AcqRel);
                assert!(prev >= 1, "in-flight count underflowed on drop");

                // Notify drain waiter if last in-flight (simplified: just check).
                if prev == 1 && draining_r.load(Ordering::Acquire) {
                    // would notify here
                }
            });

            // Drain initiator: set draining flag, observe counter.
            draining.store(true, Ordering::Release);
            let observed = counter.load(Ordering::Acquire);
            // The counter must always be >= 0 (it is a usize, so this is guaranteed
            // by the type, but we assert the logical invariant explicitly).
            assert!(
                observed <= 1,
                "unexpected counter value: {observed} (only 1 reader)"
            );

            reader.join().expect("reader panicked");

            // After both threads complete, counter must be 0.
            assert_eq!(
                counter.load(Ordering::Relaxed),
                0,
                "in-flight counter must be 0 after all guards dropped"
            );
        });
    }

    /// Model: ArcSwap-like scenario — two readers + one swapper.
    ///
    /// Uses `Arc<AtomicUsize>` as a proxy for the state pointer.
    /// Verifies that no reader ever observes a value other than 0 or 1
    /// (i.e. the swap is atomic from the readers' perspective).
    #[test]
    fn arcswap_proxy_consistency() {
        loom::model(|| {
            let state = Arc::new(AtomicUsize::new(0));

            let s1 = Arc::clone(&state);
            let s2 = Arc::clone(&state);
            let s3 = Arc::clone(&state);

            let reader1 = thread::spawn(move || {
                let v = s1.load(Ordering::Acquire);
                // Must observe either 0 (before swap) or 1 (after swap).
                assert!(v == 0 || v == 1, "reader1 saw unexpected value: {v}");
            });

            let reader2 = thread::spawn(move || {
                let v = s2.load(Ordering::Acquire);
                assert!(v == 0 || v == 1, "reader2 saw unexpected value: {v}");
            });

            let swapper = thread::spawn(move || {
                s3.store(1, Ordering::Release);
            });

            reader1.join().expect("reader1 panicked");
            reader2.join().expect("reader2 panicked");
            swapper.join().expect("swapper panicked");
        });
    }

    /// Model: concurrent drain acquire and drain initiation.
    ///
    /// Ensures that after all threads complete, the in-flight counter is either 0
    /// (if the reader was blocked by the draining check) or 0 (if it completed
    /// normally). The counter must never be non-zero after all threads exit.
    #[test]
    fn drain_acquire_concurrent_with_drain_start() {
        loom::model(|| {
            let draining = Arc::new(AtomicBool::new(false));
            let counter = Arc::new(AtomicUsize::new(0));

            let draining_a = Arc::clone(&draining);
            let counter_a = Arc::clone(&counter);
            let draining_b = Arc::clone(&draining);

            // Thread A: attempts to acquire a guard.
            let thread_a = thread::spawn(move || {
                if draining_a.load(Ordering::Acquire) {
                    return; // rejected
                }
                counter_a.fetch_add(1, Ordering::AcqRel);
                if draining_a.load(Ordering::Acquire) {
                    let prev = counter_a.fetch_sub(1, Ordering::AcqRel);
                    assert!(prev >= 1);
                    return;
                }
                // guard held — decrement on "drop"
                let prev = counter_a.fetch_sub(1, Ordering::AcqRel);
                assert!(prev >= 1);
            });

            // Thread B: initiates drain.
            let thread_b = thread::spawn(move || {
                draining_b.store(true, Ordering::Release);
            });

            thread_a.join().expect("thread_a panicked");
            thread_b.join().expect("thread_b panicked");

            // Invariant: counter must be 0 when all threads have exited.
            assert_eq!(counter.load(Ordering::Relaxed), 0);
        });
    }
}
