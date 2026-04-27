// SPDX-License-Identifier: MIT

//! Timeout, retry, and budget tracking for recursive resolution.
//!
//! [`QueryBudget`] tracks the total wall-clock budget and per-attempt timeout
//! for a single recursive query. It is created once per incoming client query
//! and threaded through the resolution pipeline.

use std::time::{Duration, Instant};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default total budget for a single recursive resolution.
const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_secs(5);

/// Default per-attempt timeout before moving to the next upstream server.
const DEFAULT_PER_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(800);

// ── QueryBudget ───────────────────────────────────────────────────────────────

/// Tracks the total wall-clock budget and per-attempt timeout for a recursive
/// query.
///
/// A single [`QueryBudget`] is created at the start of each resolution attempt
/// and carries state through the delegation-following loop.
#[derive(Debug)]
pub struct QueryBudget {
    /// Maximum total wall-clock time allowed for resolution.
    pub total_budget: Duration,
    /// Maximum time to wait for a single upstream query attempt.
    pub per_attempt_timeout: Duration,
    /// Absolute start time of this resolution attempt.
    pub start: Instant,
    /// Number of upstream query attempts made so far.
    pub attempts: u32,
}

impl QueryBudget {
    /// Creates a [`QueryBudget`] with the default total budget (5 s) and
    /// per-attempt timeout (800 ms).
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_budget: DEFAULT_TOTAL_BUDGET,
            per_attempt_timeout: DEFAULT_PER_ATTEMPT_TIMEOUT,
            start: Instant::now(),
            attempts: 0,
        }
    }

    /// Returns the time remaining in the overall budget.
    ///
    /// Returns [`Duration::ZERO`] when the budget is exhausted.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        let elapsed = self.start.elapsed();
        self.total_budget.saturating_sub(elapsed)
    }

    /// Returns `true` if the total budget has been exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.remaining() == Duration::ZERO
    }

    /// Records a single upstream query attempt, incrementing the counter.
    pub fn record_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Returns the number of milliseconds elapsed since the budget was created.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        // Truncation: a query can never legitimately run for 584 million years;
        // practical upcast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let ms = self.start.elapsed().as_millis() as u64;
        ms
    }
}

impl Default for QueryBudget {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_budget_has_remaining_time() {
        let b = QueryBudget::new();
        assert!(!b.is_exhausted());
        assert!(b.remaining() > Duration::ZERO);
    }

    #[test]
    fn record_attempt_increments_counter() {
        let mut b = QueryBudget::new();
        assert_eq!(b.attempts, 0);
        b.record_attempt();
        assert_eq!(b.attempts, 1);
        b.record_attempt();
        assert_eq!(b.attempts, 2);
    }

    #[test]
    fn elapsed_ms_is_non_negative() {
        let b = QueryBudget::new();
        assert!(
            b.elapsed_ms() < 1_000,
            "should not take a full second in a test"
        );
    }

    #[test]
    fn budget_exhausted_after_budget_duration() {
        // Create a budget with zero duration — it is already exhausted.
        let b = QueryBudget {
            total_budget: Duration::ZERO,
            per_attempt_timeout: Duration::from_millis(100),
            start: Instant::now(),
            attempts: 0,
        };
        // Give the clock a moment to advance past zero.
        std::thread::sleep(Duration::from_millis(1));
        assert!(b.is_exhausted());
    }

    #[test]
    fn remaining_does_not_underflow() {
        let b = QueryBudget {
            total_budget: Duration::from_millis(1),
            per_attempt_timeout: Duration::from_millis(100),
            start: Instant::now() - Duration::from_secs(10),
            attempts: 0,
        };
        // Budget is long past; remaining must be zero, not panic.
        assert_eq!(b.remaining(), Duration::ZERO);
        assert!(b.is_exhausted());
    }
}
