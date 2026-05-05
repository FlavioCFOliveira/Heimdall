// SPDX-License-Identifier: MIT

//! Per-query wall-clock CPU budget for DNSSEC validation (DNSSEC-045).
//!
//! A [`ValidationBudget`] is created once per query and passed through the
//! validation pipeline.  Every expensive step — RRSIG verification, NSEC3
//! hash computation — must call [`ValidationBudget::check`] before proceeding,
//! so a malicious zone with many keys or high NSEC3 iteration counts cannot
//! cause unbounded CPU usage.

use crate::dnssec::verify::BogusReason;

/// A wall-clock budget for DNSSEC validation work.
///
/// Constructed once per query, shared across all validation steps.
/// Every long-running step must call [`check`][`ValidationBudget::check`]
/// to honour the budget.
///
/// Implements DNSSEC-045: per-query CPU time cap.
pub struct ValidationBudget {
    deadline: std::time::Instant,
}

impl ValidationBudget {
    /// Default maximum wall-clock time allowed for DNSSEC validation per query.
    pub const DEFAULT_DURATION: std::time::Duration = std::time::Duration::from_millis(500);

    /// Creates a budget that expires after `duration` from now.
    #[must_use]
    pub fn new(duration: std::time::Duration) -> Self {
        Self {
            deadline: std::time::Instant::now() + duration,
        }
    }

    /// Creates a budget using [`DEFAULT_DURATION`][`ValidationBudget::DEFAULT_DURATION`].
    #[must_use]
    pub fn default_budget() -> Self {
        Self::new(Self::DEFAULT_DURATION)
    }

    /// Returns `Ok(())` if budget remains, or `Err(BogusReason::CpuBudgetExceeded)`
    /// if the deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns [`BogusReason::CpuBudgetExceeded`] when the wall-clock deadline
    /// has been exceeded.
    pub fn check(&self) -> Result<(), BogusReason> {
        if std::time::Instant::now() > self.deadline {
            Err(BogusReason::CpuBudgetExceeded)
        } else {
            Ok(())
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn budget_check_passes_immediately() {
        let budget = ValidationBudget::new(Duration::from_secs(10));
        assert!(budget.check().is_ok());
    }

    #[test]
    fn budget_check_fails_after_expiry() {
        // Zero duration — already expired on construction.
        let budget = ValidationBudget::new(Duration::ZERO);
        // Give the clock a moment to advance past the deadline.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(budget.check(), Err(BogusReason::CpuBudgetExceeded));
    }
}
