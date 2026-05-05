// SPDX-License-Identifier: MIT

//! Under-load composite signal with hysteresis (THREAT-069, task #256).
//!
//! [`LoadSignal`] evaluates a composite score from four normalised factors and
//! maintains an atomic boolean with hysteresis: the server enters load when the
//! score exceeds `HIGH_WATER` (0.8) and exits load when the score drops below
//! `LOW_WATER` (0.6).
//!
//! `cpu_pct` and `memory_pct` are provided externally by the runtime; this
//! module only evaluates the composite.

use std::sync::atomic::{AtomicBool, Ordering};

// ── thresholds ────────────────────────────────────────────────────────────────

/// Composite score above which the server is considered under load.
const HIGH_WATER: f32 = 0.8;
/// Composite score below which the server exits the under-load state.
const LOW_WATER: f32 = 0.6;

// ── LoadFactors ───────────────────────────────────────────────────────────────

/// The four normalised inputs to the composite load signal.
///
/// Each field must be in the range `0.0..=1.0`.
#[derive(Debug, Clone, Copy)]
pub struct LoadFactors {
    /// CPU utilisation fraction (`0.0` = idle, `1.0` = fully saturated).
    pub cpu_pct: f32,
    /// Memory utilisation fraction relative to the configured memory budget.
    pub memory_pct: f32,
    /// Fraction of the global pending-query cap currently consumed.
    pub pending_queries_pct: f32,
    /// Normalised recent rate-limit fire rate.
    pub rl_fires_rate: f32,
}

// ── LoadSignal ────────────────────────────────────────────────────────────────

/// Composite under-load signal with hysteresis.
///
/// # Thread safety
///
/// [`LoadSignal::update`] and [`LoadSignal::is_under_load`] are both safe to
/// call concurrently from any number of threads.  The hysteresis state is an
/// [`AtomicBool`]; a momentary race between two concurrent `update` calls is
/// benign because both callers base their decision on the same monotonically
/// advancing load score.
#[derive(Debug, Default)]
pub struct LoadSignal {
    under_load: AtomicBool,
}

impl LoadSignal {
    /// Create a new signal, initially not under load.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the signal from fresh load factors.
    ///
    /// The composite score is the arithmetic mean of the four factors.  If the
    /// server is not currently under load and the score exceeds `HIGH_WATER`, the
    /// state transitions to under-load.  If it is currently under load and the
    /// score drops below `LOW_WATER`, the state exits under-load (hysteresis).
    pub fn update(&self, factors: LoadFactors) {
        let score = composite_score(factors);
        let currently_under = self.under_load.load(Ordering::Relaxed);
        if currently_under {
            if score < LOW_WATER {
                self.under_load.store(false, Ordering::Release);
            }
        } else if score > HIGH_WATER {
            self.under_load.store(true, Ordering::Release);
        }
    }

    /// Return `true` when the server is currently classified as under load.
    #[must_use]
    pub fn is_under_load(&self) -> bool {
        self.under_load.load(Ordering::Acquire)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Arithmetic mean of the four load factors, clamped to `0.0..=1.0`.
#[inline]
fn composite_score(f: LoadFactors) -> f32 {
    let sum = f.cpu_pct + f.memory_pct + f.pending_queries_pct + f.rl_fires_rate;
    (sum / 4.0).clamp(0.0, 1.0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{HIGH_WATER, LOW_WATER, LoadFactors, LoadSignal};

    fn factors(v: f32) -> LoadFactors {
        LoadFactors {
            cpu_pct: v,
            memory_pct: v,
            pending_queries_pct: v,
            rl_fires_rate: v,
        }
    }

    #[test]
    fn starts_not_under_load() {
        let s = LoadSignal::new();
        assert!(!s.is_under_load());
    }

    #[test]
    fn enters_load_above_high_water() {
        let s = LoadSignal::new();
        // All factors = HIGH_WATER + epsilon → composite just above HIGH_WATER.
        s.update(factors(HIGH_WATER + 0.05));
        assert!(s.is_under_load());
    }

    #[test]
    fn does_not_enter_load_below_high_water() {
        let s = LoadSignal::new();
        s.update(factors(HIGH_WATER - 0.05));
        assert!(!s.is_under_load());
    }

    #[test]
    fn hysteresis_stays_under_load_until_low_water() {
        let s = LoadSignal::new();
        // Enter load.
        s.update(factors(0.9));
        assert!(s.is_under_load());
        // Score between LOW_WATER and HIGH_WATER — must STAY under load.
        s.update(factors(f32::midpoint(LOW_WATER, HIGH_WATER)));
        assert!(s.is_under_load());
        // Score below LOW_WATER — must exit.
        s.update(factors(LOW_WATER - 0.05));
        assert!(!s.is_under_load());
    }

    #[test]
    fn mixed_factors_composite_mean() {
        let s = LoadSignal::new();
        // cpu=1.0, others=0.0 → mean=0.25 < HIGH_WATER.
        s.update(LoadFactors {
            cpu_pct: 1.0,
            memory_pct: 0.0,
            pending_queries_pct: 0.0,
            rl_fires_rate: 0.0,
        });
        assert!(!s.is_under_load());
        // All four at 0.9 → mean=0.9 > HIGH_WATER.
        s.update(factors(0.9));
        assert!(s.is_under_load());
    }

    #[test]
    fn clamps_factors_above_one() {
        let s = LoadSignal::new();
        // Even with out-of-range inputs the score is clamped to 1.0.
        s.update(LoadFactors {
            cpu_pct: 10.0,
            memory_pct: 10.0,
            pending_queries_pct: 10.0,
            rl_fires_rate: 10.0,
        });
        assert!(s.is_under_load());
    }
}
