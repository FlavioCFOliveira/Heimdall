// SPDX-License-Identifier: MIT

//! Exponential backoff with bounded jitter for Redis reconnection.
//!
//! Implements the reconnection policy of `STORE-016` and `STORE-047`:
//!
//! - Floor: 100 ms.
//! - Ceiling: 30 s.
//! - ±20 % jitter applied to each computed interval.
//!
//! The jitter prevents thundering-herd reconnection when multiple Heimdall
//! instances lose contact with Redis simultaneously.
//!
//! [`BackoffIterator`] implements [`Iterator`] and yields successive
//! [`std::time::Duration`] values. Iteration stops only when explicitly
//! abandoned — it is the caller's responsibility to limit retries via
//! [`Iterator::take`] or a separate timeout.

use std::time::Duration;

/// Default backoff floor (`STORE-047`).
pub const DEFAULT_FLOOR_MS: u64 = 100;

/// Default backoff ceiling (`STORE-047`).
pub const DEFAULT_CEILING_MS: u64 = 30_000;

/// Default jitter fraction, expressed as a value in `[0.0, 1.0)`.
///
/// 0.20 = ±20 % of the computed base interval (`STORE-047`).
pub const DEFAULT_JITTER_FRACTION: f64 = 0.20;

/// Jitter source used by [`BackoffIterator`].
///
/// A separate trait allows deterministic seeds in tests while using a
/// thread-local random source in production.
pub trait JitterSource {
    /// Return a value uniformly distributed in `[0.0, 1.0)`.
    fn sample(&mut self) -> f64;
}

/// Production jitter source backed by the platform's random number generator.
///
/// Uses a simple linear-congruential generator seeded from the current thread's
/// state derived from `std::time::SystemTime`. No cryptographic quality is
/// required — jitter only needs statistical spread.
pub struct SystemJitter {
    state: u64,
}

impl SystemJitter {
    /// Create a new `SystemJitter` with a seed derived from the current time.
    #[must_use]
    pub fn new() -> Self {
        // Simple time-based seed. Multiple instances seeded in rapid succession
        // may produce correlated sequences; for reconnection backoff this is
        // acceptable — the goal is spread, not cryptographic independence.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        Self {
            state: u64::from(seed),
        }
    }
}

impl Default for SystemJitter {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterSource for SystemJitter {
    fn sample(&mut self) -> f64 {
        // Xorshift64 — fast, zero allocations, acceptable statistical properties
        // for jitter purposes.
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        // Map to [0.0, 1.0)
        let scaled = self.state >> 11; // 53-bit mantissa
        #[allow(clippy::cast_precision_loss)]
        let val = scaled as f64 / (1u64 << 53) as f64;
        val
    }
}

/// Deterministic jitter source for testing.
///
/// Returns values from a fixed sequence of `u64` seeds, cycling when exhausted.
pub struct SeededJitter {
    seeds: Vec<f64>,
    index: usize,
}

impl SeededJitter {
    /// Create a deterministic jitter source from a sequence of values in
    /// `[0.0, 1.0)`.
    ///
    /// # Panics
    ///
    /// Panics if `seeds` is empty.
    #[must_use]
    pub fn new(seeds: Vec<f64>) -> Self {
        assert!(!seeds.is_empty(), "SeededJitter requires at least one seed");
        Self { seeds, index: 0 }
    }
}

impl JitterSource for SeededJitter {
    fn sample(&mut self) -> f64 {
        let v = self.seeds[self.index % self.seeds.len()];
        self.index += 1;
        v
    }
}

/// Exponential backoff iterator.
///
/// Each call to [`Iterator::next`] returns the duration to wait before the
/// next reconnection attempt. Intervals grow exponentially from `floor` to
/// `ceiling`, with ±`jitter_fraction` randomisation applied per step.
///
/// # Example
///
/// ```
/// use heimdall_runtime::store::backoff::{BackoffIterator, SystemJitter};
///
/// let mut backoff = BackoffIterator::new(SystemJitter::new());
/// for delay in backoff.by_ref().take(5) {
///     // wait `delay` then attempt reconnection
///     let _ = delay;
/// }
/// ```
pub struct BackoffIterator<J: JitterSource> {
    floor_ms: u64,
    ceiling_ms: u64,
    jitter_fraction: f64,
    current_ms: u64,
    jitter: J,
}

impl<J: JitterSource> BackoffIterator<J> {
    /// Create a new iterator with default parameters (`STORE-047`) and the
    /// supplied `jitter` source.
    #[must_use]
    pub fn new(jitter: J) -> Self {
        Self {
            floor_ms: DEFAULT_FLOOR_MS,
            ceiling_ms: DEFAULT_CEILING_MS,
            jitter_fraction: DEFAULT_JITTER_FRACTION,
            current_ms: DEFAULT_FLOOR_MS,
            jitter,
        }
    }

    /// Override the floor, ceiling, and jitter fraction.
    ///
    /// Useful for tests or non-default deployments.
    #[must_use]
    pub fn with_params(mut self, floor_ms: u64, ceiling_ms: u64, jitter_fraction: f64) -> Self {
        self.floor_ms = floor_ms;
        self.ceiling_ms = ceiling_ms;
        self.jitter_fraction = jitter_fraction;
        self.current_ms = floor_ms;
        self
    }

    /// Reset the backoff to the floor, as if reconnection had just succeeded.
    pub fn reset(&mut self) {
        self.current_ms = self.floor_ms;
    }
}

impl<J: JitterSource> Iterator for BackoffIterator<J> {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        let base = self.current_ms;

        // Apply ±jitter_fraction * base.
        // All values fit in f64 without precision loss for the backoff range
        // we work in (100 ms .. 30 000 ms), which is well within the 52-bit
        // mantissa of f64 (2^53 ≈ 9 × 10^15 >> 30 000).
        //
        // The `as i64` / `as u64` casts below are intentional:
        // - `base` ≤ ceiling_ms ≤ 30_000 ≤ i64::MAX, so no wrap.
        // - After `.max(floor_ms)` the value is ≥ 0, so sign loss is safe.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_possible_wrap
        )]
        let jitter_range = base as f64 * self.jitter_fraction;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let offset = (self.jitter.sample() * 2.0 * jitter_range - jitter_range) as i64;
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let jittered = {
            let base_signed = base as i64;
            let floor_signed = self.floor_ms as i64;
            base_signed
                .saturating_add(offset)
                .max(floor_signed)
                .cast_unsigned()
        };
        let duration = Duration::from_millis(jittered.min(self.ceiling_ms));

        // Advance base for the next call: double, saturating at ceiling.
        self.current_ms = base.saturating_mul(2).min(self.ceiling_ms);

        Some(duration)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-jitter source — always returns 0.5 (midpoint, no offset).
    struct MidpointJitter;
    impl JitterSource for MidpointJitter {
        fn sample(&mut self) -> f64 {
            0.5
        }
    }

    #[test]
    fn backoff_starts_at_floor() {
        let mut backoff = BackoffIterator::new(MidpointJitter);
        let first = backoff.next().expect("has at least one element");
        // With midpoint jitter (0.5): offset = 0.5 * 2 * range - range = 0.
        assert_eq!(first, Duration::from_millis(DEFAULT_FLOOR_MS));
    }

    #[test]
    fn backoff_doubles_each_step() {
        // Use zero-offset jitter to get exact base values.
        let mut backoff = BackoffIterator::new(MidpointJitter);
        let delays: Vec<u64> = backoff
            .by_ref()
            .take(8)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .collect();

        // With midpoint jitter offset = 0, so delays equal the base values.
        let expected_bases = [100u64, 200, 400, 800, 1600, 3200, 6400, 12_800];
        assert_eq!(delays, expected_bases, "each step should double");
    }

    #[test]
    fn backoff_saturates_at_ceiling() {
        let mut backoff = BackoffIterator::new(MidpointJitter);
        // Skip past where ceiling is hit.
        let all: Vec<u64> = backoff
            .by_ref()
            .take(20)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .collect();
        assert!(
            all.iter().all(|&ms| ms <= DEFAULT_CEILING_MS),
            "no delay should exceed ceiling: {all:?}"
        );
        // Last few should be at or near the ceiling.
        let &last = all.last().expect("non-empty");
        assert_eq!(last, DEFAULT_CEILING_MS, "saturated at ceiling");
    }

    #[test]
    fn backoff_reset_returns_to_floor() {
        let mut backoff = BackoffIterator::new(MidpointJitter);
        // Advance a few steps.
        for _ in 0..5 {
            backoff.next();
        }
        backoff.reset();
        let after_reset = backoff.next().expect("element after reset");
        assert_eq!(after_reset, Duration::from_millis(DEFAULT_FLOOR_MS));
    }

    #[test]
    fn seeded_jitter_deterministic() {
        // Two iterators with the same seed sequence produce the same delays.
        let seeds = vec![0.0, 0.25, 0.75, 1.0 - f64::EPSILON];
        let delays_a: Vec<_> = BackoffIterator::new(SeededJitter::new(seeds.clone()))
            .take(4)
            .collect();
        let delays_b: Vec<_> = BackoffIterator::new(SeededJitter::new(seeds))
            .take(4)
            .collect();
        assert_eq!(delays_a, delays_b);
    }

    #[test]
    fn custom_params_respected() {
        let mut backoff = BackoffIterator::new(MidpointJitter).with_params(50, 1_000, 0.0);
        let delays: Vec<u64> = backoff
            .by_ref()
            .take(6)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .collect();
        let expected = [50u64, 100, 200, 400, 800, 1_000];
        assert_eq!(delays, expected);
    }
}
