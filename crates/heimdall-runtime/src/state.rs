// SPDX-License-Identifier: MIT

//! Running state container.
//!
//! [`RunningState`] is an immutable snapshot of all mutable server state. Queries
//! load a [`arc_swap::Guard`] on entry and retain it through completion so they
//! never observe a partial state transition.
//!
//! [`StateContainer`] wraps an [`arc_swap::ArcSwap`] to provide lock-free reads and
//! atomic state swaps. See ADR-0037 for the rationale.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::admission::AdmissionTelemetry;
use crate::config::Config;

/// Immutable snapshot of all mutable server state.
///
/// Every field is cheaply cloneable or reference-counted so that holding a
/// [`arc_swap::Guard`] is not a long-lived allocation.
///
/// Placeholder fields (zones, caches, NTA store, ACL, RPZ) will be added in
/// later sprints as those subsystems are implemented.
#[derive(Debug)]
pub struct RunningState {
    /// The config snapshot active for this generation.
    pub config: Arc<Config>,
    /// Monotonically increasing reload generation counter.
    ///
    /// Starts at 0. Each successful hot-reload increments by 1. Useful for
    /// correlating log events with a specific configuration epoch.
    pub generation: u64,
    /// Admission-pipeline telemetry counters.
    ///
    /// Shared with the live [`crate::admission::AdmissionPipeline`] so that
    /// the pipeline increments atomics and the observability endpoint reads
    /// them from the same allocation without any lock.
    pub admission_telemetry: Arc<AdmissionTelemetry>,
}

impl RunningState {
    /// Build the initial (generation 0) state.
    #[must_use]
    pub fn initial(config: Arc<Config>, admission_telemetry: Arc<AdmissionTelemetry>) -> Self {
        Self {
            config,
            generation: 0,
            admission_telemetry,
        }
    }

    /// Build the next-generation state from `self`, using a new config snapshot.
    ///
    /// The new generation is `self.generation + 1`. The old state continues to
    /// live as long as any [`arc_swap::Guard`] holds a reference to it.
    /// Admission telemetry is carried over unchanged — the live pipeline
    /// continues to update the same atomic counters across reloads.
    #[must_use]
    pub fn next_generation(&self, config: Arc<Config>) -> Self {
        Self {
            config,
            generation: self.generation + 1,
            admission_telemetry: Arc::clone(&self.admission_telemetry),
        }
    }
}

/// Thread-safe container for the current [`RunningState`].
///
/// Uses [`arc_swap::ArcSwap`] (ADR-0037) to provide:
/// - Lock-free reads via [`StateContainer::load`].
/// - Atomic replacement via [`StateContainer::swap`].
pub struct StateContainer {
    inner: ArcSwap<RunningState>,
}

impl StateContainer {
    /// Create a new container holding `state` as the initial running state.
    #[must_use]
    pub fn new(state: RunningState) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(state)),
        }
    }

    /// Acquire a read guard.
    ///
    /// The guard keeps the current [`RunningState`] alive for its lifetime.
    /// Callers should hold the guard only for the duration of the operation that
    /// needs the state snapshot; releasing the guard earlier allows a pending
    /// [`StateContainer::swap`] to complete sooner.
    pub fn load(&self) -> arc_swap::Guard<Arc<RunningState>> {
        self.inner.load()
    }

    /// Atomically replace the running state.
    ///
    /// Returns the previous [`RunningState`] wrapped in an [`Arc`]. The previous
    /// state is dropped only after all existing read guards are released.
    pub fn swap(&self, new_state: RunningState) -> Arc<RunningState> {
        self.inner.swap(Arc::new(new_state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> Arc<Config> {
        Arc::new(Config::default())
    }

    fn make_telemetry() -> Arc<AdmissionTelemetry> {
        Arc::new(AdmissionTelemetry::new())
    }

    #[test]
    fn initial_generation_is_zero() {
        let state = RunningState::initial(make_config(), make_telemetry());
        assert_eq!(state.generation, 0);
    }

    #[test]
    fn next_generation_increments() {
        let state = RunningState::initial(make_config(), make_telemetry());
        let next = state.next_generation(make_config());
        assert_eq!(next.generation, 1);
    }

    #[test]
    fn state_container_swap_increments_generation() {
        let config = make_config();
        let initial = RunningState::initial(config.clone(), make_telemetry());
        let container = StateContainer::new(initial);

        let gen0 = container.load().generation;
        assert_eq!(gen0, 0);

        let new_state = container.load().next_generation(config);
        container.swap(new_state);

        let gen1 = container.load().generation;
        assert_eq!(gen1, 1);
    }

    #[test]
    fn swap_returns_previous_state() {
        let config = make_config();
        let telemetry = make_telemetry();
        let initial = RunningState::initial(config.clone(), Arc::clone(&telemetry));
        let container = StateContainer::new(initial);

        let new_state = RunningState {
            config,
            generation: 42,
            admission_telemetry: telemetry,
        };
        let old = container.swap(new_state);
        assert_eq!(old.generation, 0);
        assert_eq!(container.load().generation, 42);
    }
}
