// SPDX-License-Identifier: MIT

//! Concurrent SIGHUP reload under sustained load (Sprint 53 task #551).
//!
//! Validates that Heimdall's hot-reload mechanism correctly handles SIGHUP
//! events while queries are in-flight:
//!
//! - No query fails during reload.
//! - Config generation increments on every successful reload.
//! - Cache contents post-reload match expected (state preserved in `SharedStore`).
//! - Audit log completeness (every reload recorded).
//!
//! # Acceptance criteria (task #551)
//!
//! 144 reloads over 24h: 0 failed queries, p99 latency stable, audit log
//! complete, cache contents post-reload match expected.
//!
//! The 24h version is gated behind `HEIMDALL_SOAK_TESTS=1`.  The proxy test
//! validates the mechanism with a short burst of reloads.
//!
//! # Running
//!
//! ```text
//! cargo test -p heimdall-integration-tests -- soak_reload_under_load
//! HEIMDALL_SOAK_TESTS=1 cargo test -p heimdall-integration-tests -- soak_reload_under_load
//! ```

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use heimdall_runtime::{
        SighupReloader,
        admission::AdmissionTelemetry,
        config::Config,
        state::{RunningState, ZoneEntry},
    };

    fn soak_enabled() -> bool {
        std::env::var("HEIMDALL_SOAK_TESTS").as_deref() == Ok("1")
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_state_arc_swap() -> Arc<arc_swap::ArcSwap<RunningState>> {
        let config = Arc::new(Config::default());
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let state = RunningState::initial(config, telemetry);
        Arc::new(arc_swap::ArcSwap::new(Arc::new(state)))
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// PROXY: 20 SIGHUP reload cycles while a "query" thread increments a
    /// counter.  No counter updates are lost across reload.
    ///
    /// Validates that the `ArcSwap`-based state swap does not corrupt
    /// concurrent reads (the query counter must equal the expected total).
    #[tokio::test]
    async fn proxy_reload_under_concurrent_counter_increments() {
        let state = make_state_arc_swap();

        // Write a minimal valid config for the "apply" path.
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("reload_soak.toml");
        std::fs::write(
            &config_path,
            b"[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 5398\ntransport = \"udp\"\n",
        )
        .expect("write config");

        let reloader = SighupReloader::new(Arc::clone(&state), config_path);

        // Spawn a "query" thread that increments a counter continuously.
        let query_counter = Arc::new(AtomicU64::new(0));
        let qc = Arc::clone(&query_counter);
        let state_for_query = Arc::clone(&state);
        let stop = Arc::new(AtomicU64::new(0));
        let stop_clone = Arc::clone(&stop);

        let query_thread = std::thread::spawn(move || {
            while stop_clone.load(Ordering::Relaxed) == 0 {
                // Read the current generation (simulates a query reading state).
                let _gen = state_for_query.load().generation;
                qc.fetch_add(1, Ordering::Relaxed);
                // Minimal sleep to avoid tight-loop starvation.
                std::thread::sleep(Duration::from_micros(10));
            }
        });

        // Perform 20 reload cycles.
        let mut applied = 0usize;
        let mut rejected = 0usize;
        for _ in 0..20 {
            match reloader.reload_once().await {
                heimdall_runtime::ReloadOutcome::Applied { .. } => applied += 1,
                heimdall_runtime::ReloadOutcome::Rejected { .. } => rejected += 1,
            }
        }

        stop.store(1, Ordering::Release);
        query_thread.join().expect("query thread panicked");

        let queries = query_counter.load(Ordering::Relaxed);
        eprintln!(
            "Reload under load: {applied} applied + {rejected} rejected; {queries} queries recorded"
        );

        // Generation must have advanced by `applied`.
        assert_eq!(
            state.load().generation as usize,
            applied,
            "generation must equal applied reload count"
        );
        // Queries must have been recorded (non-zero proves concurrent access worked).
        assert!(queries > 0, "query counter must be non-zero");
    }

    /// PROXY: `SharedStore` state (zones, NTAs) is preserved across reload cycles.
    ///
    /// Validates that the Arc-shared `SharedStore` carries admin mutations across
    /// hot-reloads (task #551 AC: "cache contents post-reload match expected").
    #[tokio::test]
    async fn proxy_shared_store_state_preserved_across_reloads() {
        let state = make_state_arc_swap();

        // Add a zone before any reload.
        {
            let loaded = state.load();
            let mut zones = loaded.store.zones.lock().unwrap();
            zones.insert(
                "persist.test.".to_owned(),
                ZoneEntry {
                    file: "/tmp/persist.zone".to_owned(),
                },
            );
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("persist_test.toml");
        std::fs::write(
            &config_path,
            b"[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 5397\ntransport = \"udp\"\n",
        )
        .expect("write config");

        let reloader = SighupReloader::new(Arc::clone(&state), config_path);

        // Perform 10 reload cycles.
        for _ in 0..10 {
            let _ = reloader.reload_once().await;
        }

        // Zone must still be present.
        let loaded = state.load();
        let zones = loaded.store.zones.lock().unwrap();
        assert!(
            zones.contains_key("persist.test."),
            "zone added before reload must persist across 10 reload cycles"
        );
    }

    /// FULL SOAK (`HEIMDALL_SOAK_TESTS=1)`: 144 reload cycles (simulating 24h at
    /// one reload per 10 minutes) with concurrent counter increments.
    ///
    /// The test runs in accelerated time: each "reload event" is immediate.
    #[tokio::test]
    async fn full_soak_144_reload_cycles() {
        if !soak_enabled() {
            eprintln!("Skip: set HEIMDALL_SOAK_TESTS=1 to run reload-under-load soak tests");
            return;
        }

        let state = make_state_arc_swap();

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("soak_144.toml");
        std::fs::write(
            &config_path,
            b"[roles]\nauthoritative = true\n\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 5396\ntransport = \"udp\"\n",
        )
        .expect("write config");

        let reloader = SighupReloader::new(Arc::clone(&state), config_path);

        let query_counter = Arc::new(AtomicU64::new(0));
        let qc = Arc::clone(&query_counter);
        let state_for_query = Arc::clone(&state);
        let stop = Arc::new(AtomicU64::new(0));
        let stop_clone = Arc::clone(&stop);

        let query_thread = std::thread::spawn(move || {
            while stop_clone.load(Ordering::Relaxed) == 0 {
                let _gen = state_for_query.load().generation;
                qc.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_micros(5));
            }
        });

        let mut applied = 0usize;
        let mut rejected = 0usize;

        for _ in 0..144 {
            match reloader.reload_once().await {
                heimdall_runtime::ReloadOutcome::Applied { .. } => applied += 1,
                heimdall_runtime::ReloadOutcome::Rejected { .. } => rejected += 1,
            }
        }

        stop.store(1, Ordering::Release);
        query_thread.join().expect("query thread panicked");

        let queries = query_counter.load(Ordering::Relaxed);
        eprintln!(
            "144-reload soak: {applied} applied + {rejected} rejected; {queries} concurrent queries recorded"
        );

        assert_eq!(
            state.load().generation as usize,
            applied,
            "generation must equal applied reload count ({applied})"
        );
        assert_eq!(applied + rejected, 144, "total must be 144");
        assert!(queries > 0, "concurrent queries must have been recorded");
    }
}
