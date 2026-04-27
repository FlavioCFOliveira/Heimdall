// SPDX-License-Identifier: MIT

//! Reference-implementation runner stubs (PERF-020..028).
//!
//! Actual runner scripts require live server binaries and are implemented
//! as shell script stubs in `scripts/bench/`.  This module documents the
//! interface so that future integration can call into a common driver.

/// Reference implementations benchmarked for authoritative comparison
/// (PERF-020..022).
pub const AUTH_REFERENCE_IMPLS: &[&str] = &["nsd", "knot", "bind"];

/// Reference implementations benchmarked for recursive comparison
/// (PERF-023..024).
pub const RECURSIVE_REFERENCE_IMPLS: &[&str] = &["unbound", "powerdns-recursor", "knot-resolver"];

/// Reference implementations benchmarked for forwarder/encrypted comparison
/// (PERF-025..028).
pub const FORWARDER_REFERENCE_IMPLS: &[&str] = &["dnsdist", "cloudflared", "unbound"];

/// The DNS query tool used for load generation.
pub const LOAD_GENERATOR: &str = "flamethrower";
