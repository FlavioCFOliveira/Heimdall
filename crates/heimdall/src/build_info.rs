// SPDX-License-Identifier: MIT

//! Compile-time build metadata embedded by `build.rs` (OPS-029..031, ADR-0063).
//!
//! All constants are `&'static str`; they are embedded at compile time and carry
//! zero runtime cost.

/// Cargo package version (e.g. `"1.1.0"`).
pub const VERSION: &str = env!("HEIMDALL_VERSION");

/// Short git commit SHA of HEAD at build time (e.g. `"abc1234"`), or `"unknown"`.
pub const GIT_COMMIT: &str = env!("HEIMDALL_GIT_COMMIT");

/// RFC 3339 UTC build timestamp (e.g. `"2026-05-03T14:00:00Z"`).
/// Derived from `SOURCE_DATE_EPOCH` when set; otherwise the current time.
pub const BUILD_DATE: &str = env!("HEIMDALL_BUILD_DATE");

/// `rustc` version string used to compile this binary (e.g. `"rustc 1.85.0 (…)"`).
pub const RUSTC: &str = env!("HEIMDALL_RUSTC");

/// Target triple this binary was compiled for (e.g. `"aarch64-apple-darwin"`).
pub const TARGET: &str = env!("HEIMDALL_TARGET");

/// Cargo build profile: `"debug"` or `"release"`.
pub const PROFILE: &str = env!("HEIMDALL_PROFILE");

/// Comma-separated list of enabled Cargo features, or `"none"`.
pub const FEATURES: &str = env!("HEIMDALL_FEATURES");

/// Performance tier identifier derived from the target architecture
/// (e.g. `"PERF-x86_64"`, `"PERF-aarch64"`).
pub const TIER: &str = env!("HEIMDALL_TIER");

/// Minimum Supported Rust Version (e.g. `"1.94.0"`).
pub const MSRV: &str = env!("HEIMDALL_MSRV");
