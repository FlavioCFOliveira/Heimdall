// SPDX-License-Identifier: MIT

//! OS resource-limit hardening applied at boot (BIN-036..038, THREAT-068).
//!
//! Applied after socket binding and before privilege drop so that the process
//! still holds sufficient rights to call setrlimit(2) on Linux (unprivileged
//! processes may only lower limits, not raise them above the hard limit).
//!
//! Failures are logged but never fatal: a failed setrlimit leaves the previous
//! kernel default in place, which is always safe (just possibly suboptimal).

use heimdall_runtime::config::RlimitConfig;

/// Apply RLIMIT_NOFILE, RLIMIT_NPROC, and RLIMIT_CORE from `cfg`.
///
/// Each limit is applied independently; a failure on one does not prevent the
/// others from being applied.
pub fn apply(cfg: &RlimitConfig) {
    apply_nofile(cfg.nofile);
    apply_nproc(cfg.nproc);
    apply_core(cfg.core);
}

// ── Per-resource helpers ──────────────────────────────────────────────────────

#[cfg(unix)]
fn apply_nofile(desired: u64) {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((_, hard)) => {
            let soft = desired.min(hard);
            match setrlimit(Resource::RLIMIT_NOFILE, soft, hard) {
                Ok(()) => tracing::info!(soft, hard, "RLIMIT_NOFILE applied"),
                Err(e) => tracing::warn!(error = %e, soft, hard, "failed to set RLIMIT_NOFILE"),
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to query RLIMIT_NOFILE"),
    }
}

#[cfg(not(unix))]
fn apply_nofile(_desired: u64) {}

#[cfg(target_os = "linux")]
fn apply_nproc(desired: u64) {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    match getrlimit(Resource::RLIMIT_NPROC) {
        Ok((_, hard)) => {
            let soft = desired.min(hard);
            match setrlimit(Resource::RLIMIT_NPROC, soft, hard) {
                Ok(()) => tracing::info!(soft, hard, "RLIMIT_NPROC applied"),
                Err(e) => tracing::warn!(error = %e, soft, hard, "failed to set RLIMIT_NPROC"),
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to query RLIMIT_NPROC"),
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_nproc(_desired: u64) {}

#[cfg(unix)]
fn apply_core(desired: u64) {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    match getrlimit(Resource::RLIMIT_CORE) {
        Ok((_, hard)) => {
            let soft = desired.min(hard);
            match setrlimit(Resource::RLIMIT_CORE, soft, hard) {
                Ok(()) => tracing::info!(soft, hard, "RLIMIT_CORE applied"),
                Err(e) => tracing::warn!(error = %e, soft, hard, "failed to set RLIMIT_CORE"),
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to query RLIMIT_CORE"),
    }
}

#[cfg(not(unix))]
fn apply_core(_desired: u64) {}
