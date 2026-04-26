// SPDX-License-Identifier: MIT

//! Tokio runtime boot and I/O model detection.
//!
//! Detects at start-up whether `io_uring` is available (Linux kernel ≥ 5.10) and
//! the `io-uring` Cargo feature is enabled, then builds and returns a configured
//! multi-thread tokio runtime.
//!
//! Actual `io_uring` I/O paths are implemented in later sprints; this module records
//! the detected flavour for observability.

use std::io;

/// Which I/O model the runtime uses.
///
/// Detected once at process start-up and recorded in [`RuntimeInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFlavour {
    /// Linux `io_uring` via tokio-uring (requires kernel ≥ 5.10).
    ///
    /// Only reported when the `io-uring` Cargo feature is enabled **and** the kernel
    /// version check passes. Actual `io_uring` I/O paths are deferred to later sprints.
    IoUring,
    /// Standard epoll (Linux) / kqueue (BSD/macOS) via standard tokio.
    Epoll,
}

/// Recorded at start-up; available for observability and diagnostic logging.
#[derive(Debug)]
pub struct RuntimeInfo {
    /// The I/O model selected for this process lifetime.
    pub flavour: RuntimeFlavour,
    /// Number of worker threads in the tokio multi-thread scheduler.
    pub worker_threads: usize,
}

/// Error returned by [`build_runtime`].
#[derive(Debug)]
pub enum RuntimeError {
    /// The `io-uring` Cargo feature is enabled but `io_uring` is not available on this
    /// kernel. Includes the reason string for operator log output.
    IoUringUnavailable {
        /// Human-readable reason (e.g. `"kernel 4.19 < 5.10"` or `"not Linux"`).
        reason: String,
    },
    /// tokio's runtime builder returned an error (e.g. `EMFILE`).
    TokioBuildFailed(io::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoUringUnavailable { reason } => {
                write!(f, "`io_uring` unavailable: {reason}")
            }
            Self::TokioBuildFailed(e) => write!(f, "failed to build tokio runtime: {e}"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TokioBuildFailed(e) => Some(e),
            Self::IoUringUnavailable { .. } => None,
        }
    }
}

/// Boot the async runtime.
///
/// Selects `io_uring` if available **and** the `io-uring` Cargo feature is enabled;
/// otherwise falls back to standard epoll/kqueue via tokio.
///
/// # Errors
///
/// Returns [`RuntimeError::IoUringUnavailable`] if the `io-uring` Cargo feature is
/// enabled but `io_uring` is not available on this kernel.
///
/// Returns [`RuntimeError::TokioBuildFailed`] if tokio's runtime builder fails (e.g.
/// thread creation fails due to resource limits).
pub fn build_runtime(
    worker_threads: usize,
) -> Result<(tokio::runtime::Runtime, RuntimeInfo), RuntimeError> {
    let flavour = detect_flavour()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .map_err(RuntimeError::TokioBuildFailed)?;

    let info = RuntimeInfo {
        flavour,
        worker_threads,
    };
    Ok((runtime, info))
}

/// Determine the [`RuntimeFlavour`] for this platform and feature set.
///
/// On Linux with the `io-uring` feature enabled, attempts to confirm kernel ≥ 5.10.
/// Returns `Err` only when `io_uring` was explicitly requested but is unavailable.
fn detect_flavour() -> Result<RuntimeFlavour, RuntimeError> {
    detect_flavour_impl()
}

/// Platform/feature-gated implementation of [`detect_flavour`].
///
/// Split into a separate function so that the outer function's signature is
/// unconditionally `Result<_, RuntimeError>` regardless of which `#[cfg]` branches
/// are active, avoiding a spurious `clippy::unnecessary_wraps` when the non-error
/// branch would otherwise be the only one compiled.
#[cfg(feature = "io-uring")]
fn detect_flavour_impl() -> Result<RuntimeFlavour, RuntimeError> {
    #[cfg(target_os = "linux")]
    {
        match probe_io_uring() {
            Ok(true) => return Ok(RuntimeFlavour::IoUring),
            Ok(false) => {
                return Err(RuntimeError::IoUringUnavailable {
                    reason: "kernel version < 5.10".to_owned(),
                });
            }
            Err(reason) => {
                return Err(RuntimeError::IoUringUnavailable { reason });
            }
        }
    }
    // `io-uring` feature enabled on a non-Linux platform.
    #[cfg(not(target_os = "linux"))]
    Err(RuntimeError::IoUringUnavailable {
        reason: "`io_uring` is Linux-only".to_owned(),
    })
}

/// Platform/feature-gated implementation of [`detect_flavour`].
///
/// When the `io-uring` feature is absent, always use epoll/kqueue.
///
/// The `Result` return type is structurally required to match the feature-enabled
/// variant; the `Ok(...)` wrapping is intentional, not a simplification opportunity.
#[cfg(not(feature = "io-uring"))]
#[allow(clippy::unnecessary_wraps)]
fn detect_flavour_impl() -> Result<RuntimeFlavour, RuntimeError> {
    Ok(RuntimeFlavour::Epoll)
}

/// Probe whether the running Linux kernel supports `io_uring` (≥ 5.10.0).
///
/// Reads `/proc/sys/kernel/osrelease` and parses the `major.minor` prefix.
/// Returns `Ok(true)` if ≥ 5.10, `Ok(false)` if < 5.10, `Err(reason)` on
/// any I/O or parse error.
#[cfg(target_os = "linux")]
fn probe_io_uring() -> Result<bool, String> {
    let contents = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| format!("cannot read /proc/sys/kernel/osrelease: {e}"))?;

    parse_kernel_version(contents.trim())
        .map(|(major, minor)| major > 5 || (major == 5 && minor >= 10))
}

/// Parse `"major.minor[.patch...]"` from a kernel release string.
///
/// Only the first two numeric components are required; the rest are ignored.
#[cfg(target_os = "linux")]
fn parse_kernel_version(release: &str) -> Result<(u32, u32), String> {
    // Release strings look like "5.15.0-91-generic" or "6.1.0".
    // Strip any non-numeric suffix after the first component by splitting on the
    // first non-digit, non-dot character.
    let numeric_prefix: &str = release
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or(release);

    let mut parts = numeric_prefix.splitn(3, '.');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("cannot parse major version from {release:?}"))?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("cannot parse minor version from {release:?}"))?;
    Ok((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    mod linux {
        use super::parse_kernel_version;

        #[test]
        fn parse_full_release() {
            let (maj, min) = parse_kernel_version("5.15.0-91-generic").expect("parse");
            assert_eq!(maj, 5);
            assert_eq!(min, 15);
        }

        #[test]
        fn parse_clean_release() {
            let (maj, min) = parse_kernel_version("6.1.0").expect("parse");
            assert_eq!(maj, 6);
            assert_eq!(min, 1);
        }

        #[test]
        fn parse_old_kernel() {
            let (maj, min) = parse_kernel_version("4.19.0").expect("parse");
            assert_eq!(maj, 4);
            assert_eq!(min, 19);
        }

        #[test]
        fn parse_rejects_garbage() {
            assert!(parse_kernel_version("not-a-version").is_err());
        }
    }

    #[test]
    fn build_runtime_succeeds() {
        let (rt, info) = build_runtime(2).expect("build_runtime");
        assert_eq!(info.worker_threads, 2);
        // Runtime can execute a trivial async task.
        rt.block_on(async { assert_eq!(1 + 1, 2) });
    }

    #[test]
    fn runtime_flavour_without_io_uring_feature() {
        // Without the `io-uring` feature, always `Epoll`.
        let (_rt, info) = build_runtime(1).expect("build_runtime");
        #[cfg(not(feature = "io-uring"))]
        assert_eq!(info.flavour, RuntimeFlavour::Epoll);
        // Suppress unused-variable warning when the feature is enabled.
        let _ = info;
    }
}
