// SPDX-License-Identifier: MIT

//! Tokio runtime boot (BIN-016..BIN-019, boot phase 7).
//!
//! Delegates to `heimdall_runtime::build_runtime` and logs the chosen I/O
//! backend and worker count before entering the main async loop.

use heimdall_runtime::{RuntimeError, RuntimeFlavour, RuntimeInfo, build_runtime};

/// Start the Tokio multi-thread runtime.
///
/// Logs the selected I/O backend (io_uring or epoll/kqueue) and worker count
/// at INFO level (BIN-017). On macOS and non-Linux targets, io_uring is never
/// attempted.
///
/// # Errors
///
/// Returns [`RuntimeError`] if the runtime cannot be built (e.g. resource
/// limits prevent thread creation) or if the `io-uring` feature was enabled
/// but `io_uring` is unavailable on the current kernel.
pub fn start(worker_threads: usize) -> Result<(tokio::runtime::Runtime, RuntimeInfo), RuntimeError> {
    let (rt, info) = build_runtime(worker_threads)?;

    let backend = match info.flavour {
        RuntimeFlavour::IoUring => "io_uring",
        RuntimeFlavour::Epoll => "epoll/kqueue",
    };

    tracing::info!(
        io_backend = backend,
        worker_threads = info.worker_threads,
        "Tokio runtime started"
    );

    Ok((rt, info))
}
