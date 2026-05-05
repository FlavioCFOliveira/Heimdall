// SPDX-License-Identifier: MIT

//! Config-loader wiring for the heimdall binary (boot phase 3, BIN-015).
//!
//! Wraps `heimdall_runtime::config::{ConfigLoader, ConfigError}` with
//! binary-level error reporting (stderr + structured exit codes).

use std::path::Path;

use heimdall_runtime::config::ConfigLoader;

/// Load and validate the configuration file at `path`.
///
/// On success, returns the `ConfigLoader` (which holds the live `ArcSwap<Config>`).
/// On failure, prints a human-readable diagnostic to stderr and returns the error.
///
/// # Errors
///
/// Returns `ConfigError` on I/O, parse, or validation failure.
pub fn load(path: &Path) -> Result<ConfigLoader, heimdall_runtime::config::ConfigError> {
    ConfigLoader::load(path)
}
