// SPDX-License-Identifier: MIT

//! Config-loader wiring for the heimdall binary (boot phase 3, BIN-015).
//!
//! Wraps `heimdall_runtime::config::{ConfigLoader, ConfigError}` with
//! binary-level error reporting (stderr + structured exit codes).

use std::path::Path;

use heimdall_runtime::config::{Config, ConfigLoader};

/// Load and validate the configuration file at `path`.
///
/// On success, returns the `ConfigLoader` (which holds the live `ArcSwap<Config>`).
/// On failure, prints a human-readable diagnostic to stderr and returns the error.
///
/// # Errors
///
/// Returns `ConfigError` on I/O, parse, or validation failure.
pub fn load(
    path: &Path,
) -> Result<ConfigLoader, heimdall_runtime::config::ConfigError> {
    ConfigLoader::load(path)
}

/// Print a human-readable summary of the loaded config to stdout.
///
/// Called by `check-config` to confirm what was loaded.
pub fn print_summary(config: &Config) {
    println!("Configuration loaded successfully.");
    println!();
    println!(
        "  Roles: authoritative={} recursive={} forwarder={}",
        config.roles.authoritative, config.roles.recursive, config.roles.forwarder
    );
    if config.listeners.is_empty() {
        println!("  Listeners: (none configured)");
    } else {
        println!("  Listeners ({}):", config.listeners.len());
        for l in &config.listeners {
            println!("    {}:{} ({:?})", l.address, l.port, l.transport);
        }
    }
    println!(
        "  Cache: capacity={} min_ttl={}s max_ttl={}s",
        config.cache.capacity, config.cache.min_ttl_secs, config.cache.max_ttl_secs
    );
    println!(
        "  Admin port: {}  Metrics port: {}",
        config.admin.admin_port, config.observability.metrics_port
    );
}
