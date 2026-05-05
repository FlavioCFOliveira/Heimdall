// SPDX-License-Identifier: MIT

//! Logging initialisation (BIN-004 boot phase, BIN-013, ENG-202).
//!
//! Installs a `tracing-subscriber` that emits to stderr:
//! - JSON format when stderr is not a TTY (production / log shippers).
//! - Pretty human-readable format when stderr is a TTY (interactive sessions).
//!
//! `RUST_LOG` overrides `--log-level` per BIN-013. Invalid `RUST_LOG` values
//! fall back to the CLI log level with a WARN log.

use std::io::IsTerminal as _;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::cli::{LogFormat, LogLevel};

/// Initialise the global `tracing` subscriber.
///
/// Must be called before any code that emits `tracing` events.
pub fn init(level: LogLevel, format: LogFormat) {
    let env_filter = build_env_filter(level);
    let is_tty = std::io::stderr().is_terminal();

    let use_json = match format {
        LogFormat::Json => true,
        LogFormat::Pretty => false,
    };

    let effective_json = use_json || !is_tty;

    if effective_json {
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json().with_writer(std::io::stderr));
        tracing::subscriber::set_global_default(subscriber)
            .unwrap_or_else(|e| eprintln!("heimdall: failed to install tracing subscriber: {e}"));
    } else {
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().pretty().with_writer(std::io::stderr));
        tracing::subscriber::set_global_default(subscriber)
            .unwrap_or_else(|e| eprintln!("heimdall: failed to install tracing subscriber: {e}"));
    }
}

fn build_env_filter(level: LogLevel) -> EnvFilter {
    // RUST_LOG takes precedence over --log-level per BIN-013.
    if let Ok(rust_log) = std::env::var("RUST_LOG")
        && !rust_log.is_empty()
    {
        match EnvFilter::try_new(&rust_log) {
            Ok(filter) => return filter,
            Err(e) => {
                // Cannot use tracing::warn! here — subscriber not yet installed.
                eprintln!(
                    "WARN heimdall: invalid RUST_LOG directive {:?}: {}; \
                         falling back to --log-level={}",
                    rust_log,
                    e,
                    level.as_str()
                );
            }
        }
    }
    EnvFilter::new(level.as_str())
}
