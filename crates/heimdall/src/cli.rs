// SPDX-License-Identifier: MIT

//! CLI surface for the `heimdall` binary (BIN-001..BIN-005).
//!
//! Subcommands: `start`, `check-config`, `version`.
//! Global options: `--log-level`, `--log-format`, `--color`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// High-performance, security-first DNS server.
#[derive(Debug, Parser)]
#[command(
    name = "heimdall",
    version,
    about = "High-performance, security-first DNS server",
    long_about = None,
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the Heimdall DNS daemon.
    Start(StartArgs),

    /// Validate the configuration file without starting the daemon.
    ///
    /// Performs a deep validation: TOML parse, semantic validation, Redis
    /// reachability probe, zone-load dry run, and listener bind dry run.
    /// Exits 0 on success, 2 on any failure.
    #[command(name = "check-config")]
    CheckConfig(CheckConfigArgs),

    /// Print version and build metadata.
    Version,
}

/// Arguments for the `start` subcommand (BIN-002).
#[derive(Debug, Parser)]
pub struct StartArgs {
    /// Path to the TOML configuration file.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "PATH",
        default_value = "/etc/heimdall/heimdall.toml",
        env = "HEIMDALL_CONFIG"
    )]
    pub config: PathBuf,

    /// Structured log level.
    ///
    /// Overridden by the RUST_LOG environment variable.
    #[arg(
        short = 'l',
        long = "log-level",
        value_name = "LEVEL",
        default_value = "info"
    )]
    pub log_level: LogLevel,

    /// Log output format.
    #[arg(long = "log-format", value_name = "FORMAT", default_value = "json")]
    pub log_format: LogFormat,

    /// Colour in terminal output.
    #[arg(long = "color", value_name = "WHEN", default_value = "auto")]
    pub color: ColorWhen,
}

/// Arguments for the `check-config` subcommand (BIN-003).
#[derive(Debug, Parser)]
pub struct CheckConfigArgs {
    /// Path to the TOML configuration file.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "PATH",
        default_value = "/etc/heimdall/heimdall.toml",
        env = "HEIMDALL_CONFIG"
    )]
    pub config: PathBuf,
}

/// Log level values (BIN-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Log format values (BIN-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Colour control values (BIN-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    Auto,
    Always,
    Never,
}
