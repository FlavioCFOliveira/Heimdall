// SPDX-License-Identifier: MIT

//! TOML configuration types, loader, and hot-reload plumbing.
//!
//! [`ConfigLoader`] reads and validates a TOML file into a [`Config`] struct.
//! The current config is stored in an [`arc_swap::ArcSwap`] so that all callers
//! can read it lock-free on the hot path while a reload atomically replaces it.
//!
//! # Hot-reload semantics
//!
//! Reload is all-or-nothing: if parsing or validation fails, the current config is
//! left unchanged. Only a fully valid new config replaces the running one.

use std::{net::IpAddr, path::Path, path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;
use serde::Deserialize;

// ── Default-value functions ───────────────────────────────────────────────────

fn default_identity() -> String {
    "heimdall".to_owned()
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

fn default_udp_recv_buffer() -> usize {
    // 512 KiB minus one 512-byte sector to avoid kernel fragmentation.
    425_984
}

fn default_cache_capacity() -> usize {
    1_000_000
}

fn default_min_ttl() -> u32 {
    60
}

fn default_max_ttl() -> u32 {
    86_400
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_admin_port() -> u16 {
    9443
}

// ── Config types ─────────────────────────────────────────────────────────────

/// Top-level configuration for a Heimdall server instance.
///
/// Deserialised from a TOML file. All sections except `[server]` have sane
/// defaults and may be omitted.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// Core server identity and threading parameters.
    pub server: ServerConfig,
    /// Which resolver roles are active.
    #[serde(default)]
    pub roles: RolesConfig,
    /// Network listeners.
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    /// Zone file loading.
    #[serde(default)]
    pub zones: ZonesConfig,
    /// Cache parameters.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Access control lists.
    #[serde(default)]
    pub acl: AclConfig,
    /// Response rate limiting.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Response Policy Zone (RPZ) feeds.
    #[serde(default)]
    pub rpz: Vec<RpzZoneConfig>,
    /// Metrics, tracing, and SIEM export.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Admin-RPC endpoint.
    #[serde(default)]
    pub admin: AdminConfig,
}

/// Core server parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// NSID value returned in EDNS responses (RFC 5001).
    #[serde(default = "default_identity")]
    pub identity: String,
    /// Number of tokio worker threads. Defaults to the number of logical CPUs.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            identity: default_identity(),
            worker_threads: default_worker_threads(),
        }
    }
}

/// Resolver role flags. At least one should be `true` in a production deployment.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RolesConfig {
    /// Serve authoritative answers from loaded zone files.
    pub authoritative: bool,
    /// Perform full recursive resolution.
    pub recursive: bool,
    /// Forward queries to upstream resolvers.
    pub forwarder: bool,
}

/// A single network listener binding.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    /// IP address to bind.
    pub address: IpAddr,
    /// Port to bind.
    pub port: u16,
    /// Transport protocol.
    pub transport: TransportKind,
    /// UDP receive buffer size in bytes. Must be ≥ 4096.
    /// Default: 425,984 (512 KiB − 512 B).
    #[serde(default = "default_udp_recv_buffer")]
    pub udp_recv_buffer: usize,
}

/// Transport layer used by a [`ListenerConfig`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// DNS-over-UDP.
    Udp,
    /// DNS-over-TCP.
    Tcp,
    /// DNS-over-TLS (RFC 7858).
    Dot,
    /// DNS-over-HTTPS (RFC 8484, HTTP/2).
    Doh,
    /// DNS-over-QUIC (RFC 9250).
    Doq,
}

/// Zone file loading configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ZonesConfig {
    /// Zone files to load at start-up and watch for changes.
    pub zone_files: Vec<ZoneFileEntry>,
}

/// A single zone file mapping.
#[derive(Debug, Clone, Deserialize)]
pub struct ZoneFileEntry {
    /// The zone origin (e.g. `"example.com."`).
    pub origin: String,
    /// Path to the RFC 1035 master zone file.
    pub path: PathBuf,
}

/// In-memory cache configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of `RRsets` to hold in cache.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,
    /// Minimum TTL to enforce (overrides wire TTL if lower). In seconds.
    #[serde(default = "default_min_ttl")]
    pub min_ttl_secs: u32,
    /// Maximum TTL to enforce (caps wire TTL if higher). In seconds.
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u32,
    /// If set, serve stale cached answers up to this many seconds past expiry.
    pub serve_stale_secs: Option<u32>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            min_ttl_secs: default_min_ttl(),
            max_ttl_secs: default_max_ttl(),
            serve_stale_secs: None,
        }
    }
}

/// Access control list configuration.
///
/// Placeholder — real ACL types with CIDR matching are defined in a later sprint.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AclConfig {
    /// Raw ACL rule strings. Format is validated by the ACL subsystem (later sprint).
    pub rules: Vec<String>,
}

/// Response rate limiting configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RateLimitConfig {
    /// Whether response rate limiting is active.
    pub enabled: bool,
    /// Maximum responses per second per client subnet. `None` = unlimited.
    pub responses_per_second: Option<u32>,
}

/// A single Response Policy Zone feed.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RpzZoneConfig {
    /// Zone name (e.g. `"rpz.example.com."`).
    pub zone: String,
    /// Source URI for this zone (axfr+notify or local path).
    pub source: String,
}

/// Observability configuration (metrics, tracing, SIEM).
#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// Prometheus metrics exposition port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// OTLP/gRPC endpoint for distributed tracing. `None` = tracing disabled.
    pub tracing_otlp_endpoint: Option<String>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_port: default_metrics_port(),
            tracing_otlp_endpoint: None,
        }
    }
}

/// Admin-RPC endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// Admin-RPC listening port (mTLS-protected JSON-over-HTTP/2).
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,
    /// Path to TLS certificate for the admin endpoint.
    pub tls_cert: Option<PathBuf>,
    /// Path to TLS private key for the admin endpoint.
    pub tls_key: Option<PathBuf>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            admin_port: default_admin_port(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validate a parsed [`Config`]. Returns a list of human-readable error messages.
///
/// An empty return value means the config is valid.
#[must_use]
pub fn validate_config(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();

    // At least one listener if any role is active.
    let any_role_active =
        config.roles.authoritative || config.roles.recursive || config.roles.forwarder;
    if config.listeners.is_empty() && any_role_active {
        errors.push(
            "no listeners configured; at least one [[listeners]] entry is required when a \
             role is active"
                .to_owned(),
        );
    }

    // UDP receive buffer floor.
    for (i, listener) in config.listeners.iter().enumerate() {
        if listener.transport == TransportKind::Udp && listener.udp_recv_buffer < 4096 {
            errors.push(format!(
                "listeners[{i}]: udp_recv_buffer ({}) is below the minimum of 4096 bytes",
                listener.udp_recv_buffer
            ));
        }
    }

    // Cache TTL ordering.
    if config.cache.min_ttl_secs > config.cache.max_ttl_secs {
        errors.push(format!(
            "cache.min_ttl_secs ({}) must not exceed cache.max_ttl_secs ({})",
            config.cache.min_ttl_secs, config.cache.max_ttl_secs
        ));
    }

    // Port conflict between admin and metrics.
    if config.admin.admin_port == config.observability.metrics_port {
        errors.push(format!(
            "admin.admin_port ({}) conflicts with observability.metrics_port ({}); \
             they must be distinct",
            config.admin.admin_port, config.observability.metrics_port
        ));
    }

    errors
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by [`ConfigLoader`].
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to read the config file from disk.
    Io(std::io::Error),
    /// TOML parse error (includes position information).
    Parse(toml::de::Error),
    /// Validation errors. Each element is a human-readable message.
    Validation(Vec<String>),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config I/O error: {e}"),
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::Validation(errs) => {
                write!(f, "config validation failed ({} error(s)):", errs.len())?;
                for err in errs {
                    write!(f, "\n  - {err}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Validation(_) => None,
        }
    }
}

// ── ConfigLoader ──────────────────────────────────────────────────────────────

/// Loads and hot-reloads a TOML configuration file.
///
/// The current config is accessible lock-free via [`ConfigLoader::current`].
/// [`ConfigLoader::reload`] re-reads the file and atomically replaces the current
/// config on success, leaving it unchanged on any error.
pub struct ConfigLoader {
    path: PathBuf,
    current: ArcSwap<Config>,
}

impl ConfigLoader {
    /// Load and validate config from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, parsed, or validated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let config = load_and_validate(path)?;
        Ok(Self {
            path: path.to_owned(),
            current: ArcSwap::new(Arc::new(config)),
        })
    }

    /// Reload config from disk.
    ///
    /// All-or-nothing: if reading, parsing, or validation fails, the current config
    /// remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the new config cannot be loaded or is invalid.
    pub fn reload(&self) -> Result<Arc<Config>, ConfigError> {
        let config = load_and_validate(&self.path)?;
        let new = Arc::new(config);
        self.current.store(Arc::clone(&new));
        Ok(new)
    }

    /// Read the current config lock-free.
    ///
    /// The returned [`arc_swap::Guard`] keeps the current `Arc<Config>` alive for
    /// its lifetime. Callers should hold the guard only for the duration of the
    /// operation that needs the config.
    pub fn current(&self) -> arc_swap::Guard<Arc<Config>> {
        self.current.load()
    }
}

/// Read the file at `path`, parse as TOML, and run validation.
fn load_and_validate(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    let config: Config = toml::from_str(&contents).map_err(ConfigError::Parse)?;
    let errors = validate_config(&config);
    if errors.is_empty() {
        Ok(config)
    } else {
        Err(ConfigError::Validation(errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        // Config::default() must not trip any validation rule.
        let errors = validate_config(&Config::default());
        // Default has no roles active and no listeners, so the
        // "no listeners + role active" rule should NOT fire.
        assert!(
            errors.is_empty(),
            "unexpected validation errors: {errors:?}"
        );
    }

    #[test]
    fn ttl_order_violation() {
        let mut config = Config::default();
        config.cache.min_ttl_secs = 3600;
        config.cache.max_ttl_secs = 60;
        let errors = validate_config(&config);
        assert!(
            errors.iter().any(|e| e.contains("min_ttl_secs")),
            "expected ttl ordering error, got: {errors:?}"
        );
    }

    #[test]
    fn port_conflict_detected() {
        let mut config = Config::default();
        config.admin.admin_port = 9090;
        config.observability.metrics_port = 9090;
        let errors = validate_config(&config);
        assert!(
            errors.iter().any(|e| e.contains("conflicts")),
            "expected port conflict error, got: {errors:?}"
        );
    }

    #[test]
    fn udp_recv_buffer_floor() {
        let mut config = Config::default();
        config.listeners.push(ListenerConfig {
            address: "127.0.0.1".parse().expect("valid IP"),
            port: 53,
            transport: TransportKind::Udp,
            udp_recv_buffer: 1024,
        });
        let errors = validate_config(&config);
        assert!(
            errors.iter().any(|e| e.contains("udp_recv_buffer")),
            "expected udp_recv_buffer error, got: {errors:?}"
        );
    }

    #[test]
    fn no_listener_with_active_role() {
        let mut config = Config::default();
        config.roles.authoritative = true;
        config.listeners.clear();
        let errors = validate_config(&config);
        assert!(
            errors.iter().any(|e| e.contains("no listeners")),
            "expected no-listener error, got: {errors:?}"
        );
    }
}
