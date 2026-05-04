// SPDX-License-Identifier: MIT

//! Deep configuration validation for `heimdall check-config` (BIN-003).
//!
//! Runs five independent checks in sequence and aggregates results:
//!
//! 1. **TOML parse** — already performed by the caller via `config::load`.
//! 2. **Zone files** — each `[[zones.zone_files]]` entry is opened and parsed
//!    with `heimdall_core::zone::ZoneFile::parse`.
//! 3. **Listener bind dry-run** — each `[[listeners]]` socket is bound with
//!    `SO_REUSEADDR` and immediately released; TLS material is loaded.
//! 4. **TLS material** — for DoT/DoH/DoQ listeners, the cert chain and private
//!    key are loaded by rustls.
//! 5. **Redis reachability** — if `[persistence]` is configured, a PING is
//!    sent to Redis with a 5-second timeout.
//!
//! Exit codes (BIN-003):
//! - `0` — all checks pass
//! - `2` — config semantically invalid (bad zone, bad TLS cert)
//! - `3` — external resource unreachable (Redis, port already in use)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::time::Duration;

use heimdall_core::name::Name;
use heimdall_core::zone::{ZoneFile, ZoneLimits};
use heimdall_runtime::{
    RedisAuth, RedisConfig, RedisStore, RedisTopology, TlsServerConfig,
    build_tls_server_config,
    config::{Config, PersistenceConfig, TransportKind},
};

// ── Public API ────────────────────────────────────────────────────────────────

/// A single check result.
#[derive(Debug)]
pub struct CheckItem {
    pub name: String,
    pub ok: bool,
    pub message: String,
}

/// Overall result of `check-config`.
pub struct CheckReport {
    pub items: Vec<CheckItem>,
    /// `true` only if every item is `ok`.
    pub ok: bool,
    /// Suggested exit code: 0, 2, or 3.
    pub exit_code: i32,
}

impl CheckReport {
    fn new() -> Self {
        Self { items: Vec::new(), ok: true, exit_code: 0 }
    }

    fn push(&mut self, item: CheckItem) {
        if !item.ok && self.ok {
            self.ok = false;
        }
        self.items.push(item);
    }

    /// Print in plain-text format.
    pub fn print_plain(&self) {
        for item in &self.items {
            let sym = if item.ok { "OK  " } else { "FAIL" };
            println!("[{sym}] {}: {}", item.name, item.message);
        }
        if self.ok {
            println!("\ncheck-config: all checks passed.");
        } else {
            println!("\ncheck-config: FAILED.");
        }
    }

    /// Print in JSON format (one top-level object with `ok` and `checks` array).
    pub fn print_json(&self) {
        let checks: Vec<String> = self
            .items
            .iter()
            .map(|i| {
                let ok = i.ok;
                let name = json_escape(&i.name);
                let msg = json_escape(&i.message);
                format!(r#"{{"name":"{name}","ok":{ok},"message":"{msg}"}}"#)
            })
            .collect();
        let ok = self.ok;
        let checks_json = checks.join(",");
        println!(r#"{{"ok":{ok},"checks":[{checks_json}]}}"#);
    }
}

pub fn json_escape_str(s: &str) -> String {
    json_escape(s)
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run all deep-validation checks against `config`.
///
/// The caller must have already successfully loaded the config (check 1 is
/// implicit — if we get here, parse succeeded).
pub async fn run(config: &Config) -> CheckReport {
    let mut report = CheckReport::new();

    report.push(CheckItem {
        name: "toml_parse".into(),
        ok: true,
        message: "TOML parsed and schema validated".into(),
    });

    check_zone_files(config, &mut report);
    check_listeners(config, &mut report).await;
    check_redis(config, &mut report).await;

    // Compute exit code: 0=ok, 2=config invalid, 3=external unreachable.
    if !report.ok {
        // Listener port-in-use and Redis are exit 3; others are exit 2.
        let has_external = report.items.iter().any(|i| {
            !i.ok && (i.name.starts_with("redis") || i.name.starts_with("listener_bind"))
        });
        report.exit_code = if has_external { 3 } else { 2 };
    }

    report
}

// ── Zone file checks ──────────────────────────────────────────────────────────

fn check_zone_files(config: &Config, report: &mut CheckReport) {
    if config.zones.zone_files.is_empty() {
        return;
    }

    for entry in &config.zones.zone_files {
        let origin: &str = &entry.origin;

        // Secondary zones have no local zone file to check.
        let path = match entry.path.as_ref() {
            Some(p) => p,
            None => {
                let role = entry.zone_role.as_deref().unwrap_or("primary");
                report.push(CheckItem {
                    name: format!("zone_file:{origin}"),
                    ok: true,
                    message: format!(
                        "zone '{origin}' role='{role}' — no local zone file (secondary pull)"
                    ),
                });
                continue;
            }
        };

        let name = format!("zone_file:{}", path.display());

        let name_opt: Option<Name> = Name::from_str(origin).ok();
        match ZoneFile::parse_file(path, name_opt, ZoneLimits::default()) {
            Ok(_) => {
                report.push(CheckItem {
                    name,
                    ok: true,
                    message: format!("zone '{origin}' parsed successfully"),
                });
            }
            Err(e) => {
                report.push(CheckItem {
                    name,
                    ok: false,
                    message: format!("zone '{origin}' load error: {e}"),
                });
            }
        }
    }
}

// ── Listener dry-run checks ───────────────────────────────────────────────────

async fn check_listeners(config: &Config, report: &mut CheckReport) {
    for (i, cfg) in config.listeners.iter().enumerate() {
        let addr = SocketAddr::new(cfg.address, cfg.port);

        // TLS material check (synchronous — just loads files).
        if matches!(
            cfg.transport,
            TransportKind::Dot | TransportKind::Doh | TransportKind::Doq
        ) {
            let tls_name = format!("listener_tls:{i}:{addr}");
            match check_tls(cfg.tls_cert.as_deref(), cfg.tls_key.as_deref()) {
                Ok(()) => {
                    report.push(CheckItem {
                        name: tls_name,
                        ok: true,
                        message: format!("TLS material for listeners[{i}] ({addr}) loaded"),
                    });
                }
                Err(e) => {
                    report.push(CheckItem {
                        name: tls_name,
                        ok: false,
                        message: format!("listeners[{i}] ({addr}) TLS error: {e}"),
                    });
                    continue;
                }
            }
        }

        // Bind dry-run.
        let bind_name = format!("listener_bind:{i}:{addr}");
        let bind_result = match cfg.transport {
            TransportKind::Udp => dry_bind_udp(addr).await,
            _ => dry_bind_tcp(addr).await,
        };

        match bind_result {
            Ok(()) => {
                report.push(CheckItem {
                    name: bind_name,
                    ok: true,
                    message: format!("listeners[{i}] {:?} bind {addr} OK", cfg.transport),
                });
            }
            Err(e) => {
                report.push(CheckItem {
                    name: bind_name,
                    ok: false,
                    message: format!(
                        "listeners[{i}] {:?} bind {addr} failed: {e}",
                        cfg.transport
                    ),
                });
            }
        }
    }
}

fn check_tls(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
) -> Result<(), String> {
    let cert_path = cert.ok_or_else(|| "tls_cert is required".to_owned())?;
    let key_path = key.ok_or_else(|| "tls_key is required".to_owned())?;
    let tls_cfg = TlsServerConfig {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        ..TlsServerConfig::default()
    };
    build_tls_server_config(&tls_cfg).map(|_| ()).map_err(|e| e.to_string())
}

async fn dry_bind_tcp(addr: SocketAddr) -> Result<(), String> {
    use tokio::net::TcpListener;
    TcpListener::bind(addr)
        .await
        .map(|_| ())
        .map_err(|e| format!("{addr}: {e}"))
}

async fn dry_bind_udp(addr: SocketAddr) -> Result<(), String> {
    use tokio::net::UdpSocket;
    UdpSocket::bind(addr)
        .await
        .map(|_| ())
        .map_err(|e| format!("{addr}: {e}"))
}

// ── Redis reachability check ──────────────────────────────────────────────────

async fn check_redis(config: &Config, report: &mut CheckReport) {
    let cfg = &config.persistence;
    if !cfg.is_configured() {
        return;
    }

    let addr = persistence_addr(cfg);
    let name = format!("redis:{addr}");

    let result = tokio::time::timeout(Duration::from_secs(5), probe_redis(cfg)).await;

    match result {
        Ok(Ok(())) => {
            report.push(CheckItem {
                name,
                ok: true,
                message: format!("Redis at {addr} reachable and PING succeeded"),
            });
        }
        Ok(Err(e)) => {
            report.push(CheckItem {
                name,
                ok: false,
                message: format!("Redis at {addr} unreachable: {e}"),
            });
        }
        Err(_) => {
            report.push(CheckItem {
                name,
                ok: false,
                message: format!("Redis at {addr} unreachable: connection timeout (5s)"),
            });
        }
    }
}

async fn probe_redis(cfg: &PersistenceConfig) -> Result<(), String> {
    let topology = if let Some(path) = &cfg.uds_path {
        RedisTopology::UnixSocket { path: path.clone() }
    } else {
        let host = cfg.host.clone().unwrap_or_default();
        RedisTopology::Tcp { host, port: cfg.port, tls: cfg.tls }
    };

    let redis_cfg = RedisConfig {
        topology,
        auth: RedisAuth {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        },
        pool_max_size: 1,
        pool_min_size: 1,
        pool_acquisition_timeout_ms: 3_000,
        hscan_count: 1,
    };

    let store = RedisStore::connect(redis_cfg).map_err(|e| e.to_string())?;
    let mut conn = store.connection().await.map_err(|e| e.to_string())?;
    redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn persistence_addr(cfg: &PersistenceConfig) -> String {
    if let Some(path) = &cfg.uds_path {
        format!("unix://{}", path.display())
    } else {
        let host = cfg.host.as_deref().unwrap_or("?");
        format!("redis://{}:{}", host, cfg.port)
    }
}
