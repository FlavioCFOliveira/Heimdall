// SPDX-License-Identifier: MIT

//! Role assembly for the heimdall binary (boot phase 11, BIN-021).
//!
//! Reads the active roles from configuration and instantiates each enabled
//! role with its required dependencies. Assembly is fail-closed: if any
//! required dependency of an active role is missing or invalid, the whole
//! boot sequence fails with a non-zero exit code.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use heimdall_roles::{
    AuthServer, ForwarderServer, RecursiveServer,
    auth::zone_role::ZoneConfig,
    dnssec_roles::{NtaStore, TrustAnchorStore},
    forwarder::{ClientRegistry, ForwarderPool, UpstreamTransport},
    recursive::RootHints,
};
use heimdall_runtime::{Config, ForwarderCache, RecursiveCache};

/// A secondary zone task descriptor: carries the zone config, a `tokio::sync::Notify`
/// used to wake the refresh loop on NOTIFY reception, and a reference to the
/// `AuthServer` so the loop can push the updated zone file back after a pull.
pub struct SecondaryZoneTask {
    /// Zone configuration for the secondary, including the upstream primary address.
    pub zone_config: ZoneConfig,
    /// Wake signal: the NOTIFY handler calls `.notify_one()` on this to trigger
    /// an immediate refresh instead of waiting for the SOA REFRESH timer.
    pub notify_signal: Arc<tokio::sync::Notify>,
    /// Reference to the `AuthServer` so the refresh loop can install the pulled zone.
    pub auth_server: Arc<AuthServer>,
}

/// All active role instances, assembled from configuration.
///
/// `None` for a role means it is not active in this deployment.
pub struct AssembledRoles {
    /// Authoritative server role, when `config.roles.authoritative`.
    ///
    /// Wrapped in `Arc` so that secondary refresh tasks can hold a reference
    /// and call `AuthServer::update_zone_file` after a successful pull.
    pub auth: Option<Arc<AuthServer>>,
    /// Recursive resolver role, when `config.roles.recursive`.
    pub recursive: Option<RecursiveServer>,
    /// Forwarder role, when `config.roles.forwarder`.
    pub forwarder: Option<ForwarderServer>,
    /// Secondary zone refresh tasks to spawn after the listeners are bound.
    pub secondary_tasks: Vec<SecondaryZoneTask>,
    /// Primary zone configs for which a startup NOTIFY must be emitted
    /// (RFC 1996 §3.7).  Only populated for Primary / Both zones that have
    /// at least one entry in `notify_secondaries`.
    pub startup_notify_zones: Vec<ZoneConfig>,
}

impl AssembledRoles {
    /// Returns `true` if at least one role is active.
    pub fn any_active(&self) -> bool {
        self.auth.is_some() || self.recursive.is_some() || self.forwarder.is_some()
    }
}

/// Assemble all active roles from `config`.
///
/// Uses `data_dir` for DNSSEC trust-anchor state persistence. On production
/// systems this is typically `/var/lib/heimdall`.
///
/// # Errors
///
/// Returns a human-readable error string if any required dependency fails to
/// initialise. The caller MUST exit with code 1 on error (BIN-021).
pub fn assemble(config: &Config, data_dir: &Path) -> Result<AssembledRoles, String> {
    let (auth, secondary_tasks, startup_notify_zones) = if config.roles.authoritative {
        let (auth_arc, tasks, notify_zones) = assemble_auth(config)?;
        (Some(auth_arc), tasks, notify_zones)
    } else {
        (None, Vec::new(), Vec::new())
    };

    let trust_anchor = if config.roles.recursive || config.roles.forwarder {
        Some(
            TrustAnchorStore::new(data_dir)
                .map_err(|e| format!("failed to initialise DNSSEC trust anchor: {e}"))?,
        )
    } else {
        None
    };
    let trust_anchor = trust_anchor.map(Arc::new);

    let nta_store = if config.roles.recursive || config.roles.forwarder {
        Some(Arc::new(NtaStore::new(1024)))
    } else {
        None
    };

    let recursive = if config.roles.recursive {
        let ta = trust_anchor
            .as_ref()
            .expect("trust_anchor built above")
            .clone();
        let nta = nta_store
            .as_ref()
            .expect("nta_store built above")
            .clone();
        Some(assemble_recursive(config, ta, nta)?)
    } else {
        None
    };

    let forwarder = if config.roles.forwarder {
        let ta = trust_anchor
            .as_ref()
            .expect("trust_anchor built above")
            .clone();
        let nta = nta_store
            .as_ref()
            .expect("nta_store built above")
            .clone();
        Some(assemble_forwarder(config, ta, nta)?)
    } else {
        None
    };

    Ok(AssembledRoles {
        auth,
        recursive,
        forwarder,
        secondary_tasks,
        startup_notify_zones,
    })
}

/// Assemble the authoritative role.
///
/// Returns `(Arc<AuthServer>, Vec<SecondaryZoneTask>, Vec<ZoneConfig>)` where:
/// - `secondary_tasks` must be spawned after listeners are bound.
/// - `startup_notify_zones` holds Primary/Both zone configs for which a startup
///   NOTIFY must be emitted (RFC 1996 §3.7) once listeners are bound.
fn assemble_auth(
    config: &Config,
) -> Result<(Arc<AuthServer>, Vec<SecondaryZoneTask>, Vec<ZoneConfig>), String> {
    use std::net::SocketAddr;
    use std::str::FromStr as _;

    use heimdall_core::TsigAlgorithm;
    use heimdall_core::name::Name;
    use heimdall_core::zone::{ZoneFile, ZoneLimits};
    use heimdall_roles::auth::zone_role::{TsigConfig, ZoneRole};

    let mut zone_configs: Vec<ZoneConfig> = Vec::new();
    // (apex_wire, notify_signal) pairs for secondary zones.
    let mut secondary_info: Vec<(Vec<u8>, Arc<tokio::sync::Notify>, ZoneConfig)> = Vec::new();
    // Primary / Both zones that need startup NOTIFY (RFC 1996 §3.7).
    let mut startup_notify_zones: Vec<ZoneConfig> = Vec::new();

    for ze in &config.zones.zone_files {
        let apex = Name::from_str(&ze.origin)
            .map_err(|e| format!("zone origin {:?} is not a valid DNS name: {e}", ze.origin))?;

        // Determine zone role.
        let role = match ze.zone_role.as_deref().unwrap_or("primary") {
            "primary" => ZoneRole::Primary,
            "secondary" => ZoneRole::Secondary,
            "both" => ZoneRole::Both,
            other => {
                return Err(format!(
                    "zone {:?}: unknown zone_role {:?}; expected \"primary\", \"secondary\", or \"both\"",
                    ze.origin, other
                ))
            }
        };

        // Parse optional upstream primary address (required for Secondary / Both).
        let upstream_primary: Option<SocketAddr> = ze
            .upstream_primary
            .as_deref()
            .map(|s| {
                s.parse::<SocketAddr>().map_err(|e| {
                    format!(
                        "zone {:?}: upstream_primary {:?} is not a valid socket address: {e}",
                        ze.origin, s
                    )
                })
            })
            .transpose()?;

        if matches!(role, ZoneRole::Secondary | ZoneRole::Both) && upstream_primary.is_none() {
            return Err(format!(
                "zone {:?}: upstream_primary must be set for role {:?}",
                ze.origin,
                ze.zone_role.as_deref().unwrap_or("secondary")
            ));
        }

        // Parse notify_secondaries.
        let notify_secondaries: Vec<SocketAddr> = ze
            .notify_secondaries
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>().map_err(|e| {
                    format!(
                        "zone {:?}: notify_secondaries entry {:?} is not a valid socket address: {e}",
                        ze.origin, s
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Parse optional TSIG key fields.
        let tsig_key = if let (Some(key_name), Some(alg_str), Some(secret_b64)) = (
            ze.tsig_key_name.as_deref(),
            ze.tsig_algorithm.as_deref(),
            ze.tsig_secret_base64.as_deref(),
        ) {
            let algorithm = match alg_str.to_ascii_lowercase().trim_end_matches('.') {
                "hmac-sha256" => TsigAlgorithm::HmacSha256,
                "hmac-sha384" => TsigAlgorithm::HmacSha384,
                "hmac-sha512" => TsigAlgorithm::HmacSha512,
                other => {
                    return Err(format!(
                        "zone {:?}: unsupported TSIG algorithm {:?}",
                        ze.origin, other
                    ))
                }
            };
            let secret = base64_decode(secret_b64).map_err(|e| {
                format!("zone {:?}: invalid base64 in tsig_secret_base64: {e}", ze.origin)
            })?;
            Some(TsigConfig {
                key_name: key_name.to_owned(),
                algorithm,
                secret,
            })
        } else {
            None
        };

        // Load zone file for Primary / Both roles only.
        let zone_file: Option<Arc<ZoneFile>> = if matches!(role, ZoneRole::Primary | ZoneRole::Both) {
            match &ze.path {
                Some(p) => {
                    let zf = ZoneFile::parse_file(p, Some(apex.clone()), ZoneLimits::default())
                        .map_err(|e| format!("failed to parse zone file {:?}: {e}", p))?;
                    Some(Arc::new(zf))
                }
                None => {
                    return Err(format!(
                        "zone {:?}: path is required for primary or both roles",
                        ze.origin
                    ))
                }
            }
        } else {
            // Secondary: no local zone file at startup; data arrives via AXFR.
            None
        };

        let cfg = ZoneConfig {
            apex: apex.clone(),
            role: role.clone(),
            upstream_primary,
            notify_secondaries,
            tsig_key,
            axfr_acl: ze.axfr_acl.clone(),
            zone_file,
        };

        if matches!(role, ZoneRole::Secondary | ZoneRole::Both) {
            let sig = Arc::new(tokio::sync::Notify::new());
            let apex_wire = apex.as_wire_bytes().to_ascii_lowercase();
            secondary_info.push((apex_wire, sig, cfg));
        } else {
            // Primary zone: register for startup NOTIFY if secondaries are configured.
            if !cfg.notify_secondaries.is_empty() {
                startup_notify_zones.push(cfg.clone());
            }
            zone_configs.push(cfg);
        }
    }

    // Collect all configs: primary ones already in zone_configs, add secondary ones too.
    for (_, _, cfg) in &secondary_info {
        zone_configs.push(cfg.clone());
    }

    let auth_arc = Arc::new(AuthServer::new(zone_configs));

    // Build secondary tasks now that we have the Arc<AuthServer>.
    let secondary_tasks: Vec<SecondaryZoneTask> = secondary_info
        .into_iter()
        .map(|(_, sig, cfg)| SecondaryZoneTask {
            zone_config: cfg,
            notify_signal: sig.clone(),
            auth_server: Arc::clone(&auth_arc),
        })
        .collect();

    // Register the notify signals with the AuthServer.
    for task in &secondary_tasks {
        auth_arc.register_notify_signal(
            &task.zone_config.apex.as_wire_bytes().to_ascii_lowercase(),
            Arc::clone(&task.notify_signal),
        );
    }

    Ok((auth_arc, secondary_tasks, startup_notify_zones))
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .map_err(|e| e.to_string())
}

fn assemble_recursive(
    config: &Config,
    trust_anchor: Arc<TrustAnchorStore>,
    nta_store: Arc<NtaStore>,
) -> Result<RecursiveServer, String> {
    let cap = config.cache.capacity;
    let half = cap / 2;
    let cache = Arc::new(RecursiveCache::new(half, cap - half));

    let root_hints = RootHints::from_builtin()
        .map_err(|e| format!("failed to load built-in root hints: {e}"))?;

    Ok(RecursiveServer::new(
        cache,
        trust_anchor,
        nta_store,
        Arc::new(root_hints),
    ))
}

fn assemble_forwarder(
    config: &Config,
    trust_anchor: Arc<TrustAnchorStore>,
    nta_store: Arc<NtaStore>,
) -> Result<ForwarderServer, String> {
    let forwarder_cache = Arc::new(ForwarderCache::new(
        config.cache.capacity / 2,
        config.cache.capacity - config.cache.capacity / 2,
    ));

    // Build the transport set: default to UDP/TCP only when not specified.
    let transports: HashSet<UpstreamTransport> =
        [UpstreamTransport::UdpTcp].into_iter().collect();
    let registry = Arc::new(ClientRegistry::build(&transports));
    let pool = ForwarderPool::new(registry, vec![UpstreamTransport::UdpTcp]);

    let rate_limit = config
        .rate_limit
        .responses_per_second
        .unwrap_or(1000);

    Ok(ForwarderServer::new(
        Vec::new(), // forward rules loaded from config in a later task
        pool,
        trust_anchor,
        nta_store,
        forwarder_cache,
        rate_limit,
    ))
}
