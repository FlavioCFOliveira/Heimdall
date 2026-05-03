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
    dnssec_roles::{NtaStore, TrustAnchorStore},
    forwarder::{ClientRegistry, ForwarderPool, UpstreamTransport},
    recursive::RootHints,
};
use heimdall_runtime::{Config, ForwarderCache, RecursiveCache};

/// All active role instances, assembled from configuration.
///
/// `None` for a role means it is not active in this deployment.
pub struct AssembledRoles {
    /// Authoritative server role, when `config.roles.authoritative`.
    pub auth: Option<AuthServer>,
    /// Recursive resolver role, when `config.roles.recursive`.
    pub recursive: Option<RecursiveServer>,
    /// Forwarder role, when `config.roles.forwarder`.
    pub forwarder: Option<ForwarderServer>,
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
    let auth = if config.roles.authoritative {
        Some(assemble_auth(config)?)
    } else {
        None
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
    })
}

fn assemble_auth(config: &Config) -> Result<AuthServer, String> {
    use std::str::FromStr as _;
    use std::sync::Arc;

    use heimdall_core::TsigAlgorithm;
    use heimdall_core::name::Name;
    use heimdall_core::zone::{ZoneFile, ZoneLimits};
    use heimdall_roles::ZoneConfig;
    use heimdall_roles::auth::zone_role::{TsigConfig, ZoneRole};

    let zone_configs: Vec<ZoneConfig> = config
        .zones
        .zone_files
        .iter()
        .map(|ze| {
            let apex = Name::from_str(&ze.origin)
                .map_err(|e| format!("zone origin {:?} is not a valid DNS name: {e}", ze.origin))?;

            let zone_file = ZoneFile::parse_file(&ze.path, Some(apex.clone()), ZoneLimits::default())
                .map_err(|e| format!("failed to parse zone file {:?}: {e}", ze.path))?;

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

            Ok(ZoneConfig {
                apex,
                role: ZoneRole::Primary,
                upstream_primary: None,
                notify_secondaries: Vec::new(),
                tsig_key,
                axfr_acl: ze.axfr_acl.clone(),
                zone_file: Some(Arc::new(zone_file)),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(AuthServer::new(zone_configs))
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
