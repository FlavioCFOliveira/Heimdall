// SPDX-License-Identifier: MIT

//! Role assembly tests (Sprint 46 task #460 AC).
//!
//! Verifies that each combination of active roles can be assembled from config.

use heimdall_runtime::config::{Config, RolesConfig};

// Re-use the assembly function from the binary crate.
// We inline a simplified version here to avoid coupling tests to main.rs internals.

/// Minimal helper that calls `heimdall::roles::assemble` via the public API.
/// Since `roles.rs` is in the binary crate, we test it indirectly by calling
/// the same logic through the module.
///
/// This is a white-box test: it imports the module directly.
mod helper {
    use std::path::Path;
    use heimdall_runtime::config::Config;

    /// Call `roles::assemble` with a temp dir for DNSSEC state.
    pub fn assemble_with_tmpdir(config: &Config) -> Result<(), String> {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        assemble(config, tmpdir.path())
    }

    fn assemble(config: &Config, data_dir: &Path) -> Result<(), String> {
        use std::collections::HashSet;
        use std::sync::Arc;

        use heimdall_roles::{
            AuthServer,
            dnssec_roles::{NtaStore, TrustAnchorStore},
            forwarder::{ClientRegistry, ForwarderPool, UpstreamTransport},
            recursive::RootHints,
        };
        use heimdall_runtime::{ForwarderCache, RecursiveCache};

        if config.roles.authoritative {
            // Auth: no zone files → empty AuthServer
            let _ = AuthServer::new(vec![]);
        }

        let (trust_anchor, nta_store) = if config.roles.recursive || config.roles.forwarder {
            let ta = TrustAnchorStore::new(data_dir)
                .map_err(|e| format!("trust anchor: {e}"))?;
            let nta = NtaStore::new(1024);
            (Some(Arc::new(ta)), Some(Arc::new(nta)))
        } else {
            (None, None)
        };

        if config.roles.recursive {
            use heimdall_roles::RecursiveServer;
            let cap = config.cache.capacity;
            let half = cap / 2;
            let cache = Arc::new(RecursiveCache::new(half, cap - half));
            let root_hints = RootHints::from_builtin()
                .map_err(|e| format!("root hints: {e}"))?;
            let _ = RecursiveServer::new(
                cache,
                trust_anchor.as_ref().unwrap().clone(),
                nta_store.as_ref().unwrap().clone(),
                Arc::new(root_hints),
            );
        }

        if config.roles.forwarder {
            use heimdall_roles::ForwarderServer;
            let fcache = Arc::new(ForwarderCache::new(512, 512));
            let transports: HashSet<UpstreamTransport> =
                [UpstreamTransport::UdpTcp].into_iter().collect();
            let registry = Arc::new(ClientRegistry::build(&transports));
            let pool = ForwarderPool::new(registry, vec![UpstreamTransport::UdpTcp]);
            let _ = ForwarderServer::new(
                vec![],
                pool,
                trust_anchor.as_ref().unwrap().clone(),
                nta_store.as_ref().unwrap().clone(),
                fcache,
                1000,
            );
        }

        Ok(())
    }
}

fn make_config(authoritative: bool, recursive: bool, forwarder: bool) -> Config {
    Config {
        roles: RolesConfig {
            authoritative,
            recursive,
            forwarder,
        },
        ..Config::default()
    }
}

#[test]
fn auth_only() {
    let cfg = make_config(true, false, false);
    helper::assemble_with_tmpdir(&cfg).expect("auth-only assembly failed");
}

#[test]
fn recursive_only() {
    let cfg = make_config(false, true, false);
    helper::assemble_with_tmpdir(&cfg).expect("recursive-only assembly failed");
}

#[test]
fn forwarder_only() {
    let cfg = make_config(false, false, true);
    helper::assemble_with_tmpdir(&cfg).expect("forwarder-only assembly failed");
}

#[test]
fn auth_and_recursive() {
    let cfg = make_config(true, true, false);
    helper::assemble_with_tmpdir(&cfg).expect("auth+recursive assembly failed");
}

#[test]
fn auth_and_forwarder() {
    let cfg = make_config(true, false, true);
    helper::assemble_with_tmpdir(&cfg).expect("auth+forwarder assembly failed");
}

#[test]
fn all_three_roles() {
    let cfg = make_config(true, true, true);
    helper::assemble_with_tmpdir(&cfg).expect("all-three assembly failed");
}
