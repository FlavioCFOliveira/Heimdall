// SPDX-License-Identifier: MIT

//! Root-hints loader and priming stub (PROTO-006).
//!
//! [`RootHints`] provides the initial set of root nameserver addresses used to
//! bootstrap iterative resolution.  The IANA root hints are embedded as a
//! compile-time constant and parsed on startup.
//!
//! The `prime()` method is a stub for this sprint: it logs that priming has
//! not yet been implemented and returns `Ok(())`.  Actual outbound DNS query
//! support will be wired in once the UDP/TCP transport layer is operational.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use heimdall_core::name::Name;
use tokio::sync::RwLock;
use tracing::info;

use crate::dnssec_roles::TrustAnchorStore;

// ── Built-in IANA root hints ──────────────────────────────────────────────────

/// The IANA root hints in zone-file format (A and AAAA records).
///
/// Addresses sourced from <https://www.iana.org/domains/root/files>.
/// Last verified: 2024-01.
const BUILTIN_ROOT_HINTS: &str = "\
;; Root hints - IANA\n\
; a.root-servers.net\n\
a.root-servers.net. 3600000 IN A     198.41.0.4\n\
a.root-servers.net. 3600000 IN AAAA  2001:503:ba3e::2:30\n\
; b.root-servers.net\n\
b.root-servers.net. 3600000 IN A     170.247.170.2\n\
b.root-servers.net. 3600000 IN AAAA  2801:1b8:10::b\n\
; c.root-servers.net\n\
c.root-servers.net. 3600000 IN A     192.33.4.12\n\
c.root-servers.net. 3600000 IN AAAA  2001:500:2::c\n\
; d.root-servers.net\n\
d.root-servers.net. 3600000 IN A     199.7.91.13\n\
d.root-servers.net. 3600000 IN AAAA  2001:500:2d::d\n\
; e.root-servers.net\n\
e.root-servers.net. 3600000 IN A     192.203.230.10\n\
e.root-servers.net. 3600000 IN AAAA  2001:500:a8::e\n\
; f.root-servers.net\n\
f.root-servers.net. 3600000 IN A     192.5.5.241\n\
f.root-servers.net. 3600000 IN AAAA  2001:500:2f::f\n\
; g.root-servers.net\n\
g.root-servers.net. 3600000 IN A     192.112.36.4\n\
g.root-servers.net. 3600000 IN AAAA  2001:500:12::d0d\n\
; h.root-servers.net\n\
h.root-servers.net. 3600000 IN A     198.97.190.53\n\
h.root-servers.net. 3600000 IN AAAA  2001:500:1::53\n\
; i.root-servers.net\n\
i.root-servers.net. 3600000 IN A     192.36.148.17\n\
i.root-servers.net. 3600000 IN AAAA  2001:7fe::53\n\
; j.root-servers.net\n\
j.root-servers.net. 3600000 IN A     192.58.128.30\n\
j.root-servers.net. 3600000 IN AAAA  2001:503:c27::2:30\n\
; k.root-servers.net\n\
k.root-servers.net. 3600000 IN A     193.0.14.129\n\
k.root-servers.net. 3600000 IN AAAA  2001:7fd::1\n\
; l.root-servers.net\n\
l.root-servers.net. 3600000 IN A     199.7.83.42\n\
l.root-servers.net. 3600000 IN AAAA  2001:500:9f::42\n\
; m.root-servers.net\n\
m.root-servers.net. 3600000 IN A     202.12.27.33\n\
m.root-servers.net. 3600000 IN AAAA  2001:dc3::35\n\
";

// ── Public types ──────────────────────────────────────────────────────────────

/// A single root nameserver with its associated addresses.
#[derive(Debug, Clone)]
pub struct RootNs {
    /// Fully-qualified name of the root nameserver (e.g. `a.root-servers.net.`).
    pub name: Name,
    /// IPv4 and/or IPv6 addresses for this nameserver.
    pub addrs: Vec<IpAddr>,
}

/// Errors that can arise when loading or priming root hints.
#[derive(Debug)]
pub enum RootHintsError {
    /// The built-in or file-based hints could not be parsed.
    ParseError(String),
    /// A file I/O error occurred.
    IoError(String),
    /// The hints contain no usable nameserver addresses.
    NoAddresses,
}

impl std::fmt::Display for RootHintsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(e) => write!(f, "root hints parse error: {e}"),
            Self::IoError(e) => write!(f, "root hints I/O error: {e}"),
            Self::NoAddresses => write!(f, "root hints contain no usable addresses"),
        }
    }
}

impl std::error::Error for RootHintsError {}

// ── RootHints ─────────────────────────────────────────────────────────────────

/// Root nameserver hints with atomic refresh support.
///
/// The list of root nameservers is stored behind a `tokio::sync::RwLock` so
/// that a background task can update them after a successful priming query
/// without blocking readers.
pub struct RootHints {
    nameservers: Arc<RwLock<Vec<RootNs>>>,
}

impl RootHints {
    /// Constructs [`RootHints`] from the embedded IANA root hints.
    ///
    /// # Errors
    ///
    /// Returns [`RootHintsError::ParseError`] if the embedded constants are
    /// malformed (a programming error; the process should not continue).
    pub fn from_builtin() -> Result<Self, RootHintsError> {
        let ns = parse_hints(BUILTIN_ROOT_HINTS)?;
        if ns.is_empty() {
            return Err(RootHintsError::NoAddresses);
        }
        info!(count = ns.len(), "root hints: loaded built-in hints");
        Ok(Self {
            nameservers: Arc::new(RwLock::new(ns)),
        })
    }

    /// Loads root hints from a file in zone-file format.
    ///
    /// # Errors
    ///
    /// Returns [`RootHintsError::IoError`] on I/O failure or
    /// [`RootHintsError::ParseError`] on parse failure.
    pub fn from_file(path: &Path) -> Result<Self, RootHintsError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| RootHintsError::IoError(e.to_string()))?;
        let ns = parse_hints(&content)?;
        if ns.is_empty() {
            return Err(RootHintsError::NoAddresses);
        }
        info!(
            path = %path.display(),
            count = ns.len(),
            "root hints: loaded from file"
        );
        Ok(Self {
            nameservers: Arc::new(RwLock::new(ns)),
        })
    }

    /// Sends a priming query to the root zone.
    ///
    /// **This is a stub for Sprint 30.** Actual outbound DNS query support
    /// requires the UDP/TCP transport layer to be operational, which will be
    /// wired up in a later sprint.
    ///
    /// Returns `Ok(())` immediately after logging an informational message.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`.
    // The `async` is intentional: this is the public signature that callers
    // will `await`. Removing it would be a breaking API change when the real
    // implementation is added in a future sprint.
    #[allow(clippy::unused_async)]
    pub async fn prime(&self, _trust_anchor: &TrustAnchorStore) -> Result<(), RootHintsError> {
        info!("root hints: priming query not yet implemented — using built-in root hints");
        Ok(())
    }

    /// Returns a snapshot of the current root nameserver list.
    pub async fn get_root_nameservers(&self) -> Vec<RootNs> {
        self.nameservers.read().await.clone()
    }

    /// Returns a flat list of all root nameserver IP addresses.
    pub async fn all_addresses(&self) -> Vec<IpAddr> {
        self.nameservers
            .read()
            .await
            .iter()
            .flat_map(|ns| ns.addrs.clone())
            .collect()
    }
}

// ── Internal parser ───────────────────────────────────────────────────────────

/// Parses a zone-file-style hints text into a `Vec<RootNs>`.
///
/// Only A and AAAA records are extracted; all other lines are ignored.
fn parse_hints(text: &str) -> Result<Vec<RootNs>, RootHintsError> {
    use std::collections::HashMap;

    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    for line in text.lines() {
        let line = line.trim();
        // Skip comments and blank lines.
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        // Split into whitespace-separated tokens.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Expect at least: <name> <ttl> IN <type> <rdata>
        if tokens.len() < 5 {
            continue;
        }

        let owner = tokens[0];
        let rtype = tokens[3];

        let addr: IpAddr = match rtype {
            "A" => tokens[4]
                .parse::<std::net::Ipv4Addr>()
                .map(IpAddr::V4)
                .map_err(|e| {
                    RootHintsError::ParseError(format!("invalid A address '{}': {e}", tokens[4]))
                })?,
            "AAAA" => tokens[4]
                .parse::<std::net::Ipv6Addr>()
                .map(IpAddr::V6)
                .map_err(|e| {
                    RootHintsError::ParseError(format!("invalid AAAA address '{}': {e}", tokens[4]))
                })?,
            _ => continue,
        };

        map.entry(owner.to_ascii_lowercase())
            .or_default()
            .push(addr);
    }

    let mut ns_list: Vec<RootNs> = map
        .into_iter()
        .filter_map(|(name_str, addrs)| {
            let name = Name::parse_str(&name_str).ok()?;
            Some(RootNs { name, addrs })
        })
        .collect();

    // Sort for deterministic ordering (by name presentation string).
    ns_list.sort_by_key(|a| a.name.to_string());

    Ok(ns_list)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_builtin_produces_root_servers() {
        let hints = RootHints::from_builtin().expect("INVARIANT: built-in hints must parse");
        // We expect exactly 13 root servers (a through m).
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("INVARIANT: runtime");
        let servers = rt.block_on(hints.get_root_nameservers());
        assert_eq!(servers.len(), 13, "must have all 13 root name servers");
    }

    #[test]
    fn all_servers_have_at_least_one_address() {
        let hints = RootHints::from_builtin().expect("INVARIANT: built-in hints must parse");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("INVARIANT: runtime");
        let servers = rt.block_on(hints.get_root_nameservers());
        for ns in &servers {
            assert!(
                !ns.addrs.is_empty(),
                "root server {} has no addresses",
                ns.name
            );
        }
    }

    #[test]
    fn all_addresses_includes_ipv4_and_ipv6() {
        let hints = RootHints::from_builtin().expect("INVARIANT: built-in hints must parse");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("INVARIANT: runtime");
        let addrs = rt.block_on(hints.all_addresses());
        let has_v4 = addrs.iter().any(IpAddr::is_ipv4);
        let has_v6 = addrs.iter().any(IpAddr::is_ipv6);
        assert!(has_v4, "must have at least one IPv4 address");
        assert!(has_v6, "must have at least one IPv6 address");
    }
}
