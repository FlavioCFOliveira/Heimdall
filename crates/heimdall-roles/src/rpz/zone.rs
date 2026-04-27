// SPDX-License-Identifier: MIT

//! Compiled RPZ policy zone with fast-lookup matching structures
//! (RPZ-011..015, RPZ-019..020, RPZ-027).
//!
//! A [`PolicyZone`] holds one set of pre-compiled trie/matcher structures and
//! exposes per-trigger-type evaluation methods.  The [`crate::rpz::engine::RpzEngine`]
//! drives evaluation across multiple zones in priority order.

use std::net::IpAddr;
use std::sync::Arc;

use heimdall_core::name::Name;

use crate::rpz::action::RpzAction;
use crate::rpz::trigger::{RpzEntry, RpzTrigger};
use crate::rpz::trie::{CidrTrie, NsdnameMatcher, QnameTrie};

/// Default TTL in seconds for synthetic RPZ records when none is specified (RPZ-033).
pub const DEFAULT_POLICY_TTL: u32 = 30;

// ── PolicyZone ────────────────────────────────────────────────────────────────

/// A compiled RPZ policy zone.
///
/// Each zone owns its matching structures and is identified by a name and an
/// evaluation order.  The engine evaluates zones in ascending `evaluation_order`
/// (lower = higher priority, RPZ-019).
#[derive(Debug)]
pub struct PolicyZone {
    /// The zone FQDN (e.g. `"rpz.example.com."`).
    pub name: String,
    /// Evaluation order; 0 = highest priority (RPZ-019).
    pub evaluation_order: u8,
    /// TTL for synthetic records emitted by this zone's actions (seconds, RPZ-033).
    pub policy_ttl: u32,

    // ── Matching structures (RPZ-028) ─────────────────────────────────────────
    /// QNAME trigger trie (exact + wildcard).
    pub qname: Arc<QnameTrie>,
    /// Client-IP CIDR trie.
    pub client_ip: Arc<CidrTrie>,
    /// Response-IP CIDR trie.
    pub response_ip: Arc<CidrTrie>,
    /// NSIP CIDR trie.
    pub nsip: Arc<CidrTrie>,
    /// NSDNAME exact + suffix matcher.
    pub nsdname: Arc<NsdnameMatcher>,
}

impl PolicyZone {
    /// Creates a new, empty `PolicyZone` with the given name and evaluation order.
    ///
    /// `policy_ttl` defaults to [`DEFAULT_POLICY_TTL`] (30 seconds, RPZ-033).
    #[must_use]
    pub fn new(name: String, evaluation_order: u8) -> Self {
        Self {
            name,
            evaluation_order,
            policy_ttl: DEFAULT_POLICY_TTL,
            qname: Arc::new(QnameTrie::new()),
            client_ip: Arc::new(CidrTrie::new()),
            response_ip: Arc::new(CidrTrie::new()),
            nsip: Arc::new(CidrTrie::new()),
            nsdname: Arc::new(NsdnameMatcher::new()),
        }
    }

    /// Inserts an [`RpzEntry`] into the appropriate trie based on its trigger type.
    pub fn insert(&mut self, entry: RpzEntry) {
        match entry.trigger {
            RpzTrigger::QnameExact(ref name) => {
                Arc::make_mut(&mut self.qname).insert_exact(name, entry.action);
            }
            RpzTrigger::QnameWildcard(ref suffix) => {
                Arc::make_mut(&mut self.qname).insert_wildcard(suffix, entry.action);
            }
            RpzTrigger::ClientIp(ref range) => {
                Arc::make_mut(&mut self.client_ip).insert(range, entry.action);
            }
            RpzTrigger::ResponseIp(ref range) => {
                Arc::make_mut(&mut self.response_ip).insert(range, entry.action);
            }
            RpzTrigger::Nsip(ref range) => {
                Arc::make_mut(&mut self.nsip).insert(range, entry.action);
            }
            RpzTrigger::NsdnameExact(ref name) => {
                Arc::make_mut(&mut self.nsdname).insert_exact(name, entry.action);
            }
            RpzTrigger::NsdnameSuffix(ref suffix) => {
                Arc::make_mut(&mut self.nsdname).insert_suffix(suffix, entry.action);
            }
        }
    }

    /// Removes an entry whose trigger matches the given [`RpzTrigger`].
    pub fn remove(&mut self, trigger: &RpzTrigger) {
        match trigger {
            RpzTrigger::QnameExact(name) => {
                Arc::make_mut(&mut self.qname).remove_exact(name);
            }
            RpzTrigger::QnameWildcard(suffix) => {
                Arc::make_mut(&mut self.qname).remove_wildcard(suffix);
            }
            RpzTrigger::ClientIp(range) => {
                Arc::make_mut(&mut self.client_ip).remove(range);
            }
            RpzTrigger::ResponseIp(range) => {
                Arc::make_mut(&mut self.response_ip).remove(range);
            }
            RpzTrigger::Nsip(range) => {
                Arc::make_mut(&mut self.nsip).remove(range);
            }
            RpzTrigger::NsdnameExact(name) => {
                // NsdnameMatcher does not expose a direct remove_exact; re-implement
                // by rebuilding the inner exact map is acceptable given that zone
                // mutation is a low-frequency operation.
                // For now we perform a no-op with a tracing warning; a full
                // remove API can be added when NsdnameMatcher exposes it.
                let _ = name;
                tracing::warn!(
                    zone = %self.name,
                    "NsdnameExact remove not yet supported; entry will persist until next zone reload"
                );
            }
            RpzTrigger::NsdnameSuffix(suffix) => {
                let _ = suffix;
                tracing::warn!(
                    zone = %self.name,
                    "NsdnameSuffix remove not yet supported; entry will persist until next zone reload"
                );
            }
        }
    }

    /// Evaluates the Client-IP trigger (RPZ-015, RPZ-027 highest precedence).
    ///
    /// Returns the matching action if `client_ip` falls within a stored CIDR range.
    #[must_use]
    pub fn check_client_ip(&self, client_ip: IpAddr) -> Option<RpzAction> {
        self.client_ip.lookup(client_ip).cloned()
    }

    /// Evaluates QNAME triggers (RPZ-011, RPZ-027 second precedence).
    ///
    /// Exact match takes priority over wildcard within the trie.
    #[must_use]
    pub fn check_qname(&self, qname: &Name) -> Option<RpzAction> {
        self.qname.lookup(qname).cloned()
    }

    /// Evaluates Response-IP triggers (RPZ-012).
    ///
    /// Returns the action for the most-specific CIDR that matches any address in `addrs`.
    #[must_use]
    pub fn check_response_ip(&self, addrs: &[IpAddr]) -> Option<RpzAction> {
        addrs.iter().find_map(|&ip| self.response_ip.lookup(ip).cloned())
    }

    /// Evaluates NSIP triggers (RPZ-013).
    ///
    /// Returns the action for the most-specific CIDR that matches any NS address in `ns_addrs`.
    #[must_use]
    pub fn check_nsip(&self, ns_addrs: &[IpAddr]) -> Option<RpzAction> {
        ns_addrs.iter().find_map(|&ip| self.nsip.lookup(ip).cloned())
    }

    /// Evaluates NSDNAME triggers (RPZ-014).
    ///
    /// Returns the action matching any NS name in `ns_names` (exact before suffix).
    #[must_use]
    pub fn check_nsdname(&self, ns_names: &[Name]) -> Option<RpzAction> {
        ns_names.iter().find_map(|n| self.nsdname.lookup(n).cloned())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use super::*;
    use crate::rpz::trigger::{CidrRange, RpzEntry, RpzTrigger};

    fn zone() -> PolicyZone {
        PolicyZone::new("rpz.test.".to_string(), 0)
    }

    #[test]
    fn insert_and_check_qname_exact() {
        let mut z = zone();
        let name = Name::from_str("blocked.example.com.").unwrap();
        z.insert(RpzEntry {
            trigger: RpzTrigger::QnameExact(name.clone()),
            action: RpzAction::Nxdomain,
            position: 0,
        });
        assert_eq!(z.check_qname(&name), Some(RpzAction::Nxdomain));
    }

    #[test]
    fn insert_and_check_client_ip() {
        let mut z = zone();
        let cidr = CidrRange { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), prefix_len: 8 };
        z.insert(RpzEntry {
            trigger: RpzTrigger::ClientIp(cidr.clone()),
            action: RpzAction::Drop,
            position: 0,
        });
        assert_eq!(
            z.check_client_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Some(RpzAction::Drop)
        );
        assert_eq!(z.check_client_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))), None);
    }

    #[test]
    fn client_ip_beats_qname_in_zone_evaluation() {
        // The engine handles precedence ordering; here we just confirm both lookups
        // return results independently, and that the trigger precedence values order
        // correctly.
        let client_trigger = RpzTrigger::ClientIp(CidrRange {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_len: 32,
        });
        let qname_trigger = RpzTrigger::QnameExact(Name::from_str("a.com.").unwrap());
        assert!(client_trigger.precedence() < qname_trigger.precedence());
    }

    #[test]
    fn remove_qname_exact() {
        let mut z = zone();
        let name = Name::from_str("remove.example.com.").unwrap();
        z.insert(RpzEntry {
            trigger: RpzTrigger::QnameExact(name.clone()),
            action: RpzAction::Drop,
            position: 0,
        });
        assert!(z.check_qname(&name).is_some());
        z.remove(&RpzTrigger::QnameExact(name.clone()));
        assert!(z.check_qname(&name).is_none());
    }
}
