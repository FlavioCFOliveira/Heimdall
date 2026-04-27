// SPDX-License-Identifier: MIT

//! Multi-zone RPZ evaluation engine (RPZ-019..020, RPZ-027, RPZ-032).
//!
//! The [`RpzEngine`] holds an ordered list of [`PolicyZone`]s and evaluates
//! them in priority order (ascending `evaluation_order`) against an [`RpzContext`].
//!
//! **First-match-wins**: the first zone that produces a match returns an
//! [`RpzDecision::Match`].  A `Passthru` match short-circuits further zone
//! evaluation and returns [`RpzDecision::NoMatch`] (RPZ-006).
//!
//! Within each zone, trigger types are evaluated in the precedence order defined
//! by RPZ-027:
//! 1. Client-IP
//! 2. QNAME (exact, then wildcard within the trie)
//! 3. Response-IP
//! 4. NSIP
//! 5. NSDNAME

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use heimdall_core::name::Name;
use heimdall_core::record::Rtype;

use crate::rpz::action::RpzAction;
use crate::rpz::trigger::{RpzEntry, RpzTrigger};
use crate::rpz::zone::PolicyZone;

// ── RpzContext ────────────────────────────────────────────────────────────────

/// Input context for a single RPZ evaluation pass.
pub struct RpzContext {
    /// Source IP address of the DNS client.
    pub client_ip: IpAddr,
    /// The queried domain name.
    pub qname: Name,
    /// The queried resource record type.
    pub qtype: Rtype,
    /// `true` if the query arrived over UDP.
    pub is_udp: bool,
    /// IP addresses present in the would-be upstream response (for Response-IP triggers).
    pub response_ips: Vec<IpAddr>,
    /// NS names encountered during iterative resolution (for NSDNAME triggers).
    pub ns_names: Vec<Name>,
    /// NS server IP addresses encountered during iterative resolution (for NSIP triggers).
    pub ns_ips: Vec<IpAddr>,
}

// ── RpzDecision ───────────────────────────────────────────────────────────────

/// The result of RPZ evaluation across all policy zones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpzDecision {
    /// No policy zone matched; the resolver continues normally.
    NoMatch,
    /// A policy zone matched.
    Match {
        /// FQDN of the matching policy zone.
        zone: String,
        /// The matched action to apply.
        action: RpzAction,
    },
}

// ── RpzEngine ─────────────────────────────────────────────────────────────────

/// Multi-zone RPZ evaluation engine (RPZ-019..020).
///
/// Zones are stored in an [`ArcSwap`] so that the zone list can be atomically
/// replaced at SIGHUP reload time without blocking in-flight queries (RPZ-031).
pub struct RpzEngine {
    /// Policy zones ordered by `evaluation_order` ascending (first checked = highest priority).
    zones: Arc<ArcSwap<Vec<Arc<PolicyZone>>>>,
}

impl RpzEngine {
    /// Creates a new `RpzEngine` from the given list of policy zones.
    ///
    /// Zones are sorted by `evaluation_order` ascending before storage.
    #[must_use]
    pub fn new(mut zones: Vec<PolicyZone>) -> Self {
        zones.sort_by_key(|z| z.evaluation_order);
        let arcs: Vec<Arc<PolicyZone>> = zones.into_iter().map(Arc::new).collect();
        Self { zones: Arc::new(ArcSwap::new(Arc::new(arcs))) }
    }

    /// Atomically replaces the entire zone list.
    ///
    /// The new list is sorted by `evaluation_order` before installation.
    /// In-flight `evaluate` calls using the old snapshot complete unaffected.
    pub fn reload(&self, mut zones: Vec<PolicyZone>) {
        zones.sort_by_key(|z| z.evaluation_order);
        let arcs: Vec<Arc<PolicyZone>> = zones.into_iter().map(Arc::new).collect();
        self.zones.store(Arc::new(arcs));
    }

    /// Atomically upserts one entry into the named zone.
    ///
    /// If the zone does not exist, the entry is silently discarded.
    /// The zone list is cloned and the matching zone updated; the new
    /// snapshot is installed atomically.
    pub fn upsert_entry(&self, zone_name: &str, entry: &RpzEntry) {
        let current = self.zones.load();
        let mut zones: Vec<Arc<PolicyZone>> = current.iter().cloned().collect();
        let found = zones.iter_mut().any(|z| {
            if z.name == zone_name {
                // Clone the PolicyZone, mutate it, replace the Arc.
                let mut owned = (**z).clone_shallow();
                owned.insert(entry.clone());
                *z = Arc::new(owned);
                true
            } else {
                false
            }
        });
        if !found {
            tracing::warn!(zone = zone_name, "upsert_entry: zone not found; entry discarded");
        }
        self.zones.store(Arc::new(zones));
    }

    /// Atomically removes an entry from the named zone.
    ///
    /// No-op if the zone is not found.
    pub fn remove_entry(&self, zone_name: &str, trigger: &RpzTrigger) {
        let current = self.zones.load();
        let mut zones: Vec<Arc<PolicyZone>> = current.iter().cloned().collect();
        let found = zones.iter_mut().any(|z| {
            if z.name == zone_name {
                let mut owned = (**z).clone_shallow();
                owned.remove(trigger);
                *z = Arc::new(owned);
                true
            } else {
                false
            }
        });
        if !found {
            tracing::warn!(zone = zone_name, "remove_entry: zone not found");
        }
        self.zones.store(Arc::new(zones));
    }

    /// Evaluates all policy zones against `ctx`, returning the first matching decision.
    ///
    /// Trigger evaluation order within each zone (RPZ-027):
    /// 1. Client-IP (highest priority)
    /// 2. QNAME
    /// 3. Response-IP
    /// 4. NSIP
    /// 5. NSDNAME
    ///
    /// A `Passthru` match short-circuits zone evaluation and returns [`RpzDecision::NoMatch`]
    /// (RPZ-006: the query is allowed through).
    ///
    /// Every match emits a structured audit event (RPZ-032).
    #[must_use]
    pub fn evaluate(&self, ctx: &RpzContext) -> RpzDecision {
        let zones = self.zones.load();

        for zone in zones.iter() {
            // ── Client-IP (precedence 0) ──────────────────────────────────────
            if let Some(action) = zone.check_client_ip(ctx.client_ip) {
                return decide(zone, action, "client-ip", &ctx.client_ip.to_string());
            }

            // ── QNAME (precedence 1/2, internal precedence handled by trie) ──
            if let Some(action) = zone.check_qname(&ctx.qname) {
                return decide(zone, action, "qname", &ctx.qname.to_string());
            }

            // ── Response-IP (precedence 3) ────────────────────────────────────
            if !ctx.response_ips.is_empty() && let Some(action) = zone.check_response_ip(&ctx.response_ips) {
                let val = ctx.response_ips.first().map(ToString::to_string).unwrap_or_default();
                return decide(zone, action, "response-ip", &val);
            }

            // ── NSIP (precedence 4) ───────────────────────────────────────────
            if !ctx.ns_ips.is_empty() && let Some(action) = zone.check_nsip(&ctx.ns_ips) {
                let val = ctx.ns_ips.first().map(ToString::to_string).unwrap_or_default();
                return decide(zone, action, "nsip", &val);
            }

            // ── NSDNAME (precedence 5) ────────────────────────────────────────
            if !ctx.ns_names.is_empty() && let Some(action) = zone.check_nsdname(&ctx.ns_names) {
                let val = ctx.ns_names.first().map(ToString::to_string).unwrap_or_default();
                return decide(zone, action, "nsdname", &val);
            }
        }

        RpzDecision::NoMatch
    }

}

/// Translates a raw match into an [`RpzDecision`], emitting an audit event,
/// and short-circuiting `Passthru` into `NoMatch` (RPZ-006).
fn decide(zone: &PolicyZone, action: RpzAction, trigger_type: &str, trigger_value: &str) -> RpzDecision {
    // Structured audit log (RPZ-032).
    tracing::info!(
        event = "rpz_match",
        zone = %zone.name,
        action = ?action,
        trigger_type = trigger_type,
        trigger_value = trigger_value,
    );

    if action == RpzAction::Passthru {
        // PASSTHRU short-circuits: allow through, stop zone evaluation.
        RpzDecision::NoMatch
    } else {
        RpzDecision::Match { zone: zone.name.clone(), action }
    }
}

// ── PolicyZone shallow clone helper ──────────────────────────────────────────

impl PolicyZone {
    /// Creates a shallow clone of this zone, sharing all trie `Arc`s.
    ///
    /// `Arc::make_mut` in `insert`/`remove` will then copy-on-write only the
    /// specific trie that needs changing.
    pub(crate) fn clone_shallow(&self) -> Self {
        Self {
            name: self.name.clone(),
            evaluation_order: self.evaluation_order,
            policy_ttl: self.policy_ttl,
            qname: Arc::clone(&self.qname),
            client_ip: Arc::clone(&self.client_ip),
            response_ip: Arc::clone(&self.response_ip),
            nsip: Arc::clone(&self.nsip),
            nsdname: Arc::clone(&self.nsdname),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use super::*;
    use crate::rpz::trigger::{CidrRange, RpzEntry, RpzTrigger};
    use heimdall_core::record::Rtype;

    fn ctx(qname: &str) -> RpzContext {
        RpzContext {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            qname: Name::from_str(qname).unwrap(),
            qtype: Rtype::A,
            is_udp: true,
            response_ips: vec![],
            ns_names: vec![],
            ns_ips: vec![],
        }
    }

    fn zone_with_qname(name_str: &str, order: u8, action: RpzAction) -> PolicyZone {
        let mut z = PolicyZone::new(format!("zone{order}.rpz."), order);
        z.insert(RpzEntry {
            trigger: RpzTrigger::QnameExact(Name::from_str(name_str).unwrap()),
            action,
            position: 0,
        });
        z
    }

    #[test]
    fn engine_first_match_wins() {
        let z0 = zone_with_qname("bad.example.com.", 0, RpzAction::Drop);
        let z1 = zone_with_qname("bad.example.com.", 1, RpzAction::Nxdomain);
        let engine = RpzEngine::new(vec![z0, z1]);
        let decision = engine.evaluate(&ctx("bad.example.com."));
        assert_eq!(
            decision,
            RpzDecision::Match { zone: "zone0.rpz.".to_string(), action: RpzAction::Drop }
        );
    }

    #[test]
    fn engine_passthru_stops_evaluation() {
        let z0 = zone_with_qname("allowed.example.com.", 0, RpzAction::Passthru);
        let z1 = zone_with_qname("allowed.example.com.", 1, RpzAction::Drop);
        let engine = RpzEngine::new(vec![z0, z1]);
        // Passthru short-circuits to NoMatch.
        assert_eq!(engine.evaluate(&ctx("allowed.example.com.")), RpzDecision::NoMatch);
    }

    #[test]
    fn engine_no_match_returns_no_match() {
        let z = zone_with_qname("blocked.example.com.", 0, RpzAction::Nxdomain);
        let engine = RpzEngine::new(vec![z]);
        assert_eq!(engine.evaluate(&ctx("benign.org.")), RpzDecision::NoMatch);
    }

    #[test]
    fn engine_upsert_entry_visible_immediately() {
        let engine = RpzEngine::new(vec![PolicyZone::new("rpz.test.".to_string(), 0)]);
        // Before upsert: no match.
        assert_eq!(engine.evaluate(&ctx("new.example.com.")), RpzDecision::NoMatch);

        engine.upsert_entry(
            "rpz.test.",
            &RpzEntry {
                trigger: RpzTrigger::QnameExact(Name::from_str("new.example.com.").unwrap()),
                action: RpzAction::Nxdomain,
                position: 0,
            },
        );

        // After upsert: match.
        assert_eq!(
            engine.evaluate(&ctx("new.example.com.")),
            RpzDecision::Match {
                zone: "rpz.test.".to_string(),
                action: RpzAction::Nxdomain,
            }
        );
    }

    #[test]
    fn engine_remove_entry_invisible_immediately() {
        let trigger = RpzTrigger::QnameExact(Name::from_str("remove.example.com.").unwrap());
        let mut z = PolicyZone::new("rpz.test.".to_string(), 0);
        z.insert(RpzEntry { trigger: trigger.clone(), action: RpzAction::Drop, position: 0 });
        let engine = RpzEngine::new(vec![z]);

        // Before remove: match.
        assert!(matches!(engine.evaluate(&ctx("remove.example.com.")), RpzDecision::Match { .. }));

        engine.remove_entry("rpz.test.", &trigger);

        // After remove: no match.
        assert_eq!(engine.evaluate(&ctx("remove.example.com.")), RpzDecision::NoMatch);
    }

    #[test]
    fn engine_client_ip_beats_qname() {
        let mut z = PolicyZone::new("rpz.test.".to_string(), 0);
        // Insert both a client-IP trigger and a QNAME trigger for the same context.
        z.insert(RpzEntry {
            trigger: RpzTrigger::ClientIp(CidrRange {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
            }),
            action: RpzAction::Drop,
            position: 0,
        });
        z.insert(RpzEntry {
            trigger: RpzTrigger::QnameExact(Name::from_str("example.com.").unwrap()),
            action: RpzAction::Nxdomain,
            position: 1,
        });
        let engine = RpzEngine::new(vec![z]);
        // Client-IP fires first (precedence 0 vs 1).
        assert_eq!(
            engine.evaluate(&ctx("example.com.")),
            RpzDecision::Match { zone: "rpz.test.".to_string(), action: RpzAction::Drop }
        );
    }
}
