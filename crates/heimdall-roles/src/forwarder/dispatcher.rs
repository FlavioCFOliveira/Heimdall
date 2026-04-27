// SPDX-License-Identifier: MIT

//! Forward-rule dispatcher (ROLE-010).
//!
//! [`ForwardDispatcher`] holds the live set of [`ForwardRule`]s behind an
//! [`ArcSwap`] for atomic, lock-free hot-reload without tearing down any
//! in-flight queries.  Matching follows the precedence order specified in
//! `FWD spec`:
//!
//! 1. **Exact** match (`zone == qname`).
//! 2. **Suffix** match (`qname == zone || qname.ends_with(".{zone}")`).
//! 3. **Wildcard** match (`zone` begins with `"*."`, remainder used for suffix
//!    matching; the zone apex itself does not match).
//!
//! Within each mode, the longest-zone-pattern wins (most specific).  Ties are
//! broken by rule-index order (earlier declared = higher priority).

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::forwarder::upstream::{ForwardRule, MatchMode};

// ── ForwardDispatcher ─────────────────────────────────────────────────────────

/// Matches incoming query names against the configured set of forward rules.
///
/// The rule set is held inside an [`ArcSwap`], which allows [`reload`] to
/// replace the entire set atomically without locking reader threads.
///
/// [`reload`]: ForwardDispatcher::reload
pub struct ForwardDispatcher {
    rules: Arc<ArcSwap<Vec<ForwardRule>>>,
}

impl ForwardDispatcher {
    /// Creates a new [`ForwardDispatcher`] with the given initial rule set.
    #[must_use]
    pub fn new(rules: Vec<ForwardRule>) -> Self {
        Self {
            rules: Arc::new(ArcSwap::from_pointee(rules)),
        }
    }

    /// Atomically replaces the rule set.
    ///
    /// In-flight calls to [`match_query`] that started before this call
    /// complete against the old rule set.  Any call that starts after this
    /// call completes uses the new rule set.
    ///
    /// [`match_query`]: ForwardDispatcher::match_query
    pub fn reload(&self, rules: Vec<ForwardRule>) {
        self.rules.store(Arc::new(rules));
    }

    /// Returns the best-matching [`ForwardRule`] for `qname`, or `None` if no
    /// rule matches.
    ///
    /// Matching precedence (per FWD spec):
    ///
    /// 1. Exact match (`zone == qname`).
    /// 2. Suffix match (`qname == zone || qname.ends_with(".{zone}")`).
    /// 3. Wildcard match (`zone` starts with `"*."`, suffix-match on remainder).
    ///
    /// Within each mode, the longest zone string wins (most specific).  Ties
    /// are broken by rule-index order (first declared = higher priority).
    #[must_use]
    pub fn match_query(&self, qname: &str) -> Option<ForwardRule> {
        let guard = self.rules.load();
        let rules: &[ForwardRule] = &guard;

        // Each pass selects the best candidate within one mode.
        // We check Exact first, then Suffix, then Wildcard, returning as soon
        // as a mode produces a match.

        // Pass 1 — Exact.
        if let Some(rule) = best_match(rules, qname, MatchMode::Exact) {
            return Some(rule.clone());
        }

        // Pass 2 — Suffix.
        if let Some(rule) = best_match(rules, qname, MatchMode::Suffix) {
            return Some(rule.clone());
        }

        // Pass 3 — Wildcard.
        best_match(rules, qname, MatchMode::Wildcard).cloned()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the best-matching rule for `qname` within a single `mode`.
///
/// "Best" means longest `zone` string (most specific).  Ties use rule-index
/// order (stable: `rules` preserves declaration order).
fn best_match<'a>(
    rules: &'a [ForwardRule],
    qname: &str,
    mode: MatchMode,
) -> Option<&'a ForwardRule> {
    rules
        .iter()
        .filter(|r| r.match_mode == mode && matches_rule(r, qname))
        .max_by_key(|r| r.zone.len())
}

/// Returns `true` if `qname` matches `rule` according to `rule.match_mode`.
fn matches_rule(rule: &ForwardRule, qname: &str) -> bool {
    match rule.match_mode {
        MatchMode::Exact => qname == rule.zone,
        MatchMode::Suffix => suffix_match(qname, &rule.zone),
        MatchMode::Wildcard => {
            // Strip the leading "*."; apply suffix match on the remainder.
            let Some(remainder) = rule.zone.strip_prefix("*.") else {
                return false;
            };
            // Wildcard does NOT match the apex itself (e.g. "*.example.com."
            // matches "sub.example.com." but not "example.com.").
            if qname == remainder {
                return false;
            }
            suffix_match(qname, remainder)
        }
    }
}

/// Returns `true` if `qname` equals `zone` or ends with `".{zone}"`.
///
/// This is the canonical suffix-match algorithm: RFC-compliant case-insensitive
/// comparison is left to the caller — names are expected to be in a consistent
/// case by the time they reach the dispatcher.
fn suffix_match(qname: &str, zone: &str) -> bool {
    qname == zone || qname.ends_with(&format!(".{zone}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::forwarder::upstream::{MatchMode, UpstreamConfig, UpstreamTransport};

    fn udp_upstream() -> UpstreamConfig {
        UpstreamConfig {
            host: "8.8.8.8".to_string(),
            port: 53,
            transport: UpstreamTransport::UdpTcp,
            sni: None,
            tls_verify: true,
        }
    }

    fn rule(zone: &str, mode: MatchMode) -> ForwardRule {
        ForwardRule {
            zone: zone.to_string(),
            match_mode: mode,
            upstreams: vec![udp_upstream()],
            fallback_recursive: false,
        }
    }

    #[test]
    fn exact_match_hits() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Exact)]);
        assert!(d.match_query("example.com.").is_some());
    }

    #[test]
    fn exact_match_rejects_subdomain() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Exact)]);
        assert!(d.match_query("sub.example.com.").is_none());
    }

    #[test]
    fn suffix_match_apex_and_sub() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);
        assert!(d.match_query("example.com.").is_some());
        assert!(d.match_query("sub.example.com.").is_some());
    }

    #[test]
    fn suffix_match_rejects_non_suffix() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);
        assert!(d.match_query("notexample.com.").is_none());
    }

    #[test]
    fn wildcard_match_sub_but_not_apex() {
        let d = ForwardDispatcher::new(vec![rule("*.example.com.", MatchMode::Wildcard)]);
        assert!(d.match_query("sub.example.com.").is_some());
        assert!(d.match_query("example.com.").is_none());
    }

    #[test]
    fn longest_zone_wins() {
        let d = ForwardDispatcher::new(vec![
            rule("com.", MatchMode::Suffix),
            rule("example.com.", MatchMode::Suffix),
        ]);
        let matched = d.match_query("a.example.com.").expect("must match");
        assert_eq!(matched.zone, "example.com.", "longer zone must win");
    }

    #[test]
    fn no_match_returns_none() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);
        assert!(d.match_query("other.org.").is_none());
    }

    #[test]
    fn atomic_reload_takes_effect() {
        let d = ForwardDispatcher::new(vec![rule("example.com.", MatchMode::Suffix)]);
        assert!(d.match_query("other.org.").is_none());
        d.reload(vec![rule("other.org.", MatchMode::Suffix)]);
        assert!(d.match_query("other.org.").is_some());
        assert!(d.match_query("example.com.").is_none());
    }
}
