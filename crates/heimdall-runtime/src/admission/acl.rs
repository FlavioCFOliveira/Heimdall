// SPDX-License-Identifier: MIT

//! Multi-axis ACL engine (THREAT-033 through THREAT-047).
//!
//! Rules are evaluated in declaration order; the **first matching rule wins**.
//! If no rule matches, per-operation defaults apply:
//!
//! - AXFR / IXFR: **deny** (THREAT-042).
//! - Authoritative-role standard queries: **allow** (THREAT-043).
//! - Recursive / Forwarder standard queries: **deny** (THREAT-044).
//!
//! The compiled ACL is stored behind [`AclHandle`] — an `Arc<ArcSwap<CompiledAcl>>`
//! — so it can be hot-reloaded lock-free while in-flight queries still hold a
//! snapshot of the previous version (THREAT-047).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use super::cidr::CidrSet;

// ── Transport ─────────────────────────────────────────────────────────────────

/// The transport on which a request arrived (THREAT-038).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Classic DNS over UDP on port 53.
    Udp53,
    /// Classic DNS over TCP on port 53.
    Tcp53,
    /// DNS-over-TLS.
    DoT,
    /// DNS-over-HTTPS over HTTP/2.
    DoH2,
    /// DNS-over-HTTPS over HTTP/3.
    DoH3,
    /// DNS-over-QUIC.
    DoQ,
}

impl Transport {
    /// Bit index used in the compact bitset representation.
    #[inline]
    fn bit(self) -> u8 {
        match self {
            Transport::Udp53 => 0,
            Transport::Tcp53 => 1,
            Transport::DoT => 2,
            Transport::DoH2 => 3,
            Transport::DoH3 => 4,
            Transport::DoQ => 5,
        }
    }
}

// ── Role ──────────────────────────────────────────────────────────────────────

/// The server role that would serve the query (THREAT-039).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Authoritative name server.
    Authoritative,
    /// Recursive resolver.
    Recursive,
    /// Forwarder.
    Forwarder,
}

impl Role {
    #[inline]
    fn bit(self) -> u8 {
        match self {
            Role::Authoritative => 0,
            Role::Recursive => 1,
            Role::Forwarder => 2,
        }
    }
}

// ── Operation ─────────────────────────────────────────────────────────────────

/// The DNS operation type (THREAT-040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Standard DNS query.
    Query,
    /// Authoritative zone transfer (full).
    Axfr,
    /// Authoritative zone transfer (incremental).
    Ixfr,
    /// Zone change notification.
    Notify,
}

impl Operation {
    #[inline]
    fn bit(self) -> u8 {
        match self {
            Operation::Query => 0,
            Operation::Axfr => 1,
            Operation::Ixfr => 2,
            Operation::Notify => 3,
        }
    }
}

// ── EnumSet ───────────────────────────────────────────────────────────────────

/// A compact bitset for small enums.
///
/// No external `enumset` crate is used; the set is backed by a `u8` and each
/// variant contributes one bit via its `bit()` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumSet<T> {
    bits: u8,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Copy> Default for EnumSet<T> {
    fn default() -> Self {
        Self {
            bits: 0,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: Copy> EnumSet<T> {
    /// Create an empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

impl EnumSet<Transport> {
    /// Return `true` if `t` is in the set.
    #[must_use]
    pub fn contains(&self, t: Transport) -> bool {
        (self.bits >> t.bit()) & 1 == 1
    }

    /// Insert `t` into the set.
    pub fn insert(&mut self, t: Transport) {
        self.bits |= 1 << t.bit();
    }

    /// Build a set from a slice.
    #[must_use]
    pub fn from_slice(items: &[Transport]) -> Self {
        let mut s = Self::empty();
        for &t in items {
            s.insert(t);
        }
        s
    }
}

impl EnumSet<Role> {
    /// Return `true` if `r` is in the set.
    #[must_use]
    pub fn contains(&self, r: Role) -> bool {
        (self.bits >> r.bit()) & 1 == 1
    }

    /// Insert `r` into the set.
    pub fn insert(&mut self, r: Role) {
        self.bits |= 1 << r.bit();
    }

    /// Build a set from a slice.
    #[must_use]
    pub fn from_slice(items: &[Role]) -> Self {
        let mut s = Self::empty();
        for &r in items {
            s.insert(r);
        }
        s
    }
}

impl EnumSet<Operation> {
    /// Return `true` if `op` is in the set.
    #[must_use]
    pub fn contains(&self, op: Operation) -> bool {
        (self.bits >> op.bit()) & 1 == 1
    }

    /// Insert `op` into the set.
    pub fn insert(&mut self, op: Operation) {
        self.bits |= 1 << op.bit();
    }

    /// Build a set from a slice.
    #[must_use]
    pub fn from_slice(items: &[Operation]) -> Self {
        let mut s = Self::empty();
        for &op in items {
            s.insert(op);
        }
        s
    }
}

// ── QnamePattern ──────────────────────────────────────────────────────────────

/// QNAME matching pattern (THREAT-041).
///
/// All patterns operate on **lowercase wire-encoded** fully-qualified domain names.
#[derive(Debug, Clone)]
pub enum QnamePattern {
    /// Matches the exact wire-encoded name.
    Exact(Vec<u8>),
    /// Matches the name itself and every sub-name beneath it.
    Suffix(Vec<u8>),
    /// Single-label wildcard: matches exactly one label prepended to the suffix.
    Wildcard(Vec<u8>),
}

impl QnamePattern {
    fn matches(&self, qname: &[u8]) -> bool {
        match self {
            QnamePattern::Exact(pattern) => qname == pattern.as_slice(),
            QnamePattern::Suffix(suffix) => {
                // `qname` must equal `suffix` OR end with `.<suffix>` in wire form.
                // In wire encoding, a label sequence for "sub.example.com." is
                // `\x03sub\x07example\x03com\x00`.  Suffix matching: `qname` ends
                // with `suffix`, and the byte immediately before the suffix starts
                // is the first byte of a label-length field (i.e. `qname` aligns on
                // a label boundary at the suffix start).
                if qname == suffix.as_slice() {
                    return true;
                }
                if qname.len() > suffix.len() && qname.ends_with(suffix.as_slice()) {
                    // Verify label-boundary alignment by walking the wire labels.
                    let target_offset = qname.len() - suffix.len();
                    let mut off = 0usize;
                    while off < qname.len() {
                        if off == target_offset {
                            return true;
                        }
                        let len = qname[off] as usize;
                        if len == 0 {
                            break;
                        }
                        off += 1 + len;
                    }
                    false
                } else {
                    false
                }
            }
            QnamePattern::Wildcard(suffix) => {
                // Matches exactly one additional label prepended to `suffix`.
                if qname.is_empty() || suffix.is_empty() {
                    return false;
                }
                let label_len = qname[0] as usize;
                if label_len == 0 {
                    return false;
                }
                let after_label = 1 + label_len;
                if after_label >= qname.len() {
                    return false;
                }
                &qname[after_label..] == suffix.as_slice()
            }
        }
    }
}

// ── Matcher ───────────────────────────────────────────────────────────────────

/// A single matching axis for an ACL rule (THREAT-034 through THREAT-041,
/// THREAT-111).
#[derive(Debug)]
pub enum Matcher {
    /// Match on source IP address / CIDR (THREAT-035).
    SourceCidr(CidrSet),
    /// Match on mTLS client-certificate identity (THREAT-036).
    MtlsIdentity(HashSet<String>),
    /// Match on TSIG key identity (THREAT-037).
    TsigIdentity(HashSet<String>),
    /// Match on transport (THREAT-038).
    Transport(EnumSet<Transport>),
    /// Match on serving role (THREAT-039).
    Role(EnumSet<Role>),
    /// Match on operation type (THREAT-040).
    Operation(EnumSet<Operation>),
    /// Match on QNAME pattern (THREAT-041).
    QnamePattern(QnamePattern),
    /// Invert the result of the inner matcher (THREAT-111).
    ///
    /// A rule with `Not(SourceCidr(...))` matches every request whose source
    /// is NOT in the CIDR set.  Negation applies to the individual matcher;
    /// it does not invert the rule's action.
    Not(Box<Matcher>),
}

impl Matcher {
    fn evaluate(&self, ctx: &RequestCtx) -> bool {
        match self {
            Matcher::SourceCidr(set) => set.contains(ctx.source_ip),
            Matcher::MtlsIdentity(ids) => ctx
                .mtls_identity
                .as_deref()
                .is_some_and(|id| ids.contains(id)),
            Matcher::TsigIdentity(ids) => ctx
                .tsig_identity
                .as_deref()
                .is_some_and(|id| ids.contains(id)),
            Matcher::Transport(set) => set.contains(ctx.transport),
            Matcher::Role(set) => set.contains(ctx.role),
            Matcher::Operation(set) => set.contains(ctx.operation),
            Matcher::QnamePattern(pat) => pat.matches(&ctx.qname),
            Matcher::Not(inner) => !inner.evaluate(ctx),
        }
    }
}

// ── AclAction ─────────────────────────────────────────────────────────────────

/// The terminal action of an ACL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    /// Permit the traffic.
    Allow,
    /// Reject the traffic.
    Deny,
}

// ── AclRule ───────────────────────────────────────────────────────────────────

/// A single ACL rule: all matchers must match (logical AND) for the rule to fire.
///
/// An empty `matchers` list matches every request (unconditional rule).
#[derive(Debug)]
pub struct AclRule {
    /// Conjunction of matchers; all must evaluate `true` for the rule to match.
    pub matchers: Vec<Matcher>,
    /// Action applied when the rule matches.
    pub action: AclAction,
}

impl AclRule {
    fn evaluate(&self, ctx: &RequestCtx) -> bool {
        self.matchers.iter().all(|m| m.evaluate(ctx))
    }
}

// ── RequestCtx ────────────────────────────────────────────────────────────────

/// Per-request context supplied to the ACL engine.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// Source IP address of the request.
    pub source_ip: IpAddr,
    /// mTLS client-certificate identity, if the transport is encrypted and
    /// mutual TLS was negotiated.
    pub mtls_identity: Option<String>,
    /// TSIG key identity, if the request carries a valid TSIG signature.
    pub tsig_identity: Option<String>,
    /// Transport on which the request arrived.
    pub transport: Transport,
    /// Role that would serve this request.
    pub role: Role,
    /// Operation type of the request.
    pub operation: Operation,
    /// QNAME in lowercase wire-encoded form.
    pub qname: Vec<u8>,
    /// Whether the request carries a validated DNS Cookie (THREAT-069).
    pub has_valid_cookie: bool,
}

// ── CompiledAcl ───────────────────────────────────────────────────────────────

/// An immutable, compiled ACL snapshot ready for hot-path evaluation.
///
/// The ACL is stored behind [`AclHandle`] so it can be atomically replaced
/// without locking (THREAT-047).
pub struct CompiledAcl {
    rules: Vec<AclRule>,
    /// Default action for AXFR and IXFR when no rule matches (THREAT-042).
    default_xfr: AclAction,
    /// Default action for authoritative-role standard queries (THREAT-043).
    default_auth: AclAction,
    /// Default action for recursive/forwarder queries (THREAT-044).
    default_recur: AclAction,
}

impl Default for CompiledAcl {
    /// Conservative defaults: AXFR/IXFR deny, authoritative allow, recursive deny.
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_xfr: AclAction::Deny,
            default_auth: AclAction::Allow,
            default_recur: AclAction::Deny,
        }
    }
}

impl CompiledAcl {
    /// Build a new `CompiledAcl` with the given rules and default actions.
    ///
    /// The default actions are:
    /// - AXFR / IXFR: `AclAction::Deny`
    /// - Authoritative standard queries: `AclAction::Allow`
    /// - Recursive / Forwarder queries: `AclAction::Deny`
    #[must_use]
    pub fn new(rules: Vec<AclRule>) -> Self {
        Self {
            rules,
            ..Self::default()
        }
    }

    /// Evaluate the ACL for the given request context.
    ///
    /// Rules are evaluated in order; the first matching rule's action is
    /// returned.  If no rule matches, the per-operation default applies.
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestCtx) -> AclAction {
        for rule in &self.rules {
            if rule.evaluate(ctx) {
                return rule.action;
            }
        }
        // No rule matched — apply defaults.
        match ctx.operation {
            Operation::Axfr | Operation::Ixfr => self.default_xfr,
            Operation::Notify | Operation::Query => match ctx.role {
                Role::Authoritative => self.default_auth,
                Role::Recursive | Role::Forwarder => self.default_recur,
            },
        }
    }
}

// ── AclHandle ─────────────────────────────────────────────────────────────────

/// A cloneable, lock-free handle to the current compiled ACL.
///
/// In-flight evaluations retain their snapshot via `ArcSwap::load()`; a hot
/// reload replaces the pointer atomically via `.store(new_acl)`.
pub type AclHandle = Arc<ArcSwap<CompiledAcl>>;

/// Create a new [`AclHandle`] wrapping the given compiled ACL.
#[must_use]
pub fn new_acl_handle(acl: CompiledAcl) -> AclHandle {
    Arc::new(ArcSwap::from_pointee(acl))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::admission::cidr::CidrSet;

    fn ctx(op: Operation, role: Role) -> RequestCtx {
        RequestCtx {
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            mtls_identity: None,
            tsig_identity: None,
            transport: Transport::Udp53,
            role,
            operation: op,
            qname: b"\x07example\x03com\x00".to_vec(),
            has_valid_cookie: false,
        }
    }

    #[test]
    fn default_deny_axfr() {
        let acl = CompiledAcl::default();
        let c = ctx(Operation::Axfr, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn default_deny_ixfr() {
        let acl = CompiledAcl::default();
        let c = ctx(Operation::Ixfr, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn default_allow_authoritative_query() {
        let acl = CompiledAcl::default();
        let c = ctx(Operation::Query, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn default_deny_recursive_query() {
        let acl = CompiledAcl::default();
        let c = ctx(Operation::Query, Role::Recursive);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn default_deny_forwarder_query() {
        let acl = CompiledAcl::default();
        let c = ctx(Operation::Query, Role::Forwarder);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn explicit_rule_overrides_default() {
        // Allow AXFR from 10.0.0.0/8.
        let mut cidr = CidrSet::default();
        cidr.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8);
        let rules = vec![AclRule {
            matchers: vec![
                Matcher::SourceCidr(cidr),
                Matcher::Operation(EnumSet::<Operation>::from_slice(&[Operation::Axfr])),
            ],
            action: AclAction::Allow,
        }];
        let acl = CompiledAcl::new(rules);
        let c = ctx(Operation::Axfr, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn first_rule_wins() {
        let rules = vec![
            AclRule {
                matchers: vec![],
                action: AclAction::Deny,
            },
            AclRule {
                matchers: vec![],
                action: AclAction::Allow,
            },
        ];
        let acl = CompiledAcl::new(rules);
        let c = ctx(Operation::Query, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn match_on_transport() {
        let rules = vec![AclRule {
            matchers: vec![Matcher::Transport(EnumSet::<Transport>::from_slice(&[
                Transport::DoT,
            ]))],
            action: AclAction::Deny,
        }];
        let acl = CompiledAcl::new(rules);
        let mut c = ctx(Operation::Query, Role::Authoritative);
        c.transport = Transport::DoT;
        assert_eq!(acl.evaluate(&c), AclAction::Deny);

        c.transport = Transport::Udp53;
        // Falls through to default-allow authoritative.
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn match_on_tsig_identity() {
        let ids: std::collections::HashSet<String> = ["key1".to_string()].into_iter().collect();
        let rules = vec![AclRule {
            matchers: vec![Matcher::TsigIdentity(ids)],
            action: AclAction::Allow,
        }];
        let acl = CompiledAcl::new(rules);
        let mut c = ctx(Operation::Axfr, Role::Authoritative);
        c.tsig_identity = Some("key1".to_string());
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn match_on_mtls_identity() {
        let ids: std::collections::HashSet<String> =
            ["CN=trusted".to_string()].into_iter().collect();
        let rules = vec![AclRule {
            matchers: vec![Matcher::MtlsIdentity(ids)],
            action: AclAction::Allow,
        }];
        let acl = CompiledAcl::new(rules);
        let mut c = ctx(Operation::Query, Role::Recursive);
        c.mtls_identity = Some("CN=trusted".to_string());
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn match_on_qname_exact() {
        let rules = vec![AclRule {
            matchers: vec![Matcher::QnamePattern(QnamePattern::Exact(
                b"\x07example\x03com\x00".to_vec(),
            ))],
            action: AclAction::Deny,
        }];
        let acl = CompiledAcl::new(rules);
        let c = ctx(Operation::Query, Role::Authoritative);
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
    }

    #[test]
    fn match_on_qname_suffix() {
        let rules = vec![AclRule {
            matchers: vec![Matcher::QnamePattern(QnamePattern::Suffix(
                b"\x07example\x03com\x00".to_vec(),
            ))],
            action: AclAction::Deny,
        }];
        let acl = CompiledAcl::new(rules);
        // Exact match.
        let mut c = ctx(Operation::Query, Role::Authoritative);
        c.qname = b"\x07example\x03com\x00".to_vec();
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
        // Sub-domain.
        c.qname = b"\x03www\x07example\x03com\x00".to_vec();
        assert_eq!(acl.evaluate(&c), AclAction::Deny);
        // Unrelated domain — falls through to default allow.
        c.qname = b"\x04test\x03net\x00".to_vec();
        assert_eq!(acl.evaluate(&c), AclAction::Allow);
    }

    #[test]
    fn acl_handle_hot_reload() {
        let initial = CompiledAcl::default();
        let handle = new_acl_handle(initial);
        let c = ctx(Operation::Query, Role::Recursive);

        let snap = handle.load();
        assert_eq!(snap.evaluate(&c), AclAction::Deny);

        // Hot-reload: allow recursive.
        let allow_rule = AclRule {
            matchers: vec![Matcher::Role(EnumSet::<Role>::from_slice(&[
                Role::Recursive,
            ]))],
            action: AclAction::Allow,
        };
        let new_acl = Arc::new(CompiledAcl::new(vec![allow_rule]));
        handle.store(new_acl);

        let snap2 = handle.load();
        assert_eq!(snap2.evaluate(&c), AclAction::Allow);
    }
}
