// SPDX-License-Identifier: MIT

//! Sub-linear matching data structures for RPZ (RPZ-024, RPZ-028).
//!
//! # Structures
//!
//! - [`QnameTrie`] — label-indexed map for QNAME trigger matching.
//! - [`CidrTrie`] — prefix-sorted list for IP CIDR matching.
//! - [`NsdnameMatcher`] — combined exact/suffix matcher for NSDNAME triggers.

use std::{collections::HashMap, net::IpAddr};

use heimdall_core::name::Name;

use crate::rpz::{action::RpzAction, trigger::CidrRange};

// ── Name → reversed label key conversion ─────────────────────────────────────

/// Converts a [`Name`] to a reversed sequence of label byte-vectors (root first).
///
/// For `example.com.` the result is `[b"com", b"example"]`.
/// The root name (no labels) produces an empty vector.
fn name_to_reversed_labels(name: &Name) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = name
        .iter_labels()
        .map(|l| l.iter().map(u8::to_ascii_lowercase).collect())
        .collect();
    labels.reverse();
    labels
}

// ── QnameTrie ─────────────────────────────────────────────────────────────────

/// Label-indexed map for QNAME trigger matching (RPZ-028).
///
/// Keys are stored as reversed label sequences (root→leaf order) to enable
/// efficient suffix-prefix lookups.
///
/// - Exact-match entries use the full reversed label sequence.
/// - Wildcard entries (`*.suffix.`) use the reversed suffix (without the
///   wildcard label) as the key.
///
/// During lookup, exact match takes priority over wildcard (RPZ-027), and
/// longer wildcard suffixes take priority over shorter ones (longest-match wins).
#[derive(Debug, Default, Clone)]
pub struct QnameTrie {
    exact: HashMap<Vec<Vec<u8>>, RpzAction>,
    wildcard: HashMap<Vec<Vec<u8>>, RpzAction>,
}

impl QnameTrie {
    /// Creates a new, empty `QnameTrie`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an exact QNAME trigger.
    pub fn insert_exact(&mut self, name: &Name, action: RpzAction) {
        let key = name_to_reversed_labels(name);
        self.exact.insert(key, action);
    }

    /// Inserts a wildcard QNAME trigger.
    ///
    /// `suffix` is the domain suffix without the leading wildcard label.
    /// For example, for `*.evil.com.`, pass `evil.com.`.
    pub fn insert_wildcard(&mut self, suffix: &Name, action: RpzAction) {
        let key = name_to_reversed_labels(suffix);
        self.wildcard.insert(key, action);
    }

    /// Looks up `qname`, returning the best matching action.
    ///
    /// Priority (RPZ-027):
    /// 1. Exact match.
    /// 2. Longest matching wildcard suffix.
    ///
    /// Returns `None` if no match exists.
    #[must_use]
    pub fn lookup(&self, qname: &Name) -> Option<&RpzAction> {
        let labels = name_to_reversed_labels(qname);

        // 1. Exact match.
        if let Some(action) = self.exact.get(&labels) {
            return Some(action);
        }

        // 2. Longest-matching wildcard suffix.  A wildcard `*.suffix.` matches
        //    any STRICT subdomain of `suffix.`, i.e. the qname must have at
        //    least one label beyond the suffix.
        //
        //    We check suffixes in decreasing specificity order: a qname
        //    `a.b.example.com.` has reversed labels `["com","example","b","a"]`.
        //    We check the suffix keys `["com","example","b"]`, `["com","example"]`,
        //    `["com"]`, `[]` and return the first (most-specific) hit.
        let label_count = labels.len();
        if label_count >= 2 {
            // Iterate from the most specific possible suffix (label_count - 1 labels)
            // down to 0 labels (the root wildcard, if any).
            for suffix_len in (0..label_count).rev() {
                let suffix_key = &labels[..suffix_len];
                if let Some(action) = self.wildcard.get(suffix_key) {
                    return Some(action);
                }
            }
        }

        None
    }

    /// Removes an exact QNAME entry.
    pub fn remove_exact(&mut self, name: &Name) {
        let key = name_to_reversed_labels(name);
        self.exact.remove(&key);
    }

    /// Removes a wildcard entry for the given suffix.
    pub fn remove_wildcard(&mut self, suffix: &Name) {
        let key = name_to_reversed_labels(suffix);
        self.wildcard.remove(&key);
    }

    /// Returns the total number of stored entries (exact + wildcard).
    #[must_use]
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Returns `true` if there are no stored entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }
}

// ── CidrTrie ──────────────────────────────────────────────────────────────────

/// Prefix-sorted list for IP CIDR matching (RPZ-028).
///
/// Entries are kept sorted by prefix length in descending order (most-specific
/// first) so that the first matching entry during a sequential scan is always
/// the most-specific match.
///
/// The "PATRICIA trie" property is approximated by the sorted-prefix structure:
/// for practical policy-zone sizes (< 1 M CIDR ranges), O(n) scans with
/// early-exit semantics are acceptable.
#[derive(Debug, Default, Clone)]
pub struct CidrTrie {
    /// IPv4 entries: `(network_bits, prefix_len, action)`, sorted by `prefix_len` desc.
    v4: Vec<(u32, u8, RpzAction)>,
    /// IPv6 entries: `(network_bits, prefix_len, action)`, sorted by `prefix_len` desc.
    v6: Vec<(u128, u8, RpzAction)>,
}

impl CidrTrie {
    /// Creates a new, empty `CidrTrie`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a CIDR range with its associated action.
    ///
    /// If an identical `(addr, prefix_len)` already exists, its action is replaced.
    pub fn insert(&mut self, range: &CidrRange, action: RpzAction) {
        match range.addr {
            IpAddr::V4(addr) => {
                let bits = u32::from_be_bytes(addr.octets());
                let mask = prefix_mask_v4(range.prefix_len);
                let network_bits = bits & mask;
                // Replace if already present.
                if let Some(entry) = self
                    .v4
                    .iter_mut()
                    .find(|(b, p, _)| *b == network_bits && *p == range.prefix_len)
                {
                    entry.2 = action;
                } else {
                    self.v4.push((network_bits, range.prefix_len, action));
                    self.v4.sort_unstable_by_key(|e| std::cmp::Reverse(e.1));
                }
            }
            IpAddr::V6(addr) => {
                let bits = u128::from_be_bytes(addr.octets());
                let mask = prefix_mask_v6(range.prefix_len);
                let network_bits = bits & mask;
                if let Some(entry) = self
                    .v6
                    .iter_mut()
                    .find(|(b, p, _)| *b == network_bits && *p == range.prefix_len)
                {
                    entry.2 = action;
                } else {
                    self.v6.push((network_bits, range.prefix_len, action));
                    self.v6.sort_unstable_by_key(|e| std::cmp::Reverse(e.1));
                }
            }
        }
    }

    /// Removes the entry matching `range` exactly (`addr` AND `prefix_len` must match).
    pub fn remove(&mut self, range: &CidrRange) {
        match range.addr {
            IpAddr::V4(addr) => {
                let bits = u32::from_be_bytes(addr.octets());
                let mask = prefix_mask_v4(range.prefix_len);
                let network_bits = bits & mask;
                self.v4
                    .retain(|(b, p, _)| !(*b == network_bits && *p == range.prefix_len));
            }
            IpAddr::V6(addr) => {
                let bits = u128::from_be_bytes(addr.octets());
                let mask = prefix_mask_v6(range.prefix_len);
                let network_bits = bits & mask;
                self.v6
                    .retain(|(b, p, _)| !(*b == network_bits && *p == range.prefix_len));
            }
        }
    }

    /// Returns the action for the most-specific matching CIDR range, or `None`.
    ///
    /// Iterates entries sorted by prefix length (longest first) and returns the
    /// first match.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<&RpzAction> {
        match ip {
            IpAddr::V4(addr) => {
                let bits = u32::from_be_bytes(addr.octets());
                for (network_bits, prefix_len, action) in &self.v4 {
                    let mask = prefix_mask_v4(*prefix_len);
                    if bits & mask == *network_bits {
                        return Some(action);
                    }
                }
                None
            }
            IpAddr::V6(addr) => {
                let bits = u128::from_be_bytes(addr.octets());
                for (network_bits, prefix_len, action) in &self.v6 {
                    let mask = prefix_mask_v6(*prefix_len);
                    if bits & mask == *network_bits {
                        return Some(action);
                    }
                }
                None
            }
        }
    }

    /// Returns the total number of stored entries (IPv4 + IPv6).
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Returns `true` if there are no stored entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Computes the IPv4 bitmask for `prefix_len` bits.
fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32u32.saturating_sub(u32::from(prefix_len)))
    }
}

/// Computes the IPv6 bitmask for `prefix_len` bits.
fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0u128
    } else {
        !0u128 << (128u32.saturating_sub(u32::from(prefix_len)))
    }
}

// ── NsdnameMatcher ────────────────────────────────────────────────────────────

/// Matcher for NSDNAME triggers (RPZ-028).
///
/// Combines a direct hash map for exact matches and a [`QnameTrie`] for
/// suffix (wildcard) matches.
#[derive(Debug, Default, Clone)]
pub struct NsdnameMatcher {
    exact: HashMap<Vec<u8>, RpzAction>,
    suffix: QnameTrie,
}

impl NsdnameMatcher {
    /// Creates a new, empty `NsdnameMatcher`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an exact NSDNAME trigger: fires when an NS name equals `name`.
    pub fn insert_exact(&mut self, name: &Name, action: RpzAction) {
        // Key = lowercased wire bytes for case-insensitive equality.
        let key = name
            .as_wire_bytes()
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect();
        self.exact.insert(key, action);
    }

    /// Inserts a suffix NSDNAME trigger: fires when an NS name is a subdomain of `suffix`.
    pub fn insert_suffix(&mut self, suffix: &Name, action: RpzAction) {
        self.suffix.insert_wildcard(suffix, action);
    }

    /// Looks up `ns_name`, returning the matching action (exact wins over suffix).
    #[must_use]
    pub fn lookup(&self, ns_name: &Name) -> Option<&RpzAction> {
        let key: Vec<u8> = ns_name
            .as_wire_bytes()
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect();
        if let Some(action) = self.exact.get(&key) {
            return Some(action);
        }
        self.suffix.lookup(ns_name)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use super::*;

    // ── QnameTrie ─────────────────────────────────────────────────────────────

    #[test]
    fn qname_trie_exact_match() {
        let mut trie = QnameTrie::new();
        let name = Name::from_str("blocked.example.com.").unwrap();
        trie.insert_exact(&name, RpzAction::Nxdomain);

        assert_eq!(trie.lookup(&name), Some(&RpzAction::Nxdomain));
        let other = Name::from_str("other.example.com.").unwrap();
        assert!(trie.lookup(&other).is_none());
    }

    #[test]
    fn qname_trie_wildcard_match_subdomain_only() {
        let mut trie = QnameTrie::new();
        let suffix = Name::from_str("evil.com.").unwrap();
        trie.insert_wildcard(&suffix, RpzAction::Nxdomain);

        // Strict subdomain matches.
        let sub = Name::from_str("sub.evil.com.").unwrap();
        assert_eq!(trie.lookup(&sub), Some(&RpzAction::Nxdomain));
        let deep = Name::from_str("a.b.evil.com.").unwrap();
        assert_eq!(trie.lookup(&deep), Some(&RpzAction::Nxdomain));

        // The apex itself does NOT match (wildcard means STRICT subdomain).
        let apex = Name::from_str("evil.com.").unwrap();
        assert!(trie.lookup(&apex).is_none());
    }

    #[test]
    fn qname_trie_longest_wildcard_wins() {
        let mut trie = QnameTrie::new();
        let suffix_short = Name::from_str("example.com.").unwrap();
        let suffix_long = Name::from_str("b.example.com.").unwrap();
        trie.insert_wildcard(&suffix_short, RpzAction::Nodata);
        trie.insert_wildcard(&suffix_long, RpzAction::Drop);

        // "a.b.example.com." should match the longer suffix "b.example.com.".
        let qname = Name::from_str("a.b.example.com.").unwrap();
        assert_eq!(trie.lookup(&qname), Some(&RpzAction::Drop));

        // "c.example.com." only matches the shorter suffix.
        let qname2 = Name::from_str("c.example.com.").unwrap();
        assert_eq!(trie.lookup(&qname2), Some(&RpzAction::Nodata));
    }

    #[test]
    fn qname_trie_exact_beats_wildcard() {
        let mut trie = QnameTrie::new();
        let suffix = Name::from_str("example.com.").unwrap();
        let exact = Name::from_str("sub.example.com.").unwrap();
        trie.insert_wildcard(&suffix, RpzAction::Nodata);
        trie.insert_exact(&exact, RpzAction::Passthru);

        assert_eq!(trie.lookup(&exact), Some(&RpzAction::Passthru));
    }

    #[test]
    fn qname_trie_no_match() {
        let mut trie = QnameTrie::new();
        let name = Name::from_str("blocked.example.com.").unwrap();
        trie.insert_exact(&name, RpzAction::Nxdomain);

        let other = Name::from_str("benign.org.").unwrap();
        assert!(trie.lookup(&other).is_none());
    }

    #[test]
    fn qname_trie_len_and_is_empty() {
        let mut trie = QnameTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        trie.insert_exact(&Name::from_str("a.com.").unwrap(), RpzAction::Drop);
        trie.insert_wildcard(&Name::from_str("b.com.").unwrap(), RpzAction::Drop);
        assert_eq!(trie.len(), 2);
        assert!(!trie.is_empty());
    }

    // ── CidrTrie ──────────────────────────────────────────────────────────────

    #[test]
    fn cidr_trie_v4_match() {
        let mut trie = CidrTrie::new();
        trie.insert(
            &CidrRange {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                prefix_len: 16,
            },
            RpzAction::Drop,
        );
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(&RpzAction::Drop)
        );
        assert!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .is_none()
        );
    }

    #[test]
    fn cidr_trie_most_specific_wins() {
        let mut trie = CidrTrie::new();
        trie.insert(
            &CidrRange {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            },
            RpzAction::Nodata,
        );
        trie.insert(
            &CidrRange {
                addr: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
                prefix_len: 24,
            },
            RpzAction::Drop,
        );
        // 10.1.0.5 is in both /8 and /24 — /24 must win.
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))),
            Some(&RpzAction::Drop)
        );
        // 10.2.0.1 is only in /8.
        assert_eq!(
            trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))),
            Some(&RpzAction::Nodata)
        );
    }

    #[test]
    fn cidr_trie_remove() {
        let mut trie = CidrTrie::new();
        let range = CidrRange {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            prefix_len: 32,
        };
        trie.insert(&range, RpzAction::Drop);
        assert!(trie.lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).is_some());
        trie.remove(&range);
        assert!(trie.lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).is_none());
    }
}
