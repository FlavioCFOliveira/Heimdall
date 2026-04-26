// SPDX-License-Identifier: MIT

//! CIDR prefix-tree for O(depth) longest-prefix-match on IPv4 and IPv6 addresses.
//!
//! The trie is a classic binary trie: each node branches on a single bit of the
//! address, and a `matches` flag at depth *n* signals that the /n prefix ending
//! at that node is present in the set.  Lookup walks the full address width (32
//! bits for IPv4, 128 bits for IPv6) and returns `true` if **any** ancestor node
//! — including the final node — has `matches = true`.

use std::net::IpAddr;

// ── TrieNode ──────────────────────────────────────────────────────────────────

/// A single node in the binary trie.
#[derive(Default, Debug)]
struct TrieNode {
    /// Branch on bit 0 (children[0]) or bit 1 (children[1]).
    children: [Option<Box<TrieNode>>; 2],
    /// `true` when an inserted prefix ends exactly at this node.
    matches: bool,
}

// ── BitTrie ───────────────────────────────────────────────────────────────────

/// Binary bit-trie generic over the address word type `T`.
///
/// Internally the trie only uses `T`'s bit-width, which is derived from
/// `std::mem::size_of::<T>() * 8`.  `T` must implement the bit-extraction
/// helpers exposed via the [`BitWord`] sealed trait.
#[derive(Debug)]
struct BitTrie<T: BitWord> {
    root: TrieNode,
    _marker: std::marker::PhantomData<T>,
}

impl<T: BitWord> Default for BitTrie<T> {
    fn default() -> Self {
        Self {
            root: TrieNode::default(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: BitWord> BitTrie<T> {
    /// Insert the prefix consisting of the top `prefix_len` bits of `addr`.
    ///
    /// Inserting a /0 prefix sets the root's `matches` flag, causing every
    /// address to match.  Inserting a /N prefix for N > width is a no-op.
    fn insert(&mut self, addr: T, prefix_len: u32) {
        let depth = prefix_len.min(T::BITS);
        let mut node = &mut self.root;
        for i in 0..depth {
            let bit = addr.bit(i) as usize;
            node = node.children[bit].get_or_insert_with(Box::default);
        }
        node.matches = true;
    }

    /// Return `true` when any prefix in the trie covers `addr`.
    fn contains(&self, addr: T) -> bool {
        let mut node = &self.root;
        if node.matches {
            return true;
        }
        for i in 0..T::BITS {
            let bit = addr.bit(i) as usize;
            match node.children[bit].as_deref() {
                None => return false,
                Some(child) => {
                    if child.matches {
                        return true;
                    }
                    node = child;
                }
            }
        }
        false
    }
}

// ── BitWord ───────────────────────────────────────────────────────────────────

/// Sealed helper trait for address words that the trie can traverse bit-by-bit.
trait BitWord: Copy + Sized {
    /// Total number of bits in the address word.
    const BITS: u32;
    /// Extract the bit at position `idx` (0 = most-significant bit).
    fn bit(self, idx: u32) -> u8;
}

impl BitWord for u32 {
    const BITS: u32 = 32;

    #[inline]
    fn bit(self, idx: u32) -> u8 {
        ((self >> (31 - idx)) & 1) as u8
    }
}

impl BitWord for u128 {
    const BITS: u32 = 128;

    #[inline]
    fn bit(self, idx: u32) -> u8 {
        ((self >> (127 - idx)) & 1) as u8
    }
}

// ── CidrSet ───────────────────────────────────────────────────────────────────

/// A set of CIDR prefixes supporting `O(prefix_len)` lookup via a binary bit-trie.
///
/// Both IPv4 and IPv6 prefixes are supported; the two address families are stored
/// in separate tries so their key spaces never overlap.
///
/// # Examples
///
/// ```rust
/// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// use heimdall_runtime::admission::CidrSet;
///
/// let mut set = CidrSet::default();
/// set.insert("192.168.1.0".parse().unwrap(), 24);
/// assert!(set.contains("192.168.1.42".parse().unwrap()));
/// assert!(!set.contains("10.0.0.1".parse().unwrap()));
/// ```
#[derive(Default, Debug)]
pub struct CidrSet {
    v4: BitTrie<u32>,
    v6: BitTrie<u128>,
}

impl CidrSet {
    /// Insert the CIDR prefix `addr / prefix_len` into the set.
    ///
    /// Only the top `prefix_len` bits of `addr` are significant; the remaining
    /// host bits are ignored.  A `prefix_len` of 0 creates a catch-all prefix
    /// that matches every address of the same family.
    pub fn insert(&mut self, addr: IpAddr, prefix_len: u8) {
        match addr {
            IpAddr::V4(v4) => {
                let word = u32::from(v4);
                self.v4.insert(word, u32::from(prefix_len));
            }
            IpAddr::V6(v6) => {
                let word = u128::from(v6);
                self.v6.insert(word, u32::from(prefix_len));
            }
        }
    }

    /// Return `true` when any prefix in the set covers `addr`.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.v4.contains(u32::from(v4)),
            IpAddr::V6(v6) => self.v6.contains(u128::from(v6)),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::CidrSet;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn exact_host_match_v4() {
        let mut set = CidrSet::default();
        set.insert(v4("10.0.0.1"), 32);
        assert!(set.contains(v4("10.0.0.1")));
        assert!(!set.contains(v4("10.0.0.2")));
    }

    #[test]
    fn prefix_match_v4() {
        let mut set = CidrSet::default();
        set.insert(v4("192.168.1.0"), 24);
        assert!(set.contains(v4("192.168.1.0")));
        assert!(set.contains(v4("192.168.1.1")));
        assert!(set.contains(v4("192.168.1.255")));
        assert!(!set.contains(v4("192.168.2.0")));
        assert!(!set.contains(v4("10.0.0.1")));
    }

    #[test]
    fn no_match_v4() {
        let set = CidrSet::default();
        assert!(!set.contains(v4("1.2.3.4")));
    }

    #[test]
    fn slash_zero_matches_all_v4() {
        let mut set = CidrSet::default();
        set.insert(v4("0.0.0.0"), 0);
        assert!(set.contains(v4("1.2.3.4")));
        assert!(set.contains(v4("255.255.255.255")));
    }

    #[test]
    fn slash_128_exact_v6() {
        let mut set = CidrSet::default();
        set.insert(v6("2001:db8::1"), 128);
        assert!(set.contains(v6("2001:db8::1")));
        assert!(!set.contains(v6("2001:db8::2")));
    }

    #[test]
    fn prefix_match_v6() {
        let mut set = CidrSet::default();
        set.insert(v6("2001:db8::"), 32);
        assert!(set.contains(v6("2001:db8::1")));
        assert!(set.contains(v6("2001:db8:ffff::1")));
        assert!(!set.contains(v6("2001:db9::1")));
    }

    #[test]
    fn slash_zero_matches_all_v6() {
        let mut set = CidrSet::default();
        set.insert(v6("::"), 0);
        assert!(set.contains(v6("::1")));
        assert!(set.contains(v6("2001:db8::1")));
    }

    #[test]
    fn mixed_v4_v6_independent() {
        let mut set = CidrSet::default();
        set.insert(v4("10.0.0.0"), 8);
        set.insert(v6("fe80::"), 10);
        assert!(set.contains(v4("10.1.2.3")));
        assert!(!set.contains(v4("172.16.0.1")));
        assert!(set.contains(v6("fe80::1")));
        assert!(!set.contains(v6("2001:db8::1")));
    }

    #[test]
    fn longest_prefix_match() {
        let mut set = CidrSet::default();
        // Insert a /8 but NOT the specific /32 — ensure /8 still matches.
        set.insert(v4("10.0.0.0"), 8);
        assert!(set.contains(v4("10.255.255.255")));
    }
}
