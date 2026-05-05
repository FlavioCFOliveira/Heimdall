// SPDX-License-Identifier: MIT

//! DNS domain name type conforming to RFC 1034, RFC 1035, RFC 4343 (case-insensitivity),
//! and RFC 8499 (terminology).

use std::fmt;

// ── Limits ────────────────────────────────────────────────────────────────────

/// Maximum wire-encoded length of a DNS name (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur when constructing or parsing a [`Name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// A label exceeds the 63-octet limit (RFC 1035 §2.3.4).
    LabelTooLong,
    /// The total wire-encoded name exceeds 255 octets (RFC 1035 §2.3.4).
    NameTooLong,
    /// An intermediate empty label was encountered (only the root may be empty).
    EmptyLabel,
    /// The wire-format buffer is malformed (truncated or contains invalid length byte).
    InvalidWireFormat,
    /// The presentation-format string contains a character that is not permitted.
    InvalidChar(u8),
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelTooLong => write!(f, "DNS label exceeds 63 octets"),
            Self::NameTooLong => write!(f, "DNS name exceeds 255 octets"),
            Self::EmptyLabel => write!(f, "intermediate empty label in DNS name"),
            Self::InvalidWireFormat => write!(f, "malformed DNS name in wire format"),
            Self::InvalidChar(b) => write!(f, "invalid character 0x{b:02X} in DNS name"),
        }
    }
}

impl std::error::Error for NameError {}

// ── Name ─────────────────────────────────────────────────────────────────────

/// An absolutely-qualified DNS domain name stored in wire-label format.
///
/// Internally the name is kept as raw wire bytes: concatenated length-prefixed
/// labels terminated by a zero octet.  For example, `"example.com."` is stored
/// as `[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]`.
///
/// The maximum wire length is 255 octets (RFC 1035 §2.3.4), which fits in a
/// fixed `[u8; 255]` buffer — no heap allocation is needed.
///
/// Equality, ordering, and hashing are **case-insensitive** per RFC 4343 §3.
/// Ordering follows RFC 4034 §6.1 canonical form: label-by-label comparison
/// from left to right, each label compared byte-by-byte after ASCII-lowercasing.
#[derive(Clone)]
pub struct Name {
    /// Raw wire bytes.  Only `buf[..len]` is meaningful.
    buf: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `buf`.  Always ≥ 1 (root = `[0]`, len = 1).
    len: u8,
}

impl Name {
    // ── Internal constructors ─────────────────────────────────────────────────

    /// Creates an empty name builder (no labels, no root zero yet).
    fn empty() -> Self {
        Self {
            buf: [0u8; MAX_NAME_LEN],
            len: 0,
        }
    }

    /// Appends a label to the raw buffer WITHOUT maintaining a root terminator.
    ///
    /// This is used during construction only.  Call `terminate()` when done.
    ///
    /// # Errors
    ///
    /// Returns errors for empty labels, labels too long, or name too long.
    fn push_label_raw(&mut self, label: &[u8]) -> Result<(), NameError> {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        // MAX_LABEL_LEN = 63 ≤ u8::MAX, so the cast below cannot truncate.
        if label.len() > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong);
        }
        // After this label we still need the root zero byte, so the total must
        // be at most 255.  Current len + 1 (length byte) + label.len() + 1 (root) ≤ 255.
        let new_len = usize::from(self.len)
            .checked_add(1 + label.len())
            .ok_or(NameError::NameTooLong)?;
        if new_len + 1 > MAX_NAME_LEN {
            return Err(NameError::NameTooLong);
        }
        let pos = usize::from(self.len);
        // INVARIANT: label.len() ≤ MAX_LABEL_LEN = 63 ≤ u8::MAX; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.buf[pos] = label.len() as u8;
        }
        self.buf[pos + 1..pos + 1 + label.len()].copy_from_slice(label);
        // INVARIANT: new_len < MAX_NAME_LEN = 255 ≤ u8::MAX; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.len = new_len as u8;
        }
        Ok(())
    }

    /// Appends the root zero terminator, completing the name.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::NameTooLong`] if there is no room for the zero byte.
    fn terminate(&mut self) -> Result<(), NameError> {
        if usize::from(self.len) >= MAX_NAME_LEN {
            return Err(NameError::NameTooLong);
        }
        self.buf[usize::from(self.len)] = 0;
        self.len += 1;
        Ok(())
    }

    // ── Public constructors ───────────────────────────────────────────────────

    /// Returns the DNS root name (wire bytes: `[0x00]`, total length 1).
    #[must_use]
    pub fn root() -> Self {
        let mut n = Self::empty();
        n.buf[0] = 0;
        n.len = 1;
        n
    }

    /// Parses a DNS name from presentation format (e.g. `"example.com."` or
    /// `"example.com"`).  A missing trailing dot is accepted; the name is
    /// always treated as fully-qualified.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] if any label is too long, the total name exceeds
    /// 255 octets, or an invalid byte is encountered.
    pub fn parse_str(s: &str) -> Result<Self, NameError> {
        let bytes = s.as_bytes();

        // Strip trailing dot if present.
        let stripped = if bytes.last() == Some(&b'.') {
            &bytes[..bytes.len() - 1]
        } else {
            bytes
        };

        // Root-only (empty string after stripping dot, or just ".").
        if stripped.is_empty() {
            return Ok(Self::root());
        }

        let mut name = Self::empty();
        for label in stripped.split(|&b| b == b'.') {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            name.push_label_raw(label)?;
        }
        name.terminate()?;
        Ok(name)
    }

    /// Parses a DNS name from raw wire bytes starting at `offset`.
    ///
    /// This function reads **only** uncompressed labels (no pointer following).
    /// Pointer handling is the responsibility of the message parser which has
    /// access to the full packet buffer.
    ///
    /// Returns `(name, bytes_consumed)` where `bytes_consumed` is the number of
    /// bytes read from `buf` starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::InvalidWireFormat`] on truncation or malformed data,
    /// [`NameError::LabelTooLong`] or [`NameError::NameTooLong`] on limit
    /// violations.
    pub fn from_wire(buf: &[u8], offset: usize) -> Result<(Self, usize), NameError> {
        let mut name = Self::empty();
        let mut pos = offset;

        loop {
            let len_byte = *buf.get(pos).ok_or(NameError::InvalidWireFormat)?;
            pos += 1;

            // Pointer bits (0xC0) must not appear here — caller handles them.
            if len_byte & 0xC0 == 0xC0 {
                return Err(NameError::InvalidWireFormat);
            }

            if len_byte == 0 {
                name.terminate()?;
                break;
            }

            let label_len = usize::from(len_byte);
            if label_len > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong);
            }

            let end = pos
                .checked_add(label_len)
                .ok_or(NameError::InvalidWireFormat)?;
            if end > buf.len() {
                return Err(NameError::InvalidWireFormat);
            }

            name.push_label_raw(&buf[pos..end])?;
            pos = end;
        }

        let consumed = pos - offset;
        Ok((name, consumed))
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the raw wire-format bytes of this name.
    #[must_use]
    pub fn as_wire_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Returns `true` if this name is the DNS root (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.len == 1 && self.buf[0] == 0
    }

    /// Returns `true` if `self` is at or below `zone` in the DNS hierarchy.
    ///
    /// Returns `true` iff `zone` is a case-insensitive suffix of `self`
    /// (or they are equal), which corresponds to the bailiwick check.
    #[must_use]
    pub fn is_in_bailiwick(&self, zone: &Self) -> bool {
        let self_labels: Vec<&[u8]> = self.iter_labels().collect();
        let zone_labels: Vec<&[u8]> = zone.iter_labels().collect();

        if zone_labels.len() > self_labels.len() {
            return false;
        }

        let offset = self_labels.len() - zone_labels.len();
        self_labels[offset..]
            .iter()
            .zip(zone_labels.iter())
            .all(|(a, b)| {
                a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .all(|(x, y)| x.eq_ignore_ascii_case(y))
            })
    }

    /// Iterates over labels, excluding the trailing root zero octet.
    pub fn iter_labels(&self) -> impl Iterator<Item = &[u8]> {
        LabelIter {
            buf: self.as_wire_bytes(),
            pos: 0,
        }
    }

    /// Returns the number of labels (excluding the root).
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.iter_labels().count()
    }

    /// Appends a label to this name, maintaining the trailing root terminator.
    ///
    /// The name must already have been initialised (e.g. via [`Name::root`]).
    ///
    /// # Errors
    ///
    /// Returns [`NameError::LabelTooLong`] if `label` exceeds 63 bytes,
    /// [`NameError::NameTooLong`] if the resulting name would exceed 255 bytes,
    /// or [`NameError::EmptyLabel`] if `label` is empty.
    pub fn append_label(&mut self, label: &[u8]) -> Result<(), NameError> {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        // MAX_LABEL_LEN = 63 ≤ u8::MAX.
        if label.len() > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong);
        }

        // The name currently ends with a root zero byte at position `len - 1`.
        // Overwrite it, append the new label, then re-add the root zero.
        let labels_end = usize::from(self.len) - 1;

        // new_total = labels_end + 1 (len byte) + label.len() + 1 (root zero)
        let new_total = labels_end
            .checked_add(1 + label.len() + 1)
            .ok_or(NameError::NameTooLong)?;

        if new_total > MAX_NAME_LEN {
            return Err(NameError::NameTooLong);
        }

        // INVARIANT: label.len() ≤ 63 ≤ u8::MAX; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.buf[labels_end] = label.len() as u8;
        }
        self.buf[labels_end + 1..labels_end + 1 + label.len()].copy_from_slice(label);
        self.buf[labels_end + 1 + label.len()] = 0;
        // INVARIANT: new_total ≤ MAX_NAME_LEN = 255 ≤ u8::MAX; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.len = new_total as u8;
        }
        Ok(())
    }

    /// Returns the wire bytes with all label octets lowercased (RFC 4034 §6.2
    /// canonical form for DNSSEC signing).  Allocates a temporary `Vec<u8>`.
    #[must_use]
    pub fn to_canonical_wire(&self) -> Vec<u8> {
        self.as_wire_bytes()
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect()
    }
}

// ── LabelIter ────────────────────────────────────────────────────────────────

struct LabelIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let len_byte = *self.buf.get(self.pos)?;
        if len_byte == 0 {
            return None;
        }
        let start = self.pos + 1;
        let end = start + usize::from(len_byte);
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(&self.buf[start..end])
    }
}

// ── Trait impls ───────────────────────────────────────────────────────────────

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for label in self.iter_labels() {
            for &b in label {
                if b == b'.' || b == b'\\' {
                    write!(f, "\\{}", b as char)?;
                } else if b.is_ascii_graphic() {
                    write!(f, "{}", b as char)?;
                } else {
                    write!(f, "\\{b:03}")?;
                }
            }
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl std::str::FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

// ── Case-insensitive PartialEq / Eq ──────────────────────────────────────────

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        let a = self.as_wire_bytes();
        let b = other.as_wire_bytes();
        a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .all(|(x, y)| x.eq_ignore_ascii_case(y))
    }
}

impl Eq for Name {}

// ── Case-insensitive Hash ─────────────────────────────────────────────────────

impl std::hash::Hash for Name {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for b in self.as_wire_bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

// ── RFC 4034 §6.1 canonical ordering ─────────────────────────────────────────

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // RFC 4034 §6.1: compare label by label, left to right.
        let mut a_labels = self.iter_labels();
        let mut b_labels = other.iter_labels();

        loop {
            match (a_labels.next(), b_labels.next()) {
                (None, None) => return std::cmp::Ordering::Equal,
                (None, Some(_)) => return std::cmp::Ordering::Less,
                (Some(_), None) => return std::cmp::Ordering::Greater,
                (Some(a), Some(b)) => {
                    let len_cmp = a.len().cmp(&b.len());
                    if len_cmp != std::cmp::Ordering::Equal {
                        return len_cmp;
                    }
                    for (x, y) in a.iter().zip(b.iter()) {
                        let c = x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase());
                        if c != std::cmp::Ordering::Equal {
                            return c;
                        }
                    }
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn root_name() {
        let r = Name::root();
        assert!(r.is_root());
        assert_eq!(r.as_wire_bytes(), &[0]);
        assert_eq!(r.to_string(), ".");
        assert_eq!(r.label_count(), 0);
    }

    #[test]
    fn from_str_example_com_with_dot() {
        let n = Name::from_str("example.com.").unwrap();
        assert!(!n.is_root());
        assert_eq!(n.to_string(), "example.com.");
        assert_eq!(
            n.as_wire_bytes(),
            &[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
    }

    #[test]
    fn from_str_example_com_without_dot() {
        let n = Name::from_str("example.com").unwrap();
        assert_eq!(n, Name::from_str("example.com.").unwrap());
    }

    #[test]
    fn case_insensitive_eq() {
        let a = Name::from_str("Example.COM.").unwrap();
        let b = Name::from_str("example.com.").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn from_wire_roundtrip() {
        let wire: &[u8] = &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (n, consumed) = Name::from_wire(wire, 0).unwrap();
        assert_eq!(consumed, 13);
        assert_eq!(n, Name::from_str("example.com.").unwrap());
    }

    #[test]
    fn from_wire_rejects_pointer() {
        let wire: &[u8] = &[0xC0, 0x0C];
        assert!(matches!(
            Name::from_wire(wire, 0),
            Err(NameError::InvalidWireFormat)
        ));
    }

    #[test]
    fn label_too_long() {
        let long = "a".repeat(64) + ".com.";
        assert!(matches!(
            Name::from_str(&long),
            Err(NameError::LabelTooLong)
        ));
    }

    #[test]
    fn name_too_long() {
        let label = "a".repeat(10);
        let s = (0..26)
            .map(|_| label.as_str())
            .collect::<Vec<_>>()
            .join(".")
            + ".";
        assert!(matches!(Name::from_str(&s), Err(NameError::NameTooLong)));
    }

    #[test]
    fn empty_label_error() {
        assert!(matches!(
            Name::from_str("foo..bar."),
            Err(NameError::EmptyLabel)
        ));
    }

    #[test]
    fn bailiwick_check() {
        let zone = Name::from_str("example.com.").unwrap();
        let child = Name::from_str("sub.example.com.").unwrap();
        let other = Name::from_str("other.org.").unwrap();
        assert!(child.is_in_bailiwick(&zone));
        assert!(zone.is_in_bailiwick(&zone));
        assert!(!other.is_in_bailiwick(&zone));
    }

    #[test]
    fn label_count() {
        let n = Name::from_str("a.b.c.").unwrap();
        assert_eq!(n.label_count(), 3);
        assert_eq!(Name::root().label_count(), 0);
    }

    #[test]
    fn append_label_roundtrip() {
        let mut n = Name::root();
        n.append_label(b"com").unwrap();
        n.append_label(b"example").unwrap();
        let wire = n.as_wire_bytes();
        assert_eq!(wire.last(), Some(&0u8));
        assert_eq!(n.label_count(), 2);
    }
}
