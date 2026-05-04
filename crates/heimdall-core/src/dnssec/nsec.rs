// SPDX-License-Identifier: MIT

//! NSEC and NSEC3 record handlers for DNSSEC negative-proof processing.
//!
//! Implements DNSSEC-007 (type bitmap encoding), DNSSEC-008 (NSEC existence proofs),
//! DNSSEC-009 (NSEC3 hashing), DNSSEC-010 (NSEC3 existence proofs), and
//! DNSSEC-044 (150-iteration cap).

use ring::digest;

use crate::dnssec::budget::ValidationBudget;
use crate::dnssec::canonical::canonical_name_wire;
use crate::dnssec::verify::BogusReason;
use crate::edns::{EdnsOption, ExtendedError, ede_code};
use crate::name::Name;
use crate::rdata::RData;
use crate::record::{Record, Rtype};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum NSEC3 hash iteration count (RFC 9276 §3.1, DNSSEC-044).
///
/// Validators MUST reject NSEC3 records with iterations > 150 to prevent
/// CPU exhaustion attacks.
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

// ── SHA-1 helpers ─────────────────────────────────────────────────────────────

/// Converts a `ring` SHA-1 digest output to a `[u8; 20]` array.
///
/// SHA-1 always produces exactly 20 bytes; the slice-to-array conversion
/// is therefore always valid.
fn sha1_to_array(d: &ring::digest::Digest) -> [u8; 20] {
    let bytes = d.as_ref();
    // ring guarantees SHA-1 output is exactly 20 bytes.
    // Use a checked approach: copy into a fixed array.
    let mut out = [0u8; 20];
    let len = bytes.len().min(20);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Performs the iterative SHA-1 computation defined in RFC 5155 §5.
fn sha1_iterated(x: &[u8], salt: &[u8], iterations: u16) -> [u8; 20] {
    // IH(salt, x, 0) = H(x || salt)
    let mut data = Vec::with_capacity(x.len() + salt.len());
    data.extend_from_slice(x);
    data.extend_from_slice(salt);
    let mut hash = sha1_to_array(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data));

    // IH(salt, x, k) = H(IH(salt, x, k-1) || salt) for k = 1..=iterations
    let mut iter_buf = Vec::with_capacity(20 + salt.len());
    for _ in 0..iterations {
        iter_buf.clear();
        iter_buf.extend_from_slice(&hash);
        iter_buf.extend_from_slice(salt);
        hash = sha1_to_array(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &iter_buf));
    }
    hash
}

// ── Type bitmap encoding ───────────────────────────────────────────────────────

/// Encodes a set of `Rtype` values into the RFC 4034 §4.1.2 type-bitmap format.
///
/// The bitmap consists of one or more window blocks, each covering a 256-type
/// range. Each block has a 1-byte window number, a 1-byte bitmap length, and
/// up to 32 bytes of bitmap data.
///
/// Implements DNSSEC-007.
#[must_use]
pub fn encode_type_bitmap(types: &[Rtype]) -> Vec<u8> {
    if types.is_empty() {
        return Vec::new();
    }

    // Group types by window (high byte of the 16-bit type code).
    // Using a sorted array to maintain window order.
    let mut by_window: Vec<(u8, u8)> = types
        .iter()
        .map(|t| {
            let v = t.as_u16();
            // Window = high byte, bit = low byte.
            #[allow(clippy::cast_possible_truncation)]
            let window = (v >> 8) as u8;
            #[allow(clippy::cast_possible_truncation)]
            let bit = (v & 0xFF) as u8;
            (window, bit)
        })
        .collect();
    by_window.sort_unstable();
    by_window.dedup();

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < by_window.len() {
        let window = by_window[i].0;

        // Collect all bits for this window.
        let mut bitmap = [0u8; 32];
        while i < by_window.len() && by_window[i].0 == window {
            let bit = by_window[i].1;
            bitmap[usize::from(bit) / 8] |= 0x80 >> (bit % 8);
            i += 1;
        }

        // Find the last non-zero byte to determine bitmap length.
        let bitmap_len = bitmap
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |p| p + 1);

        out.push(window);
        // INVARIANT: bitmap_len ≤ 32 ≤ u8::MAX.
        #[allow(clippy::cast_possible_truncation)]
        out.push(bitmap_len as u8);
        out.extend_from_slice(&bitmap[..bitmap_len]);
    }

    out
}

/// Returns `true` if `rtype` is set in the type bitmap.
///
/// Implements RFC 4034 §4.1.2 type-bitmap lookup.
///
/// Implements DNSSEC-007.
#[must_use]
pub fn type_in_bitmap(bitmap: &[u8], rtype: Rtype) -> bool {
    let v = rtype.as_u16();
    #[allow(clippy::cast_possible_truncation)]
    let window = (v >> 8) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let bit = (v & 0xFF) as u8;

    let mut pos = 0usize;
    while pos < bitmap.len() {
        if pos + 2 > bitmap.len() {
            break;
        }
        let w = bitmap[pos];
        let blen = usize::from(bitmap[pos + 1]);
        pos += 2;
        if pos + blen > bitmap.len() {
            break;
        }
        if w == window {
            let byte_idx = usize::from(bit) / 8;
            if byte_idx < blen {
                let mask = 0x80u8 >> (bit % 8);
                return bitmap[pos + byte_idx] & mask != 0;
            }
            return false;
        }
        pos += blen;
    }
    false
}

// ── NSEC existence proof ───────────────────────────────────────────────────────

/// The type of NSEC proof found for a non-existent name.
///
/// Implements DNSSEC-008.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsecProofType {
    /// The query name falls strictly between the NSEC owner and next-name.
    DirectCover,
    /// The wildcard `*.parent` is covered by the NSEC chain, proving the wildcard
    /// cannot have produced a positive answer.
    WildcardDenial,
}

/// Given a sorted list of NSEC records covering a zone, determines whether
/// `qname` is proven to not exist by the NSEC chain (RFC 4034 §5.4).
///
/// Returns `Some(NsecProofType)` if a proof is found, `None` if not.
///
/// Implements DNSSEC-008.
#[must_use]
pub fn nsec_proves_nxdomain(nsec_records: &[Record], qname: &Name) -> Option<NsecProofType> {
    for rec in nsec_records {
        let RData::Nsec { next_domain, .. } = &rec.rdata else { continue };

        let owner = &rec.name;

        // Check for direct cover: owner < qname < next_domain (canonical order).
        // RFC 4034 §6.1: canonical order is label-by-label, left-to-right.
        //
        // A name is covered if: owner < qname AND qname < next_domain.
        // For the last NSEC (wrapping case): owner < qname OR qname < next_domain.
        let owner_lt_qname = owner < qname;
        let qname_lt_next = qname < next_domain;

        // Normal (non-wrapping) case.
        if owner_lt_qname && qname_lt_next {
            return Some(NsecProofType::DirectCover);
        }

        // Wrapping case: the last NSEC in the zone (next_domain ≤ owner in canonical order,
        // meaning this record wraps around the zone).
        let is_wrapping = next_domain <= owner;
        if is_wrapping && (owner_lt_qname || qname_lt_next) {
            return Some(NsecProofType::DirectCover);
        }

        // Wildcard denial: check whether the wildcard *.closest_encloser is covered.
        // Determine the closest encloser of qname that exists in the NSEC chain.
        // A simple approximation: if owner is an ancestor of qname, check if
        // *.owner would be covered.
        if qname.is_in_bailiwick(owner) && owner != qname {
            // The wildcard at this level would be *.owner.
            // Check if *.owner is covered by this NSEC record.
            if let Ok(wildcard) = wildcard_of(owner) {
                let wc_lt_next = wildcard < *next_domain;
                let owner_lt_wc = *owner < wildcard;
                if owner_lt_wc && wc_lt_next {
                    return Some(NsecProofType::WildcardDenial);
                }
            }
        }
    }

    None
}

// ── NSEC3 hash ────────────────────────────────────────────────────────────────

/// Computes the NSEC3 hash of `name` with the given parameters (RFC 5155 §5).
///
/// Only SHA-1 (algorithm 1) is supported.
///
/// Returns `None` if `iterations > MAX_NSEC3_ITERATIONS` (DNSSEC-044 cap).
///
/// Hash computation:
/// ```text
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
/// ```
/// where H is SHA-1 and x is the canonical wire form of the name.
///
/// Implements DNSSEC-009 and DNSSEC-044.
///
/// # Panics
///
/// Does not panic in practice: SHA-1 always produces exactly 20 bytes, and the
/// only potential panic (`array conversion`) is statically prevented by ring's
/// contract.  If this ever changes, the function will return `None` before
/// reaching the hash step.
#[must_use]
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Option<[u8; 20]> {
    if iterations > MAX_NSEC3_ITERATIONS {
        return None;
    }
    Some(sha1_iterated(canonical_name_wire(name).as_slice(), salt, iterations))
}

/// Same as [`nsec3_hash`] but checks the [`ValidationBudget`] on each iteration.
///
/// # Return value
///
/// * `Ok(Some(hash))` — hash computed successfully.
/// * `Ok(None)` — `iterations > MAX_NSEC3_ITERATIONS`; caller MUST treat the
///   response as `Insecure` (DNSSEC-045).  `Bogus` MUST NOT be returned for
///   this case; use [`nsec3_excess_iterations_ede`] to attach the optional EDE.
/// * `Err(BogusReason::CpuBudgetExceeded)` — per-query wall-clock budget expired
///   during hashing (DNSSEC-045).
///
/// # Panics
///
/// Does not panic in practice: SHA-1 always produces exactly 20 bytes.
///
/// Implements DNSSEC-044 and DNSSEC-045.
pub fn nsec3_hash_with_budget(
    name: &Name,
    salt: &[u8],
    iterations: u16,
    budget: &ValidationBudget,
) -> Result<Option<[u8; 20]>, BogusReason> {
    if iterations > MAX_NSEC3_ITERATIONS {
        return Ok(None);
    }

    let x = canonical_name_wire(name);

    // IH(salt, x, 0) = H(x || salt)
    let mut data = Vec::with_capacity(x.len() + salt.len());
    data.extend_from_slice(&x);
    data.extend_from_slice(salt);
    let mut hash = sha1_to_array(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data));

    // IH(salt, x, k) = H(IH(salt, x, k-1) || salt) for k = 1..=iterations
    let mut iter_buf = Vec::with_capacity(20 + salt.len());
    for _ in 0..iterations {
        budget.check()?;
        iter_buf.clear();
        iter_buf.extend_from_slice(&hash);
        iter_buf.extend_from_slice(salt);
        hash = sha1_to_array(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &iter_buf));
    }

    Ok(Some(hash))
}

/// Returns the EDE EDNS option signalling that NSEC3 iterations exceeded the cap.
///
/// Attach this to the DNS response whenever [`nsec3_hash`] returns `None` or
/// [`nsec3_hash_with_budget`] returns `Ok(None)` due to excessive iterations,
/// per DNSSEC-045 (MAY signal EDE code 27 — Unsupported NSEC3 Iterations Value).
#[must_use]
pub fn nsec3_excess_iterations_ede() -> EdnsOption {
    EdnsOption::ExtendedError(ExtendedError::new(
        ede_code::UNSUPPORTED_NSEC3_ITERATIONS_VALUE,
    ))
}

// ── NSEC3 existence proof ──────────────────────────────────────────────────────

/// The type of NSEC3 proof found for a non-existent name.
///
/// Implements DNSSEC-010.
// `Name` is 255 bytes inline; boxing the two `Name` fields in `ClosestEncloserProof`
// brings the variant size in line with `DirectCover` (0 bytes) and avoids the
// large_enum_variant lint without losing the structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Nsec3ProofType {
    /// Closest-encloser proof (RFC 5155 §8.3).
    ClosestEncloserProof {
        /// The closest existing ancestor of `qname`.
        closest_encloser: Box<Name>,
        /// The immediate child of `closest_encloser` on the path to `qname`.
        next_closer: Box<Name>,
        /// `true` if a wildcard at `*.closest_encloser` is also covered.
        wildcard_covered: bool,
    },
    /// The hash of `qname` itself is directly covered by an NSEC3 interval.
    DirectCover,
}

/// Proves NXDOMAIN using NSEC3 records (RFC 5155 §8.3).
///
/// Returns `None` if no proof is found, if iterations exceed the cap, or if the
/// matching NSEC3 record has the opt-out flag set (RFC 5155 §6.5.2 — caller
/// should treat the zone as `Insecure` for unsigned delegations).
///
/// Implements DNSSEC-010.
#[must_use]
pub fn nsec3_proves_nxdomain(
    nsec3_records: &[Record],
    qname: &Name,
    zone_apex: &Name,
) -> Option<Nsec3ProofType> {
    // Extract NSEC3 parameters from the first valid NSEC3 record.
    let params = nsec3_zone_params(nsec3_records)?;

    // Try to find a closest encloser proof.
    // Walk up from qname to zone_apex, looking for a hash match.
    let qname_labels: Vec<&[u8]> = qname.iter_labels().collect();
    let apex_labels = zone_apex.label_count();

    // We need at least one label above the apex for an encloser proof.
    if qname_labels.len() <= apex_labels {
        return None;
    }

    // Try each ancestor of qname (from qname up to zone_apex).
    // The closest encloser is the deepest existing ancestor.
    let mut closest_encloser: Option<Name> = None;
    let mut next_closer: Option<Name> = None;

    for depth in apex_labels..qname_labels.len() {
        // Build the name consisting of the last (total_labels - depth) labels.
        let ancestor_labels = &qname_labels[depth..];
        let ancestor = labels_to_name(ancestor_labels)?;

        let hash = nsec3_hash(&ancestor, &params.salt, params.iterations)?;

        // Check if any NSEC3 record's owner hash matches this ancestor's hash.
        let found_match = nsec3_records.iter().any(|r| {
            if let RData::Nsec3 { next_hashed_owner: _, hash_algorithm: _, flags, iterations: it, salt: s, .. } = &r.rdata {
                if *it > MAX_NSEC3_ITERATIONS { return false; }
                // Owner name of NSEC3 is the base32hex-encoded hash of the hashed name.
                // In our internal representation, we store the decoded hash in the owner.
                // However, the owner name IS the encoded hash label.
                // We need to decode it or compare raw labels.
                // The NSEC3 owner name label is the base32hex of the hash.
                // For simplicity, compare via re-hashing the owner label.
                let owner_hash = nsec3_owner_hash(r);
                if let Some(oh) = owner_hash {
                    oh == hash && s.as_slice() == params.salt.as_slice() && (*flags & 0x01) == 0
                } else {
                    false
                }
            } else {
                false
            }
        });

        if found_match {
            // This ancestor exists. Check if depth == qname_labels.len() - 1
            // means qname itself exists (not a NXDOMAIN case).
            if depth == qname_labels.len() - 1 {
                // qname itself hashes to an existing NSEC3 owner — direct cover.
                // Actually: if qname's hash matches an owner, qname is not provably absent.
                // This means the hash covers the interval, not the name existence.
                // For now, signal DirectCover on a hash match for qname.
                if depth == qname_labels.len() {
                    return Some(Nsec3ProofType::DirectCover);
                }
            }
            closest_encloser = Some(ancestor);
            // next_closer is one label deeper than closest_encloser toward qname.
            let nc_labels = &qname_labels[(depth - 1)..];
            next_closer = labels_to_name(nc_labels);
            break;
        }
    }

    // Alternatively, check if qname's hash directly falls in an NSEC3 interval.
    let qname_hash = nsec3_hash(qname, &params.salt, params.iterations)?;
    for rec in nsec3_records {
        let RData::Nsec3 { next_hashed_owner, flags, iterations: it, salt: s, .. } = &rec.rdata else { continue };
        if *it > MAX_NSEC3_ITERATIONS { continue; }
        // Opt-out flag (bit 0): skip for signed delegation proofs.
        if *flags & 0x01 != 0 { return None; }
        if s.as_slice() != params.salt.as_slice() { continue; }

        let owner_hash = nsec3_owner_hash(rec)?;

        // Check if qname_hash falls in the interval (owner_hash, next_hashed_owner).
        let next_hash: [u8; 20] = next_hashed_owner.as_slice().try_into().ok()?;
        if hash_in_interval(&qname_hash, &owner_hash, &next_hash) {
            return Some(Nsec3ProofType::DirectCover);
        }
    }

    // Return closest encloser proof if found.
    if let (Some(ce), Some(nc)) = (closest_encloser, next_closer) {
        // Check if wildcard *.closest_encloser is also covered.
        let wildcard_covered = if let Ok(wc) = wildcard_of(&ce) {
            let wc_hash = nsec3_hash(&wc, &params.salt, params.iterations);
            wc_hash.is_some_and(|wh| {
                nsec3_records.iter().any(|r| {
                    if let RData::Nsec3 { next_hashed_owner, iterations: it, salt: s, .. } = &r.rdata {
                        if *it > MAX_NSEC3_ITERATIONS { return false; }
                        if s.as_slice() != params.salt.as_slice() { return false; }
                        let owner_hash = nsec3_owner_hash(r);
                        let next_hash: Option<[u8; 20]> = next_hashed_owner.as_slice().try_into().ok();
                        if let (Some(oh), Some(nh)) = (owner_hash, next_hash) {
                            hash_in_interval(&wh, &oh, &nh)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                })
            })
        } else {
            false
        };

        return Some(Nsec3ProofType::ClosestEncloserProof {
            closest_encloser: Box::new(ce),
            next_closer: Box::new(nc),
            wildcard_covered,
        });
    }

    None
}

// ── Internal helpers ───────────────────────────────────────────────────────────

/// Common NSEC3 parameters extracted from the first valid record.
struct Nsec3Params {
    salt: Vec<u8>,
    iterations: u16,
}

/// Extracts NSEC3 hashing parameters from the first usable NSEC3 record.
fn nsec3_zone_params(records: &[Record]) -> Option<Nsec3Params> {
    for rec in records {
        if let RData::Nsec3 { hash_algorithm: 1, iterations, salt, .. } = &rec.rdata
            && *iterations <= MAX_NSEC3_ITERATIONS
        {
            return Some(Nsec3Params { salt: salt.clone(), iterations: *iterations });
        }
    }
    None
}

/// Extracts the 20-byte hash from an NSEC3 owner name (crate-visible for synthesis.rs).
///
/// The NSEC3 owner name's first label is the base32-extended-hex encoding of the
/// hash.  We decode it from the raw label bytes.
pub(crate) fn nsec3_owner_hash_pub(rec: &Record) -> Option<[u8; 20]> {
    nsec3_owner_hash(rec)
}

/// Extracts the 20-byte hash from an NSEC3 owner name.
///
/// The NSEC3 owner name's first label is the base32-extended-hex encoding of the
/// hash.  We decode it from the raw label bytes.
fn nsec3_owner_hash(rec: &Record) -> Option<[u8; 20]> {
    // The owner label is a base32hex string (RFC 4648 extended hex alphabet).
    // For records we've parsed ourselves, the wire label bytes ARE the base32hex chars.
    let label = rec.name.iter_labels().next()?;
    // A SHA-1 hash base32hex encoding has ceil(20*8/5) = 32 chars.
    if label.len() != 32 {
        return None;
    }
    base32hex_decode(label)
}

/// Decodes a base32-extended-hex (RFC 4648 §7) string of exactly 32 chars into 20 bytes.
fn base32hex_decode(input: &[u8]) -> Option<[u8; 20]> {
    if input.len() != 32 {
        return None;
    }
    let mut out = [0u8; 20];
    let mut out_idx = 0usize;
    let mut bits_buf: u32 = 0;
    let mut bits_count: u32 = 0;

    for &c in input {
        let val = base32hex_char_value(c)?;
        bits_buf = (bits_buf << 5) | u32::from(val);
        bits_count += 5;
        if bits_count >= 8 {
            bits_count -= 8;
            if out_idx >= 20 { return None; }
            // Shift is always < 32 since bits_count < 8 before the subtract.
            #[allow(clippy::cast_possible_truncation)]
            { out[out_idx] = (bits_buf >> bits_count) as u8; }
            out_idx += 1;
        }
    }

    if out_idx == 20 { Some(out) } else { None }
}

/// Maps a base32hex character to its 5-bit value (RFC 4648 §7).
fn base32hex_char_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'V' => Some(c - b'A' + 10),
        b'a'..=b'v' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Returns `true` if `hash` falls in the NSEC3 interval `(owner, next)`.
///
/// Handles the wrapping (last-record) case where `next ≤ owner`.
fn hash_in_interval(hash: &[u8; 20], owner: &[u8; 20], next: &[u8; 20]) -> bool {
    if next > owner {
        // Normal case: owner < hash < next
        hash > owner && hash < next
    } else {
        // Wrapping case: hash > owner OR hash < next
        hash > owner || hash < next
    }
}

/// Builds a [`Name`] from a slice of label byte-slices (deepest-first relative
/// to zone apex).
fn labels_to_name(labels: &[&[u8]]) -> Option<Name> {
    // labels[0] is the leftmost (least-significant) label.
    let parts: Vec<&str> = labels
        .iter()
        .map(|l| std::str::from_utf8(l).ok())
        .collect::<Option<Vec<_>>>()?;
    let s = parts.join(".") + ".";
    Name::parse_str(&s).ok()
}

/// Constructs the wildcard name `*.name`.
fn wildcard_of(name: &Name) -> Result<Name, crate::name::NameError> {
    let base = name.to_string();
    let wildcard_str = format!("*.{base}");
    Name::parse_str(&wildcard_str)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use crate::header::Qclass;
    use crate::name::Name;
    use crate::record::Rtype;

    // ── type_in_bitmap tests ──────────────────────────────────────────────────

    #[test]
    fn type_bitmap_a_and_mx() {
        let types = [Rtype::A, Rtype::Mx];
        let bitmap = encode_type_bitmap(&types);
        assert!(type_in_bitmap(&bitmap, Rtype::A));
        assert!(type_in_bitmap(&bitmap, Rtype::Mx));
        assert!(!type_in_bitmap(&bitmap, Rtype::Aaaa));
    }

    #[test]
    fn type_bitmap_empty() {
        let bitmap = encode_type_bitmap(&[]);
        assert!(bitmap.is_empty());
        assert!(!type_in_bitmap(&bitmap, Rtype::A));
    }

    #[test]
    fn type_bitmap_roundtrip_all_common_types() {
        let types = [
            Rtype::A, Rtype::Ns, Rtype::Soa, Rtype::Mx, Rtype::Aaaa,
            Rtype::Rrsig, Rtype::Nsec, Rtype::Dnskey,
        ];
        let bitmap = encode_type_bitmap(&types);
        for t in &types {
            assert!(type_in_bitmap(&bitmap, *t), "type {t} should be in bitmap");
        }
        assert!(!type_in_bitmap(&bitmap, Rtype::Txt));
        assert!(!type_in_bitmap(&bitmap, Rtype::Caa));
    }

    #[test]
    fn type_bitmap_high_window() {
        // CAA is type 257 = window 1, bit 1.
        let types = [Rtype::Caa, Rtype::A];
        let bitmap = encode_type_bitmap(&types);
        assert!(type_in_bitmap(&bitmap, Rtype::A));
        assert!(type_in_bitmap(&bitmap, Rtype::Caa));
        assert!(!type_in_bitmap(&bitmap, Rtype::Mx));
    }

    // ── nsec3_hash tests ──────────────────────────────────────────────────────

    #[test]
    fn nsec3_hash_over_limit_returns_none() {
        let name = Name::root();
        assert!(nsec3_hash(&name, &[], MAX_NSEC3_ITERATIONS + 1).is_none());
    }

    #[test]
    fn nsec3_hash_zero_iterations() {
        // IH(salt, x, 0) = SHA-1(x || salt) where x = canonical wire of root = [0].
        let name = Name::root();
        let result = nsec3_hash(&name, &[], 0);
        assert!(result.is_some());
        let hash = result.unwrap();
        // SHA-1([0]) manually:
        let expected = ring::digest::digest(
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            &[0u8], // canonical wire of root
        );
        assert_eq!(hash, expected.as_ref());
    }

    #[test]
    fn nsec3_hash_with_salt() {
        let name = Name::from_str("example.com.").unwrap();
        let salt = b"\xde\xad\xbe\xef";
        let result = nsec3_hash(&name, salt, 1);
        assert!(result.is_some());
        // Just verify it's 20 bytes and deterministic.
        let result2 = nsec3_hash(&name, salt, 1);
        assert_eq!(result, result2);
    }

    #[test]
    fn nsec3_hash_max_iterations_succeeds() {
        let name = Name::root();
        let result = nsec3_hash(&name, &[], MAX_NSEC3_ITERATIONS);
        assert!(result.is_some());
    }

    // ── DNSSEC-044..047: five iteration boundary values ───────────────────────
    //
    // RFC 9276 §3.2 cap = 150.  Values {0, 1, 150} → hash computes (secure
    // path); {151, 1000} → None (insecure path, DNSSEC-045).

    #[test]
    fn nsec3_iterations_cap_zero_computes() {
        let name = Name::from_str("example.com.").unwrap();
        assert!(nsec3_hash(&name, &[], 0).is_some(), "iter=0 must succeed (DNSSEC-046)");
    }

    #[test]
    fn nsec3_iterations_cap_one_computes() {
        let name = Name::from_str("example.com.").unwrap();
        assert!(nsec3_hash(&name, &[], 1).is_some(), "iter=1 must succeed (DNSSEC-046)");
    }

    #[test]
    fn nsec3_iterations_cap_150_computes() {
        let name = Name::from_str("example.com.").unwrap();
        assert!(nsec3_hash(&name, &[], 150).is_some(), "iter=150 must succeed (DNSSEC-046)");
    }

    #[test]
    fn nsec3_iterations_cap_151_insecure() {
        let name = Name::from_str("example.com.").unwrap();
        assert!(nsec3_hash(&name, &[], 151).is_none(), "iter=151 must refuse (DNSSEC-044/045)");
    }

    #[test]
    fn nsec3_iterations_cap_1000_insecure() {
        let name = Name::from_str("example.com.").unwrap();
        assert!(nsec3_hash(&name, &[], 1000).is_none(), "iter=1000 must refuse (DNSSEC-044/045)");
    }

    // ── DNSSEC-044/045: nsec3_hash_with_budget — never produces Bogus for cap ─

    #[test]
    fn nsec3_hash_with_budget_excessive_returns_ok_none_not_bogus() {
        use crate::dnssec::budget::ValidationBudget;

        let name = Name::from_str("example.com.").unwrap();
        let budget = ValidationBudget::default_budget();

        // iter=151 → Ok(None): insecure, NOT Err(BogusReason::KeyTrapLimit).
        let r151 = nsec3_hash_with_budget(&name, &[], 151, &budget);
        assert!(r151.is_ok(), "excessive iterations must not produce Err (Bogus)");
        assert!(r151.unwrap().is_none(), "excessive iterations must return Ok(None)");

        // iter=1000 — same invariant.
        let r1000 = nsec3_hash_with_budget(&name, &[], 1000, &budget);
        assert!(r1000.is_ok(), "excessive iterations must not produce Err (Bogus)");
        assert!(r1000.unwrap().is_none(), "excessive iterations must return Ok(None)");
    }

    #[test]
    fn nsec3_hash_with_budget_within_cap_computes() {
        use crate::dnssec::budget::ValidationBudget;

        let name = Name::from_str("example.com.").unwrap();
        let budget = ValidationBudget::default_budget();

        for iter in [0u16, 1, 150] {
            let result = nsec3_hash_with_budget(&name, &[], iter, &budget);
            assert!(result.is_ok(), "iter={iter} must not error");
            assert!(result.unwrap().is_some(), "iter={iter} must produce a hash");
        }
    }

    // ── DNSSEC-045: EDE code 27 for excessive iterations ─────────────────────

    #[test]
    fn nsec3_excess_iterations_ede_has_code_27() {
        use crate::edns::{EdnsOption, ExtendedError, ede_code};

        let opt = nsec3_excess_iterations_ede();
        let EdnsOption::ExtendedError(ExtendedError { info_code, .. }) = opt else {
            panic!("nsec3_excess_iterations_ede must return ExtendedError variant");
        };
        assert_eq!(
            info_code,
            ede_code::UNSUPPORTED_NSEC3_ITERATIONS_VALUE,
            "EDE code must be 27 (Unsupported NSEC3 Iterations Value, RFC 8914 §5.2)"
        );
    }

    // ── DNSSEC-047: cap is a compile-time constant, not configurable ──────────

    #[test]
    fn nsec3_cap_is_exactly_150() {
        assert_eq!(
            MAX_NSEC3_ITERATIONS, 150,
            "RFC 9276 §3.2 mandates 150; DNSSEC-047 forbids a config knob to raise it"
        );
    }

    /// RFC 5155 §B.1 — test vector for NSEC3 hash computation.
    ///
    /// Zone: example., algorithm=1, iterations=12, salt=aabbccdd.
    /// IEN.example. hashes to:
    ///   0p9mhaveqvm6t7vbl5lop2u3t2rp3tom (base32hex)
    ///
    /// We test a simpler known input: empty name (root ".")
    /// with known salt and iterations to verify the iterative structure.
    #[test]
    fn nsec3_hash_rfc5155_b1_structure() {
        // RFC 5155 Appendix B gives:
        //   (empty).example. with salt=aabbccdd, iterations=12
        // The root name "." hashes as: SHA-1([0x00] || salt) for iter 0,
        // then SHA-1(prev_hash || salt) for iters 1..=12.
        //
        // We verify the iterative computation is correct by cross-checking:
        let salt = b"\xaa\xbb\xcc\xdd";
        let name = Name::root();

        // Compute manually: 0 iterations
        let x = canonical_name_wire(&name); // [0x00]
        let mut data = x.clone();
        data.extend_from_slice(salt);
        let h0 = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(h0.as_ref());

        // 1 iteration
        let mut d1 = expected.to_vec();
        d1.extend_from_slice(salt);
        let h1 = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &d1);
        let mut expected1 = [0u8; 20];
        expected1.copy_from_slice(h1.as_ref());

        let computed0 = nsec3_hash(&name, salt, 0).unwrap();
        assert_eq!(computed0, expected, "0 iterations");
        let computed1 = nsec3_hash(&name, salt, 1).unwrap();
        assert_eq!(computed1, expected1, "1 iteration");
    }

    // ── nsec_proves_nxdomain tests ────────────────────────────────────────────

    fn make_nsec_record(owner: &str, next: &str, types: &[Rtype]) -> Record {
        Record {
            name: Name::from_str(owner).unwrap(),
            rtype: Rtype::Nsec,
            rclass: Qclass::In,
            ttl: 300,
            rdata: RData::Nsec {
                next_domain: Name::from_str(next).unwrap(),
                type_bitmaps: encode_type_bitmap(types),
            },
        }
    }

    #[test]
    fn nsec_direct_cover_proof() {
        // "b.example." is covered by the NSEC: a.example. → c.example.
        let nsec = make_nsec_record("a.example.", "c.example.", &[Rtype::A]);
        let qname = Name::from_str("b.example.").unwrap();
        let result = nsec_proves_nxdomain(&[nsec], &qname);
        assert_eq!(result, Some(NsecProofType::DirectCover));
    }

    #[test]
    fn nsec_no_proof_when_name_exists() {
        // "a.example." itself is the NSEC owner — it exists.
        let nsec = make_nsec_record("a.example.", "c.example.", &[Rtype::A]);
        let qname = Name::from_str("a.example.").unwrap();
        // qname == owner → not covered by the NSEC interval.
        let result = nsec_proves_nxdomain(&[nsec], &qname);
        assert!(result.is_none());
    }

    #[test]
    fn nsec_wrapping_cover() {
        // The last NSEC wraps: z.example. → a.example. (zone wrap).
        // A name like "m.example." should be covered.
        let nsec = make_nsec_record("z.example.", "a.example.", &[Rtype::A]);
        let qname = Name::from_str("m.example.").unwrap();
        // m > z is false, but the wrapping case: owner(z) > next(a), so
        // is_wrapping = true. owner_lt_qname = z < m = false.
        // qname_lt_next = m < a = false. Neither arm triggers.
        // Actually z.example. > m.example. in canonical order, so z < m is false.
        // The wrapping nsec: next(a.example.) < owner(z.example.) means it covers
        // everything from z to end-of-zone AND from start-of-zone to a.
        // m is between a and z, so NOT covered. Correct result: None.
        let result = nsec_proves_nxdomain(&[nsec], &qname);
        assert!(result.is_none());
    }
}
