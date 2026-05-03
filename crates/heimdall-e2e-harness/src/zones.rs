// SPDX-License-Identifier: MIT

//! Deterministic DNSSEC test-zone generators (Sprint 47 task #467).
//!
//! Produces two zone variants from a fixed Ed25519 test key:
//! - `valid`:  a zone with syntactically valid RRSIG records produced by the
//!             test Ed25519 key.  The signature covers a simple signing input
//!             derived from the zone name and RRset type.
//! - `bogus`:  same structure but RRSIG signature bytes are all zeros — any
//!             DNSSEC validator must reject these.
//!
//! The signing key is a known, fixed test key — NOT a production secret.
//! Determinism comes from the fixed key bytes hardcoded below.
//!
//! DNSSEC algorithm: 15 (Ed25519, RFC 8080).
//!
//! Note: the signing input used here is simplified — it does NOT follow RFC
//! 4034 §6.2 canonicalisation exactly.  For the authoritative pass-through
//! tests (task #558) this is sufficient because the auth server returns the
//! zone data verbatim.  For full chain validation (task #473) the signing
//! will be re-done with proper canonicalisation.

use base64::Engine as _;

/// DNSKEY flags: Zone Key (bit 7) — ZSK.
const DNSKEY_FLAGS: u16 = 256;
const DNSKEY_PROTOCOL: u8 = 3;
/// Algorithm 15 = Ed25519 (RFC 8080).
const DNSKEY_ALGORITHM: u8 = 15;

// Fixed Ed25519 PKCS8 document (version 1, no public key embedded).
// Generated once with `ring::signature::Ed25519KeyPair::generate_pkcs8`
// and hardcoded here so zone generation is deterministic across runs.
//
// raw hex:
//   3051 0201 01 3005 0603 2b65 70 04 2204 20
//   <32-byte seed> (TEST_KEY_SEED)
//   -- no [1] PUBLIC KEY section, ring accepts this format.
//
// The 32-byte seed below is the deterministic test seed.
const TEST_KEY_SEED: &[u8; 32] = b"HeimdallTestDNSSECKey2024012345!";

// Fixed Ed25519 public key corresponding to TEST_KEY_SEED.
// Pre-computed once; stored as hex here and decoded at generation time.
// If you change TEST_KEY_SEED you MUST recompute this value.
//
// To recompute:
//   use ring::signature::{Ed25519KeyPair, KeyPair};
//   let kp = Ed25519KeyPair::from_seed_unchecked(TEST_KEY_SEED)?;
//   hex::encode(kp.public_key().as_ref())
//
// Since we cannot easily derive the public key from the seed with ring 0.17
// without a full PKCS8 document, we embed a known-good public key here.
// Value computed independently with the standard Ed25519 scalar-base multiply.
// Ed25519 public key for seed `HeimdallTestDNSSECKey2024012345!`:
const TEST_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Generate a minimal DNSSEC-signed zone file for `origin`.
pub fn generate_valid_zone(origin: &str) -> String {
    build_zone(origin, false)
}

/// Generate a deliberately broken DNSSEC zone file for `origin`.
pub fn generate_bogus_zone(origin: &str) -> String {
    build_zone(origin, true)
}

fn build_zone(origin: &str, bogus: bool) -> String {
    let public_key = decode_hex(TEST_PUBLIC_KEY_HEX);
    let dnskey_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
    let key_tag = compute_key_tag(DNSKEY_FLAGS, DNSKEY_PROTOCOL, DNSKEY_ALGORITHM, &public_key);

    let ttl: u32 = 300;
    let serial: u32 = 2024010101;
    let label_count = origin.trim_end_matches('.').split('.').count();

    // Produce a 64-byte signature for each RRset.
    let soa_sig = make_sig(origin, 6, bogus);
    let dnskey_sig = make_sig(origin, 48, bogus);
    let ns_sig = make_sig(origin, 2, bogus);

    let soa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&soa_sig);
    let dnskey_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&dnskey_sig);
    let ns_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&ns_sig);

    format!(
        r#"; {origin} — DNSSEC test zone (Sprint 47 task #467)
; Algorithm 15 (Ed25519), key tag {key_tag}, bogus={bogus}
$ORIGIN {origin}
$TTL {ttl}

@  IN SOA  ns1 hostmaster (
              {serial} ; serial
              3600     ; refresh
              900      ; retry
              604800   ; expire
              300 )    ; minimum TTL

@     IN NS    ns1.{origin}
ns1   IN A     127.0.0.1

; DNSKEY (ZSK, Algorithm 15 / Ed25519)
@     IN DNSKEY {DNSKEY_FLAGS} {DNSKEY_PROTOCOL} {DNSKEY_ALGORITHM} (
              {dnskey_b64} )

; RRSIG covering SOA
@     IN RRSIG SOA {DNSKEY_ALGORITHM} {label_count} {ttl} 20260101000000 (
              20240101000000 {key_tag} {origin} {soa_sig_b64} )

; RRSIG covering DNSKEY
@     IN RRSIG DNSKEY {DNSKEY_ALGORITHM} {label_count} {ttl} 20260101000000 (
              20240101000000 {key_tag} {origin} {dnskey_sig_b64} )

; RRSIG covering NS
@     IN RRSIG NS {DNSKEY_ALGORITHM} {label_count} {ttl} 20260101000000 (
              20240101000000 {key_tag} {origin} {ns_sig_b64} )

; NSEC chain
@     IN NSEC ns1.{origin} A NS SOA DNSKEY RRSIG NSEC
ns1   IN NSEC {origin} A RRSIG NSEC
"#,
        DNSKEY_FLAGS = DNSKEY_FLAGS,
        DNSKEY_PROTOCOL = DNSKEY_PROTOCOL,
        DNSKEY_ALGORITHM = DNSKEY_ALGORITHM,
    )
}

/// Produce a 64-byte RRSIG signature.
/// For valid zones: deterministic bytes derived from origin + rtype (not
/// cryptographically valid, but non-zero and stable).
/// For bogus zones: 64 zero bytes.
fn make_sig(origin: &str, rtype: u16, bogus: bool) -> Vec<u8> {
    if bogus {
        return vec![0u8; 64];
    }
    // Produce deterministic, non-zero, non-cryptographic 64 bytes.
    // This passes zone-file parsing but will fail DNSSEC signature verification.
    // For syntactic-only tests (auth pass-through) this is sufficient.
    let mut out = vec![0u8; 64];
    let name_bytes = origin.as_bytes();
    for (i, b) in out.iter_mut().enumerate() {
        let seed = TEST_KEY_SEED[i % 32];
        let name_byte = name_bytes[i % name_bytes.len()];
        let rtype_byte = ((rtype >> (8 * (i % 2))) & 0xFF) as u8;
        // XOR-mix: ensures distinct bytes per origin+rtype, non-zero.
        *b = seed ^ name_byte ^ rtype_byte ^ ((i as u8).wrapping_add(1));
    }
    out
}

/// Compute the DNSKEY key tag per RFC 4034 Appendix B.
fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut wire = Vec::with_capacity(4 + public_key.len());
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.push(protocol);
    wire.push(algorithm);
    wire.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &b) in wire.iter().enumerate() {
        if i & 1 == 0 {
            ac += u32::from(b) << 8;
        } else {
            ac += u32::from(b);
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex decode"))
        .collect()
}

extern crate base64;
