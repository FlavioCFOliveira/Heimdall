// SPDX-License-Identifier: MIT

//! DNSSEC test-zone generators (Sprint 47 task #473).
//!
//! Three zone variants, all produced with a fresh Ed25519 key pair generated
//! at test time using `ring`:
//!
//! - **valid** (`generate_valid_zone`): real Ed25519 signatures via `ring` +
//!   `rrset_signing_input`.  A DNSSEC-validating resolver must return
//!   `ValidationOutcome::Secure` for queries into these zones.
//! - **bogus** (`generate_bogus_zone`): identical structure, but all RRSIG
//!   signature bytes are zeroed — any conformant validator must return `Bogus`.
//! - **insecure** (`generate_insecure_zone`): no DNSSEC records (no DNSKEY,
//!   no RRSIG) — validators must return `Insecure`.
//!
//! A fresh key pair is generated per `generate_valid_zone` / `generate_bogus_zone`
//! call; the DNSKEY public key in the zone always matches the signing key.

use std::net::Ipv4Addr;
use std::str::FromStr as _;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use heimdall_core::dnssec::{RsigFields, encode_type_bitmap, rrset_signing_input};
use heimdall_core::header::Qclass;
use heimdall_core::name::Name;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};

// ── DNSKEY parameters ─────────────────────────────────────────────────────────

/// DNSKEY flags: Zone Key (bit 8 set per RFC 4034 §2.1.1) — ZSK.
const DNSKEY_FLAGS: u16 = 256;
const DNSKEY_PROTOCOL: u8 = 3;
/// Algorithm 15 = Ed25519 (RFC 8080).
const DNSKEY_ALGORITHM: u8 = 15;

// ── Validity window ───────────────────────────────────────────────────────────

/// Signature inception: Unix 1_000_000_000 = 2001-09-09T01:46:40Z
const SIG_INCEPTION_SECS: u32 = 1_000_000_000;
/// Signature expiration: Unix 2_000_000_000 = 2033-05-18T03:33:20Z
const SIG_EXPIRATION_SECS: u32 = 2_000_000_000;

const SIG_INCEPTION_STR: &str = "20010909014640";
const SIG_EXPIRATION_STR: &str = "20330518033320";

// ── TTL and serial ────────────────────────────────────────────────────────────

const ZONE_TTL: u32 = 300;
const ZONE_SERIAL: u32 = 2024010101;

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a DNSSEC-signed zone file for `origin` with real Ed25519 signatures.
///
/// A fresh key pair is generated using `ring::rand::SystemRandom` so the
/// DNSKEY and RRSIG bytes are always consistent.
pub fn generate_valid_zone(origin: &str) -> String {
    build_zone(origin, false)
}

/// Generate a deliberately broken DNSSEC zone file for `origin`.
///
/// Zone structure is identical to `generate_valid_zone`, but all RRSIG
/// signature bytes are zeroed — a conformant validator must return `Bogus`.
pub fn generate_bogus_zone(origin: &str) -> String {
    build_zone(origin, true)
}

/// Generate an unsigned (insecure) zone file for `origin`.
///
/// No DNSKEY or RRSIG records are present.
pub fn generate_insecure_zone(origin: &str) -> String {
    format!(
        r#"; {origin} — unsigned (insecure) test zone
$ORIGIN {origin}
$TTL {ZONE_TTL}

@  IN SOA  ns1 hostmaster (
              {ZONE_SERIAL} ; serial
              3600          ; refresh
              900           ; retry
              604800        ; expire
              300 )         ; minimum TTL

@     IN NS    ns1.{origin}
ns1   IN A     127.0.0.1
host  IN A     192.0.2.1
"#
    )
}

/// Generate a DNSSEC-signed zone file for `origin` that includes NSEC records.
///
/// The zone contains three names in canonical order:
/// `{origin}` → `host.{origin}` → `ns1.{origin}` → (wraps back to `{origin}`).
/// Each name has a corresponding NSEC record and a valid RRSIG covering it.
///
/// This variant is used by E2E tests that verify aggressive NSEC synthesis
/// (RFC 8198): the recursive resolver must synthesize NXDOMAIN responses for
/// names provably absent from the NSEC chain without issuing upstream queries.
pub fn generate_nsec_zone(origin: &str) -> String {
    // Generate a fresh Ed25519 key pair for this zone invocation.
    let rng = SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("INVARIANT: Ed25519 key generation succeeded");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
        .expect("INVARIANT: Ed25519 key pair construction succeeded");
    let public_key: Vec<u8> = key_pair.public_key().as_ref().to_vec();

    let dnskey_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
    let key_tag = compute_key_tag(DNSKEY_FLAGS, DNSKEY_PROTOCOL, DNSKEY_ALGORITHM, &public_key);

    // Canonical name ordering: apex < host.{origin} < ns1.{origin}
    // ('h' < 'n' alphabetically at the leftmost label).
    let origin_name = Name::from_str(origin).expect("INVARIANT: valid zone origin");
    let apex_labels = count_labels(&origin_name);

    let ns1_name = Name::from_str(&format!("ns1.{origin}"))
        .expect("INVARIANT: valid ns1 name");
    let hostmaster_name = Name::from_str(&format!("hostmaster.{origin}"))
        .expect("INVARIANT: valid hostmaster name");
    let host_name = Name::from_str(&format!("host.{origin}"))
        .expect("INVARIANT: valid host name");
    let host_labels = count_labels(&host_name);
    let ns1_labels = count_labels(&ns1_name);

    // ── Build base RRsets ─────────────────────────────────────────────────────

    let soa_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Soa,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Soa {
            mname: ns1_name.clone(),
            rname: hostmaster_name,
            serial: ZONE_SERIAL,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: ZONE_TTL,
        },
    }];

    let ns_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Ns,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Ns(ns1_name.clone()),
    }];

    let dnskey_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Dnskey,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Dnskey {
            flags: DNSKEY_FLAGS,
            protocol: DNSKEY_PROTOCOL,
            algorithm: DNSKEY_ALGORITHM,
            public_key: public_key.clone(),
        },
    }];

    let host_a_rrset = vec![Record {
        name: host_name.clone(),
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    }];

    // ── Build NSEC RRsets ─────────────────────────────────────────────────────
    // Canonical NSEC chain (RFC 4034 §6.1):
    //   apex  → host  (apex covers NS SOA RRSIG NSEC DNSKEY)
    //   host  → ns1   (host  covers A RRSIG)
    //   ns1   → apex  (ns1   covers A RRSIG — wraps)

    let apex_nsec_types = &[Rtype::Ns, Rtype::Soa, Rtype::Rrsig, Rtype::Nsec, Rtype::Dnskey];
    let host_nsec_types = &[Rtype::A, Rtype::Rrsig];
    let ns1_nsec_types = &[Rtype::A, Rtype::Rrsig];

    let apex_nsec_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Nsec,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Nsec {
            next_domain: host_name.clone(),
            type_bitmaps: encode_type_bitmap(apex_nsec_types),
        },
    }];

    let host_nsec_rrset = vec![Record {
        name: host_name.clone(),
        rtype: Rtype::Nsec,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Nsec {
            next_domain: ns1_name.clone(),
            type_bitmaps: encode_type_bitmap(host_nsec_types),
        },
    }];

    let ns1_nsec_rrset = vec![Record {
        name: ns1_name.clone(),
        rtype: Rtype::Nsec,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Nsec {
            next_domain: origin_name.clone(),
            type_bitmaps: encode_type_bitmap(ns1_nsec_types),
        },
    }];

    // ── Sign all RRsets (bogus=false — real signatures) ───────────────────────

    let soa_sig = sign_rrset_or_zeros(
        &soa_rrset, Rtype::Soa, apex_labels, &origin_name, key_tag, false, &key_pair,
    );
    let ns_sig = sign_rrset_or_zeros(
        &ns_rrset, Rtype::Ns, apex_labels, &origin_name, key_tag, false, &key_pair,
    );
    let dnskey_sig = sign_rrset_or_zeros(
        &dnskey_rrset, Rtype::Dnskey, apex_labels, &origin_name, key_tag, false, &key_pair,
    );
    let host_a_sig = sign_rrset_or_zeros(
        &host_a_rrset, Rtype::A, host_labels, &origin_name, key_tag, false, &key_pair,
    );
    let apex_nsec_sig = sign_rrset_or_zeros(
        &apex_nsec_rrset, Rtype::Nsec, apex_labels, &origin_name, key_tag, false, &key_pair,
    );
    let host_nsec_sig = sign_rrset_or_zeros(
        &host_nsec_rrset, Rtype::Nsec, host_labels, &origin_name, key_tag, false, &key_pair,
    );
    let ns1_nsec_sig = sign_rrset_or_zeros(
        &ns1_nsec_rrset, Rtype::Nsec, ns1_labels, &origin_name, key_tag, false, &key_pair,
    );

    let soa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&soa_sig);
    let ns_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&ns_sig);
    let dnskey_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&dnskey_sig);
    let host_a_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&host_a_sig);
    let apex_nsec_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&apex_nsec_sig);
    let host_nsec_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&host_nsec_sig);
    let ns1_nsec_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&ns1_nsec_sig);

    // Render type lists for the NSEC text records.
    let apex_nsec_types_str = "NS SOA RRSIG NSEC DNSKEY";
    let host_nsec_types_str = "A RRSIG";
    let ns1_nsec_types_str = "A RRSIG";

    format!(
        r#"; {origin} — DNSSEC+NSEC test zone (Sprint 47 task #542)
; Algorithm 15 (Ed25519), key tag {key_tag}
$ORIGIN {origin}
$TTL {ZONE_TTL}

@  IN SOA  ns1 hostmaster (
              {ZONE_SERIAL} ; serial
              3600          ; refresh
              900           ; retry
              604800        ; expire
              300 )         ; minimum TTL

@     IN NS    ns1.{origin}
ns1   IN A     127.0.0.1
host  IN A     192.0.2.1

; DNSKEY (ZSK, Algorithm 15 / Ed25519, RFC 8080)
@     IN DNSKEY {DNSKEY_FLAGS} {DNSKEY_PROTOCOL} {DNSKEY_ALGORITHM} ( {dnskey_b64} )

; RRSIG covering SOA
@     IN RRSIG SOA {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {soa_sig_b64} )

; RRSIG covering DNSKEY
@     IN RRSIG DNSKEY {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {dnskey_sig_b64} )

; RRSIG covering NS
@     IN RRSIG NS {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {ns_sig_b64} )

; RRSIG covering A at host
host  IN RRSIG A {DNSKEY_ALGORITHM} {host_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {host_a_sig_b64} )

; NSEC chain: apex → host → ns1 → apex (RFC 4034 §6.1)
@     IN NSEC host.{origin} {apex_nsec_types_str}
host  IN NSEC ns1.{origin}  {host_nsec_types_str}
ns1   IN NSEC {origin}      {ns1_nsec_types_str}

; RRSIG covering NSEC at apex
@     IN RRSIG NSEC {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {apex_nsec_sig_b64} )

; RRSIG covering NSEC at host
host  IN RRSIG NSEC {DNSKEY_ALGORITHM} {host_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {host_nsec_sig_b64} )

; RRSIG covering NSEC at ns1
ns1   IN RRSIG NSEC {DNSKEY_ALGORITHM} {ns1_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {ns1_nsec_sig_b64} )
"#,
        DNSKEY_FLAGS = DNSKEY_FLAGS,
        DNSKEY_PROTOCOL = DNSKEY_PROTOCOL,
        DNSKEY_ALGORITHM = DNSKEY_ALGORITHM,
        ZONE_TTL = ZONE_TTL,
        ZONE_SERIAL = ZONE_SERIAL,
        SIG_EXPIRATION_STR = SIG_EXPIRATION_STR,
        SIG_INCEPTION_STR = SIG_INCEPTION_STR,
    )
}

// ── Zone builder ──────────────────────────────────────────────────────────────

fn build_zone(origin: &str, bogus: bool) -> String {
    // Generate a fresh Ed25519 key pair.  ring::rand::SystemRandom supplies
    // cryptographically secure entropy.  The key is scoped to this single
    // test zone file and is never persisted or reused.
    let rng = SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("INVARIANT: Ed25519 key generation succeeded");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
        .expect("INVARIANT: Ed25519 key pair construction succeeded");
    let public_key: Vec<u8> = key_pair.public_key().as_ref().to_vec();

    let dnskey_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);
    let key_tag = compute_key_tag(DNSKEY_FLAGS, DNSKEY_PROTOCOL, DNSKEY_ALGORITHM, &public_key);

    let origin_name = Name::from_str(origin).expect("INVARIANT: valid zone origin");
    let apex_labels = count_labels(&origin_name);

    let ns1_name = Name::from_str(&format!("ns1.{origin}"))
        .expect("INVARIANT: valid ns1 name");
    let hostmaster_name = Name::from_str(&format!("hostmaster.{origin}"))
        .expect("INVARIANT: valid hostmaster name");
    let host_name = Name::from_str(&format!("host.{origin}"))
        .expect("INVARIANT: valid host name");
    let host_labels = count_labels(&host_name);

    // ── Build RRsets for signing ──────────────────────────────────────────────

    let soa_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Soa,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Soa {
            mname: ns1_name.clone(),
            rname: hostmaster_name,
            serial: ZONE_SERIAL,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: ZONE_TTL,
        },
    }];

    let ns_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Ns,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Ns(ns1_name),
    }];

    let dnskey_rrset = vec![Record {
        name: origin_name.clone(),
        rtype: Rtype::Dnskey,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::Dnskey {
            flags: DNSKEY_FLAGS,
            protocol: DNSKEY_PROTOCOL,
            algorithm: DNSKEY_ALGORITHM,
            public_key: public_key.clone(),
        },
    }];

    let a_rrset = vec![Record {
        name: host_name,
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: ZONE_TTL,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    }];

    // ── Sign (or zero-fill for bogus) ─────────────────────────────────────────

    let soa_sig = sign_rrset_or_zeros(
        &soa_rrset, Rtype::Soa, apex_labels, &origin_name, key_tag, bogus, &key_pair,
    );
    let ns_sig = sign_rrset_or_zeros(
        &ns_rrset, Rtype::Ns, apex_labels, &origin_name, key_tag, bogus, &key_pair,
    );
    let dnskey_sig = sign_rrset_or_zeros(
        &dnskey_rrset, Rtype::Dnskey, apex_labels, &origin_name, key_tag, bogus, &key_pair,
    );
    let a_sig = sign_rrset_or_zeros(
        &a_rrset, Rtype::A, host_labels, &origin_name, key_tag, bogus, &key_pair,
    );

    let soa_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&soa_sig);
    let ns_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&ns_sig);
    let dnskey_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&dnskey_sig);
    let a_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&a_sig);

    format!(
        r#"; {origin} — DNSSEC test zone (Sprint 47 task #473), bogus={bogus}
; Algorithm 15 (Ed25519), key tag {key_tag}
$ORIGIN {origin}
$TTL {ZONE_TTL}

@  IN SOA  ns1 hostmaster (
              {ZONE_SERIAL} ; serial
              3600          ; refresh
              900           ; retry
              604800        ; expire
              300 )         ; minimum TTL

@     IN NS    ns1.{origin}
ns1   IN A     127.0.0.1
host  IN A     192.0.2.1

; DNSKEY (ZSK, Algorithm 15 / Ed25519, RFC 8080)
@     IN DNSKEY {DNSKEY_FLAGS} {DNSKEY_PROTOCOL} {DNSKEY_ALGORITHM} ( {dnskey_b64} )

; RRSIG covering SOA
@     IN RRSIG SOA {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {soa_sig_b64} )

; RRSIG covering DNSKEY
@     IN RRSIG DNSKEY {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {dnskey_sig_b64} )

; RRSIG covering NS
@     IN RRSIG NS {DNSKEY_ALGORITHM} {apex_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {ns_sig_b64} )

; RRSIG covering A at host
host  IN RRSIG A {DNSKEY_ALGORITHM} {host_labels} {ZONE_TTL} {SIG_EXPIRATION_STR} (
              {SIG_INCEPTION_STR} {key_tag} {origin} {a_sig_b64} )
"#,
        DNSKEY_FLAGS = DNSKEY_FLAGS,
        DNSKEY_PROTOCOL = DNSKEY_PROTOCOL,
        DNSKEY_ALGORITHM = DNSKEY_ALGORITHM,
        ZONE_TTL = ZONE_TTL,
        ZONE_SERIAL = ZONE_SERIAL,
        SIG_EXPIRATION_STR = SIG_EXPIRATION_STR,
        SIG_INCEPTION_STR = SIG_INCEPTION_STR,
    )
}

// ── Signing ───────────────────────────────────────────────────────────────────

fn sign_rrset_or_zeros(
    rrset: &[Record],
    type_covered: Rtype,
    labels: u8,
    signer_name: &Name,
    key_tag: u16,
    bogus: bool,
    key_pair: &Ed25519KeyPair,
) -> Vec<u8> {
    if bogus {
        return vec![0u8; 64];
    }

    let rrsig_fields = RsigFields {
        type_covered,
        algorithm: DNSKEY_ALGORITHM,
        labels,
        original_ttl: ZONE_TTL,
        sig_expiration: SIG_EXPIRATION_SECS,
        sig_inception: SIG_INCEPTION_SECS,
        key_tag,
        signer_name: signer_name.clone(),
    };

    let signing_input = rrset_signing_input(&rrsig_fields, rrset);
    key_pair.sign(&signing_input).as_ref().to_vec()
}

// ── Key tag ───────────────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Count the number of non-root labels in `name`.
fn count_labels(name: &Name) -> u8 {
    let wire = name.as_wire_bytes();
    let mut count = 0u8;
    let mut pos = 0;
    while pos < wire.len() {
        let len = wire[pos] as usize;
        if len == 0 {
            break;
        }
        count = count.saturating_add(1);
        pos += 1 + len;
    }
    count
}
