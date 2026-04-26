// SPDX-License-Identifier: MIT

//! Property-based roundtrip tests: serialise → parse must be an identity
//! transformation for all valid [`Message`] values.
//!
//! Run with:
//! ```text
//! cargo test -p heimdall-core --test proptest_roundtrip
//! ```
//!
//! The number of test cases is controlled by the `PROPTEST_CASES` environment
//! variable (default: 256).

use std::str::FromStr;

use heimdall_core::header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
use heimdall_core::name::Name;
use heimdall_core::parser::Message;
use heimdall_core::rdata::RData;
use heimdall_core::record::{Record, Rtype};
use heimdall_core::serialiser::Serialiser;
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ── Name strategies ───────────────────────────────────────────────────────────

/// Generates a valid single DNS label (1–8 alphanumeric ASCII bytes).
fn arb_label() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(b'a'..=b'z', 1..=8)
}

/// Generates a valid [`Name`] with 0–5 labels of 1–8 bytes each.
///
/// Total wire length is guaranteed ≤ 255 bytes because 5 × (1 + 8) + 1 = 46.
fn arb_name() -> impl Strategy<Value = Name> {
    proptest::collection::vec(arb_label(), 0..=5).prop_map(|labels| {
        if labels.is_empty() {
            return Name::root();
        }
        // Build by joining labels with dots and parsing.
        let s = labels
            .iter()
            .map(|l| std::str::from_utf8(l).unwrap_or("a"))
            .collect::<Vec<_>>()
            .join(".");
        // parse_str is infallible for valid labels of ≤ 8 bytes.
        Name::from_str(&s).unwrap_or_else(|_| Name::root())
    })
}

// ── Header strategies ─────────────────────────────────────────────────────────

/// Generates a valid [`Header`] with consistent counts (set to 0; counts are
/// overridden by [`arb_message`]).
fn arb_header() -> impl Strategy<Value = Header> {
    (
        any::<u16>(),           // id
        any::<bool>(),          // qr
        0u8..=6u8,              // opcode raw
        any::<bool>(),          // aa
        any::<bool>(),          // tc
        any::<bool>(),          // rd
        any::<bool>(),          // ra
        any::<bool>(),          // ad
        any::<bool>(),          // cd
        0u8..=10u8,             // rcode raw
    )
        .prop_map(|(id, qr, opcode_raw, aa, tc, rd, ra, ad, cd, rcode_raw)| {
            let mut h = Header::default();
            h.id = id;
            h.set_qr(qr);
            h.set_opcode(Opcode::from_u8(opcode_raw));
            h.set_aa(aa);
            h.set_tc(tc);
            h.set_rd(rd);
            h.set_ra(ra);
            h.set_ad(ad);
            h.set_cd(cd);
            h.set_rcode(Rcode::from_u8(rcode_raw));
            h
        })
}

// ── Question strategies ───────────────────────────────────────────────────────

/// Generates a valid [`Question`].
fn arb_question() -> impl Strategy<Value = Question> {
    (arb_name(), 0u16..=65u16, 1u16..=4u16).prop_map(|(qname, qtype_raw, qclass_raw)| {
        Question {
            qname,
            qtype: Qtype::from_u16(qtype_raw),
            qclass: Qclass::from_u16(qclass_raw),
        }
    })
}

// ── RData strategies ──────────────────────────────────────────────────────────

/// Generates a simple [`RData::A`] value.
fn arb_rdata_a() -> impl Strategy<Value = RData> {
    any::<[u8; 4]>().prop_map(|b| RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
}

/// Generates a simple [`RData::Aaaa`] value.
fn arb_rdata_aaaa() -> impl Strategy<Value = RData> {
    any::<[u8; 16]>().prop_map(|b| {
        RData::Aaaa(Ipv6Addr::from(b))
    })
}

/// Generates an [`RData::Txt`] with 1–3 character strings of 0–16 bytes.
fn arb_rdata_txt() -> impl Strategy<Value = RData> {
    proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..=16),
        1..=3,
    )
    .prop_map(RData::Txt)
}

/// Generates an [`RData::Mx`] value.
fn arb_rdata_mx() -> impl Strategy<Value = RData> {
    (any::<u16>(), arb_name()).prop_map(|(preference, exchange)| RData::Mx {
        preference,
        exchange,
    })
}

/// Generates an [`RData::Ns`] value.
fn arb_rdata_ns() -> impl Strategy<Value = RData> {
    arb_name().prop_map(RData::Ns)
}

/// Generates an [`RData::Cname`] value.
fn arb_rdata_cname() -> impl Strategy<Value = RData> {
    arb_name().prop_map(RData::Cname)
}

/// Generates one of several simple [`RData`] variants.
fn arb_rdata() -> impl Strategy<Value = RData> {
    prop_oneof![
        arb_rdata_a(),
        arb_rdata_aaaa(),
        arb_rdata_txt(),
        arb_rdata_mx(),
        arb_rdata_ns(),
        arb_rdata_cname(),
    ]
}

// ── Record strategies ─────────────────────────────────────────────────────────

/// Returns the [`Rtype`] corresponding to an [`RData`] variant.
fn rtype_of(rdata: &RData) -> Rtype {
    match rdata {
        RData::A(_) => Rtype::A,
        RData::Aaaa(_) => Rtype::Aaaa,
        RData::Txt(_) => Rtype::Txt,
        RData::Mx { .. } => Rtype::Mx,
        RData::Ns(_) => Rtype::Ns,
        RData::Cname(_) => Rtype::Cname,
        _ => Rtype::Unknown(0),
    }
}

/// Generates a valid [`Record`] in the IN class.
fn arb_record() -> impl Strategy<Value = Record> {
    (arb_name(), any::<u32>(), arb_rdata()).prop_map(|(name, ttl, rdata)| {
        let rtype = rtype_of(&rdata);
        Record {
            name,
            rtype,
            rclass: Qclass::In,
            ttl,
            rdata,
        }
    })
}

// ── Message strategy ──────────────────────────────────────────────────────────

/// Generates a [`Message`] with 0–4 questions and 0–8 records per section.
fn arb_message() -> impl Strategy<Value = Message> {
    (
        arb_header(),
        proptest::collection::vec(arb_question(), 0..=4),
        proptest::collection::vec(arb_record(), 0..=8),
        proptest::collection::vec(arb_record(), 0..=8),
        proptest::collection::vec(arb_record(), 0..=8),
    )
        .prop_map(|(mut header, questions, answers, authority, additional)| {
            // Set counts to match generated sections.
            header.qdcount = questions.len() as u16;
            header.ancount = answers.len() as u16;
            header.nscount = authority.len() as u16;
            header.arcount = additional.len() as u16;
            Message { header, questions, answers, authority, additional }
        })
}

// ── Roundtrip property ────────────────────────────────────────────────────────

proptest! {
    /// For any valid [`Message`], serialising (without compression) then parsing
    /// must produce a structurally equal message.
    #[test]
    fn message_serialise_parse_roundtrip(msg in arb_message()) {
        let mut ser = Serialiser::new(false);
        ser.write_message(&msg).unwrap();
        let wire = ser.finish();

        let parsed = Message::parse(&wire).unwrap();
        prop_assert_eq!(parsed, msg);
    }

    /// The same property holds when compression is enabled.
    #[test]
    fn message_serialise_parse_roundtrip_compressed(msg in arb_message()) {
        let mut ser = Serialiser::new(true);
        ser.write_message(&msg).unwrap();
        let wire = ser.finish();

        let parsed = Message::parse(&wire).unwrap();
        prop_assert_eq!(parsed, msg);
    }
}
