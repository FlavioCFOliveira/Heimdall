// SPDX-License-Identifier: MIT

//! Fuzzing target for the DNSSEC validator (RRSIG canonical-form construction,
//! signature verification, NSEC/NSEC3 negative-proof state machine).
//!
//! The harness parses arbitrary input as a wire-format DNS message, then for
//! every (RRset, RRSIG, DNSKEY) triple discoverable in the parsed sections it
//! calls [`heimdall_core::dnssec::verify::verify_rrsig`]. The validator must
//! never panic, abort, integer-overflow, or block — it must return a
//! `ValidationOutcome` on any input, regardless of how malformed the
//! signature, key, or covered records are.
//!
//! Run with cargo-fuzz (requires nightly):
//! ```text
//! cargo +nightly fuzz run fuzz_dnssec_verify
//! ```

#![no_main]

use heimdall_core::{
    dnssec::verify::verify_rrsig,
    parser::Message,
    rdata::RData,
    record::{Record, Rtype},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Phase 1: try to parse the bytes as a DNS message. The parser itself is
    // fuzzed elsewhere (fuzz_parse_message); here we only want to exercise the
    // validator with parsed records that *do* survive the parser.
    let Ok(msg) = Message::parse(data) else {
        return;
    };

    // Phase 2: aggregate every RRset across answers + authority + additional,
    // and every RRSIG that covers them.
    let all: Vec<&Record> = msg
        .answers
        .iter()
        .chain(msg.authority.iter())
        .chain(msg.additional.iter())
        .collect();
    if all.is_empty() {
        return;
    }

    // Collect DNSKEY records — candidate signing keys.
    let dnskeys: Vec<Record> = all
        .iter()
        .filter(|r| r.rtype == Rtype::Dnskey)
        .map(|r| (*r).clone())
        .collect();
    if dnskeys.is_empty() {
        return;
    }

    // Use a deterministic "now" derived from the first 8 bytes of the input
    // so the fuzzer can explore time-bounded code paths without divergent
    // wall-clock behaviour across runs.
    let now_unix: u64 = if data.len() >= 8 {
        u64::from_be_bytes(data[..8].try_into().expect("8 bytes"))
    } else {
        0
    };

    // Cap the KeyTrap attempts low — the fuzzer must spend its budget on
    // breadth, not exhausting a single iteration on attempt enumeration.
    const MAX_ATTEMPTS: usize = 4;

    // Phase 3: for every RRSIG-typed record, try to validate it against the
    // first non-RRSIG record of its covered type.
    for rrsig in all.iter().filter(|r| r.rtype == Rtype::Rrsig) {
        let RData::Rrsig { type_covered, .. } = &rrsig.rdata else {
            continue;
        };
        // Heuristic: take every record sharing the covered type as the candidate
        // rrset. Real validation would partition by owner_name + type + class
        // — the validator handles that internally and we want to feed it
        // structurally interesting (and structurally invalid) inputs alike.
        let rrset_records: Vec<Record> = all
            .iter()
            .filter(|r| r.rtype == *type_covered && r.rtype != Rtype::Rrsig)
            .map(|r| (*r).clone())
            .collect();
        if rrset_records.is_empty() {
            continue;
        }
        // The validator must not panic on any combination.
        let _ = verify_rrsig(&rrset_records, &rrsig.rdata, &dnskeys, now_unix, MAX_ATTEMPTS);
    }
});
