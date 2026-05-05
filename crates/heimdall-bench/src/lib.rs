// SPDX-License-Identifier: MIT

//! Shared utilities for Heimdall performance benchmarks.
//!
//! This crate provides pre-built wire packets and message fixtures used by
//! all benchmark binaries.  Every fixture is verified at test time to be
//! parseable, so benchmark-time failures are limited to genuine regressions
//! in the hot path rather than fixture rot.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::str::FromStr;

use heimdall_core::{
    header::{Header, Qclass, Qtype, Question},
    name::Name,
    parser::Message,
    rdata::RData,
    record::{Record, Rtype},
    serialiser::Serialiser,
};

// ── Public wire fixtures ──────────────────────────────────────────────────────

/// Returns a hardcoded valid DNS A-query wire packet for `example.com. A IN`.
///
/// The message has ID `0xCAFE`, RD bit set, one question, and no answers.
///
/// # Panics
///
/// Never panics in practice.  The `expect` calls guard invariants on
/// compile-time-literal names and addresses; any panic would indicate a bug
/// in `heimdall-core`, not in the benchmark caller.
#[must_use]
#[allow(clippy::expect_used)] // fixture invariants on compile-time literals
pub fn example_query_wire() -> Vec<u8> {
    let msg = example_query_message();
    let mut ser = Serialiser::new(false);
    ser.write_message(&msg)
        .expect("INVARIANT: example query is always serialisable");
    ser.finish()
}

/// Returns a hardcoded valid DNS A-response wire packet for
/// `example.com. A IN → 93.184.216.34` (the IANA-assigned example address).
///
/// The message has ID `0xCAFE`, QR=1, AA=1, RD=1, RA=1, one question,
/// and one answer A record with TTL 86400.
///
/// # Panics
///
/// Never panics in practice.  The `expect` calls guard invariants on
/// compile-time-literal names and addresses; any panic would indicate a bug
/// in `heimdall-core`, not in the benchmark caller.
#[must_use]
#[allow(clippy::expect_used)] // fixture invariants on compile-time literals
pub fn example_response_wire() -> Vec<u8> {
    let msg = example_response_message();
    let mut ser = Serialiser::new(false);
    ser.write_message(&msg)
        .expect("INVARIANT: example response is always serialisable");
    ser.finish()
}

// ── Public message fixtures ───────────────────────────────────────────────────

/// Returns a [`Message`] representing a standard DNS A-query for `example.com.`.
///
/// Used by serialisation benchmarks that need a ready-made `Message` struct.
///
/// # Panics
///
/// Never panics in practice.  The `expect` call guards an invariant on a
/// compile-time-literal domain name.
#[must_use]
#[allow(clippy::expect_used)] // fixture invariant on compile-time literal
pub fn example_query_message() -> Message {
    let qname =
        Name::from_str("example.com.").expect("INVARIANT: 'example.com.' is a valid DNS name");
    let question = Question {
        qname,
        qtype: Qtype::A,
        qclass: Qclass::In,
    };

    Message {
        header: Header {
            id: 0xCAFE,
            flags: {
                // RD bit only.
                let mut h = Header::default();
                h.set_rd(true);
                h.qdcount = 1;
                h.flags
            },
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
        questions: vec![question],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

/// Returns a [`Message`] representing a standard DNS A-response for
/// `example.com. → 93.184.216.34`.
///
/// Used by serialisation benchmarks that need a ready-made `Message` struct.
///
/// # Panics
///
/// Never panics in practice.  The `expect` calls guard invariants on
/// compile-time-literal domain names and IP addresses.
#[must_use]
#[allow(clippy::expect_used)] // fixture invariants on compile-time literals
pub fn example_response_message() -> Message {
    let qname =
        Name::from_str("example.com.").expect("INVARIANT: 'example.com.' is a valid DNS name");
    let question = Question {
        qname: qname.clone(),
        qtype: Qtype::A,
        qclass: Qclass::In,
    };

    // 93.184.216.34 — the IANA-designated IP address for example.com.
    let answer = Record {
        name: qname,
        rtype: Rtype::A,
        rclass: Qclass::In,
        ttl: 86_400,
        rdata: RData::A(
            "93.184.216.34"
                .parse()
                .expect("INVARIANT: '93.184.216.34' is a valid IPv4 address"),
        ),
    };

    // Build flags: QR=1, AA=1, RD=1, RA=1.
    let flags = {
        let mut h = Header::default();
        h.set_qr(true);
        h.set_aa(true);
        h.set_rd(true);
        h.set_ra(true);
        h.flags
    };

    Message {
        header: Header {
            id: 0xCAFE,
            flags,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        },
        questions: vec![question],
        answers: vec![answer],
        authority: vec![],
        additional: vec![],
    }
}

pub mod reference;
