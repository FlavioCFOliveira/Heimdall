// SPDX-License-Identifier: MIT

//! # heimdall-core
//!
//! Wire-format DNS types, parser, and serialiser for the Heimdall DNS server.
//!
//! This crate provides the complete DNS message model as defined in RFC 1035
//! and extended by numerous subsequent RFCs.  It is the foundation upon which
//! Heimdall's protocol handling is built.
//!
//! ## Modules
//!
//! - [`name`] — [`Name`]: DNS domain name in wire-label format (RFC 1034/1035/4343).
//! - [`header`] — [`Header`], [`Opcode`], [`Rcode`], [`Question`], [`Qtype`], [`Qclass`].
//! - [`record`] — [`Record`], [`RRset`], [`Rtype`]: resource record structure and types.
//! - [`rdata`] — [`RData`]: resource record data payloads for all supported types.
//! - [`parser`] — [`Message`], [`ParseError`]: full DNS message parser with name decompression.
//! - [`serialiser`] — [`Serialiser`], [`SerialiseError`]: DNS message serialiser with optional compression.
//! - [`edns`] — EDNS(0) OPT framework (RFC 6891), DNS Cookies (RFC 7873), padding (RFC 7830/8467),
//!   Extended DNS Errors (RFC 8914), NSID (RFC 5001), and TCP keepalive (RFC 7828).
//! - [`tsig`] — TSIG transaction authentication (RFC 8945).
//! - [`sig0`] — SIG(0) message authentication verification (RFC 2931).
//!
//! ## Example
//!
//! ```rust
//! use std::str::FromStr;
//! use heimdall_core::parser::Message;
//! use heimdall_core::header::{Header, Qclass, Qtype};
//! use heimdall_core::name::Name;
//! use heimdall_core::serialiser::Serialiser;
//! use heimdall_core::header::Question;
//!
//! // Build a minimal DNS query for "example.com. A IN".
//! let mut header = Header::default();
//! header.id = 0x1234;
//! header.set_rd(true);
//! header.qdcount = 1;
//!
//! let qname = Name::from_str("example.com.").unwrap();
//! let question = Question {
//!     qname,
//!     qtype: Qtype::A,
//!     qclass: Qclass::In,
//! };
//! let msg = Message {
//!     header,
//!     questions: vec![question],
//!     answers: vec![],
//!     authority: vec![],
//!     additional: vec![],
//! };
//!
//! // Serialise without compression.
//! let mut ser = Serialiser::new(false);
//! ser.write_message(&msg).unwrap();
//! let wire = ser.finish();
//!
//! // Parse it back.
//! let parsed = Message::parse(&wire).unwrap();
//! assert_eq!(parsed.header.id, 0x1234);
//! assert_eq!(parsed.questions[0].qname.to_string(), "example.com.");
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
// Test-side pedantic lint allowances.  Production code (everything compiled
// without `cfg(test)`) keeps the workspace lint posture intact; tests get a
// pragmatic relaxation that matches the conventions already established in
// `heimdall-e2e-harness`. Each entry corresponds to a pattern that is
// idiomatic in test fixtures and harmless under `cargo test`:
//
// - `unwrap_used` / `expect_used` — panicking on a fixture invariant is the
//   intended behaviour; encoding it as `?` would obscure the assertion.
// - `unreadable_literal` / `cast_*` — wire-format constants and bounded-
//   length collections are common in tests and do not benefit from
//   underscore separators or `try_from`.
// - `items_after_statements` / `match_same_arms` / `default_trait_access` /
//   `field_reassign_with_default` — readability micro-lints whose
//   stylistic value is lower in tests than in production code.
// - `missing_panics_doc` / `missing_errors_doc` — test helpers do not need
//   the full rustdoc contract; the test driver itself documents intent.
// - `needless_pass_by_value` / `redundant_closure_for_method_calls` /
//   `single_match_else` / `collapsible_if` — small fixture builders read
//   more naturally without these refactors applied.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreadable_literal,
        clippy::items_after_statements,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::match_same_arms,
        clippy::needless_pass_by_value,
        clippy::default_trait_access,
        clippy::field_reassign_with_default,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::redundant_closure_for_method_calls,
        clippy::single_match_else,
        clippy::collapsible_if,
        clippy::ignored_unit_patterns,
        clippy::decimal_bitwise_operands,
        clippy::struct_excessive_bools,
        clippy::redundant_else,
    )
)]

pub mod dnssec;
pub mod edns;
pub mod header;
pub mod name;
pub mod parser;
pub mod rdata;
pub mod record;
pub mod serialiser;
pub mod sig0;
pub mod tsig;
pub mod zone;

// Re-export key types at crate root for ergonomic use.
pub use edns::{
    EdnsCookie, EdnsOption, ExtendedError, OptRr, derive_server_cookie, ede_code, full_rcode,
    nsid_option, padding_len, tcp_keepalive_option, verify_server_cookie,
};
pub use header::{Header, Opcode, ParseError, Qclass, Qtype, Question, Rcode};
pub use name::{Name, NameError};
pub use parser::Message;
pub use rdata::RData;
pub use record::{RRset, Record, Rtype};
pub use serialiser::{SerialiseError, Serialiser};
pub use sig0::{Sig0Algorithm, Sig0Error, Sig0Verifier};
pub use tsig::{TsigAlgorithm, TsigError, TsigRecord, TsigSigner};
pub use zone::{ZoneError, ZoneFile, ZoneLimits};
