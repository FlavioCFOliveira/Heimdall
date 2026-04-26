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
#![warn(missing_docs)]

pub mod header;
pub mod name;
pub mod parser;
pub mod rdata;
pub mod record;
pub mod serialiser;

// Re-export key types at crate root for ergonomic use.
pub use header::{Header, Opcode, Qclass, Qtype, Question, Rcode};
pub use name::{Name, NameError};
pub use header::ParseError;
pub use parser::Message;
pub use rdata::RData;
pub use record::{RRset, Rtype, Record};
pub use serialiser::{SerialiseError, Serialiser};
