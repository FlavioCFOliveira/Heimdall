// SPDX-License-Identifier: MIT

//! Fuzzing target for the DNS message parser.
//!
//! Run with cargo-fuzz (requires nightly):
//! ```text
//! cargo +nightly fuzz run fuzz_parse_message
//! ```
//!
//! The parser must never panic on arbitrary input — only return `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must not panic on any input.
    let _ = heimdall_core::parser::Message::parse(data);
});
