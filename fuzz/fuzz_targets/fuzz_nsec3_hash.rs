// SPDX-License-Identifier: MIT

//! Fuzz target for [`heimdall_core::dnssec::nsec::nsec3_hash`].
//!
//! Verifies that `nsec3_hash` never panics for any combination of
//! iteration count and salt, including counts above the 150-iteration cap.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let iterations = u16::from_be_bytes([data[0], data[1]]);
    let salt = &data[2..data.len().min(34)];
    // nsec3_hash must not panic for any input, including iterations > 150.
    let _ = heimdall_core::dnssec::nsec::nsec3_hash(
        &heimdall_core::Name::root(),
        salt,
        iterations,
    );
});
