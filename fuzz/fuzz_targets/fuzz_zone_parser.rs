// SPDX-License-Identifier: MIT

//! Fuzz target for the zone-file parser (Task #219).
//!
//! Feeds arbitrary UTF-8 input to [`ZoneFile::parse`] and verifies that the
//! parser never panics — it must always return either `Ok(_)` or `Err(_)`.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let _ = heimdall_core::zone::ZoneFile::parse(
            src,
            None,
            heimdall_core::zone::ZoneLimits::default(),
        );
    }
});
