// SPDX-License-Identifier: MIT

//! Fuzzing target for the runtime configuration TOML parser (SIGHUP reload
//! path).
//!
//! OPS-001..006 mandates all-or-nothing reload: a malformed configuration
//! MUST NOT take effect, and MUST NOT cause the daemon to panic. This fuzz
//! target feeds arbitrary bytes to the TOML decoder and the structural
//! validator and asserts that neither path panics.
//!
//! Run with cargo-fuzz (requires nightly):
//! ```text
//! cargo +nightly fuzz run fuzz_config_toml
//! ```

#![no_main]

use heimdall_runtime::config::{Config, validate_config};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The reload path takes the raw file contents as a UTF-8 string.
    // Non-UTF-8 input is rejected upstream of the TOML parser; we mimic that
    // policy by skipping non-UTF-8 inputs rather than panic.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Phase 1: TOML decoder must never panic on adversarial input.
    let parse_result: Result<Config, _> = toml::from_str(text);

    // Phase 2: when the decoder accepted the input, the structural validator
    // (validate_config) MUST run to completion and return a Vec<String> of
    // errors — it MUST NOT panic.
    if let Ok(cfg) = parse_result {
        let _errors = validate_config(&cfg);
    }
});
