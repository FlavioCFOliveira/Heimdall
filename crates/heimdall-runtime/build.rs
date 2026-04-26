// SPDX-License-Identifier: MIT
// Build script for heimdall-runtime.
//
// Declares the `loom` cfg flag so that rustc does not emit `unexpected_cfg` warnings
// when tests are run with RUSTFLAGS='--cfg loom' (ADR-0040, ENG-056).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(loom)");
}
