// SPDX-License-Identifier: MIT

//! Hardening drift check binary.
//!
//! Validates that `contrib/systemd/heimdall.service`, `contrib/openbsd/heimdall.rc`,
//! and `contrib/macos/heimdall.sb` are consistent with the threat model specification.
//!
//! Exit codes:
//! - `0` — no drift detected.
//! - `1` — one or more drift findings.

use std::path::PathBuf;

fn main() {
    let repo_root = find_repo_root();

    let report = heimdall_ci_tools::check_all(&repo_root);
    println!("{report}");

    if !report.is_clean() {
        std::process::exit(1);
    }
}

fn find_repo_root() -> PathBuf {
    if let Some(root) = std::env::args().nth(1) {
        return PathBuf::from(root);
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
