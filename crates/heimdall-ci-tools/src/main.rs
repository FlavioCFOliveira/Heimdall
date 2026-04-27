// SPDX-License-Identifier: MIT

//! Hardening drift check and docs-vs-spec reference sync binary.
//!
//! Validates that `contrib/systemd/heimdall.service`, `contrib/openbsd/heimdall.rc`,
//! and `contrib/macos/heimdall.sb` are consistent with the threat model specification,
//! and optionally checks that every spec ID token referenced in `docs/**/*.md`
//! resolves to an entry in `specification/*.md`.
//!
//! # Exit codes
//!
//! - `0` — all checks passed.
//! - `1` — one or more findings (drift or unknown spec IDs).
//!
//! # Flags
//!
//! - `--check-docs` — run the docs-vs-spec reference check instead of the
//!   hardening drift check.
//! - `[repo_root]` — optional positional argument specifying the repository root
//!   directory. Defaults to the current working directory.

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Determine which check to run and where the repo root is.
    let (check_docs, repo_root) = parse_args(&args[1..]);

    if check_docs {
        run_check_docs(&repo_root);
    } else {
        run_check_drift(&repo_root);
    }
}

fn run_check_drift(repo_root: &PathBuf) {
    let report = heimdall_ci_tools::check_all(repo_root);
    println!("{report}");

    if !report.is_clean() {
        std::process::exit(1);
    }
}

fn run_check_docs(repo_root: &PathBuf) {
    let report = heimdall_ci_tools::check_docs_spec_refs(repo_root);

    if report.unknown_ids.is_empty() {
        println!("OK: all spec IDs in docs resolved");
    } else {
        eprintln!(
            "DOCS-SPEC DRIFT DETECTED ({} unknown ID(s)):",
            report.unknown_ids.len()
        );
        for id in &report.unknown_ids {
            eprintln!("  - {id}");
        }
        std::process::exit(1);
    }
}

/// Parses command-line arguments.
///
/// Returns `(check_docs, repo_root)` where `check_docs` is `true` when
/// `--check-docs` is present and `repo_root` is the first non-flag argument
/// or the current working directory.
fn parse_args(args: &[String]) -> (bool, PathBuf) {
    let mut check_docs = false;
    let mut repo_root: Option<PathBuf> = None;

    for arg in args {
        if arg == "--check-docs" {
            check_docs = true;
        } else if !arg.starts_with('-') {
            repo_root = Some(PathBuf::from(arg));
        }
    }

    let root = repo_root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    (check_docs, root)
}
