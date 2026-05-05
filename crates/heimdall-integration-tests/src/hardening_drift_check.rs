// SPDX-License-Identifier: MIT

//! CI drift gate: spec ↔ profile consistency (Sprint 37 task #378).
//!
//! Calls [`heimdall_ci_tools::check_all`] with the repository root derived from
//! `CARGO_MANIFEST_DIR` and asserts that the returned `DriftReport` is clean.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ parent must exist")
            .parent()
            .expect("repo root must exist")
            .to_path_buf()
    }

    /// Asserts that all hardening artefacts are consistent with the threat model
    /// specification. This test is self-contained and runs in any CI environment
    /// that has access to the repository.
    #[test]
    fn hardening_artefacts_are_consistent_with_spec() {
        let root = repo_root();
        let report = heimdall_ci_tools::check_all(&root);

        assert!(
            report.is_clean(),
            "hardening drift detected — artefacts do not match the spec:\n{report}"
        );
    }
}
