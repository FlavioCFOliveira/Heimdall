// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # heimdall-ci-tools
//!
//! CI drift detection and documentation consistency checks for Heimdall.
//!
//! ## Hardening drift check
//!
//! The [`check_all`] function asserts that the platform hardening artefacts in
//! `contrib/` are consistent with the threat model specification. It parses the
//! systemd unit, OpenBSD rc.d script, and macOS sandbox profile and returns a
//! [`DriftReport`] listing any missing or inconsistent directives.
//!
//! ## Docs-vs-spec reference check
//!
//! The [`check_docs_spec_refs`] function scans all Markdown files under `docs/`
//! for spec ID tokens (pattern: `[A-Z]+-[0-9]+`, e.g. `THREAT-024`, `ROLE-001`)
//! and verifies that each referenced ID appears somewhere in the `specification/`
//! directory. IDs that appear in docs but cannot be found in any spec file are
//! returned as unknown IDs in the [`DocsSpecReport`].
//!
//! ## Usage
//!
//! ```no_run
//! use heimdall_ci_tools::{check_all, check_docs_spec_refs, DriftReport};
//! use std::path::Path;
//!
//! let drift = check_all(Path::new("."));
//! if !drift.is_clean() {
//!     eprintln!("{drift}");
//!     std::process::exit(1);
//! }
//!
//! let refs = check_docs_spec_refs(Path::new("."));
//! if !refs.unknown_ids.is_empty() {
//!     for id in &refs.unknown_ids {
//!         eprintln!("unknown spec ID in docs: {id}");
//!     }
//!     std::process::exit(1);
//! }
//! ```

use std::{collections::BTreeSet, fmt, path::Path};

// ── Hardening drift check ─────────────────────────────────────────────────────

/// A single drift finding: one directive or pattern that is missing or inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftFinding {
    /// Human-readable description of what is missing or wrong.
    pub description: String,
    /// The file in which the issue was found (relative to repo root).
    pub file: String,
}

impl fmt::Display for DriftFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.file, self.description)
    }
}

/// Aggregated result of a hardening drift check run.
#[derive(Debug, Default)]
pub struct DriftReport {
    findings: Vec<DriftFinding>,
}

impl DriftReport {
    /// Returns `true` if no inconsistencies were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns the list of individual drift findings.
    #[must_use]
    pub fn findings(&self) -> &[DriftFinding] {
        &self.findings
    }

    fn push(&mut self, file: impl Into<String>, description: impl Into<String>) {
        self.findings.push(DriftFinding {
            description: description.into(),
            file: file.into(),
        });
    }
}

impl fmt::Display for DriftReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return write!(f, "OK: no drift detected");
        }
        writeln!(f, "DRIFT DETECTED ({} finding(s)):", self.findings.len())?;
        for finding in &self.findings {
            writeln!(f, "  - {finding}")?;
        }
        Ok(())
    }
}

/// Checks all hardening artefacts under `repo_root` for consistency with the
/// threat model specification (THREAT-022..032, THREAT-089..090, THREAT-031).
///
/// # Errors (as findings, not Rust errors)
///
/// Missing directives are reported as [`DriftFinding`] entries in the returned
/// [`DriftReport`], not as `Err`. File read errors are also reported as findings
/// so the caller gets a complete picture even if one file is missing.
#[must_use]
pub fn check_all(repo_root: &Path) -> DriftReport {
    let mut report = DriftReport::default();

    check_systemd_unit(repo_root, &mut report);
    check_openbsd_rc(repo_root, &mut report);
    check_macos_sandbox(repo_root, &mut report);

    report
}

fn check_systemd_unit(repo_root: &Path, report: &mut DriftReport) {
    const FILE: &str = "contrib/systemd/heimdall.service";

    let content = match std::fs::read_to_string(repo_root.join(FILE)) {
        Ok(c) => c,
        Err(e) => {
            report.push(FILE, format!("cannot read file: {e}"));
            return;
        }
    };

    let required_directives = [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=",
        "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes",
        "MemoryDenyWriteExecute=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "User=heimdall",
        "Group=heimdall",
    ];

    for directive in &required_directives {
        if !content.contains(directive) {
            report.push(FILE, format!("missing required directive: {directive}"));
        }
    }
}

fn check_openbsd_rc(repo_root: &Path, report: &mut DriftReport) {
    const FILE: &str = "contrib/openbsd/heimdall.rc";

    let content = match std::fs::read_to_string(repo_root.join(FILE)) {
        Ok(c) => c,
        Err(e) => {
            report.push(FILE, format!("cannot read file: {e}"));
            return;
        }
    };

    let required = [
        (
            "daemon_user=\"_heimdall\"",
            "daemon_user must be set to _heimdall",
        ),
        (
            "rc_pre()",
            "rc_pre hook must be defined for runtime directory setup",
        ),
    ];

    for (pattern, description) in &required {
        if !content.contains(pattern) {
            report.push(FILE, format!("missing: {description} (pattern: {pattern})"));
        }
    }
}

fn check_macos_sandbox(repo_root: &Path, report: &mut DriftReport) {
    const FILE: &str = "contrib/macos/heimdall.sb";

    let content = match std::fs::read_to_string(repo_root.join(FILE)) {
        Ok(c) => c,
        Err(e) => {
            report.push(FILE, format!("cannot read file: {e}"));
            return;
        }
    };

    let required = [
        ("(deny default)", "must have a top-level deny-default rule"),
        ("(deny process-exec)", "must explicitly deny process-exec"),
        ("(deny process-fork)", "must explicitly deny process-fork"),
    ];

    for (pattern, description) in &required {
        if !content.contains(pattern) {
            report.push(FILE, format!("missing: {description} (pattern: {pattern})"));
        }
    }
}

// ── Docs-vs-spec reference check ─────────────────────────────────────────────

/// Report produced by [`check_docs_spec_refs`].
///
/// `unknown_ids` contains every spec ID token (e.g. `THREAT-024`, `ROLE-001`)
/// that appears in a `docs/**/*.md` file but cannot be found in any file under
/// the `specification/` directory.
#[derive(Debug, Default)]
pub struct DocsSpecReport {
    /// Spec ID tokens referenced in `docs/**/*.md` that were not found in any
    /// `specification/*.md` file.
    pub unknown_ids: Vec<String>,
}

/// Scans all `docs/**/*.md` files under `repo_root` for spec ID tokens
/// (pattern: one or more uppercase ASCII letters, a hyphen, one or more
/// decimal digits — e.g. `THREAT-024`, `ROLE-001`, `ENV-028`, `ENG-052`),
/// then verifies that each referenced ID appears somewhere in a file under
/// `specification/`.
///
/// Returns a [`DocsSpecReport`] whose `unknown_ids` list contains every ID
/// that appears in docs but is absent from the specification directory.
///
/// File-read errors are silently skipped so that a single unreadable file
/// does not abort the entire scan; the missing content simply produces no
/// ID tokens from that file.
#[must_use]
pub fn check_docs_spec_refs(repo_root: &Path) -> DocsSpecReport {
    // 1. Collect all spec content from specification/*.md
    let spec_content = collect_spec_content(repo_root);

    // 2. Collect all ID tokens from docs/**/*.md
    let doc_ids = collect_doc_ids(repo_root);

    // 3. Find IDs referenced in docs but absent from spec
    let mut unknown_ids: Vec<String> = doc_ids
        .into_iter()
        .filter(|id| !spec_content.contains(id.as_str()))
        .collect();
    unknown_ids.sort();

    DocsSpecReport { unknown_ids }
}

/// Returns the concatenated text content of all `specification/*.md` files.
fn collect_spec_content(repo_root: &Path) -> String {
    let spec_dir = repo_root.join("specification");
    let mut content = String::new();

    let Ok(entries) = std::fs::read_dir(&spec_dir) else {
        return content;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("md")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            content.push_str(&text);
            content.push('\n');
        }
    }

    content
}

/// Returns the deduplicated set of spec ID tokens found in all `docs/**/*.md`
/// files under `repo_root`.
///
/// The token pattern is: `[A-Z]+-[0-9]+` — one or more uppercase ASCII
/// letters, a hyphen, then one or more decimal digits.
fn collect_doc_ids(repo_root: &Path) -> BTreeSet<String> {
    let docs_dir = repo_root.join("docs");
    let mut ids = BTreeSet::new();
    collect_doc_ids_recursive(&docs_dir, &mut ids);
    ids
}

fn collect_doc_ids_recursive(dir: &Path, ids: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_doc_ids_recursive(&path, ids);
        } else if path.extension().and_then(|e| e.to_str()) == Some("md")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            extract_spec_ids(&text, ids);
        }
    }
}

/// Extracts all tokens matching `[A-Z]+-[0-9]+` from `text` into `ids`.
fn extract_spec_ids(text: &str, ids: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Find start of an uppercase-letter sequence
        if bytes[i].is_ascii_uppercase() {
            let start = i;
            // Consume uppercase letters
            while i < len && bytes[i].is_ascii_uppercase() {
                i += 1;
            }
            // Must be followed by a hyphen
            if i < len && bytes[i] == b'-' {
                i += 1; // consume hyphen
                let digit_start = i;
                // Must be followed by one or more decimal digits
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > digit_start {
                    // Valid token: slice from start to i
                    // Safety: all bytes are ASCII so the slice is valid UTF-8.
                    let token = &text[start..i];
                    ids.insert(token.to_owned());
                }
            }
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn extract_spec_ids_basic() {
        let mut ids = BTreeSet::new();
        extract_spec_ids("See THREAT-024 and ROLE-001 for details.", &mut ids);
        assert!(ids.contains("THREAT-024"));
        assert!(ids.contains("ROLE-001"));
    }

    #[test]
    fn extract_spec_ids_no_false_positives() {
        let mut ids = BTreeSet::new();
        // lowercase prefix should not match
        extract_spec_ids("threat-024 is not a token", &mut ids);
        assert!(ids.is_empty());
    }

    #[test]
    fn extract_spec_ids_requires_digits() {
        let mut ids = BTreeSet::new();
        extract_spec_ids("THREAT- is incomplete", &mut ids);
        assert!(ids.is_empty());
    }

    #[test]
    fn extract_spec_ids_multiple_in_line() {
        let mut ids = BTreeSet::new();
        extract_spec_ids("SEC-001, SEC-002, and ENV-028.", &mut ids);
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("SEC-001"));
        assert!(ids.contains("SEC-002"));
        assert!(ids.contains("ENV-028"));
    }
}
