// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # heimdall-ci-tools
//!
//! CI drift detection: asserts that the platform hardening artefacts in
//! `contrib/` are consistent with the threat model specification.
//!
//! The [`check_all`] function is the primary entry-point. It parses the
//! systemd unit, OpenBSD rc.d script, and macOS sandbox profile and returns
//! a [`DriftReport`] listing any missing or inconsistent directives.
//!
//! ## Usage
//!
//! ```no_run
//! use heimdall_ci_tools::{check_all, DriftReport};
//! use std::path::Path;
//!
//! let report = check_all(Path::new("."));
//! if !report.is_clean() {
//!     eprintln!("{report}");
//!     std::process::exit(1);
//! }
//! ```

use std::fmt;
use std::path::Path;

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
        ("daemon_user=\"_heimdall\"", "daemon_user must be set to _heimdall"),
        ("rc_pre()", "rc_pre hook must be defined for runtime directory setup"),
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
