// SPDX-License-Identifier: MIT

#![deny(unsafe_code)]
#![warn(missing_docs)]
// See `crates/heimdall-core/src/lib.rs` for the rationale.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreadable_literal,
        clippy::items_after_statements,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
    )
)]

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
//! and verifies that each referenced *project-internal* ID resolves: either
//! to a verbatim mention in `specification/*.md`, or, for `ADR-NNNN`, to a
//! file `docs/adr/NNNN-*.md`. Tokens whose prefix is not project-internal
//! (cryptographic algorithms, licences, RFCs, RUSTSEC/CVE/CWE entries, …)
//! are silently skipped, as are template files whose name contains
//! `template`. Unresolved internal IDs are returned in the
//! [`DocsSpecReport`].
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
/// that appears in a `docs/**/*.md` file and uses a *project-internal*
/// prefix (one that occurs in `specification/*.md`, plus the special-cased
/// `ADR` prefix) but cannot be resolved.
///
/// Tokens whose prefix never appears in `specification/` are treated as
/// references to external documents (e.g. `AGPL-3`, `ISO-8601`,
/// `RUSTSEC-2021`, `RSA-1024`, `CWE-1`) and silently skipped.
#[derive(Debug, Default)]
pub struct DocsSpecReport {
    /// Project-internal spec ID tokens referenced in `docs/**/*.md` that were
    /// not found in `specification/` content (or, for `ADR-NNNN`, that were
    /// not found as a file under `docs/adr/`).
    pub unknown_ids: Vec<String>,
}

/// Prefixes that the regex `[A-Z]+-[0-9]+` may match in spec or doc text but
/// that name external artefacts (cryptographic algorithms with key sizes,
/// licences, vulnerability identifiers, standards bodies, RFC-style numbered
/// documents). They are subtracted from the auto-derived project-prefix set
/// so that, e.g., a `RSA-2048` mention in `003-crypto-policy.md` does not
/// promote `RSA` to a "project prefix" and turn `RSA-1024` in a test-vector
/// table into a spurious drift finding.
const EXTERNAL_PREFIXES: &[&str] = &[
    // Cryptographic primitives and key sizes
    "RSA", "DSA", "ECDSA", "EDDSA", "ECC", "AES", "SHA", "MD", "HMAC", "GCM", "CBC", "CTR",
    // Standards / specifications
    "RFC", "ISO", "NIST", "FIPS", "IEEE", // Licences
    "AGPL", "GPL", "LGPL", "BSD", "MIT", "APACHE",
    // Vulnerability and weakness databases
    "CWE", "CVE", "RUSTSEC", "GHSA", "OSV",
];

/// Scans all `docs/**/*.md` files under `repo_root` for spec ID tokens
/// (pattern: one or more uppercase ASCII letters, a hyphen, one or more
/// decimal digits — e.g. `THREAT-024`, `ROLE-001`, `ENV-028`, `ENG-052`),
/// then verifies that each referenced project-internal ID resolves.
///
/// # Resolution rules
///
/// - Tokens are partitioned by prefix. A prefix is *project-internal* if it
///   appears in at least one `specification/*.md` file (e.g. `THREAT`, `SEC`,
///   `ENG`), is the special-cased `ADR` prefix (whose entries live under
///   `docs/adr/` rather than `specification/`), and is not in
///   [`EXTERNAL_PREFIXES`] (which subtracts cryptographic, standards,
///   licence, and CVE-style prefixes that incidentally appear in spec text).
/// - `ADR-NNNN` is resolved by looking for a file named `NNNN-*.md` under
///   `docs/adr/`. The leading-zero-padded number must match exactly.
/// - Every other internal token must appear verbatim somewhere in the
///   concatenated text of the top-level `specification/*.md` files.
///
/// Files whose name contains `template` (case-insensitive) are excluded from
/// the doc scan: their IDs are placeholders, not real references.
///
/// Returns a [`DocsSpecReport`] whose `unknown_ids` list contains every
/// internal ID that appears in docs but cannot be resolved.
///
/// File-read errors are silently skipped so that a single unreadable file
/// does not abort the entire scan; the missing content simply produces no
/// ID tokens from that file.
#[must_use]
pub fn check_docs_spec_refs(repo_root: &Path) -> DocsSpecReport {
    let spec_content = collect_spec_content(repo_root);
    let mut known_prefixes = extract_prefixes(&spec_content);
    for ext in EXTERNAL_PREFIXES {
        known_prefixes.remove(*ext);
    }
    // ADRs are project-internal but stored outside specification/.
    known_prefixes.insert("ADR".to_owned());

    let adr_files = collect_adr_files(repo_root);
    let doc_ids = collect_doc_ids(repo_root);

    let mut unknown_ids: Vec<String> = doc_ids
        .into_iter()
        .filter(|id| {
            let Some((prefix, _)) = id.split_once('-') else {
                return false;
            };
            if !known_prefixes.contains(prefix) {
                return false;
            }
            if prefix == "ADR" {
                return !adr_files.contains(id);
            }
            !spec_content.contains(id.as_str())
        })
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
            && !is_template_file(&path)
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            extract_spec_ids(&text, ids);
        }
    }
}

/// Returns `true` when the file's stem contains `template` in any case.
///
/// Template files (`findings-triage-template.md`, `sign-off-template.md`,
/// etc.) carry placeholder IDs (e.g. `FINDING-001`) that are not real
/// project references and must not be validated against the spec.
fn is_template_file(path: &Path) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.to_ascii_lowercase().contains("template"))
}

/// Returns the set of ID-prefix tokens (the `[A-Z]+` part of `[A-Z]+-[0-9]+`)
/// that appear in the supplied text.
fn extract_prefixes(text: &str) -> BTreeSet<String> {
    let mut prefixes = BTreeSet::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i].is_ascii_uppercase() {
            let start = i;
            while i < len && bytes[i].is_ascii_uppercase() {
                i += 1;
            }
            if i < len && bytes[i] == b'-' {
                let prefix_end = i;
                i += 1;
                let digit_start = i;
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > digit_start {
                    prefixes.insert(text[start..prefix_end].to_owned());
                }
            }
        } else {
            i += 1;
        }
    }

    prefixes
}

/// Returns the set of ADR IDs (`ADR-NNNN`) that exist as files in
/// `docs/adr/`, derived from each filename's leading digit run.
///
/// Filenames are expected to follow the `NNNN-title.md` convention. The
/// digit run preserves leading zeros so that `0007-foo.md` produces
/// `ADR-0007`, matching the citation form used in docs.
fn collect_adr_files(repo_root: &Path) -> BTreeSet<String> {
    let adr_dir = repo_root.join("docs").join("adr");
    let mut set = BTreeSet::new();

    let Ok(entries) = std::fs::read_dir(&adr_dir) else {
        return set;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let digits_end = stem.bytes().take_while(u8::is_ascii_digit).count();
        if digits_end == 0 {
            continue;
        }
        set.insert(format!("ADR-{}", &stem[..digits_end]));
    }

    set
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

    #[test]
    fn extract_prefixes_captures_unique_prefixes() {
        let prefixes = extract_prefixes("THREAT-001, ROLE-002, THREAT-003, plain text.");
        assert_eq!(prefixes.len(), 2);
        assert!(prefixes.contains("THREAT"));
        assert!(prefixes.contains("ROLE"));
    }

    #[test]
    fn extract_prefixes_ignores_orphan_prefix() {
        // Prefix without trailing digits is not a token and yields no entry.
        let prefixes = extract_prefixes("THREAT- and SEC-");
        assert!(prefixes.is_empty());
    }

    #[test]
    fn check_docs_spec_refs_skips_external_prefixes() {
        // Build a transient repo layout in a tempdir.
        let tmp = std::env::temp_dir().join(format!(
            "heimdall-ci-tools-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let spec = tmp.join("specification");
        let docs = tmp.join("docs");
        std::fs::create_dir_all(&spec).expect("create spec dir");
        std::fs::create_dir_all(&docs).expect("create docs dir");
        // Spec defines THREAT-001 only.
        std::fs::write(spec.join("threats.md"), "THREAT-001 is real.\n").expect("write spec file");
        // Docs reference (a) a real internal ID, (b) an unknown internal ID,
        // (c) several external prefixes that must be ignored.
        std::fs::write(
            docs.join("guide.md"),
            "See THREAT-001 and THREAT-999.\n\
             Licences: AGPL-3, GPL-3, LGPL-2.\n\
             Standards: ISO-8601, RUSTSEC-2021, CWE-1, RSA-1024.\n",
        )
        .expect("write doc file");

        let report = check_docs_spec_refs(&tmp);
        assert_eq!(
            report.unknown_ids,
            vec!["THREAT-999".to_owned()],
            "only the unknown internal ID should be reported"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn check_docs_spec_refs_resolves_adr_via_files() {
        let tmp = std::env::temp_dir().join(format!(
            "heimdall-ci-tools-adr-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let spec = tmp.join("specification");
        let docs = tmp.join("docs");
        let adrs = docs.join("adr");
        std::fs::create_dir_all(&spec).expect("create spec dir");
        std::fs::create_dir_all(&adrs).expect("create adr dir");
        // Spec mentions ADR so the prefix is recognised, but ADR resolution
        // happens through the file set, not through spec text.
        std::fs::write(spec.join("policies.md"), "Refer to ADR-0042 for context.\n")
            .expect("write spec");
        std::fs::write(adrs.join("0007-example.md"), "# ADR-0007\n").expect("write adr 7");
        std::fs::write(adrs.join("0042-redis.md"), "# ADR-0042\n").expect("write adr 42");
        // Doc references ADR-0007 (resolved via file), ADR-0042 (also via
        // file), and ADR-0099 (no file → unknown).
        std::fs::write(
            docs.join("guide.md"),
            "Per ADR-0007, ADR-0042, ADR-0099 the policy is …\n",
        )
        .expect("write doc");

        let report = check_docs_spec_refs(&tmp);
        assert_eq!(report.unknown_ids, vec!["ADR-0099".to_owned()]);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn check_docs_spec_refs_skips_template_files() {
        let tmp = std::env::temp_dir().join(format!(
            "heimdall-ci-tools-tpl-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let spec = tmp.join("specification");
        let docs = tmp.join("docs").join("audit");
        std::fs::create_dir_all(&spec).expect("create spec dir");
        std::fs::create_dir_all(&docs).expect("create docs dir");
        std::fs::write(spec.join("findings.md"), "FINDING- is the prefix.\n").expect("write spec");
        // Real audit doc with a real reference (must be flagged).
        std::fs::write(
            docs.join("findings-2026.md"),
            "We tracked FINDING-001 to closure.\n",
        )
        .expect("write real");
        // Template doc with placeholder IDs (must be ignored).
        std::fs::write(
            docs.join("findings-triage-template.md"),
            "# FINDING-001 placeholder\nFINDING-042 placeholder\n",
        )
        .expect("write tpl");

        // Spec contains the prefix `FINDING-` (in `FINDING- is the prefix.`)
        // but no concrete IDs, so FINDING-001 in the real doc is unknown
        // while the template's IDs are skipped before any check.
        // Wait: extract_prefixes requires digits, so `FINDING-` alone does
        // not register the prefix. Use a digit so the prefix is recognised
        // as project-internal.
        std::fs::write(spec.join("findings.md"), "Tracker: FINDING-000.\n").expect("rewrite spec");

        let report = check_docs_spec_refs(&tmp);
        assert_eq!(
            report.unknown_ids,
            vec!["FINDING-001".to_owned()],
            "real-doc ID flagged, template-doc IDs silently ignored"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }
}
