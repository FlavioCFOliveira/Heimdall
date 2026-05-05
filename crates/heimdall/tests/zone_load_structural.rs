// SPDX-License-Identifier: MIT

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::default_trait_access,
    clippy::field_reassign_with_default,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::collapsible_if,
    clippy::ignored_unit_patterns,
    clippy::decimal_bitwise_operands,
    clippy::struct_excessive_bools,
    clippy::redundant_else,
    clippy::undocumented_unsafe_blocks,
    clippy::used_underscore_binding,
    clippy::unused_async
)]

//! Integration tests for zone-load structural checks (Sprint 47 task #588).
//!
//! Each test verifies that a deliberately invalid zone fixture is rejected at
//! load time with a unique, documented error class, AND that `heimdall
//! check-config` also rejects it (exit code 2).
//!
//! ## Fixtures under `tests/fixtures/zones/invalid/`
//!
//! | File                      | Violation    | Error class                   |
//! |---------------------------|--------------|-------------------------------|
//! | nsec3_no_nsec3param.zone  | DNSSEC-067   | `IntegrityError::Nsec3ParamMissing`        |
//! | nsec_and_nsec3.zone       | DNSSEC-068   | `IntegrityError::Nsec3AndNsecCoexist`      |
//! | rrsig_expired.zone        | DNSSEC-077   | `IntegrityError::AllRrsigsExpired`         |
//! | must_not_only.zone        | DNSSEC-062   | `IntegrityError::MustNotAlgorithmOnly`     |
//! | zone.json                 | PROTO-101    | `ZoneError::UnsupportedFormat`             |
//! | zone.yaml                 | PROTO-101    | `ZoneError::UnsupportedFormat`             |

use std::{path::PathBuf, process::Command};

use heimdall_core::zone::{IntegrityError, ZoneError, ZoneFile, ZoneLimits};
use heimdall_e2e_harness::free_port;

const BIN: &str = env!("CARGO_BIN_EXE_heimdall");

fn invalid_zone(name: &str) -> PathBuf {
    let base = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(format!("{base}/tests/fixtures/zones/invalid/{name}"))
}

fn parse_invalid(name: &str) -> ZoneError {
    let path = invalid_zone(name);
    let origin = "example.com.".parse::<heimdall_core::name::Name>().ok();
    ZoneFile::parse_file(&path, origin, ZoneLimits::default())
        .expect_err(&format!("'{name}' should be rejected by the zone loader"))
}

fn check_config_exits(zone_name: &str, expected_code: i32) {
    let zone_path = invalid_zone(zone_name);
    let port = free_port();

    // Write a minimal TOML config that references the invalid zone.
    let config = format!(
        "[roles]\nauthoritative = true\n\n\
         [[listeners]]\naddress = \"127.0.0.1\"\nport = {port}\ntransport = \"udp\"\n\n\
         [[zones.zone_files]]\norigin = \"example.com.\"\npath = \"{path}\"\n",
        path = zone_path.display()
    );
    let config_path = std::env::temp_dir().join(format!(
        "heimdall_struct_test_{zone_name}_{}.toml",
        std::process::id()
    ));
    std::fs::write(&config_path, &config).unwrap();

    let out = Command::new(BIN)
        .args(["check-config", "--config", config_path.to_str().unwrap()])
        .output()
        .expect("failed to run heimdall check-config");

    let _ = std::fs::remove_file(&config_path);

    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        expected_code,
        "check-config on '{zone_name}' expected exit {expected_code} got {code};\
         \nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ── (a) DNSSEC-067: NSEC3 without NSEC3PARAM ─────────────────────────────────

/// Zone with NSEC3 records but no NSEC3PARAM at apex is rejected with
/// `IntegrityError::Nsec3ParamMissing`.
#[test]
fn nsec3_no_nsec3param_loader_error() {
    let err = parse_invalid("nsec3_no_nsec3param.zone");
    assert!(
        matches!(
            err,
            ZoneError::IntegrityError(IntegrityError::Nsec3ParamMissing)
        ),
        "expected Nsec3ParamMissing, got: {err}"
    );
}

#[test]
fn nsec3_no_nsec3param_check_config_exits_two() {
    check_config_exits("nsec3_no_nsec3param.zone", 2);
}

// ── (b) DNSSEC-068: NSEC + NSEC3 coexistence ─────────────────────────────────

/// Zone with both NSEC and NSEC3 records is rejected with
/// `IntegrityError::Nsec3AndNsecCoexist`.
#[test]
fn nsec_and_nsec3_loader_error() {
    let err = parse_invalid("nsec_and_nsec3.zone");
    assert!(
        matches!(
            err,
            ZoneError::IntegrityError(IntegrityError::Nsec3AndNsecCoexist)
        ),
        "expected Nsec3AndNsecCoexist, got: {err}"
    );
}

#[test]
fn nsec_and_nsec3_check_config_exits_two() {
    check_config_exits("nsec_and_nsec3.zone", 2);
}

// ── (c) DNSSEC-077: all RRSIGs expired ───────────────────────────────────────

/// Zone whose only RRSIG for the SOA `RRset` is expired is rejected with
/// `IntegrityError::AllRrsigsExpired`.
#[test]
fn rrsig_expired_loader_error() {
    let err = parse_invalid("rrsig_expired.zone");
    assert!(
        matches!(
            err,
            ZoneError::IntegrityError(IntegrityError::AllRrsigsExpired { .. })
        ),
        "expected AllRrsigsExpired, got: {err}"
    );
}

#[test]
fn rrsig_expired_check_config_exits_two() {
    check_config_exits("rrsig_expired.zone", 2);
}

// ── (d) DNSSEC-062: MUST-NOT algorithm only ──────────────────────────────────

/// Zone signed exclusively with algorithm 1 (RSAMD5, MUST NOT per RFC 8624)
/// is rejected with `IntegrityError::MustNotAlgorithmOnly`.
#[test]
fn must_not_only_loader_error() {
    let err = parse_invalid("must_not_only.zone");
    assert!(
        matches!(
            err,
            ZoneError::IntegrityError(IntegrityError::MustNotAlgorithmOnly { .. })
        ),
        "expected MustNotAlgorithmOnly, got: {err}"
    );
}

#[test]
fn must_not_only_check_config_exits_two() {
    check_config_exits("must_not_only.zone", 2);
}

// ── (e) PROTO-101: JSON zone file ────────────────────────────────────────────

/// Zone file with `.json` extension is rejected with `ZoneError::UnsupportedFormat`.
#[test]
fn json_zone_loader_error() {
    let err = parse_invalid("zone.json");
    assert!(
        matches!(err, ZoneError::UnsupportedFormat { .. }),
        "expected UnsupportedFormat, got: {err}"
    );
    assert!(
        err.to_string().contains("json"),
        "error message must mention the extension; got: {err}"
    );
}

#[test]
fn json_zone_check_config_exits_two() {
    check_config_exits("zone.json", 2);
}

// ── (f) PROTO-101: YAML zone file ────────────────────────────────────────────

/// Zone file with `.yaml` extension is rejected with `ZoneError::UnsupportedFormat`.
#[test]
fn yaml_zone_loader_error() {
    let err = parse_invalid("zone.yaml");
    assert!(
        matches!(err, ZoneError::UnsupportedFormat { .. }),
        "expected UnsupportedFormat, got: {err}"
    );
    assert!(
        err.to_string().contains("yaml"),
        "error message must mention the extension; got: {err}"
    );
}

#[test]
fn yaml_zone_check_config_exits_two() {
    check_config_exits("zone.yaml", 2);
}
