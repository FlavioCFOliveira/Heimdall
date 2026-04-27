// SPDX-License-Identifier: MIT

//! Regression comparison tool for Heimdall benchmarks.
//!
//! Reads two criterion estimates JSON files (baseline and current), computes
//! per-benchmark delta as a percentage change, prints a formatted table, and
//! exits non-zero if any benchmark regressed by more than the configured
//! threshold (default 5 %).
//!
//! # Usage
//!
//! ```text
//! heimdall-bench-compare <baseline.json> <current.json>
//! ```
//!
//! Each JSON file is the `estimates.json` produced by criterion for a single
//! benchmark function.  The relevant field is `mean.point_estimate`, expressed
//! in nanoseconds.
//!
//! # Exit codes
//!
//! - `0` — no regressions detected.
//! - `1` — one or more benchmarks regressed beyond the threshold.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::path::Path;

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: heimdall-bench-compare <baseline.json> <current.json>");
        return std::process::ExitCode::FAILURE;
    }

    let baseline = match load_criterion_json(&args[1]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error reading baseline '{}': {e}", args[1]);
            return std::process::ExitCode::FAILURE;
        }
    };

    let current = match load_criterion_json(&args[2]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error reading current '{}': {e}", args[2]);
            return std::process::ExitCode::FAILURE;
        }
    };

    print_table(&baseline, &current);

    let regressions = compare(&baseline, &current, REGRESSION_THRESHOLD_PCT);
    if regressions.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!(
            "{} benchmark(s) regressed by >{REGRESSION_THRESHOLD_PCT:.0}%",
            regressions.len()
        );
        std::process::ExitCode::FAILURE
    }
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Percentage change above which a benchmark is flagged as a regression.
const REGRESSION_THRESHOLD_PCT: f64 = 5.0;

// ── Core functions (also used by integration tests in tests/) ─────────────────

/// Loads a criterion `estimates.json` file, returning a map from benchmark
/// name to mean nanoseconds.
///
/// The criterion estimates JSON format is:
/// ```json
/// {"mean": {"point_estimate": <ns>, ...}, ...}
/// ```
///
/// This function reads the `mean.point_estimate` field.
///
/// # Errors
///
/// Returns a descriptive error string on I/O failure, JSON parse error, or
/// missing expected fields.
pub fn load_criterion_json(path: &str) -> Result<HashMap<String, f64>, String> {
    let content = std::fs::read_to_string(Path::new(path))
        .map_err(|e| format!("I/O error reading '{path}': {e}"))?;

    // Parse the `mean.point_estimate` field using targeted string scanning
    // so that no external JSON parser dependency is required.
    let mean_ns = extract_mean_ns(&content)
        .ok_or_else(|| format!("Could not find 'mean.point_estimate' in '{path}'"))?;

    // Use the file stem (without extension) as the benchmark name.
    let name = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_owned();

    let mut map = HashMap::new();
    map.insert(name, mean_ns);
    Ok(map)
}

/// Returns benchmarks whose mean time increased by more than `threshold_pct`
/// relative to the baseline.
///
/// Benchmarks present only in `current` (no baseline) are not flagged.
/// Benchmarks present only in `baseline` (removed) are not flagged.
pub fn compare<S: BuildHasher>(
    baseline: &HashMap<String, f64, S>,
    current: &HashMap<String, f64, S>,
    threshold_pct: f64,
) -> Vec<String> {
    let mut regressions = Vec::new();
    for (name, &base_ns) in baseline {
        if let Some(&curr_ns) = current.get(name)
            && base_ns > 0.0
        {
            let delta_pct = (curr_ns - base_ns) / base_ns * 100.0;
            if delta_pct > threshold_pct {
                regressions.push(name.clone());
            }
        }
    }
    regressions.sort_unstable();
    regressions
}

/// Prints a formatted comparison table to stdout.
pub fn print_table<S: BuildHasher>(
    baseline: &HashMap<String, f64, S>,
    current: &HashMap<String, f64, S>,
) {
    // Collect all benchmark names present in either map.
    let mut names: Vec<&str> = baseline
        .keys()
        .chain(current.keys())
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names.dedup();

    println!(
        "{:<40} {:>14} {:>14} {:>10}",
        "Benchmark", "Baseline (ns)", "Current (ns)", "Delta"
    );
    println!("{}", "-".repeat(82));

    for name in names {
        let base = baseline.get(name).copied();
        let curr = current.get(name).copied();
        match (base, curr) {
            (Some(b), Some(c)) => {
                let delta = if b > 0.0 {
                    format!("{:+.1}%", (c - b) / b * 100.0)
                } else {
                    "N/A".to_owned()
                };
                println!("{name:<40} {b:>14.1} {c:>14.1} {delta:>10}");
            }
            (Some(b), None) => {
                println!("{name:<40} {b:>14.1} {:>14} {:>10}", "(removed)", "N/A");
            }
            (None, Some(c)) => {
                println!("{name:<40} {:>14} {c:>14.1} {:>10}", "(new)", "N/A");
            }
            (None, None) => {
                // Cannot happen since we built `names` from both maps.
            }
        }
    }
}

// ── JSON parsing helper ───────────────────────────────────────────────────────

/// Extracts the `mean.point_estimate` field from criterion's `estimates.json`
/// without an external JSON parser.
///
/// The field always appears as a JSON number following `"point_estimate":` inside
/// the `"mean"` object.  We locate the first occurrence of the key string and
/// parse the subsequent number literal.
fn extract_mean_ns(json: &str) -> Option<f64> {
    // Locate "mean" object boundary, then the first "point_estimate" within it.
    let mean_pos = json.find("\"mean\"")?;
    let after_mean = &json[mean_pos..];
    let pe_pos = after_mean.find("\"point_estimate\"")?;
    let after_pe = &after_mean[pe_pos + "\"point_estimate\"".len()..];

    // Skip over whitespace, colon, and optional whitespace.
    let after_colon = after_pe.trim_start().strip_prefix(':')?.trim_start();

    // Read digits (including decimal point and exponent notation).
    let end = after_colon
        .find(|c: char| {
            !c.is_ascii_digit() && c != '.' && c != 'e' && c != 'E' && c != '-' && c != '+'
        })
        .unwrap_or(after_colon.len());

    after_colon[..end].parse().ok()
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_mean_ns_parses_criterion_format() {
        let json = r#"{"mean":{"confidence_interval":{"lower_bound":1000.0,"upper_bound":1100.0},"point_estimate":1050.5,"standard_error":25.0}}"#;
        let result = extract_mean_ns(json);
        assert!(result.is_some(), "should extract a value");
        let ns = result.expect("just checked is_some");
        assert!(
            (ns - 1050.5).abs() < f64::EPSILON,
            "expected 1050.5, got {ns}"
        );
    }

    #[test]
    fn extract_mean_ns_returns_none_for_missing_field() {
        let json = r#"{"median":{"point_estimate":999.0}}"#;
        assert!(extract_mean_ns(json).is_none());
    }
}
