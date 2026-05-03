// SPDX-License-Identifier: MIT

//! Build script — embeds version metadata as `rustc-env` variables.
//!
//! Variables produced (all readable via `env!` in the binary):
//!
//! | Variable                | Source                                              |
//! |-------------------------|-----------------------------------------------------|
//! | `HEIMDALL_VERSION`      | `CARGO_PKG_VERSION`                                 |
//! | `HEIMDALL_GIT_COMMIT`   | `git rev-parse HEAD` (short), or "unknown"          |
//! | `HEIMDALL_BUILD_DATE`   | `SOURCE_DATE_EPOCH` → RFC 3339 UTC, or current time |
//! | `HEIMDALL_RUSTC`        | `rustc --version`                                   |
//! | `HEIMDALL_TARGET`       | `TARGET` (cargo env)                                |
//! | `HEIMDALL_PROFILE`      | `PROFILE` (cargo env): "debug" or "release"         |
//! | `HEIMDALL_FEATURES`     | Comma-separated list of enabled Cargo features      |
//!
//! For reproducible builds, set `SOURCE_DATE_EPOCH` to a fixed Unix timestamp
//! before building (standard for reproducible-build toolchains).
//!
//! No external crates are used — all data comes from environment variables and
//! standard subprocess calls (`git`, `rustc`). This keeps the build-dependency
//! graph minimal (ADR-0063).

use std::process::Command;

fn main() {
    // Version from Cargo — always available.
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=HEIMDALL_VERSION={version}");

    // Git commit hash — short SHA, fallback to "unknown" if git is unavailable.
    let git_commit = git_short_sha().unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=HEIMDALL_GIT_COMMIT={git_commit}");

    // Build date — RFC 3339 UTC. Use SOURCE_DATE_EPOCH for reproducibility.
    let build_date = build_date_rfc3339();
    println!("cargo:rustc-env=HEIMDALL_BUILD_DATE={build_date}");

    // rustc version string.
    let rustc = rustc_version().unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=HEIMDALL_RUSTC={rustc}");

    // Target triple from Cargo.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=HEIMDALL_TARGET={target}");

    // Build profile: "debug" or "release".
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=HEIMDALL_PROFILE={profile}");

    // Enabled Cargo features (CARGO_FEATURE_<UPPER_FEATURE_NAME> is set to "1").
    let features = enabled_features();
    println!("cargo:rustc-env=HEIMDALL_FEATURES={features}");

    // Rerun if HEAD changes or SOURCE_DATE_EPOCH changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

/// Returns the short (7-char) git SHA of HEAD, or `None` if git is unavailable
/// or the working directory is not a git repository.
fn git_short_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if output.status.success() {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if sha.is_empty() { None } else { Some(sha) }
    } else {
        None
    }
}

/// Returns an RFC 3339 UTC timestamp.
///
/// If `SOURCE_DATE_EPOCH` is set, parses it as a Unix timestamp (for
/// reproducible builds). Otherwise uses the current system time.
fn build_date_rfc3339() -> String {
    let secs: i64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64)
        });

    // Format as YYYY-MM-DDTHH:MM:SSZ without pulling in chrono.
    let epoch = secs.max(0) as u64;
    let secs_per_day = 86_400u64;
    let days = epoch / secs_per_day;
    let time_of_day = epoch % secs_per_day;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days since Unix epoch to (year, month, day) in the proleptic Gregorian
/// calendar.  Algorithm by Henry F. Fliegel and Thomas C. Van Flandern (1968).
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Shift epoch from 1970-01-01 to the Julian Day Number epoch.
    let jd = days as i64 + 2_440_588;
    let l = jd + 68_569;
    let n = 4 * l / 146_097;
    let l = l - (146_097 * n + 3) / 4;
    let i = 4000 * (l + 1) / 1_461_001;
    let l = l - 1461 * i / 4 + 31;
    let j = 80 * l / 2447;
    let d = l - 2447 * j / 80;
    let l = j / 11;
    let m = j + 2 - 12 * l;
    let y = 100 * (n - 49) + i + l;
    (y as u32, m as u32, d as u32)
}

/// Returns the `rustc --version` string, or `None` if `rustc` is unavailable.
fn rustc_version() -> Option<String> {
    let output = Command::new("rustc").arg("--version").output().ok()?;
    if output.status.success() {
        let v = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if v.is_empty() { None } else { Some(v) }
    } else {
        None
    }
}

/// Collects enabled Cargo features from environment variables.
///
/// Cargo sets `CARGO_FEATURE_<UPPER_SNAKE>` to `"1"` for each enabled feature.
/// We read all such variables from the environment and collect the feature names.
fn enabled_features() -> String {
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| {
            k.strip_prefix("CARGO_FEATURE_").map(|f| f.to_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort();
    if features.is_empty() {
        "none".into()
    } else {
        features.join(",")
    }
}
