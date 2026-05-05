// SPDX-License-Identifier: MIT

//! macOS sandbox-profile runtime validation tests (THREAT-030, Sprint 37 task #373).

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

    /// Test A (self-contained, any platform): parse the macOS sandbox profile and
    /// assert structural invariants required by THREAT-030.
    #[test]
    fn macos_sandbox_profile_structural_invariants() {
        let profile_path = repo_root().join("contrib/macos/heimdall.sb");
        let content = std::fs::read_to_string(&profile_path)
            .expect("contrib/macos/heimdall.sb must be readable");

        assert!(
            content.contains("(deny default)"),
            "sandbox profile must have a top-level deny-default rule"
        );

        assert!(
            content.contains("(deny process-exec)"),
            "sandbox profile must explicitly deny process-exec"
        );

        assert!(
            content.contains("(deny process-fork)"),
            "sandbox profile must explicitly deny process-fork"
        );

        assert!(
            content.contains("(allow network*)") || content.contains("(allow network-bind"),
            "sandbox profile must allow network-bind for DNS ports"
        );

        let line_count = content.lines().count();
        assert!(
            line_count > 50,
            "sandbox profile is unexpectedly short ({line_count} lines); likely truncated"
        );
    }

    /// Test B (macOS-only): verify sandbox-exec accepts the profile with /bin/true.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_sandbox_exec_accepts_profile() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }

        let profile_path = repo_root().join("contrib/macos/heimdall.sb");
        let profile_content = std::fs::read_to_string(&profile_path)
            .expect("contrib/macos/heimdall.sb must be readable");

        let status = std::process::Command::new("sandbox-exec")
            .arg("-p")
            .arg(&profile_content)
            .arg("/bin/true")
            .status()
            .expect("sandbox-exec must be available on macOS");

        assert!(status.success(), "sandbox-exec /bin/true must exit 0");
    }

    /// Test C (macOS-only): verify the sandbox denies writes outside the allowlist.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_sandbox_denies_tmp_write() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }

        let profile_path = repo_root().join("contrib/macos/heimdall.sb");
        let profile_content = std::fs::read_to_string(&profile_path)
            .expect("contrib/macos/heimdall.sb must be readable");

        let pid = std::process::id();
        let test_file = format!("/tmp/heimdall_sandbox_test_{pid}");

        let status = std::process::Command::new("sandbox-exec")
            .arg("-p")
            .arg(&profile_content)
            .arg("sh")
            .arg("-c")
            .arg(format!("touch {test_file}"))
            .status()
            .expect("sandbox-exec sh must spawn");

        assert!(
            !status.success(),
            "sandbox should deny writing to /tmp/{test_file}"
        );
    }
}
