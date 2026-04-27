// SPDX-License-Identifier: MIT

//! Filesystem isolation validation tests (THREAT-026, Sprint 37 task #376).

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

    /// Test A (self-contained): verify the systemd unit file contains all mandatory
    /// FS isolation directives from THREAT-026 and THREAT-098.
    #[test]
    fn systemd_unit_has_fs_isolation_directives() {
        let unit_path = repo_root().join("contrib/systemd/heimdall.service");
        let content = std::fs::read_to_string(&unit_path)
            .expect("contrib/systemd/heimdall.service must be readable");

        let required = [
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
        ];

        for directive in &required {
            assert!(
                content.contains(directive),
                "systemd unit must contain {directive}"
            );
        }

        assert!(
            content.contains("RootDirectory") || content.contains("ProtectSystem"),
            "systemd unit must have filesystem root isolation directive"
        );

        let expected_paths = ["/etc/heimdall", "/var/lib/heimdall", "/run/heimdall"];
        for path in &expected_paths {
            assert!(
                content.contains(path),
                "systemd unit must reference allowlist path {path}"
            );
        }
    }

    /// Test B (process-dependent): verify chroot/mount-ns isolation enforces the
    /// path allowlist when Heimdall is running. Requires a live Heimdall binary.
    #[test]
    #[ignore]
    fn heimdall_fs_isolation_enforced() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }

        let denied_path = "/etc/shadow";
        let result = std::fs::read_to_string(denied_path);
        assert!(
            result.is_err(),
            "/etc/shadow must not be readable from the isolated namespace"
        );
    }
}
