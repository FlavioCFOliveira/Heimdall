// SPDX-License-Identifier: MIT

//! Privilege-drop validation tests (THREAT-022/023, Sprint 37 task #375).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
    /// Test A (self-contained, Linux): parse /proc/self/status and verify the
    /// current process has only 0 or CAP_NET_BIND_SERVICE in Permitted/Effective.
    #[test]
    #[cfg(target_os = "linux")]
    fn verify_current_process_capabilities() {
        use heimdall_runtime::security::privdrop;

        privdrop::verify_capabilities()
            .expect("verify_capabilities must pass for an unprivileged test process");
    }

    /// Test B (process-dependent, Linux): spawn Heimdall and verify it drops to
    /// an unprivileged user with only CAP_NET_BIND_SERVICE in CapPrm.
    #[test]
    #[cfg(target_os = "linux")]
    fn heimdall_drops_privileges_correctly() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }

        let binary = std::env::var("HEIMDALL_BINARY")
            .unwrap_or_else(|_| "/usr/local/bin/heimdall".to_string());

        let mut child = std::process::Command::new(binary)
            .args(["--version"])
            .spawn()
            .expect("Heimdall binary must spawn");

        let pid = child.id();
        let status_path = format!("/proc/{pid}/status");
        let status = std::fs::read_to_string(&status_path)
            .expect("proc status must be readable after spawn");

        let uid_line = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .expect("Uid field must be in /proc/pid/status");
        let uid: u32 = uid_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("Uid must be a valid integer");

        assert_ne!(uid, 0, "Heimdall must not run as root after privilege drop");

        let cap_prm_line = status
            .lines()
            .find(|l| l.starts_with("CapPrm:"))
            .expect("CapPrm field must be in /proc/pid/status");
        let cap_prm = u64::from_str_radix(
            cap_prm_line.split(':').nth(1).unwrap_or("").trim(),
            16,
        )
        .expect("CapPrm must be a hex integer");

        assert_eq!(
            cap_prm,
            heimdall_runtime::security::privdrop::CAP_NET_BIND_SERVICE,
            "CapPrm must be exactly CAP_NET_BIND_SERVICE (0x400)"
        );

        child.kill().ok();
        child.wait().ok();
    }
}
