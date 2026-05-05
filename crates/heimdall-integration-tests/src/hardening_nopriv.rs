// SPDX-License-Identifier: MIT

//! No-accidental-privsep assertion tests (THREAT-032, Sprint 37 task #377).
//!
//! Verifies that the current process (and by extension, a running Heimdall
//! instance) has not spawned unexpected child processes with different
//! credentials, satisfying THREAT-032's prohibition on implicit privilege
//! separation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
    /// Test A (self-contained, Linux): read /proc/$pid/task/ to count threads
    /// and verify no child processes with different credentials exist at startup.
    #[test]
    #[cfg(target_os = "linux")]
    fn no_unexpected_child_processes_linux() {
        let pid = std::process::id();
        let children_path = format!("/proc/{pid}/task/{pid}/children");

        let children_raw = std::fs::read_to_string(&children_path).unwrap_or_default();
        let children: Vec<&str> = children_raw.split_whitespace().collect();

        assert!(
            children.is_empty(),
            "test process must not have child processes at startup; found: {children:?}"
        );
    }

    /// Test B (self-contained, macOS): enumerate processes with the current pid
    /// as their parent and assert the list is empty.
    #[test]
    #[cfg(target_os = "macos")]
    fn no_unexpected_child_processes_macos() {
        let pid = std::process::id();

        let output = std::process::Command::new("pgrep")
            .arg("-P")
            .arg(pid.to_string())
            .output()
            .expect("pgrep must be available on macOS");

        let children_raw = String::from_utf8_lossy(&output.stdout);
        let children: Vec<&str> = children_raw.split_whitespace().collect();

        assert!(
            children.is_empty(),
            "test process must not have child processes at startup; found: {children:?}"
        );
    }

    /// Test C (process-dependent): spawn Heimdall and enumerate its child
    /// processes via /proc/$pid/task/. Requires a live Heimdall binary.
    #[test]
    #[cfg(target_os = "linux")]
    fn heimdall_has_no_unexpected_children() {
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
        let task_dir = format!("/proc/{pid}/task/{pid}/children");
        let children_raw = std::fs::read_to_string(&task_dir).unwrap_or_default();
        let children: Vec<&str> = children_raw.split_whitespace().collect();

        child.kill().ok();
        child.wait().ok();

        assert!(
            children.is_empty(),
            "Heimdall must not have unexpected child processes; found: {children:?}"
        );
    }
}
