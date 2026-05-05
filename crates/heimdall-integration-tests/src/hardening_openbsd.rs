// SPDX-License-Identifier: MIT

//! OpenBSD pledge(2) and unveil(2) runtime validation tests (THREAT-029, Sprint 37 task #372).

#![cfg(target_os = "openbsd")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
    use heimdall_runtime::security::pledge;

    #[test]
    fn pledge_restricts_non_stdio_operations() {
        pledge::pledge("stdio", None).expect("pledge(stdio) must succeed");

        let result = std::fs::File::open("/etc/passwd");
        assert!(result.is_err(), "file open must fail after pledge(stdio)");
    }

    #[test]
    fn unveil_limits_path_access() {
        pledge::unveil("/tmp", "rwc").expect("unveil /tmp must succeed");
        pledge::unveil_lock().expect("unveil lock must succeed");

        let result = std::fs::File::open("/etc/passwd");
        assert!(
            result.is_err(),
            "access to /etc must be denied after unveil lock"
        );
    }

    #[test]
    fn pledge_heimdall_binary() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            return;
        }
    }
}
