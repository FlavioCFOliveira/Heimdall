// SPDX-License-Identifier: MIT

//! W^X enforcement validation (THREAT-027, Sprint 37 task #374).
//!
//! Verifies that no mapped memory region in the current process simultaneously
//! holds Write and Execute permissions, and that the ELF binary has a
//! non-executable stack segment (`PT_GNU_STACK` without `PF_X`).

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
    /// Test: on Linux, parse /proc/self/maps and assert no W+X region exists.
    #[test]
    #[cfg(target_os = "linux")]
    fn no_wx_mappings_in_proc_self_maps() {
        let maps = std::fs::read_to_string("/proc/self/maps")
            .expect("/proc/self/maps must be readable");

        let mut wx_regions: Vec<&str> = Vec::new();
        for line in maps.lines() {
            let perms = line.split_whitespace().nth(1).unwrap_or("");
            if perms.contains('w') && perms.contains('x') {
                wx_regions.push(line);
            }
        }

        assert!(
            wx_regions.is_empty(),
            "found W+X memory regions — W^X violation:\n{}",
            wx_regions.join("\n")
        );
    }

    /// Test: verify the test binary's ELF has a non-executable stack and a RELRO segment.
    #[test]
    #[cfg(target_os = "linux")]
    fn elf_binary_has_nonexec_stack_and_relro() {
        let exe = std::env::current_exe().expect("current_exe must resolve");
        let data = std::fs::read(&exe).expect("test binary must be readable");

        // ELF64 magic check.
        assert_eq!(
            &data[..4],
            &[0x7f, b'E', b'L', b'F'],
            "binary must start with ELF magic"
        );

        // ELF64 header offsets.
        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;

        assert_eq!(e_phentsize, 56, "ELF64 phdr entry size must be 56 bytes");

        const PT_GNU_STACK: u32 = 0x6474_e551;
        const PT_GNU_RELRO: u32 = 0x6474_e552;
        const PF_X: u32 = 0x1;

        let mut found_nonexec_stack = false;
        let mut found_relro = false;

        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if off + 56 > data.len() {
                break;
            }
            let phdr = &data[off..off + 56];
            let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
            let p_flags = u32::from_le_bytes(phdr[4..8].try_into().unwrap());

            if p_type == PT_GNU_STACK {
                assert_eq!(
                    p_flags & PF_X,
                    0,
                    "PT_GNU_STACK must not have PF_X (executable stack detected)"
                );
                found_nonexec_stack = true;
            }
            if p_type == PT_GNU_RELRO {
                found_relro = true;
            }
        }

        assert!(
            found_nonexec_stack,
            "binary must have a PT_GNU_STACK segment (non-executable stack)"
        );
        assert!(
            found_relro,
            "binary must have a PT_GNU_RELRO segment (RELRO hardening required)"
        );
    }

    /// Test: on macOS, use vmmap to check for W+X regions.
    /// Gated on `HEIMDALL_HARDENING_TESTS=1` because vmmap requires elevated
    /// permissions or SIP entitlements in some configurations.
    #[test]
    #[cfg(target_os = "macos")]
    fn no_wx_mappings_macos_vmmap() {
        if std::env::var("HEIMDALL_HARDENING_TESTS").as_deref() != Ok("1") {
            eprintln!("Skip: set HEIMDALL_HARDENING_TESTS=1 to run vmmap W^X check");
            return;
        }
        let pid = std::process::id();
        let output = std::process::Command::new("vmmap")
            .arg("--wide")
            .arg(pid.to_string())
            .output()
            .expect("vmmap must be available on macOS");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut wx_regions: Vec<&str> = Vec::new();

        for line in stdout.lines() {
            if line.contains("rw-/rwx") || line.contains("rwx") {
                wx_regions.push(line);
            }
        }

        assert!(
            wx_regions.is_empty(),
            "found W+X memory regions on macOS:\n{}",
            wx_regions.join("\n")
        );
    }
}
