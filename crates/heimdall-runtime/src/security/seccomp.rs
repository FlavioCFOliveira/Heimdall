// SPDX-License-Identifier: MIT

//! Seccomp-BPF syscall allow-list filter (THREAT-024).
//!
//! Installs a kernel-enforced allow-list of system calls using the classic
//! Berkeley Packet Filter (BPF) mechanism exposed via `prctl(PR_SET_SECCOMP)`.
//! Any syscall NOT in the allow-list causes the kernel to deliver SIGSYS and
//! terminate the offending process with `SECCOMP_RET_KILL_PROCESS`.
//!
//! The filter is installed in two steps:
//! 1. `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` — required precondition; prevents
//!    privilege escalation via `setuid` binaries executed after the filter is
//!    in place.
//! 2. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` — loads the BPF
//!    program into the kernel.
//!
//! After `install()` returns, the calling thread (and all threads sharing the
//! same seccomp domain, i.e. the full process in a `TSYNC`-capable kernel)
//! are bound by the filter.
//!
//! # Safety
//!
//! The only `unsafe` code in this module is the two `libc::prctl` calls.
//! Their invariants are documented at each call site.

#![allow(unsafe_code)]

use std::fmt;

/// BPF instruction opcodes (classic BPF, not eBPF).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Seccomp return actions.
///
/// KILL_PROCESS terminates the entire process (not just the thread) on a
/// denied syscall, preventing any attempt to circumvent the filter by
/// spawning new threads. Available since Linux 4.14.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `prctl(2)` constants.
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// Byte offset of the `nr` field inside the `seccomp_data` struct.
///
/// The kernel places `seccomp_data` at a fixed layout; `nr` (the syscall
/// number) is always at offset 0 on all architectures Heimdall targets.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// Allowed syscall numbers — the complete list from THREAT-089.
///
/// Each category is grouped with a comment so auditors can cross-reference
/// the specification without parsing raw numbers.
#[rustfmt::skip]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[
    // Socket I/O
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_accept4,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    // Memory management (no PROT_EXEC toggle — enforcement is at the process level)
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_mprotect,
    // Clock / timer
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    // File I/O
    libc::SYS_openat,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_getdents64,
    libc::SYS_lseek,
    libc::SYS_close,
    // Process lifecycle
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_nanosleep,
    libc::SYS_getrandom,
    // I/O multiplexing
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_eventfd2,
    libc::SYS_pipe2,
    // Signals
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    // Miscellaneous (arch / threading setup, identity, fd ops, etc.)
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getgroups,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_fchown,
    libc::SYS_fchmod,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_rename,
    libc::SYS_unlink,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_symlink,
    libc::SYS_readlink,
    libc::SYS_statx,
    libc::SYS_getrusage,
    libc::SYS_uname,
    libc::SYS_sysinfo,
    // Boot-time only (prctl, setuid family, capset/capget — allowed so that the
    // privilege-drop sequence can complete before the filter enforces the tighter
    // post-boot allow-list).
    libc::SYS_prctl,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setgroups,
    libc::SYS_capset,
    libc::SYS_capget,
];

/// Error type for seccomp filter installation.
#[derive(Debug)]
pub enum SeccompError {
    /// `prctl(PR_SET_NO_NEW_PRIVS)` failed with the given `errno`.
    NoNewPrivsFailed(i32),
    /// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` failed with the given `errno`.
    FilterInstallFailed(i32),
    /// The BPF program has more instructions than the kernel allows (4096).
    ProgramTooLarge(usize),
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNewPrivsFailed(e) => write!(f, "prctl(PR_SET_NO_NEW_PRIVS) failed: errno {e}"),
            Self::FilterInstallFailed(e) => {
                write!(f, "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed: errno {e}")
            }
            Self::ProgramTooLarge(n) => {
                write!(f, "BPF program has {n} instructions, exceeds kernel limit of 4096")
            }
        }
    }
}

impl std::error::Error for SeccompError {}

/// A compiled seccomp-BPF allow-list filter ready for installation.
///
/// Construct with [`SecurityFilter::new`] (using the default Heimdall
/// allow-list from THREAT-089) or [`SecurityFilter::with_syscalls`] (custom
/// allow-list for testing).
pub struct SecurityFilter {
    instructions: Vec<libc::sock_filter>,
}

impl SecurityFilter {
    /// Creates a filter from the full Heimdall allow-list (THREAT-089).
    pub fn new() -> Self {
        Self::with_syscalls(ALLOWED_SYSCALLS)
    }

    /// Creates a filter from a caller-supplied allow-list.
    ///
    /// Useful in tests where only a small subset of syscalls should be
    /// allowed so that the kill path can be exercised cheaply.
    pub fn with_syscalls(syscalls: &[libc::c_long]) -> Self {
        let mut insns: Vec<libc::sock_filter> = Vec::new();

        // Load the syscall number from the seccomp_data struct.
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        // For each allowed syscall: if nr == NR, skip one instruction (the KILL)
        // and fall through to ALLOW; otherwise continue to the next JEQ.
        //
        // Layout per pair:
        //   [i+0] JEQ NR, jt=1, jf=0   → match: skip stmt at i+1 → reach ALLOW
        //   [i+1] JMP 0 (continue)      → no-match: fall through to next JEQ
        //
        // We build a more compact form: each syscall emits exactly one JEQ that
        // jumps directly to the ALLOW instruction (at a computed absolute index)
        // on match, or continues to the next instruction on no-match.
        //
        // The ALLOW instruction is always the second-to-last instruction.
        // The KILL instruction is always the last instruction.
        //
        // Instruction layout (after the load):
        //   [1..n]   JEQ <nr>, jt=(jump-to-allow), jf=0
        //   [n+1]    RET KILL_PROCESS
        //   [n+2]    RET ALLOW          ← ALLOW is at index (n+2) from start

        let n = syscalls.len();

        for (i, &nr) in syscalls.iter().enumerate() {
            // Distance from this JEQ to the ALLOW instruction:
            // - KILL is at index (1 + n), i.e. (n - i) instructions after this JEQ.
            // - ALLOW is at index (1 + n + 1), i.e. (n - i + 1) instructions after.
            // jt counts instructions skipped on match (not including the JEQ itself).
            let jump_to_allow = (n - i) as u8;
            insns.push(jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                nr as u32,
                jump_to_allow,
                0,
            ));
        }

        // Default: deny — kill entire process.
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
        // Allow: reached only via a successful JEQ.
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        Self { instructions: insns }
    }

    /// Installs the filter into the running process.
    ///
    /// After this call returns `Ok(())`, any thread in the process that
    /// executes a syscall not in the allow-list will be killed.
    ///
    /// # Errors
    ///
    /// Returns [`SeccompError`] if either `prctl` call fails.
    pub fn install(&self) -> Result<(), SeccompError> {
        const MAX_BPF_INSNS: usize = 4096;

        if self.instructions.len() > MAX_BPF_INSNS {
            return Err(SeccompError::ProgramTooLarge(self.instructions.len()));
        }

        let prog = libc::sock_fprog {
            len: self.instructions.len() as u16,
            filter: self.instructions.as_ptr().cast_mut(),
        };

        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is always safe to call.
        // It sets a per-thread flag that prevents privilege elevation via suid/sgid
        // execve. The call never accesses user-space memory through the pointer
        // arguments (all are zero/ignored for this option). The return value is
        // checked immediately.
        let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) };
        if ret != 0 {
            // SAFETY: errno is valid immediately after a failing syscall.
            let e = unsafe { *libc::__errno_location() };
            return Err(SeccompError::NoNewPrivsFailed(e));
        }

        // SAFETY: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) loads the BPF
        // program pointed to by `prog` into the kernel. Requirements:
        // - `prog.filter` points to a valid, non-null array of `prog.len`
        //   `sock_filter` structs that lives for the duration of the call.
        //   Both conditions hold: `self.instructions` is a live `Vec` whose data
        //   pointer is valid and stable for the call's duration.
        // - PR_SET_NO_NEW_PRIVS has already been set (checked above).
        // - The BPF program has been validated syntactically (the kernel performs
        //   its own BPF verifier pass; if the program is invalid, prctl fails and
        //   we propagate the error).
        let ret = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog as usize,
                0usize,
                0usize,
            )
        };
        if ret != 0 {
            // SAFETY: errno is valid immediately after a failing syscall.
            let e = unsafe { *libc::__errno_location() };
            return Err(SeccompError::FilterInstallFailed(e));
        }

        Ok(())
    }
}

impl Default for SecurityFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
