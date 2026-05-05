// SPDX-License-Identifier: MIT

//! Privilege drop at boot phase 14 (BIN-041..BIN-043, THREAT-022/023).
//!
//! On Linux: when running as root, look up the `heimdall` system user, set
//! `KEEPCAPS`, raise the ambient `CAP_NET_BIND_SERVICE`, then `setuid`/`setgid`
//! to the unprivileged user. When not running as root, log a warning for each
//! listener bound to a port below 1024.
//!
//! On macOS and other non-Linux platforms: no-op (privilege management is
//! handled by the system sandbox or pledge/unveil in their own tasks).

use heimdall_runtime::config::Config;
use tracing::warn;

/// Apply privilege-drop policy after all listeners have been bound.
///
/// # Errors
///
/// Returns a human-readable message on Linux if `setuid`/`setgid` or
/// capability setup fails while running as root.
#[allow(clippy::unnecessary_wraps)] // On non-Linux the function is always Ok(()), but on Linux it can fail.
pub fn apply(config: &Config) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(config)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        non_linux_warn(config);
    }
    Ok(())
}

// ── Non-Linux stub ────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn non_linux_warn(config: &Config) {
    for listener in &config.listeners {
        if listener.port < 1024 {
            warn!(
                address = %listener.address,
                port = listener.port,
                "listener uses privileged port but privilege-drop is Linux-only"
            );
        }
    }
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use nix::unistd::User;
    use tracing::{info, warn};

    use heimdall_runtime::config::Config;
    use heimdall_runtime::security::privdrop::{
        drop_privileges, retain_cap_net_bind_service, verify_capabilities,
    };

    /// Apply the privilege-drop sequence on Linux.
    pub fn apply(config: &Config) -> Result<(), String> {
        // SAFETY: getuid() is always safe to call.
        let is_root = unsafe { libc::getuid() } == 0;

        if !is_root {
            // Already unprivileged — just warn for low ports.
            for listener in &config.listeners {
                if listener.port < 1024 {
                    warn!(
                        address = %listener.address,
                        port = listener.port,
                        "listener uses privileged port but process is not root; bind may fail"
                    );
                }
            }
            return Ok(());
        }

        let user = User::from_name("heimdall")
            .map_err(|e| format!("failed to look up heimdall user: {e}"))?
            .ok_or_else(|| "user 'heimdall' not found; create it before starting the daemon"
                .to_owned())?;

        let uid = user.uid.as_raw();
        let gid = user.gid.as_raw();

        retain_cap_net_bind_service()
            .map_err(|e| format!("failed to set KEEPCAPS/ambient cap: {e}"))?;

        drop_privileges(uid, gid)
            .map_err(|e| format!("failed to drop privileges to uid={uid} gid={gid}: {e}"))?;

        verify_capabilities()
            .map_err(|e| format!("post-drop capability verification failed: {e}"))?;

        info!(uid, gid, "privileges dropped to heimdall user");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use libc;
