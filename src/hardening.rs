// src/hardening.rs
//
// Applies strict kernel-level limits to prevent state exfiltration,
// swap leakage, or privilege escalation.

use anyhow::{Context, Result};
use tracing::{info, warn};

#[cfg(unix)]
use libc::{
    prctl,
    mlockall,
    MCL_CURRENT,
    MCL_FUTURE,
    PR_SET_DUMPABLE,
    PR_SET_NO_NEW_PRIVS,
};

#[cfg(unix)]
use rlimit::Resource;

/// Applies a suite of security hardening measures to the current process.
/// If 'strict' is true, failures in critical protections like mlockall will abort startup.
pub fn apply_protections(strict: bool) -> Result<()> {
    #[cfg(unix)]
    {
        // 1. Lock virtual memory into physical RAM (prevents disk paging/swap)
        // This is critical to ensure sensitive SOCKS data never reaches the VPS disk.
        let ret = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            let raw_err = err.raw_os_error().unwrap_or(0);
            
            if strict {
                // If this fails with errno 1 (EPERM), AppArmor or no-new-privs is likely blocking CAP_IPC_LOCK.
                // If it fails with errno 12 (ENOMEM), you have hit the user limit for locked memory.
                anyhow::bail!(
                    "FATAL: Failed to lock memory via mlockall: {} (errno: {}). \
                     Strict mode requires CAP_IPC_LOCK and unlimited memlock ulimits.", 
                    err, raw_err
                );
            } else {
                warn!("mlockall failed: {} (errno: {}). Process memory may be swapped to disk.", err, raw_err);
            }
        }

        // 2. Disable core dumps (prevents memory exfiltration via crash dumps on disk)
        rlimit::setrlimit(Resource::CORE, 0, 0)
            .context("Failed to disable core dumps")?;

        // 3. Disable dumpability (prevents ptrace and debugger attachment by other users)
        let ret = unsafe { prctl(PR_SET_DUMPABLE, 0) };
        if ret != 0 {
            if strict {
                anyhow::bail!("Failed to disable dumpability via prctl(PR_SET_DUMPABLE)");
            } else {
                warn!("Failed to disable dumpability");
            }
        }

        // 4. Enforce no-new-privileges
        // Prevents the process and its children from gaining new privileges via execve (e.g., setuid binaries).
        let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            if strict {
                anyhow::bail!("Failed to set no_new_privs via prctl");
            } else {
                warn!("Failed to set no_new_privs");
            }
        }

        // 5. Resource exhaustion protection
        // Restrict the ability to spawn new processes to prevent fork bombs.
        rlimit::setrlimit(Resource::NPROC, 0, 0)
            .context("Failed to restrict process spawning (NPROC)")?;
            
        // Lift the file write size limit to allow normal operation, but prevent core files.
        rlimit::setrlimit(Resource::FSIZE, u64::MAX, u64::MAX)
            .context("Failed to lift file write size limit")?;
    }

    info!("Process hardening applied");
    Ok(())
}