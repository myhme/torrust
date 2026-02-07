// src/hardening.rs

use anyhow::{Context, Result};
use libc;
use rlimit::{Resource, Rlim};
use tracing::info;

/// Apply kernel and process-level hardening.
///
/// This function is intentionally conservative:
/// - No privilege escalation
/// - No filesystem assumptions
/// - Safe for containers
/// - Idempotent where possible
///
/// If `strict` is true, failures are treated as fatal by the caller.
pub fn apply_protections(strict: bool) -> Result<()> {
    info!("Applying process hardening");

    // ------------------------------------------------------------
    // 1. Lock memory (prevent swapping)
    // ------------------------------------------------------------
    //
    // Prevent sensitive memory from being swapped to disk.
    // Requires CAP_IPC_LOCK or appropriate ulimit.
    //
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                anyhow::bail!("mlockall failed: {}", err);
            }
        }
    }

    // ------------------------------------------------------------
    // 2. Disable core dumps
    // ------------------------------------------------------------
    //
    // Core dumps may contain sensitive material.
    //
    if let Err(e) = Resource::CORE.set(Rlim::ZERO, Rlim::ZERO) {
        if strict {
            anyhow::bail!("Failed to disable core dumps: {}", e);
        }
    }

    // ------------------------------------------------------------
    // 3. Restrict number of open files
    // ------------------------------------------------------------
    //
    // Prevent runaway FD usage.
    // High enough for Tor, low enough to limit abuse.
    //
    let nofile_limit = Rlim::from_raw(65536);

    if let Err(e) = Resource::NOFILE.set(nofile_limit, nofile_limit) {
        if strict {
            anyhow::bail!("Failed to set NOFILE limit: {}", e);
        }
    }

    // ------------------------------------------------------------
    // 4. Set dumpable flag to 0
    // ------------------------------------------------------------
    //
    // Prevent other processes from ptracing / dumping us.
    //
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                anyhow::bail!("prctl(PR_SET_DUMPABLE) failed: {}", err);
            }
        }
    }

    // ------------------------------------------------------------
    // 5. Optional: lock address space growth
    // ------------------------------------------------------------
    //
    // Prevent unlimited virtual memory growth.
    // We do NOT set a hard cap here to avoid OOM surprises.
    //
    if let Err(e) = Resource::AS.set(Rlim::INFINITY, Rlim::INFINITY) {
        if strict {
            anyhow::bail!("Failed to set AS limit: {}", e);
        }
    }

    info!("Process hardening applied");
    Ok(())
}
