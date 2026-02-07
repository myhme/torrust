// src/hardening.rs

use anyhow::{Context, Result};
use tracing::{info, warn};

/// Apply kernel- and process-level hardening.
///
/// In strict mode:
/// - failure is fatal
/// - zero-trust assumptions are enforced
///
/// In non-strict mode:
/// - best-effort only
pub fn apply_protections(strict: bool) -> Result<()> {
    // ------------------------------------------------------------
    // 1. Lock memory (best-effort)
    // ------------------------------------------------------------
    //
    // Prevent secrets from being swapped to disk.
    // In containers, this requires IPC_LOCK capability.
    //
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(err).context("mlockall failed in strict mode");
            } else {
                warn!("mlockall failed (non-strict): {}", err);
            }
        } else {
            info!("Memory locked (mlockall)");
        }
    }

    // ------------------------------------------------------------
    // 2. Disable core dumps
    // ------------------------------------------------------------
    //
    // Prevent memory disclosure via core files.
    //
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(err).context("Failed to disable core dumps");
            } else {
                warn!("Failed to disable core dumps (non-strict): {}", err);
            }
        } else {
            info!("Core dumps disabled");
        }
    }

    // ------------------------------------------------------------
    // 3. Restrict file descriptor count
    // ------------------------------------------------------------
    //
    // Helps limit damage from FD leaks.
    //
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 65536,
            rlim_max: 65536,
        };

        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(err).context("Failed to set RLIMIT_NOFILE");
            } else {
                warn!("Failed to set RLIMIT_NOFILE (non-strict): {}", err);
            }
        } else {
            info!("File descriptor limit set");
        }
    }

    Ok(())
}
