// src/hardening.rs
//
// Process-level hardening only.
// No network effects, no timing effects, no Tor behavior changes.
// Designed for untrusted VPS / container environments.

use anyhow::{Context, Result};
use tracing::info;

#[cfg(unix)]
use libc::{
    prctl,
    PR_SET_DUMPABLE,
    PR_SET_NO_NEW_PRIVS,
};

#[cfg(unix)]
use rlimit::Resource;

/// Apply zero-trust process protections.
///
/// If `strict` is true:
/// - failure is fatal
/// - assumes hostile host
///
/// If `strict` is false:
/// - best-effort only
pub fn apply_protections(strict: bool) -> Result<()> {
    #[cfg(unix)]
    {
        // ------------------------------------------------------------
        // 1. Disable core dumps (prevents memory exfil via crashes)
        // ------------------------------------------------------------
        rlimit::setrlimit(Resource::CORE, 0, 0)
            .context("Failed to disable core dumps")?;

        // ------------------------------------------------------------
        // 2. Disable ptrace & debugger attachment
        // ------------------------------------------------------------
        let ret = unsafe { prctl(PR_SET_DUMPABLE, 0) };
        if ret != 0 && strict {
            anyhow::bail!("Failed to disable dumpability");
        }

        // ------------------------------------------------------------
        // 3. Enforce no-new-privileges
        // ------------------------------------------------------------
        let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 && strict {
            anyhow::bail!("Failed to set no_new_privs");
        }

        // ------------------------------------------------------------
        // 4. Reduce accidental resource abuse
        // ------------------------------------------------------------
        rlimit::setrlimit(Resource::FSIZE, 0, 0)
            .context("Failed to restrict file write size")?;

        rlimit::setrlimit(Resource::NPROC, 0, 0)
            .context("Failed to restrict process spawning")?;
    }

    info!("Process hardening applied");
    Ok(())
}
