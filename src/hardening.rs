// src/hardening.rs

use anyhow::{Context, Result};
use tracing::info;

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

pub fn apply_protections(strict: bool) -> Result<()> {
    #[cfg(unix)]
    {
        // 1. Lock virtual memory into physical RAM (prevents disk paging)
        let ret = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if ret != 0 && strict {
            anyhow::bail!("Failed to lock memory via mlockall. Check CAP_IPC_LOCK.");
        }

        // 2. Disable core dumps (prevents memory exfil via crashes)
        rlimit::setrlimit(Resource::CORE, 0, 0)
            .context("Failed to disable core dumps")?;

        // 3. Disable ptrace & debugger attachment
        let ret = unsafe { prctl(PR_SET_DUMPABLE, 0) };
        if ret != 0 && strict {
            anyhow::bail!("Failed to disable dumpability");
        }

        // 4. Enforce no-new-privileges
        let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 && strict {
            anyhow::bail!("Failed to set no_new_privs");
        }

        // 5. Reduce accidental resource abuse
        rlimit::setrlimit(Resource::FSIZE, u64::MAX, u64::MAX)
            .context("Failed to lift file write size limit")?;

        rlimit::setrlimit(Resource::NPROC, 0, 0)
            .context("Failed to restrict process spawning")?;
    }

    info!("Process hardening applied");
    Ok(())
}