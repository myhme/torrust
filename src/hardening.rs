// src/hardening.rs

use anyhow::{Result}; // Removed unused Context
use libc;
use rlimit::Resource;
use tracing::info;

pub fn apply_protections(strict: bool) -> Result<()> {
    info!("Applying process hardening");

    // 1. Lock memory
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                anyhow::bail!("mlockall failed: {}", err);
            }
        }
    }

    // 2. Disable core dumps (API Fix: use explicit u64/Limit)
    if let Err(e) = Resource::CORE.set(0, 0) {
        if strict {
            anyhow::bail!("Failed to disable core dumps: {}", e);
        }
    }

    // 3. Restrict number of open files
    let nofile_limit = 65536;
    if let Err(e) = Resource::NOFILE.set(nofile_limit, nofile_limit) {
        if strict {
            anyhow::bail!("Failed to set NOFILE limit: {}", e);
        }
    }

    // 4. Set dumpable flag to 0
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                anyhow::bail!("prctl(PR_SET_DUMPABLE) failed: {}", err);
            }
        }
    }

    // 5. Optional: lock address space growth
    // Rlimit::INFINITY is now Resource::INFINITY
    if let Err(e) = Resource::AS.set(rlimit::INFINITY, rlimit::INFINITY) {
        if strict {
            anyhow::bail!("Failed to set AS limit: {}", e);
        }
    }

    info!("Process hardening applied");
    Ok(())
}