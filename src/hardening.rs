use anyhow::Result;
use tracing::info;
use rlimit::{setrlimit, Resource};

pub fn apply_protections(strict: bool) -> Result<()> {
    // 1. Disable Core Dumps (RLIMIT_CORE = 0)
    match setrlimit(Resource::CORE, 0, 0) {
        Ok(_) => info!("Hardening: Core dumps disabled via RLIMIT."),
        Err(e) => {
            if strict { return Err(e.into()); }
            info!("Hardening Warning: Failed to disable core dumps.");
        }
    }

    // 2. Anti-Tracing (PR_SET_DUMPABLE)
    // This prevents gdb, ptrace, and other processes from reading our RAM.
    #[cfg(target_os = "linux")]
    unsafe {
        let result = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if result != 0 {
            let err = std::io::Error::last_os_error();
            if strict {
                return Err(anyhow::anyhow!("Anti-trace failed (PR_SET_DUMPABLE): {}", err));
            }
            info!("Hardening Warning: Anti-trace failed.");
        } else {
            info!("Hardening: Process marked non-dumpable (Anti-ptrace).");
        }
    }

    Ok(())
}