//! eBPF Bytecode loader module utilizing the Aya framework.

use anyhow::{Context, Result};
use aya::{Ebpf, EbpfLoader};
use std::path::Path;
use tracing::{debug, info};

/// Bumps the `RLIMIT_MEMLOCK` resource limit to unlimited if possible.
///
/// Kernels older than 5.11 require this to allocate eBPF maps.
/// Modern kernels (5.11+) use cgroups for memory accounting, but bumping
/// rlimit ensures backwards compatibility and prevents map creation errors.
pub fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        debug!("setrlimit(RLIMIT_MEMLOCK) returned error (often benign on modern kernels): {err}");
    } else {
        debug!("Successfully raised RLIMIT_MEMLOCK to infinity");
    }
    Ok(())
}

/// Loads an eBPF ELF binary into the Linux kernel.
///
/// Reads the compiled ELF binary, loads all sections into the kernel verifier,
/// and returns the initialized `Ebpf` handle.
pub fn load_ebpf_bytecode(path: &Path) -> Result<Ebpf> {
    info!(path = %path.display(), "Reading eBPF bytecode");

    let bytecode = std::fs::read(path)
        .with_context(|| format!("Failed to read eBPF bytecode file from {}", path.display()))?;

    bump_memlock_rlimit()?;

    info!("Loading eBPF bytecode into Linux kernel via Aya...");
    let mut loader = EbpfLoader::new();

    let mut ebpf = loader
        .load(&bytecode)
        .context(
            "Kernel verifier rejected eBPF bytecode or failed to load eBPF object.\n\
             Note: eBPF map and program loading requires root privileges (CAP_BPF/CAP_NET_ADMIN).\n\
             Please run with: sudo ./target/debug/abyss-daemon"
        )?;

    // Attempt to initialize aya-log if logging maps exist in the program
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("eBPF logger not initialized (no logging macros in bytecode or already initialized): {e}");
    }

    info!("Successfully loaded eBPF object into Linux kernel");
    Ok(ebpf)
}
