//! BPF filesystem (bpffs) pinning management for active eBPF maps.

use anyhow::Result;
use aya::Ebpf;
use std::path::Path;
use tracing::{info, warn};

/// Pins all named non-internal eBPF maps in `ebpf` to `bpf_dir`.
pub fn pin_maps_for_ebpf(ebpf: &Ebpf, bpf_dir: &Path) -> Result<()> {
    if !bpf_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(bpf_dir) {
            warn!(
                dir = %bpf_dir.display(),
                error = %e,
                "Unable to create bpffs directory (bpffs might not be mounted or root required)"
            );
            return Ok(());
        }
    }

    for (name, map) in ebpf.maps() {
        if name.starts_with('.') {
            continue;
        }
        let pin_path = bpf_dir.join(name);
        if pin_path.exists() {
            let _ = std::fs::remove_file(&pin_path);
        }
        info!(map = name, path = %pin_path.display(), "Pinning eBPF map to bpffs");
        if let Err(e) = map.pin(&pin_path) {
            warn!(
                map = name,
                path = %pin_path.display(),
                error = %e,
                "Failed to pin eBPF map (requires CAP_SYS_ADMIN/root and bpffs mount)"
            );
        }
    }

    Ok(())
}

/// Unpins all pinned map files and removes `bpf_dir` on clean shutdown.
pub fn unpin_maps(bpf_dir: &Path) {
    if bpf_dir.exists() {
        info!(path = %bpf_dir.display(), "Cleaning up pinned eBPF maps");
        if let Ok(entries) = std::fs::read_dir(bpf_dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(bpf_dir);
    }
}
