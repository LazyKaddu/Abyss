//! Security module bay orchestration and dynamic tail-call linking.

use abyss_common::dispatcher::{ModuleSlot, ModuleStatus};
use abyss_common::rate_limit::RateLimitConfig;
use anyhow::{Context, Result};
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::Xdp;
use aya::Ebpf;
use tracing::info;

/// Represents an active dynamic linkage of a security module into `abyss-core`.
pub struct ModuleLink {
    pub slot: ModuleSlot,
    pub module_slots: ProgramArray<MapData>,
    pub module_status: Array<MapData, ModuleStatus>,
}

impl ModuleLink {
    /// Unlinks the module from the jump table and marks it disabled in `MODULE_STATUS`.
    pub fn unlink(mut self) -> Result<()> {
        let slot_idx = self.slot as u32;
        info!(slot = slot_idx, "Disabling module in MODULE_STATUS map");
        self.module_status
            .set(slot_idx, &ModuleStatus::default(), 0)
            .context("Failed to zero MODULE_STATUS slot")?;

        info!(slot = slot_idx, "Clearing program FD from MODULE_SLOTS map");
        self.module_slots
            .clear_index(&slot_idx)
            .context("Failed to clear MODULE_SLOTS jump table index")?;

        info!(slot = slot_idx, "Module successfully unlinked from dispatch table");
        Ok(())
    }
}

/// Dynamically links `abyss-tide` into `abyss-core` at `ModuleSlot::RateLimiter` (slot 0).
pub fn link_rate_limiter(
    core_ebpf: &mut Ebpf,
    tide_ebpf: &mut Ebpf,
    max_pps: u64,
) -> Result<ModuleLink> {
    info!(max_pps, "Preparing abyss-tide rate limiter module");

    // 1. Configure global rate limiter parameters in RATE_LIMIT_CFG before borrowing programs
    if let Some(cfg_map) = tide_ebpf.take_map("RATE_LIMIT_CFG") {
        info!(max_pps, "Writing rate-limit configuration to RATE_LIMIT_CFG");
        let mut cfg_array: Array<_, RateLimitConfig> = Array::try_from(cfg_map)
            .context("Failed to initialize Array for 'RATE_LIMIT_CFG'")?;
        cfg_array
            .set(
                0,
                &RateLimitConfig {
                    max_pps,
                    refill_interval_ns: 1_000_000_000, // 1 second
                },
                0,
            )
            .context("Failed to write to RATE_LIMIT_CFG[0]")?;
    }

    // 2. Load the abyss_tide XDP program into the kernel
    let tide_program: &mut Xdp = tide_ebpf
        .program_mut("abyss_tide")
        .context("XDP program 'abyss_tide' not found in tide eBPF object")?
        .try_into()
        .context("Program 'abyss_tide' is not an XDP program")?;

    info!("Loading 'abyss_tide' XDP program into kernel");
    tide_program
        .load()
        .context("Failed to load 'abyss_tide' program into the kernel")?;

    let prog_fd = tide_program
        .fd()
        .context("Failed to obtain file descriptor for 'abyss_tide'")?;

    // 3. Take ownership of jump table maps from core_ebpf
    let slots_map = core_ebpf
        .take_map("MODULE_SLOTS")
        .context("Map 'MODULE_SLOTS' not found in abyss-core object")?;
    let mut module_slots = ProgramArray::try_from(slots_map)
        .context("Failed to initialize ProgramArray for 'MODULE_SLOTS'")?;

    let status_map = core_ebpf
        .take_map("MODULE_STATUS")
        .context("Map 'MODULE_STATUS' not found in abyss-core object")?;
    let mut module_status = Array::try_from(status_map)
        .context("Failed to initialize Array for 'MODULE_STATUS'")?;

    // 4. Insert program FD into MODULE_SLOTS[0]
    let slot_idx = ModuleSlot::RateLimiter as u32;
    info!(slot = slot_idx, "Inserting abyss-tide FD into MODULE_SLOTS jump table");
    module_slots
        .set(slot_idx, prog_fd, 0)
        .context("Failed to populate MODULE_SLOTS[0]")?;

    // 5. Set status enabled = 1 in MODULE_STATUS[0]
    info!(slot = slot_idx, "Activating module in MODULE_STATUS");
    let status = ModuleStatus {
        enabled: 1,
        _pad: 0,
        packets_processed: 0,
        packets_dropped: 0,
    };
    module_status
        .set(slot_idx, &status, 0)
        .context("Failed to update MODULE_STATUS[0]")?;

    info!("abyss-tide successfully linked into abyss-core Root Dispatcher");

    Ok(ModuleLink {
        slot: ModuleSlot::RateLimiter,
        module_slots,
        module_status,
    })
}
