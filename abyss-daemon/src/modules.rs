//! Security module bay orchestration and dynamic tail-call linking.

use abyss_common::dispatcher::{ModuleSlot, ModuleStatus};
use abyss_common::dpi::DpiSignature;
use abyss_common::rate_limit::RateLimitConfig;
use anyhow::{Context, Result};
use aya::maps::{Array, MapData, ProgramArray};
use aya::programs::Xdp;
use aya::Ebpf;
use tracing::info;

/// Bay manager holding the jump tables and status maps across active eBPF objects.
pub struct ModuleBay {
    pub core_slots: ProgramArray<MapData>,
    pub core_status: Array<MapData, ModuleStatus>,
    pub tide_slots: Option<ProgramArray<MapData>>,
    pub tide_status: Option<Array<MapData, ModuleStatus>>,
}

impl ModuleBay {
    /// Initializes the module bay by taking ownership of jump tables and status arrays.
    pub fn new(core_ebpf: &mut Ebpf, tide_ebpf: Option<&mut Ebpf>) -> Result<Self> {
        let core_slots_map = core_ebpf
            .take_map("MODULE_SLOTS")
            .context("Map 'MODULE_SLOTS' not found in abyss-core object")?;
        let core_slots = ProgramArray::try_from(core_slots_map)
            .context("Failed to initialize ProgramArray for abyss-core 'MODULE_SLOTS'")?;

        let core_status_map = core_ebpf
            .take_map("MODULE_STATUS")
            .context("Map 'MODULE_STATUS' not found in abyss-core object")?;
        let core_status = Array::try_from(core_status_map)
            .context("Failed to initialize Array for abyss-core 'MODULE_STATUS'")?;

        let (tide_slots, tide_status) = if let Some(tide) = tide_ebpf {
            let slots = tide
                .take_map("MODULE_SLOTS")
                .map(ProgramArray::try_from)
                .transpose()
                .context("Failed to initialize ProgramArray for abyss-tide 'MODULE_SLOTS'")?;
            let status = tide
                .take_map("MODULE_STATUS")
                .map(Array::try_from)
                .transpose()
                .context("Failed to initialize Array for abyss-tide 'MODULE_STATUS'")?;
            (slots, status)
        } else {
            (None, None)
        };

        Ok(Self {
            core_slots,
            core_status,
            tide_slots,
            tide_status,
        })
    }

    /// Links `abyss-tide` into `ModuleSlot::RateLimiter` (slot 0).
    pub fn link_rate_limiter(
        &mut self,
        tide_ebpf: &mut Ebpf,
        max_pps: u64,
    ) -> Result<()> {
        info!(max_pps, "Configuring abyss-tide rate limiter module");

        // 1. Ensure the abyss_tide XDP program is loaded in kernel
        let prog_fd = {
            let tide_prog: &mut Xdp = tide_ebpf
                .program_mut("abyss_tide")
                .context("XDP program 'abyss_tide' not found in tide eBPF object")?
                .try_into()
                .context("Program 'abyss_tide' is not an XDP program")?;

            if tide_prog.fd().is_err() {
                info!("Loading 'abyss_tide' XDP program into kernel");
                tide_prog
                    .load()
                    .context("Failed to load 'abyss_tide' program into the kernel")?;
            }

            tide_prog
                .fd()
                .context("Failed to obtain file descriptor for 'abyss_tide'")?
                .try_clone()
                .context("Failed to clone ProgramFd for 'abyss_tide'")?
        };

        // 2. Configure RATE_LIMIT_CFG
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

        // 3. Insert program FD into core_slots[0] and enable in core_status[0]
        let slot_idx = ModuleSlot::RateLimiter as u32;
        info!(slot = slot_idx, "Inserting abyss-tide FD into dispatch table");
        self.core_slots
            .set(slot_idx, &prog_fd, 0)
            .context("Failed to populate core MODULE_SLOTS[0]")?;

        let status = ModuleStatus {
            enabled: 1,
            _pad: 0,
            packets_processed: 0,
            packets_dropped: 0,
        };
        self.core_status
            .set(slot_idx, &status, 0)
            .context("Failed to update core MODULE_STATUS[0]")?;

        info!("abyss-tide successfully linked into Slot 0");
        Ok(())
    }

    /// Links `abyss-gaze` into `ModuleSlot::Dpi` (slot 1) and configures signature patterns.
    pub fn link_dpi(
        &mut self,
        gaze_ebpf: &mut Ebpf,
        signatures: &[DpiSignature],
    ) -> Result<()> {
        info!(rules_count = signatures.len(), "Configuring abyss-gaze DPI engine");

        // 1. Ensure the abyss_gaze XDP program is loaded in kernel
        let prog_fd = {
            let gaze_prog: &mut Xdp = gaze_ebpf
                .program_mut("abyss_gaze")
                .context("XDP program 'abyss_gaze' not found in gaze eBPF object")?
                .try_into()
                .context("Program 'abyss_gaze' is not an XDP program")?;

            if gaze_prog.fd().is_err() {
                info!("Loading 'abyss_gaze' XDP program into kernel");
                gaze_prog
                    .load()
                    .context("Failed to load 'abyss_gaze' program into the kernel")?;
            }

            gaze_prog
                .fd()
                .context("Failed to obtain file descriptor for 'abyss_gaze'")?
                .try_clone()
                .context("Failed to clone ProgramFd for 'abyss_gaze'")?
        };

        // 2. Populate DPI_SIGNATURES array map in abyss-gaze
        if let Some(sig_map) = gaze_ebpf.take_map("DPI_SIGNATURES") {
            info!(count = signatures.len(), "Loading signature patterns into DPI_SIGNATURES");
            let mut sig_array: Array<_, DpiSignature> = Array::try_from(sig_map)
                .context("Failed to initialize Array for 'DPI_SIGNATURES'")?;

            for (idx, sig) in signatures.iter().enumerate() {
                sig_array
                    .set(idx as u32, sig, 0)
                    .with_context(|| format!("Failed to write rule #{} into DPI_SIGNATURES", idx))?;
            }

            // Zero-out the subsequent slot if room exists to mark end of active rules
            if (signatures.len() as u32) < abyss_common::dpi::MAX_SIGNATURES {
                let _ = sig_array.set(signatures.len() as u32, &DpiSignature::default(), 0);
            }
        }

        // 3. Insert program FD into core_slots[1] (fallback when rate limiter is disabled)
        let slot_idx = ModuleSlot::Dpi as u32;
        info!(slot = slot_idx, "Inserting abyss-gaze FD into core dispatch table");
        self.core_slots
            .set(slot_idx, &prog_fd, 0)
            .context("Failed to populate core MODULE_SLOTS[1]")?;

        let status = ModuleStatus {
            enabled: 1,
            _pad: 0,
            packets_processed: 0,
            packets_dropped: 0,
        };
        self.core_status
            .set(slot_idx, &status, 0)
            .context("Failed to activate DPI in core MODULE_STATUS[1]")?;

        // 4. Also insert program FD into tide_slots[1] (pipeline chaining when tide is active)
        if let Some(ref mut tide_slots) = self.tide_slots {
            info!(slot = slot_idx, "Inserting abyss-gaze FD into tide jump table");
            tide_slots
                .set(slot_idx, &prog_fd, 0)
                .context("Failed to populate tide MODULE_SLOTS[1]")?;
        }
        if let Some(ref mut tide_status) = self.tide_status {
            tide_status
                .set(slot_idx, &status, 0)
                .context("Failed to activate DPI in tide MODULE_STATUS[1]")?;
        }

        info!("abyss-gaze successfully linked into Slot 1");
        Ok(())
    }

    /// Cleanly unlinks all populated module slots from all dispatch tables.
    pub fn unlink_all(&mut self) -> Result<()> {
        info!("Unlinking all security modules from dispatch tables");
        for slot in [ModuleSlot::RateLimiter, ModuleSlot::Dpi] {
            let slot_idx = slot as u32;
            let _ = self.core_status.set(slot_idx, &ModuleStatus::default(), 0);
            let _ = self.core_slots.clear_index(&slot_idx);

            if let Some(ref mut tide_status) = self.tide_status {
                let _ = tide_status.set(slot_idx, &ModuleStatus::default(), 0);
            }
            if let Some(ref mut tide_slots) = self.tide_slots {
                let _ = tide_slots.clear_index(&slot_idx);
            }
        }
        info!("All security modules cleanly unlinked");
        Ok(())
    }
}
