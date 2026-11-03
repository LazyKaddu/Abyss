//! # abyss-daemon (User-Space Orchestrator)
//!
//! Bridges user space and Linux Ring 0:
//! 1. Compiles and loads `abyss-core` eBPF bytecode into the Linux kernel using Aya.
//! 2. Dynamically links security modules (`abyss-tide`, `abyss-gaze`) into `MODULE_SLOTS` jump tables.
//! 3. Attaches the Root Dispatcher XDP program to the designated network interface.
//! 4. Asynchronously polls lock-free per-CPU telemetry maps across core and active modules.
//! 5. Guarantees deterministic module unlinking and XDP detachment on graceful shutdown (Ctrl+C).

use anyhow::{Context, Result};
use aya::maps::PerCpuArray;
use clap::Parser;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

use abyss_daemon::{
    attach,
    config::Config,
    loader,
    modules::ModuleBay,
    telemetry::{self, TelemetryPoller},
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    // 1. Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .init();

    info!("Starting Abyss Daemon (Ring 0 eBPF Orchestrator)");

    // 2. Safety guard: Validate target interface
    attach::validate_interface(&config.iface, config.allow_primary_iface)
        .context("Interface validation failed")?;

    // 3. Resolve and load abyss-core eBPF bytecode into Linux kernel
    let core_bytecode_path = config
        .resolve_bytecode_path()
        .context("Failed to resolve abyss-core bytecode path")?;

    let mut core_ebpf = loader::load_ebpf_bytecode(&core_bytecode_path)
        .context("Failed to load abyss-core bytecode into kernel")?;

    // 4. Optionally load abyss-tide rate limiter module
    let tide_bytecode_path = config
        .resolve_tide_bytecode_path()
        .context("Error resolving abyss-tide bytecode path")?;

    let mut tide_ebpf = None;
    let mut tide_counters = None;

    if let Some(ref tide_path) = tide_bytecode_path {
        info!(path = %tide_path.display(), "Loading abyss-tide rate limiter module");
        let mut tide = loader::load_ebpf_bytecode(tide_path)
            .context("Failed to load abyss-tide bytecode into kernel")?;

        if let Some(tide_stats_map) = tide.take_map("TIDE_STATS") {
            let stats: PerCpuArray<_, abyss_common::telemetry::PacketCounters> =
                PerCpuArray::try_from(tide_stats_map)
                    .context("Failed to initialize PerCpuArray for 'TIDE_STATS'")?;
            tide_counters = Some(stats);
        }

        tide_ebpf = Some(tide);
    } else {
        info!("abyss-tide rate limiter is disabled or bytecode not present.");
    }

    // 5. Initialize the ModuleBay to manage jump tables and pipeline chaining
    let mut bay = ModuleBay::new(&mut core_ebpf, tide_ebpf.as_mut())
        .context("Failed to initialize ModuleBay")?;

    // Link abyss-tide into Slot 0 if loaded
    if let Some(ref mut tide) = tide_ebpf {
        bay.link_rate_limiter(tide, config.rate_limit_pps)
            .context("Failed to link abyss-tide into Slot 0")?;
    }

    // 6. Optionally load and link abyss-gaze DPI module
    let gaze_bytecode_path = config
        .resolve_gaze_bytecode_path()
        .context("Error resolving abyss-gaze bytecode path")?;

    let mut gaze_counters = None;
    let mut _gaze_ebpf = None;

    if let Some(ref gaze_path) = gaze_bytecode_path {
        info!(path = %gaze_path.display(), "Loading abyss-gaze DPI module");
        let mut gaze = loader::load_ebpf_bytecode(gaze_path)
            .context("Failed to load abyss-gaze bytecode into kernel")?;

        if let Some(gaze_stats_map) = gaze.take_map("GAZE_STATS") {
            let stats: PerCpuArray<_, abyss_common::telemetry::PacketCounters> =
                PerCpuArray::try_from(gaze_stats_map)
                    .context("Failed to initialize PerCpuArray for 'GAZE_STATS'")?;
            gaze_counters = Some(stats);
        }

        let signatures = config
            .load_dpi_signatures()
            .context("Failed to load DPI signature ruleset")?;
        info!(count = signatures.len(), "Loaded active DPI signatures");

        bay.link_dpi(&mut gaze, &signatures)
            .context("Failed to link abyss-gaze into Slot 1")?;

        _gaze_ebpf = Some(gaze);
    } else {
        info!("abyss-gaze DPI engine is disabled or bytecode not present.");
    }

    // 7. Take ownership of the PACKET_COUNTERS map from core before attaching
    let counters_map = core_ebpf
        .take_map("PACKET_COUNTERS")
        .context("eBPF map 'PACKET_COUNTERS' not found in loaded abyss-core object")?;
    let core_counters: PerCpuArray<_, abyss_common::telemetry::PacketCounters> =
        PerCpuArray::try_from(counters_map)
            .context("Failed to initialize PerCpuArray for 'PACKET_COUNTERS'")?;

    // 8. Attach XDP Root Dispatcher to network interface
    let attachment = attach::attach_xdp(&mut core_ebpf, &config.iface, config.mode)
        .context("Failed to attach XDP program to network interface")?;

    info!(
        iface = %config.iface,
        mode = ?config.mode,
        rate_limiter_active = tide_ebpf.is_some(),
        dpi_active = _gaze_ebpf.is_some(),
        interval_ms = config.poll_interval_ms,
        "Abyss Root Dispatcher active. Beginning asynchronous telemetry monitoring..."
    );

    // 9. Spawn telemetry polling ticker and listen for shutdown signal
    let mut poller = TelemetryPoller::new(core_counters, tide_counters, gaze_counters);
    let mut ticker = interval(Duration::from_millis(config.poll_interval_ms));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C). Initiating graceful cleanup...");
        }
        _ = async {
            loop {
                ticker.tick().await;
                if let Err(e) = poller.poll_once() {
                    error!("Error polling telemetry counters: {e}");
                }
            }
        } => {}
    }

    // 10. Deterministic cleanup: Unlink all modules and detach XDP program
    if let Err(e) = bay.unlink_all() {
        error!("Error during security modules unlinking: {e}");
    }

    info!("Detaching XDP filter from '{}'...", config.iface);
    if let Err(e) = attachment.detach(&mut core_ebpf) {
        error!("Error during XDP detachment: {e}");
    }

    // 11. Final flush of metrics
    if let Ok(final_stats) = poller.poll_once() {
        info!(
            "Session Summary: Processed {} packets ({}) | Dropped: {} packets (Rate-Limit: {} | DPI: {})",
            final_stats.packets_passed,
            telemetry::format_bytes(final_stats.bytes_total),
            final_stats.packets_dropped,
            final_stats.packets_dropped_rate_limit,
            final_stats.packets_dropped_dpi
        );
    }

    info!("Abyss Daemon shutdown cleanly.");
    Ok(())
}
