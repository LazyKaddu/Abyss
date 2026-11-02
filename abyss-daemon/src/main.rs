//! # abyss-daemon (User-Space Orchestrator)
//!
//! Bridges user space and Linux Ring 0:
//! 1. Compiles and loads `abyss-core` eBPF bytecode into the Linux kernel using Aya.
//! 2. Attaches the Root Dispatcher XDP program to the designated network interface.
//! 3. Asynchronously polls `PACKET_COUNTERS` lock-free per-CPU telemetry maps.
//! 4. Guarantees deterministic XDP detachment on graceful shutdown (Ctrl+C).

mod attach;
mod config;
mod loader;
mod telemetry;

use anyhow::{Context, Result};
use aya::maps::PerCpuArray;
use clap::Parser;
use config::Config;
use std::time::Duration;
use telemetry::TelemetryPoller;
use tokio::time::interval;
use tracing::{error, info};

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

    // 3. Resolve and load eBPF bytecode into Linux kernel
    let bytecode_path = config
        .resolve_bytecode_path()
        .context("Failed to resolve abyss-core bytecode path")?;

    let mut ebpf = loader::load_ebpf_bytecode(&bytecode_path)
        .context("Failed to load eBPF bytecode into kernel")?;

    // 4. Take ownership of the PACKET_COUNTERS map before attaching
    let counters_map = ebpf
        .take_map("PACKET_COUNTERS")
        .context("eBPF map 'PACKET_COUNTERS' not found in loaded object")?;
    let counters: PerCpuArray<_, abyss_common::telemetry::PacketCounters> =
        PerCpuArray::try_from(counters_map)
            .context("Failed to initialize PerCpuArray for 'PACKET_COUNTERS'")?;

    // 5. Attach XDP Root Dispatcher to network interface
    let attachment = attach::attach_xdp(&mut ebpf, &config.iface, config.mode)
        .context("Failed to attach XDP program to network interface")?;

    info!(
        iface = %config.iface,
        mode = ?config.mode,
        interval_ms = config.poll_interval_ms,
        "Abyss Root Dispatcher active. Beginning asynchronous telemetry monitoring..."
    );

    // 6. Spawn telemetry polling ticker and listen for shutdown signal
    let mut poller = TelemetryPoller::new(counters);
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

    // 7. Deterministic cleanup: Detach XDP program from interface
    info!("Detaching XDP filter from '{}'...", config.iface);
    if let Err(e) = attachment.detach(&mut ebpf) {
        error!("Error during XDP detachment: {e}");
    }

    // 8. Final flush of metrics
    if let Ok(final_stats) = poller.poll_once() {
        info!(
            "Session Summary: Processed {} packets ({}) | Dropped: {} packets",
            final_stats.packets_passed,
            telemetry::format_bytes(final_stats.bytes_total),
            final_stats.packets_dropped
        );
    }

    info!("Abyss Daemon shutdown cleanly.");
    Ok(())
}
