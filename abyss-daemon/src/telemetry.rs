//! Asynchronous telemetry monitor reading eBPF per-CPU maps.

use abyss_common::telemetry::PacketCounters;
use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use std::time::Instant;
use tracing::info;

/// Formats a byte count into a human-readable string (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Aggregates per-CPU packet counters into a global sum.
pub fn aggregate_counters(
    map: &PerCpuArray<MapData, PacketCounters>,
) -> Result<PacketCounters> {
    // PACKET_COUNTERS has a single entry at index 0
    let per_cpu_values = map
        .get(&0, 0)
        .context("Failed to read index 0 from PACKET_COUNTERS map")?;

    let mut total = PacketCounters::default();
    for cpu_val in per_cpu_values.iter() {
        total.packets_passed += cpu_val.packets_passed;
        total.packets_dropped += cpu_val.packets_dropped;
        total.bytes_total += cpu_val.bytes_total;
        total.packets_dropped_rate_limit += cpu_val.packets_dropped_rate_limit;
        total.packets_dropped_dpi += cpu_val.packets_dropped_dpi;
    }

    Ok(total)
}

/// Telemetry polling state keeping track of deltas and rates.
pub struct TelemetryPoller {
    counters_map: PerCpuArray<MapData, PacketCounters>,
    last_counters: PacketCounters,
    last_tick: Instant,
}

impl TelemetryPoller {
    /// Creates a new poller from the `PACKET_COUNTERS` eBPF map.
    pub fn new(counters_map: PerCpuArray<MapData, PacketCounters>) -> Self {
        Self {
            counters_map,
            last_counters: PacketCounters::default(),
            last_tick: Instant::now(),
        }
    }

    /// Reads one tick of counters, logs current totals and throughput rates.
    pub fn poll_once(&mut self) -> Result<PacketCounters> {
        let current = aggregate_counters(&self.counters_map)?;
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick).as_secs_f64();

        if elapsed > 0.0 {
            let delta_passed = current.packets_passed.saturating_sub(self.last_counters.packets_passed);
            let delta_dropped = current.packets_dropped.saturating_sub(self.last_counters.packets_dropped);
            let delta_bytes = current.bytes_total.saturating_sub(self.last_counters.bytes_total);

            let pps = delta_passed as f64 / elapsed;
            let drop_pps = delta_dropped as f64 / elapsed;
            let bps = delta_bytes as f64 / elapsed;

            info!(
                "[TELEMETRY] Ingress: {:>6.0} pkts/s ({:>8}/s) | Dropped: {:>4.0} pkts/s | Cumulative: {} pkts ({}) | Total Drops: {}",
                pps,
                format_bytes(bps as u64),
                drop_pps,
                current.packets_passed,
                format_bytes(current.bytes_total),
                current.packets_dropped
            );
        }

        self.last_counters = current;
        self.last_tick = now;

        Ok(current)
    }
}
