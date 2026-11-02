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
    // Map has a single entry at index 0
    let per_cpu_values = map
        .get(&0, 0)
        .context("Failed to read index 0 from per-CPU counter map")?;

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

/// Telemetry polling state keeping track of deltas and rates across core and module maps.
pub struct TelemetryPoller {
    core_counters: PerCpuArray<MapData, PacketCounters>,
    tide_counters: Option<PerCpuArray<MapData, PacketCounters>>,
    last_counters: PacketCounters,
    last_tick: Instant,
}

impl TelemetryPoller {
    /// Creates a new poller from the `PACKET_COUNTERS` and optional `TIDE_STATS` eBPF maps.
    pub fn new(
        core_counters: PerCpuArray<MapData, PacketCounters>,
        tide_counters: Option<PerCpuArray<MapData, PacketCounters>>,
    ) -> Self {
        Self {
            core_counters,
            tide_counters,
            last_counters: PacketCounters::default(),
            last_tick: Instant::now(),
        }
    }

    /// Reads one tick of counters, logs current totals and throughput rates.
    pub fn poll_once(&mut self) -> Result<PacketCounters> {
        let core_total = aggregate_counters(&self.core_counters)?;
        let tide_total = match &self.tide_counters {
            Some(tide_map) => aggregate_counters(tide_map)?,
            None => PacketCounters::default(),
        };

        let current = PacketCounters {
            packets_passed: core_total.packets_passed + tide_total.packets_passed,
            packets_dropped: core_total.packets_dropped + tide_total.packets_dropped,
            bytes_total: core_total.bytes_total.max(tide_total.bytes_total),
            packets_dropped_rate_limit: core_total.packets_dropped_rate_limit
                + tide_total.packets_dropped_rate_limit,
            packets_dropped_dpi: core_total.packets_dropped_dpi + tide_total.packets_dropped_dpi,
        };

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick).as_secs_f64();

        if elapsed > 0.0 {
            let delta_passed = current
                .packets_passed
                .saturating_sub(self.last_counters.packets_passed);
            let delta_dropped = current
                .packets_dropped
                .saturating_sub(self.last_counters.packets_dropped);
            let delta_rate_limit = current
                .packets_dropped_rate_limit
                .saturating_sub(self.last_counters.packets_dropped_rate_limit);
            let delta_bytes = current
                .bytes_total
                .saturating_sub(self.last_counters.bytes_total);
            let delta_ingress = delta_passed + delta_dropped;

            let ingress_pps = delta_ingress as f64 / elapsed;
            let passed_pps = delta_passed as f64 / elapsed;
            let dropped_pps = delta_dropped as f64 / elapsed;
            let rate_limit_pps = delta_rate_limit as f64 / elapsed;
            let bps = delta_bytes as f64 / elapsed;

            info!(
                "[TELEMETRY] Ingress: {:>6.0} pkts/s ({:>8}/s) | Passed: {:>6.0} pkts/s | Dropped: {:>4.0} pkts/s (Rate-Limit: {:>4.0} pkts/s) | Total Drops: {}",
                ingress_pps,
                format_bytes(bps as u64),
                passed_pps,
                dropped_pps,
                rate_limit_pps,
                current.packets_dropped
            );
        }

        self.last_counters = current;
        self.last_tick = now;

        Ok(current)
    }
}
