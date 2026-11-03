//! Handler for `abyssctl stats`.

use crate::maps::MapResolver;
use crate::style::Stylize;
use abyss_common::telemetry::PacketCounters;
use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct AggregateStats {
    pub packets_ingress: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub bytes_total: u64,
    pub packets_dropped_rate_limit: u64,
    pub packets_dropped_dpi: u64,
    pub packets_dropped_blocked: u64,
}

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct CpuCounterStats {
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub bytes_total: u64,
    pub packets_dropped_rate_limit: u64,
    pub packets_dropped_dpi: u64,
    pub packets_dropped_blocked: u64,
}

impl From<&PacketCounters> for CpuCounterStats {
    fn from(c: &PacketCounters) -> Self {
        Self {
            packets_passed: c.packets_passed,
            packets_dropped: c.packets_dropped,
            bytes_total: c.bytes_total,
            packets_dropped_rate_limit: c.packets_dropped_rate_limit,
            packets_dropped_dpi: c.packets_dropped_dpi,
            packets_dropped_blocked: c.packets_dropped_blocked,
        }
    }
}

#[derive(Serialize)]
pub struct StatsReport {
    pub total: AggregateStats,
    pub bytes_formatted: String,
    pub per_cpu: Option<Vec<CpuCounterStats>>,
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if bytes >= TIB {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn sum_per_cpu(map: &PerCpuArray<MapData, PacketCounters>) -> Result<(PacketCounters, Vec<PacketCounters>)> {
    let values = map.get(&0, 0).context("Failed to read per-cpu counters at index 0")?;
    let mut sum = PacketCounters::default();
    let mut per_cpu = Vec::new();

    for core in values.iter() {
        sum.packets_passed += core.packets_passed;
        sum.packets_dropped += core.packets_dropped;
        sum.bytes_total += core.bytes_total;
        sum.packets_dropped_rate_limit += core.packets_dropped_rate_limit;
        sum.packets_dropped_dpi += core.packets_dropped_dpi;
        sum.packets_dropped_blocked += core.packets_dropped_blocked;
        per_cpu.push(*core);
    }

    Ok((sum, per_cpu))
}

pub fn collect_stats(resolver: &MapResolver, include_per_cpu: bool) -> Result<StatsReport> {
    let core_map = resolver.packet_counters()?;
    let (core_sum, core_cores) = sum_per_cpu(&core_map)?;

    let tide_sum = if let Ok(Some(map)) = resolver.tide_stats() {
        sum_per_cpu(&map)?.0
    } else {
        PacketCounters::default()
    };

    let gaze_sum = if let Ok(Some(map)) = resolver.gaze_stats() {
        sum_per_cpu(&map)?.0
    } else {
        PacketCounters::default()
    };

    let total_passed = core_sum.packets_passed + tide_sum.packets_passed + gaze_sum.packets_passed;
    let total_dropped = core_sum.packets_dropped + tide_sum.packets_dropped + gaze_sum.packets_dropped;
    let total_bytes = core_sum.bytes_total.max(tide_sum.bytes_total).max(gaze_sum.bytes_total);
    let total_rl = core_sum.packets_dropped_rate_limit + tide_sum.packets_dropped_rate_limit + gaze_sum.packets_dropped_rate_limit;
    let total_dpi = core_sum.packets_dropped_dpi + tide_sum.packets_dropped_dpi + gaze_sum.packets_dropped_dpi;
    let total_blocked = core_sum.packets_dropped_blocked + tide_sum.packets_dropped_blocked + gaze_sum.packets_dropped_blocked;

    let aggregate = AggregateStats {
        packets_ingress: total_passed + total_dropped,
        packets_passed: total_passed,
        packets_dropped: total_dropped,
        bytes_total: total_bytes,
        packets_dropped_rate_limit: total_rl,
        packets_dropped_dpi: total_dpi,
        packets_dropped_blocked: total_blocked,
    };

    Ok(StatsReport {
        total: aggregate,
        bytes_formatted: format_bytes(total_bytes),
        per_cpu: if include_per_cpu {
            Some(core_cores.iter().map(CpuCounterStats::from).collect())
        } else {
            None
        },
    })
}

pub async fn execute(
    resolver: &MapResolver,
    watch: bool,
    interval_ms: u64,
    per_cpu: bool,
    json: bool,
) -> Result<()> {
    if !watch {
        let report = collect_stats(resolver, per_cpu)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        println!("{}", "===========================================================".cyan().bold());
        println!("             {}             ", "ABYSS FIREWALL METRICS".bold());
        println!("{}", "===========================================================".cyan().bold());
        println!("{:<28} : {:>12}", "Total Ingress Packets".bold(), report.total.packets_ingress);
        println!("{:<28} : {:>12}", "Total Processed Data".bold(), report.bytes_formatted.green());
        println!("{:<28} : {:>12}", "Passed Packets".bold(), report.total.packets_passed.to_string().green());
        println!("{:<28} : {:>12}", "Total Dropped Packets".bold(), report.total.packets_dropped.to_string().red().bold());
        println!("{}", "-----------------------------------------------------------".dimmed());
        println!("{:<28} : {:>12}", "  - Dropped by IP Blocklist".bold(), report.total.packets_dropped_blocked.to_string().yellow());
        println!("{:<28} : {:>12}", "  - Dropped by Rate Limiter".bold(), report.total.packets_dropped_rate_limit.to_string().yellow());
        println!("{:<28} : {:>12}", "  - Dropped by DPI Inspection".bold(), report.total.packets_dropped_dpi.to_string().yellow());
        println!("{}", "===========================================================".cyan().bold());

        if let Some(cores) = report.per_cpu {
            println!("\n{}", "--- Per-CPU Core Breakdown ---".cyan().bold());
            for (idx, core) in cores.iter().enumerate() {
                println!(
                    "  CPU {:>2}: Passed: {:>8} | Dropped: {:>6} (RL: {:>4}, DPI: {:>4}, Block: {:>4})",
                    idx,
                    core.packets_passed,
                    core.packets_dropped,
                    core.packets_dropped_rate_limit,
                    core.packets_dropped_dpi,
                    core.packets_dropped_blocked
                );
            }
        }
        return Ok(());
    }

    // Live watch mode
    println!("{}", "Starting live stats monitoring. Press Ctrl+C to stop.".dimmed());
    let mut last_stats = collect_stats(resolver, false)?.total;
    let mut last_time = Instant::now();

    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n{}", "Stopped monitoring.".dimmed());
                break;
            }
            _ = interval.tick() => {
                let current = collect_stats(resolver, false)?.total;
                let now = Instant::now();
                let elapsed = now.duration_since(last_time).as_secs_f64();

                if elapsed > 0.0 {
                    let d_passed = current.packets_passed.saturating_sub(last_stats.packets_passed);
                    let d_dropped = current.packets_dropped.saturating_sub(last_stats.packets_dropped);
                    let d_ingress = d_passed + d_dropped;
                    let d_bytes = current.bytes_total.saturating_sub(last_stats.bytes_total);
                    let d_rl = current.packets_dropped_rate_limit.saturating_sub(last_stats.packets_dropped_rate_limit);
                    let d_dpi = current.packets_dropped_dpi.saturating_sub(last_stats.packets_dropped_dpi);
                    let d_blk = current.packets_dropped_blocked.saturating_sub(last_stats.packets_dropped_blocked);

                    let ingress_pps = d_ingress as f64 / elapsed;
                    let passed_pps = d_passed as f64 / elapsed;
                    let dropped_pps = d_dropped as f64 / elapsed;
                    let bps = d_bytes as f64 / elapsed;
                    let rl_pps = d_rl as f64 / elapsed;
                    let dpi_pps = d_dpi as f64 / elapsed;
                    let blk_pps = d_blk as f64 / elapsed;

                    if json {
                        let json_line = serde_json::json!({
                            "ingress_pps": ingress_pps,
                            "passed_pps": passed_pps,
                            "dropped_pps": dropped_pps,
                            "bandwidth_bps": bps,
                            "rate_limit_dropped_pps": rl_pps,
                            "dpi_dropped_pps": dpi_pps,
                            "blocklist_dropped_pps": blk_pps,
                            "total_dropped": current.packets_dropped,
                        });
                        println!("{}", serde_json::to_string(&json_line)?);
                    } else {
                        println!(
                            "[{}] Ingress: {:>6.0} pps ({:>8}/s) | Passed: {:>6.0} pps | Drops: {:>5.0} pps (Block: {:>3.0}/s | RL: {:>3.0}/s | DPI: {:>3.0}/s) | Total Drops: {}",
                            chrono_now(),
                            ingress_pps,
                            format_bytes(bps as u64),
                            passed_pps,
                            dropped_pps,
                            blk_pps,
                            rl_pps,
                            dpi_pps,
                            current.packets_dropped.to_string().red()
                        );
                    }
                }

                last_stats = current;
                last_time = now;
            }
        }
    }

    Ok(())
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() % 86400;
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, s)
}
