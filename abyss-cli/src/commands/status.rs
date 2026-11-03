//! Handler for `abyssctl status`.

use crate::maps::MapResolver;
use crate::style::Stylize;
use abyss_common::dispatcher::ModuleSlot;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
pub struct ModuleStatusReport {
    pub slot: u32,
    pub name: String,
    pub enabled: bool,
    pub packets_processed: u64,
    pub packets_dropped: u64,
}

#[derive(Serialize)]
pub struct SystemStatusReport {
    pub core_active: bool,
    pub blocked_ips_count: usize,
    pub dpi_signatures_count: usize,
    pub rate_limit_pps: Option<u64>,
    pub modules: Vec<ModuleStatusReport>,
}

pub fn execute(resolver: &MapResolver, json: bool) -> Result<()> {
    let module_status_map = resolver.module_status()?;
    let status_slot0 = module_status_map.get(&0, 0).unwrap_or_default();
    let status_slot1 = module_status_map.get(&1, 0).unwrap_or_default();

    let blocked_ips_count = match resolver.blocked_ips() {
        Ok(map) => map.keys().count(),
        Err(_) => 0,
    };

    let dpi_signatures_count = match resolver.dpi_signatures() {
        Ok(Some(sigs)) => {
            let mut count = 0;
            for i in 0..abyss_common::dpi::MAX_SIGNATURES {
                if let Ok(sig) = sigs.get(&i, 0) {
                    if sig.pattern_len > 0 {
                        count += 1;
                    } else {
                        break;
                    }
                }
            }
            count
        }
        _ => 0,
    };

    let rate_limit_pps = match resolver.rate_limit_cfg() {
        Ok(Some(cfg_map)) => cfg_map.get(&0, 0).ok().map(|c| c.max_pps),
        _ => None,
    };

    let report = SystemStatusReport {
        core_active: true,
        blocked_ips_count,
        dpi_signatures_count,
        rate_limit_pps,
        modules: vec![
            ModuleStatusReport {
                slot: ModuleSlot::RateLimiter as u32,
                name: "RateLimiter (abyss-tide)".to_string(),
                enabled: status_slot0.enabled != 0,
                packets_processed: status_slot0.packets_processed,
                packets_dropped: status_slot0.packets_dropped,
            },
            ModuleStatusReport {
                slot: ModuleSlot::Dpi as u32,
                name: "Deep Packet Inspection (abyss-gaze)".to_string(),
                enabled: status_slot1.enabled != 0,
                packets_processed: status_slot1.packets_processed,
                packets_dropped: status_slot1.packets_dropped,
            },
        ],
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "===========================================================".cyan().bold());
    println!("  {}  {}", "ABYSS eBPF PRE-FIREWALL CONTROLLER".bold(), "[ONLINE]".green().bold());
    println!("{}", "===========================================================".cyan().bold());
    println!("{:<25} : {}", "Dispatcher (Ring 0)".bold(), "Active & Attached".green());
    println!(
        "{:<25} : {} rule(s)",
        "Blocked IP Blacklist".bold(),
        report.blocked_ips_count.to_string().yellow().bold()
    );
    println!(
        "{:<25} : {} signature(s)",
        "DPI Rules Active".bold(),
        report.dpi_signatures_count.to_string().yellow().bold()
    );
    if let Some(pps) = report.rate_limit_pps {
        println!("{:<25} : {} pkts/s", "Rate Limit Threshold".bold(), pps);
    }

    println!("\n{}", "--- Security Module Bay Slots ---".cyan().bold());
    for m in &report.modules {
        let badge = if m.enabled {
            "[ACTIVE]".green().bold()
        } else {
            "[DISABLED]".red().bold()
        };
        println!(
            "  Slot {}: {:<32} {}",
            m.slot.to_string().yellow(),
            m.name.bold(),
            badge
        );
        println!(
            "          Processed: {:>10} pkts | Dropped: {:>8} pkts",
            m.packets_processed, m.packets_dropped
        );
    }
    println!("{}", "===========================================================".cyan().bold());

    Ok(())
}
