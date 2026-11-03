//! Handlers for `abyssctl block`, `abyssctl unblock`, and `abyssctl blocked`.

use crate::maps::MapResolver;
use crate::style::Stylize;
use abyss_common::ip::{parse_ipv4_addr, u32_to_octets};
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct BlockResult {
    pub action: String,
    pub ip: String,
    pub ip_int: u32,
    pub success: bool,
}

#[derive(Serialize)]
pub struct BlockedListReport {
    pub count: usize,
    pub blocked_ips: Vec<String>,
}

pub fn block_ip(resolver: &MapResolver, ip_str: &str, json: bool) -> Result<()> {
    let ip_u32 = parse_ipv4_addr(ip_str)
        .map_err(|_| anyhow::anyhow!("Invalid IPv4 address format: '{}'", ip_str))?;

    let mut blocked_map = resolver.blocked_ips()?;
    blocked_map
        .insert(&ip_u32, &1u8, 0)
        .with_context(|| format!("Failed to insert '{ip_str}' into BLOCKED_IPS eBPF map"))?;

    let result = BlockResult {
        action: "block".to_string(),
        ip: ip_str.to_string(),
        ip_int: ip_u32,
        success: true,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} IP {} is now permanently blacklisted in Ring 0.",
            "[BLOCKED]".red().bold(),
            ip_str.yellow().bold()
        );
    }

    Ok(())
}

pub fn unblock_ip(resolver: &MapResolver, ip_str: &str, json: bool) -> Result<()> {
    let ip_u32 = parse_ipv4_addr(ip_str)
        .map_err(|_| anyhow::anyhow!("Invalid IPv4 address format: '{}'", ip_str))?;

    let mut blocked_map = resolver.blocked_ips()?;
    let _ = blocked_map.remove(&ip_u32);

    let result = BlockResult {
        action: "unblock".to_string(),
        ip: ip_str.to_string(),
        ip_int: ip_u32,
        success: true,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} IP {} has been removed from the Ring 0 blocklist.",
            "[UNBLOCKED]".green().bold(),
            ip_str.yellow().bold()
        );
    }

    Ok(())
}

pub fn list_blocked(resolver: &MapResolver, json: bool) -> Result<()> {
    let blocked_map = resolver.blocked_ips()?;
    let mut ips = Vec::new();

    for key_res in blocked_map.keys() {
        if let Ok(ip_u32) = key_res {
            let octets = u32_to_octets(ip_u32);
            ips.push(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]));
        }
    }

    ips.sort();

    let report = BlockedListReport {
        count: ips.len(),
        blocked_ips: ips.clone(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "===========================================================".cyan().bold());
    println!("          {}          ", "RING 0 BLOCKED IP BLACKLIST".bold());
    println!("{}", "===========================================================".cyan().bold());
    println!("{:<25} : {}", "Total Blocked IPs".bold(), report.count.to_string().yellow().bold());
    println!("{}", "-----------------------------------------------------------".dimmed());

    if ips.is_empty() {
        println!("  {}", "(No IP addresses currently blocked)".dimmed());
    } else {
        for ip in &ips {
            println!("  - {:<18} {}", ip.bold(), "[XDP_DROP]".red());
        }
    }
    println!("{}", "===========================================================".cyan().bold());

    Ok(())
}
