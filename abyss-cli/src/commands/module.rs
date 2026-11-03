//! Handlers for `abyssctl module enable` and `abyssctl module disable`.

use crate::maps::MapResolver;
use crate::style::Stylize;
use abyss_common::dispatcher::ModuleSlot;
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct ModuleToggleResult {
    pub module: String,
    pub slot: u32,
    pub enabled: bool,
    pub success: bool,
}

pub fn parse_slot(name_or_slot: &str) -> Result<(u32, &'static str)> {
    let lower = name_or_slot.to_ascii_lowercase();
    match lower.as_str() {
        "0" | "rate-limiter" | "ratelimiter" | "tide" => Ok((ModuleSlot::RateLimiter as u32, "RateLimiter (abyss-tide)")),
        "1" | "dpi" | "gaze" => Ok((ModuleSlot::Dpi as u32, "DPI (abyss-gaze)")),
        _ => anyhow::bail!("Unknown module '{}'. Supported modules: 'rate-limiter' (slot 0), 'dpi' (slot 1)", name_or_slot),
    }
}

pub fn set_module_enabled(resolver: &MapResolver, name_or_slot: &str, enable: bool, json: bool) -> Result<()> {
    let (slot_idx, module_name) = parse_slot(name_or_slot)?;
    let mut status_map = resolver.module_status()?;

    let mut status = status_map
        .get(&slot_idx, 0)
        .with_context(|| format!("Failed to read MODULE_STATUS[{slot_idx}]"))?;

    status.enabled = if enable { 1 } else { 0 };

    status_map
        .set(slot_idx, &status, 0)
        .with_context(|| format!("Failed to update MODULE_STATUS[{slot_idx}]"))?;

    let result = ModuleToggleResult {
        module: module_name.to_string(),
        slot: slot_idx,
        enabled: enable,
        success: true,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let state_badge = if enable {
            "[ENABLED]".green().bold()
        } else {
            "[DISABLED]".red().bold()
        };
        println!(
            "{} Security module {} (Slot {}) is now {}.",
            state_badge,
            module_name.bold(),
            slot_idx.to_string().yellow(),
            if enable { "active" } else { "inactive" }
        );
    }

    Ok(())
}
