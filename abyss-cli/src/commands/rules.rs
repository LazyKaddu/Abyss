//! Handler for `abyssctl rules`.

use crate::maps::MapResolver;
use crate::style::Stylize;
use abyss_common::dpi::{DpiAction, MAX_SIGNATURES};
use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct DpiRuleEntry {
    pub index: u32,
    pub action: String,
    pub payload_offset: u32,
    pub pattern: String,
    pub pattern_len: u8,
}

#[derive(Serialize)]
pub struct DpiRulesReport {
    pub count: usize,
    pub rules: Vec<DpiRuleEntry>,
}

pub fn execute(resolver: &MapResolver, json: bool) -> Result<()> {
    let sigs_map = match resolver.dpi_signatures()? {
        Some(m) => m,
        None => {
            if json {
                println!("{}", serde_json::to_string_pretty(&DpiRulesReport { count: 0, rules: Vec::new() })?);
            } else {
                println!("{}", "DPI signatures map is not active (abyss-gaze module unlinked or disabled).".yellow());
            }
            return Ok(());
        }
    };

    let mut rules = Vec::new();
    for i in 0..MAX_SIGNATURES {
        if let Ok(sig) = sigs_map.get(&i, 0) {
            let len = sig.pattern_len as usize;
            if len == 0 {
                break;
            }
            let pat_str = String::from_utf8_lossy(&sig.pattern[..len]).to_string();
            let action_str = match sig.action {
                DpiAction::Drop => "DROP",
                DpiAction::Alert => "ALERT",
            };

            rules.push(DpiRuleEntry {
                index: i,
                action: action_str.to_string(),
                payload_offset: sig.payload_offset,
                pattern: pat_str,
                pattern_len: sig.pattern_len,
            });
        }
    }

    let report = DpiRulesReport {
        count: rules.len(),
        rules: rules.clone(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "===========================================================".cyan().bold());
    println!("      {}      ", "DEEP PACKET INSPECTION (DPI) SIGNATURE RULES".bold());
    println!("{}", "===========================================================".cyan().bold());
    println!("{:<25} : {}", "Active Signatures".bold(), report.count.to_string().yellow().bold());
    println!("{}", "-----------------------------------------------------------".dimmed());

    if rules.is_empty() {
        println!("  {}", "(No active DPI rules populated)".dimmed());
    } else {
        println!("  {:<6} {:<8} {:<8} {}", "INDEX".bold(), "ACTION".bold(), "OFFSET".bold(), "PATTERN".bold());
        for r in &rules {
            let act_color = if r.action == "DROP" {
                r.action.red().bold()
            } else {
                r.action.yellow().bold()
            };
            println!("  {:<6} {:<8} {:<8} {}", r.index, act_color, r.payload_offset, r.pattern.green());
        }
    }
    println!("{}", "===========================================================".cyan().bold());

    Ok(())
}
