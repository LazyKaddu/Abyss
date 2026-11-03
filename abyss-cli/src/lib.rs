//! Library exports for `abyss-cli`.

pub mod commands;
pub mod maps;
pub mod style;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "abyssctl",
    about = "Abyss eBPF/XDP Pre-Firewall & Traffic Dispatcher Controller",
    version = "0.1.0"
)]
pub struct Cli {
    /// Base directory in bpffs where active maps are pinned
    #[arg(long, default_value = "/sys/fs/bpf/abyss", global = true)]
    pub bpf_dir: PathBuf,

    /// Format output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Commands {
    /// Display system health, dispatcher status, and active security modules
    Status,

    /// Display telemetry packet counters and bandwidth metrics
    Stats {
        /// Continuously poll and stream live metrics to terminal
        #[arg(short, long)]
        watch: bool,

        /// Poll interval in milliseconds when in watch mode
        #[arg(short, long, default_value_t = 1000)]
        interval_ms: u64,

        /// Display per-CPU core breakdown
        #[arg(long)]
        per_cpu: bool,
    },

    /// Blacklist an IPv4 address to immediately drop all traffic at Ring 0
    Block {
        /// IPv4 address to block (e.g. 10.200.1.2)
        ip: String,
    },

    /// Remove an IPv4 address from the Ring 0 blacklist
    Unblock {
        /// IPv4 address to unblock (e.g. 10.200.1.2)
        ip: String,
    },

    /// List all IP addresses currently dropped by the Ring 0 blocklist
    Blocked,

    /// List loaded Deep Packet Inspection (DPI) attack signatures
    Rules,

    /// Dynamically enable or disable pluggable security modules
    Module {
        #[command(subcommand)]
        sub: ModuleCommands,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum ModuleCommands {
    /// Enable a security module in kernel runtime
    Enable {
        /// Module name or slot ('rate-limiter' / '0' or 'dpi' / '1')
        module: String,
    },
    /// Disable a security module in kernel runtime
    Disable {
        /// Module name or slot ('rate-limiter' / '0' or 'dpi' / '1')
        module: String,
    },
}
