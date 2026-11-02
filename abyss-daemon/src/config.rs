//! Configuration and command-line argument parsing for `abyss-daemon`.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// XDP Attachment Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum XdpMode {
    /// SKB / Generic mode: Kernel emulation, works on all virtual interfaces (veth) and all drivers.
    #[default]
    Skb,
    /// Driver / Native mode: Hardware-adjacent, executed by the NIC driver before sk_buff allocation.
    Drv,
}

/// Abyss Daemon: Ring 0 eBPF Orchestrator & Telemetry Monitor.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "abyss-daemon",
    author = "Abyss Team",
    version,
    about = "Loads abyss-core into Linux Ring 0 and monitors real-time telemetry counters."
)]
pub struct Config {
    /// Target network interface name to attach XDP to (e.g. veth-abyss, eth0).
    #[arg(short, long, default_value = "veth-abyss")]
    pub iface: String,

    /// XDP attachment mode (skb for virtual/generic, drv for native NIC driver).
    #[arg(short, long, value_enum, default_value_t = XdpMode::Skb)]
    pub mode: XdpMode,

    /// Path to the compiled abyss-core eBPF ELF bytecode binary.
    /// Defaults to the workspace target directory if unspecified.
    #[arg(short, long)]
    pub bytecode: Option<PathBuf>,

    /// Interval in milliseconds between telemetry counter reads from eBPF maps.
    #[arg(short, long, default_value_t = 1000)]
    pub poll_interval_ms: u64,

    /// Safety override flag: must be explicitly passed if attaching to a physical/primary network interface.
    #[arg(long, default_value_t = false)]
    pub allow_primary_iface: bool,

    /// Log filter directive (e.g. info, debug, trace, abyss_daemon=trace).
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

impl Config {
    /// Resolves the bytecode path, checking the explicit CLI argument first,
    /// and falling back to standard workspace paths.
    pub fn resolve_bytecode_path(&self) -> anyhow::Result<PathBuf> {
        if let Some(ref path) = self.bytecode {
            if path.exists() {
                return Ok(path.clone());
            }
            anyhow::bail!("Specified bytecode path does not exist: {}", path.display());
        }

        // Candidates relative to current working directory or workspace root
        let candidates = [
            PathBuf::from("target/bpfel-unknown-none/release/abyss-core"),
            PathBuf::from("../target/bpfel-unknown-none/release/abyss-core"),
            PathBuf::from("../../target/bpfel-unknown-none/release/abyss-core"),
            PathBuf::from("kernel-modules/abyss-core/target/bpfel-unknown-none/release/abyss-core"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return Ok(candidate.canonicalize().unwrap_or_else(|_| candidate.clone()));
            }
        }

        anyhow::bail!(
            "Could not locate abyss-core eBPF bytecode. Looked in: {:?}.\n\
             Please specify --bytecode <PATH> or compile it first with:\n\
             RUSTC_BOOTSTRAP=1 cargo build -Z build-std=core --target bpfel-unknown-none -p abyss-core --release",
            candidates
        );
    }
}
