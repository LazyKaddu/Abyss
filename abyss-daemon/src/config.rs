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

    /// Path to the compiled abyss-tide eBPF ELF bytecode binary.
    /// Defaults to searching standard workspace target directories if unspecified.
    #[arg(long)]
    pub tide_bytecode: Option<PathBuf>,

    /// Maximum packets per second (PPS) allowed per source IP for abyss-tide rate limiter.
    #[arg(long, default_value_t = 1000)]
    pub rate_limit_pps: u64,

    /// Disable the abyss-tide rate limiter module even if bytecode is present.
    #[arg(long, default_value_t = false)]
    pub disable_rate_limiter: bool,

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

    /// Resolves the abyss-tide bytecode path.
    ///
    /// If `--disable-rate-limiter` is set, returns `Ok(None)`.
    /// If `--tide-bytecode` is explicitly provided, verifies existence and returns `Ok(Some(path))`.
    /// Otherwise, checks candidate paths in the workspace and returns `Ok(Some(path))` if found,
    /// or `Ok(None)` if no bytecode was found.
    pub fn resolve_tide_bytecode_path(&self) -> anyhow::Result<Option<PathBuf>> {
        if self.disable_rate_limiter {
            return Ok(None);
        }

        if let Some(ref path) = self.tide_bytecode {
            if path.exists() {
                return Ok(Some(path.canonicalize().unwrap_or_else(|_| path.clone())));
            }
            anyhow::bail!("Specified tide bytecode path does not exist: {}", path.display());
        }

        let candidates = [
            PathBuf::from("target/bpfel-unknown-none/release/abyss-tide"),
            PathBuf::from("../target/bpfel-unknown-none/release/abyss-tide"),
            PathBuf::from("../../target/bpfel-unknown-none/release/abyss-tide"),
            PathBuf::from("kernel-modules/abyss-tide/target/bpfel-unknown-none/release/abyss-tide"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return Ok(Some(candidate.canonicalize().unwrap_or_else(|_| candidate.clone())));
            }
        }

        Ok(None)
    }
}

