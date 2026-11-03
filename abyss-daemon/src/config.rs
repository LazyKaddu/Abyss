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

    /// Path to the compiled abyss-gaze eBPF ELF bytecode binary.
    /// Defaults to searching standard workspace target directories if unspecified.
    #[arg(long)]
    pub gaze_bytecode: Option<PathBuf>,

    /// Disable the abyss-gaze Deep Packet Inspection (DPI) module.
    #[arg(long, default_value_t = false)]
    pub disable_dpi: bool,

    /// Optional path to an external signature rules file for abyss-gaze.
    #[arg(long)]
    pub dpi_signatures: Option<PathBuf>,

    /// Disable the default built-in attack signatures (run exclusively with --dpi-signatures).
    #[arg(long, default_value_t = false)]
    pub no_default_signatures: bool,

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

    /// Resolves the abyss-gaze bytecode path.
    ///
    /// If `--disable-dpi` is set, returns `Ok(None)`.
    /// If `--gaze-bytecode` is explicitly provided, verifies existence and returns `Ok(Some(path))`.
    /// Otherwise, checks candidate paths in the workspace and returns `Ok(Some(path))` if found,
    /// or `Ok(None)` if no bytecode was found.
    pub fn resolve_gaze_bytecode_path(&self) -> anyhow::Result<Option<PathBuf>> {
        if self.disable_dpi {
            return Ok(None);
        }

        if let Some(ref path) = self.gaze_bytecode {
            if path.exists() {
                return Ok(Some(path.canonicalize().unwrap_or_else(|_| path.clone())));
            }
            anyhow::bail!("Specified gaze bytecode path does not exist: {}", path.display());
        }

        let candidates = [
            PathBuf::from("target/bpfel-unknown-none/release/abyss-gaze"),
            PathBuf::from("../target/bpfel-unknown-none/release/abyss-gaze"),
            PathBuf::from("../../target/bpfel-unknown-none/release/abyss-gaze"),
            PathBuf::from("kernel-modules/abyss-gaze/target/bpfel-unknown-none/release/abyss-gaze"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return Ok(Some(candidate.canonicalize().unwrap_or_else(|_| candidate.clone())));
            }
        }

        Ok(None)
    }

    /// Loads active DPI signatures according to `--dpi-signatures` and `--no-default-signatures`.
    pub fn load_dpi_signatures(&self) -> anyhow::Result<Vec<abyss_common::dpi::DpiSignature>> {
        use abyss_common::dpi::{DpiAction, DpiSignature, MAX_SIGNATURES, MAX_SIGNATURE_LEN};
        use anyhow::Context;

        let mut signatures = Vec::new();

        // 1. Built-in defaults unless explicitly omitted
        if !self.no_default_signatures {
            let defaults: [(&[u8], u32, DpiAction); 4] = [
                (b"../..", 0, DpiAction::Drop),
                (b"/etc/passwd", 0, DpiAction::Drop),
                (b"UNION SELECT", 0, DpiAction::Drop),
                (b"<script", 0, DpiAction::Drop),
            ];

            for (pattern, offset, action) in defaults {
                let mut sig = DpiSignature {
                    pattern: [0u8; MAX_SIGNATURE_LEN],
                    pattern_len: pattern.len() as u8,
                    action,
                    _pad: [0; 2],
                    payload_offset: offset,
                };
                sig.pattern[..pattern.len()].copy_from_slice(pattern);
                signatures.push(sig);
            }
        }

        // 2. Load custom signatures from file if specified
        if let Some(ref path) = self.dpi_signatures {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read DPI signatures file from {}", path.display()))?;

            for (idx, line) in content.lines().enumerate() {
                if let Some(sig) = parse_signature_line(line)
                    .with_context(|| format!("{}:{}: invalid signature syntax", path.display(), idx + 1))?
                {
                    if signatures.len() >= MAX_SIGNATURES as usize {
                        anyhow::bail!(
                            "Exceeded maximum allowed DPI signatures limit of {} rules",
                            MAX_SIGNATURES
                        );
                    }
                    signatures.push(sig);
                }
            }
        }

        Ok(signatures)
    }
}

/// Parses a single line from a DPI signatures ruleset file.
///
/// Supported formats:
/// - `# Comment line` (ignored)
/// - Empty lines (ignored)
/// - `[action:[offset:]]pattern` (e.g. `drop:0:/etc/passwd` or `alert:10:<script` or bare `UNION SELECT`)
pub fn parse_signature_line(line: &str) -> anyhow::Result<Option<abyss_common::dpi::DpiSignature>> {
    use abyss_common::dpi::{DpiAction, DpiSignature, MAX_SIGNATURE_LEN};

    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let (action, offset, pattern) = if let Some((first, rest)) = trimmed.split_once(':') {
        let first_lower = first.to_ascii_lowercase();
        if first_lower == "drop" || first_lower == "alert" {
            let act = if first_lower == "drop" {
                DpiAction::Drop
            } else {
                DpiAction::Alert
            };

            if let Some((offset_str, pat)) = rest.split_once(':') {
                let off: u32 = offset_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid offset '{}'", offset_str))?;
                (act, off, pat)
            } else {
                (act, 0u32, rest)
            }
        } else {
            // Not an action, entire line is pattern
            (DpiAction::Drop, 0u32, trimmed)
        }
    } else {
        (DpiAction::Drop, 0u32, trimmed)
    };

    let pat_bytes = pattern.as_bytes();
    if pat_bytes.is_empty() {
        return Ok(None);
    }

    if pat_bytes.len() > MAX_SIGNATURE_LEN {
        anyhow::bail!(
            "Signature pattern '{}' exceeds maximum allowed length of {} bytes (got {} bytes)",
            pattern,
            MAX_SIGNATURE_LEN,
            pat_bytes.len()
        );
    }

    let mut sig = DpiSignature {
        pattern: [0u8; MAX_SIGNATURE_LEN],
        pattern_len: pat_bytes.len() as u8,
        action,
        _pad: [0; 2],
        payload_offset: offset,
    };
    sig.pattern[..pat_bytes.len()].copy_from_slice(pat_bytes);

    Ok(Some(sig))
}


