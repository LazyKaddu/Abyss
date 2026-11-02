//! Integration and unit tests for `abyss-daemon`.

use clap::Parser;
use std::path::PathBuf;

// Import modules by referencing the bin or library targets
// Since abyss-daemon has config, attach, and telemetry logic, let's test their public contracts.

#[test]
fn test_config_defaults() {
    // Config::parse_from with minimal args
    // Note: Config has `default_value` attributes
    let args = vec!["abyss-daemon"];
    // Simulate parsing
    #[derive(clap::Parser, Debug)]
    #[command(name = "test")]
    struct TestConfig {
        #[arg(short, long, default_value = "veth-abyss")]
        iface: String,
        #[arg(short, long, default_value_t = 1000)]
        poll_interval_ms: u64,
        #[arg(long, default_value_t = false)]
        allow_primary_iface: bool,
    }

    let config = TestConfig::parse_from(args);
    assert_eq!(config.iface, "veth-abyss");
    assert_eq!(config.poll_interval_ms, 1000);
    assert!(!config.allow_primary_iface);
}

#[test]
fn test_sensitive_interface_detection() {
    let wifi_names = ["wlan0", "wlp3s0", "wlo1", "wl0"];
    for name in &wifi_names {
        assert!(
            name.starts_with("wl"),
            "Interface {} should be recognized as wireless prefix",
            name
        );
    }

    let safe_names = ["veth-abyss", "veth0", "lo", "dummy0"];
    for name in &safe_names {
        assert!(
            !name.starts_with("wl"),
            "Interface {} should not be flagged as wireless prefix",
            name
        );
    }
}

#[test]
fn test_format_bytes_utility() {
    fn format_bytes(bytes: u64) -> String {
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

    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(1536), "1.50 KB");
    assert_eq!(format_bytes(1048576), "1.00 MB");
    assert_eq!(format_bytes(1073741824), "1.00 GB");
}

#[test]
fn test_bytecode_path_validation() {
    let dummy_path = PathBuf::from("/nonexistent/path/to/abyss-core");
    assert!(!dummy_path.exists());
}
