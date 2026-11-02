//! Integration and unit tests for `abyss-daemon`.

use abyss_daemon::{
    attach::is_sensitive_interface,
    config::{Config, XdpMode},
    telemetry::format_bytes,
};
use clap::Parser;
use std::path::PathBuf;

#[test]
fn test_config_defaults() {
    let args = vec!["abyss-daemon"];
    let config = Config::parse_from(args);

    assert_eq!(config.iface, "veth-abyss");
    assert_eq!(config.mode, XdpMode::Skb);
    assert_eq!(config.poll_interval_ms, 1000);
    assert!(!config.allow_primary_iface);
    assert_eq!(config.rate_limit_pps, 1000);
    assert!(!config.disable_rate_limiter);
    assert!(config.bytecode.is_none());
    assert!(config.tide_bytecode.is_none());
}

#[test]
fn test_config_rate_limiter_options() {
    let args = vec![
        "abyss-daemon",
        "--rate-limit-pps",
        "5000",
        "--disable-rate-limiter",
    ];
    let config = Config::parse_from(args);

    assert_eq!(config.rate_limit_pps, 5000);
    assert!(config.disable_rate_limiter);

    // When disabled, resolve_tide_bytecode_path must return Ok(None)
    let resolved = config.resolve_tide_bytecode_path().unwrap();
    assert!(resolved.is_none());
}

#[test]
fn test_config_explicit_tide_bytecode_nonexistent() {
    let args = vec![
        "abyss-daemon",
        "--tide-bytecode",
        "/nonexistent/path/to/abyss-tide",
    ];
    let config = Config::parse_from(args);

    let result = config.resolve_tide_bytecode_path();
    assert!(
        result.is_err(),
        "Explicitly specified non-existent tide bytecode must return an error"
    );
}

#[test]
fn test_sensitive_interface_detection() {
    let wifi_names = ["wlan0", "wlp3s0", "wlo1", "wl0"];
    for name in &wifi_names {
        assert!(
            is_sensitive_interface(name),
            "Interface {} should be recognized as wireless/sensitive",
            name
        );
    }

    let safe_names = ["veth-abyss", "veth0", "lo", "dummy0"];
    for name in &safe_names {
        assert!(
            !is_sensitive_interface(name),
            "Interface {} should not be flagged as sensitive",
            name
        );
    }
}

#[test]
fn test_format_bytes_utility() {
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
