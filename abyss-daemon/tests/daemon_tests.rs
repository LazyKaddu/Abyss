//! Integration and unit tests for `abyss-daemon`.

use abyss_common::dpi::DpiAction;
use abyss_daemon::{
    attach::is_sensitive_interface,
    config::{parse_signature_line, Config, XdpMode},
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
    assert!(config.gaze_bytecode.is_none());
    assert!(!config.disable_dpi);
    assert!(config.dpi_signatures.is_none());
    assert!(!config.no_default_signatures);
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
fn test_config_dpi_options() {
    let args = vec!["abyss-daemon", "--disable-dpi", "--no-default-signatures"];
    let config = Config::parse_from(args);

    assert!(config.disable_dpi);
    assert!(config.no_default_signatures);

    let resolved = config.resolve_gaze_bytecode_path().unwrap();
    assert!(resolved.is_none());

    // When no-default-signatures is passed with no file, rules list is empty
    let signatures = config.load_dpi_signatures().unwrap();
    assert!(signatures.is_empty());
}

#[test]
fn test_config_default_signatures() {
    let args = vec!["abyss-daemon"];
    let config = Config::parse_from(args);

    let signatures = config.load_dpi_signatures().unwrap();
    assert_eq!(
        signatures.len(),
        4,
        "Must load 4 default attack signatures (traversal, passwd, sqli, xss)"
    );
}

#[test]
fn test_parse_signature_line() {
    // 1. Comment and empty line
    assert!(parse_signature_line("# this is a comment").unwrap().is_none());
    assert!(parse_signature_line("   ").unwrap().is_none());

    // 2. Bare pattern
    let sig1 = parse_signature_line("UNION SELECT").unwrap().unwrap();
    assert_eq!(sig1.action, DpiAction::Drop);
    assert_eq!(sig1.payload_offset, 0);
    assert_eq!(&sig1.pattern[..sig1.pattern_len as usize], b"UNION SELECT");

    // 3. Action and offset
    let sig2 = parse_signature_line("alert:10:<script").unwrap().unwrap();
    assert_eq!(sig2.action, DpiAction::Alert);
    assert_eq!(sig2.payload_offset, 10);
    assert_eq!(&sig2.pattern[..sig2.pattern_len as usize], b"<script");

    // 4. Drop with explicit offset 0
    let sig3 = parse_signature_line("drop:0:/etc/shadow").unwrap().unwrap();
    assert_eq!(sig3.action, DpiAction::Drop);
    assert_eq!(sig3.payload_offset, 0);
    assert_eq!(&sig3.pattern[..sig3.pattern_len as usize], b"/etc/shadow");

    // 5. Exceeding max length error (> 32 bytes)
    let long_line = "A".repeat(33);
    assert!(parse_signature_line(&long_line).is_err());
}

#[test]
fn test_load_custom_signature_file() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("abyss_test_signatures.txt");
    std::fs::write(
        &file_path,
        b"# Custom rules\n\
          drop:0:/admin/secret\n\
          alert:5:eval(\n\
          \n",
    )
    .unwrap();

    let args = vec![
        "abyss-daemon",
        "--dpi-signatures",
        file_path.to_str().unwrap(),
        "--no-default-signatures",
    ];
    let config = Config::parse_from(args);
    let signatures = config.load_dpi_signatures().unwrap();

    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0].action, DpiAction::Drop);
    assert_eq!(
        &signatures[0].pattern[..signatures[0].pattern_len as usize],
        b"/admin/secret"
    );
    assert_eq!(signatures[1].action, DpiAction::Alert);
    assert_eq!(signatures[1].payload_offset, 5);

    let _ = std::fs::remove_file(file_path);
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
