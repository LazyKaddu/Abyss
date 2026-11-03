//! Unit and integration tests for `abyssctl`.

use abyss_cli::{
    commands::{module::parse_slot, stats::format_bytes},
    Cli, Commands, ModuleCommands,
};
use clap::Parser;
use std::path::PathBuf;

#[test]
fn test_cli_status_defaults() {
    let args = vec!["abyssctl", "status"];
    let cli = Cli::parse_from(args);

    assert_eq!(cli.bpf_dir, PathBuf::from("/sys/fs/bpf/abyss"));
    assert!(!cli.json);
    assert_eq!(cli.command, Commands::Status);
}

#[test]
fn test_cli_status_custom_bpf_dir_and_json() {
    let args = vec!["abyssctl", "--bpf-dir", "/tmp/bpf/test", "--json", "status"];
    let cli = Cli::parse_from(args);

    assert_eq!(cli.bpf_dir, PathBuf::from("/tmp/bpf/test"));
    assert!(cli.json);
    assert_eq!(cli.command, Commands::Status);
}

#[test]
fn test_cli_stats_arguments() {
    let args = vec!["abyssctl", "stats", "--watch", "--interval-ms", "500", "--per-cpu"];
    let cli = Cli::parse_from(args);

    assert_eq!(
        cli.command,
        Commands::Stats {
            watch: true,
            interval_ms: 500,
            per_cpu: true,
        }
    );
}

#[test]
fn test_cli_block_and_unblock() {
    let args_block = vec!["abyssctl", "block", "10.200.1.50"];
    let cli_block = Cli::parse_from(args_block);
    assert_eq!(
        cli_block.command,
        Commands::Block {
            ip: "10.200.1.50".to_string(),
        }
    );

    let args_unblock = vec!["abyssctl", "unblock", "10.200.1.50"];
    let cli_unblock = Cli::parse_from(args_unblock);
    assert_eq!(
        cli_unblock.command,
        Commands::Unblock {
            ip: "10.200.1.50".to_string(),
        }
    );

    let args_blocked = vec!["abyssctl", "blocked"];
    let cli_blocked = Cli::parse_from(args_blocked);
    assert_eq!(cli_blocked.command, Commands::Blocked);
}

#[test]
fn test_cli_rules() {
    let args = vec!["abyssctl", "rules"];
    let cli = Cli::parse_from(args);
    assert_eq!(cli.command, Commands::Rules);
}

#[test]
fn test_cli_module_commands() {
    let args_en = vec!["abyssctl", "module", "enable", "rate-limiter"];
    let cli_en = Cli::parse_from(args_en);
    assert_eq!(
        cli_en.command,
        Commands::Module {
            sub: ModuleCommands::Enable {
                module: "rate-limiter".to_string(),
            }
        }
    );

    let args_dis = vec!["abyssctl", "module", "disable", "dpi"];
    let cli_dis = Cli::parse_from(args_dis);
    assert_eq!(
        cli_dis.command,
        Commands::Module {
            sub: ModuleCommands::Disable {
                module: "dpi".to_string(),
            }
        }
    );
}

#[test]
fn test_cli_invalid_command() {
    let args = vec!["abyssctl", "nonexistent-command"];
    assert!(Cli::try_parse_from(args).is_err());
}

#[test]
fn test_parse_slot_names() {
    assert_eq!(parse_slot("rate-limiter").unwrap().0, 0);
    assert_eq!(parse_slot("0").unwrap().0, 0);
    assert_eq!(parse_slot("tide").unwrap().0, 0);

    assert_eq!(parse_slot("dpi").unwrap().0, 1);
    assert_eq!(parse_slot("1").unwrap().0, 1);
    assert_eq!(parse_slot("gaze").unwrap().0, 1);

    assert!(parse_slot("unknown").is_err());
}

#[test]
fn test_format_bytes() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.00 KiB");
    assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TiB");
}

