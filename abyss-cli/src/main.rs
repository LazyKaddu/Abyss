//! # abyssctl
//!
//! Command-line controller for the Abyss eBPF/XDP Pre-Firewall.
//! Interacts directly with active eBPF maps to inspect telemetry,
//! manage IP blocklists, view DPI rules, and dynamically toggle security modules.

use abyss_cli::{
    commands,
    maps::MapResolver,
    style::Stylize,
    Cli, Commands, ModuleCommands,
};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let resolver = MapResolver::new(&cli.bpf_dir);

    let res = match cli.command {
        Commands::Status => commands::status::execute(&resolver, cli.json),
        Commands::Stats { watch, interval_ms, per_cpu } => {
            commands::stats::execute(&resolver, watch, interval_ms, per_cpu, cli.json).await
        }
        Commands::Block { ip } => commands::block::block_ip(&resolver, &ip, cli.json),
        Commands::Unblock { ip } => commands::block::unblock_ip(&resolver, &ip, cli.json),
        Commands::Blocked => commands::block::list_blocked(&resolver, cli.json),
        Commands::Rules => commands::rules::execute(&resolver, cli.json),
        Commands::Module { sub } => match sub {
            ModuleCommands::Enable { module } => {
                commands::module::set_module_enabled(&resolver, &module, true, cli.json)
            }
            ModuleCommands::Disable { module } => {
                commands::module::set_module_enabled(&resolver, &module, false, cli.json)
            }
        },
    };

    if let Err(e) = res {
        if cli.json {
            eprintln!(
                "{}",
                serde_json::json!({
                    "error": format!("{e:#}"),
                    "success": false
                })
            );
        } else {
            eprintln!("{} {e:#}", "error:".red().bold());
        }
        std::process::exit(1);
    }

    Ok(())
}
