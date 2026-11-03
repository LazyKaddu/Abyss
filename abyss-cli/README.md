# `abyss-cli` (`abyssctl`)

`abyssctl` is the command-line control panel for the Abyss eBPF Pre-Firewall. It provides operators with real-time visibility and dynamic control over the Ring 0 packet filtering engine.

---

## Features

- **Hybrid Map Resolution**: Seamlessly locates live eBPF maps via pinned `/sys/fs/bpf/abyss/` paths with automatic fallback to kernel ID discovery (`aya::maps::loaded_maps`).
- **Real-Time Telemetry**: Aggregated and per-CPU core packet throughput metrics with live watch mode (`--watch`).
- **Ring 0 IP Blacklisting**: Add and remove IPv4 addresses from the kernel blocklist on the fly.
- **Dynamic Module Management**: Enable or disable security module slots (`rate-limiter`, `dpi`) at runtime without restarting the daemon.
- **DPI Rule Inspection**: Inspect active attack signature rules.
- **Machine-Readable Output**: All commands support `--json` for automation and external monitoring integration.

---

## Quick Usage

```bash
# Check firewall status:
sudo ./target/debug/abyssctl status

# View live telemetry counters:
sudo ./target/debug/abyssctl stats

# Block an IP address:
sudo ./target/debug/abyssctl block 192.168.1.100

# View blocked IPs:
sudo ./target/debug/abyssctl blocked

# Unblock an IP address:
sudo ./target/debug/abyssctl unblock 192.168.1.100

# Toggle modules dynamically:
sudo ./target/debug/abyssctl module disable rate-limiter
sudo ./target/debug/abyssctl module enable rate-limiter
```

---

## Documentation

- [Complete `abyssctl` CLI Reference](../docs/cli-reference.md)
- [Testing & Verification Guide](../docs/testing-and-verification.md)

