# `abyss-daemon`

`abyss-daemon` is the user-space orchestrator service for the Abyss eBPF firewall. It handles eBPF bytecode loading, map pinning, network interface attachment, and real-time telemetry aggregation.

---

## Key Responsibilities

1. **eBPF Lifecycle via Aya**: Loads `abyss-core`, `abyss-tide`, and `abyss-gaze` into the kernel.
2. **Tail-Call Routing Setup**: Populates `MODULE_SLOTS` with module program file descriptors.
3. **Map Pinning**: Pins active eBPF maps to `/sys/fs/bpf/abyss/` for CLI interaction.
4. **Interface Attachment**: Attaches the Root Dispatcher (`abyss_dispatcher`) in SKB or Native driver mode.
5. **Asynchronous Telemetry**: Polls `PACKET_COUNTERS` every second and calculates live throughput.

---

## Quick Start

```bash
# Build the daemon:
cargo build -p abyss-daemon

# Run the daemon on a specific interface:
sudo ./target/debug/abyss-daemon --iface eth0 --mode skb
```

---

## Documentation

- [Daemon Configuration & Deployment Guide](../docs/daemon-configuration.md)
- [System Architecture Blueprint](../docs/architecture.md)
- [Testing & Verification Guide](../docs/testing-and-verification.md)
