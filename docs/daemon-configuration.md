# `abyss-daemon` Configuration & Deployment Guide

`abyss-daemon` is the Ring 0 orchestrator for the Abyss firewall platform. It runs as a background system service, loads compiled eBPF bytecode into the Linux kernel via Aya, configures tail-call routing tables, pins maps to `/sys/fs/bpf/abyss/`, and monitors telemetry.

---

## 1. Command-Line Arguments

```text
abyss-daemon [OPTIONS]
```

| Option | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--iface <IFACE>` | `-i` | Target network interface to attach the XDP program | `eth0` |
| `--mode <MODE>` | `-m` | XDP attachment mode (`skb`, `drv`, `hw`) | `skb` |
| `--bpf-dir <PATH>` | `-b` | bpffs directory where eBPF maps are pinned | `/sys/fs/bpf/abyss` |
| `--core-bytecode <PATH>` | `-c` | Path to compiled `abyss-core` eBPF bytecode | Auto-detected |
| `--tide-bytecode <PATH>` | `-t` | Path to compiled `abyss-tide` eBPF bytecode | Auto-detected |
| `--gaze-bytecode <PATH>` | `-g` | Path to compiled `abyss-gaze` eBPF bytecode | Auto-detected |
| `--max-pps <N>` | - | Token bucket rate limit threshold (packets/second) | `1000` |
| `--signatures <PATH>` | `-s` | Path to custom DPI signatures file | Built-in rules |
| `--no-rate-limit` | - | Start daemon with Slot 0 (Rate Limiter) disabled | `false` |
| `--no-dpi` | - | Start daemon with Slot 1 (DPI) disabled | `false` |
| `--no-pin` | - | Skip pinning maps to bpffs | `false` |
| `--interval <MS>` | - | Telemetry logging interval in milliseconds | `1000` |

---

## 2. XDP Attachment Modes

Abyss supports all standard Linux XDP attachment modes:

1. **`skb` (Generic XDP)**:
   - Operates after the network driver allocates an `sk_buff` but before it enters the TCP/IP stack.
   - Works on **any** Linux network interface (including virtual interfaces like `veth`, `tun`, and cloud network drivers).
   - Ideal for development, testing, and virtualized container environments.

2. **`drv` (Native / Driver XDP)**:
   - Executes directly inside the NIC driver's receive ring before memory allocation.
   - Delivers maximum performance (millions of packets per second with minimal CPU usage).
   - Requires driver support (e.g. `ixgbe`, `i40e`, `mlx5`, `e1000e`).

3. **`hw` (Hardware Offloaded XDP)**:
   - Offloads eBPF bytecode directly onto SmartNIC hardware processors (e.g., Netronome Agilio).
   - Zero host CPU utilization.

---

## 3. bpffs Map Pinning & Permissions

When `abyss-daemon` starts, it ensures the BPF virtual filesystem (`/sys/fs/bpf`) is mounted and creates `/sys/fs/bpf/abyss`:
```bash
# Verify bpffs is mounted:
mount | grep bpf

# Check pinned maps:
ls -la /sys/fs/bpf/abyss/
```

### Stale Pin Handling
If a prior daemon session crashed or terminated ungracefully, `abyss-daemon` automatically unpins stale map references during startup before creating fresh maps.

---

## 4. Production Systemd Service Example

To deploy `abyss-daemon` as a persistent Linux system service:

Create `/etc/systemd/system/abyss.service`:
```ini
[Unit]
Description=Abyss eBPF Pre-Firewall Orchestrator
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/abyss-daemon --iface eth0 --mode drv --max-pps 10000
Restart=always
RestartSec=3
LimitMEMLOCK=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now abyss
sudo systemctl status abyss
```

