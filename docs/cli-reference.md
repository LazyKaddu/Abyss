# `abyssctl` Command-Line Reference

`abyssctl` is the administrative control utility for the Abyss eBPF Pre-Firewall. It interacts directly with live eBPF maps in the Linux kernel via `/sys/fs/bpf/abyss/` or dynamic kernel map discovery.

---

## 1. Global Options

```text
abyssctl [OPTIONS] <COMMAND>
```

| Option | Description | Default |
| :--- | :--- | :--- |
| `-b, --bpf-dir <PATH>` | Directory where Abyss eBPF maps are pinned | `/sys/fs/bpf/abyss` |
| `-j, --json` | Output response in structured JSON format | `false` |
| `-h, --help` | Print help information | - |
| `-V, --version` | Print version information | - |

---

## 2. Command Reference

### 2.1 `status`
Displays overall system health, Ring 0 Dispatcher state, active rule counts, and individual module bay slot statuses.

```bash
sudo abyssctl status
```

#### Example Output:
```text
===========================================================
  ABYSS eBPF PRE-FIREWALL CONTROLLER  [ONLINE]
===========================================================
Dispatcher (Ring 0) : Active & Attached
Blocked IP Blacklist : 0 rule(s)
DPI Rules Active : 4 signature(s)
Rate Limit Threshold : 1000 pkts/s

--- Security Module Bay Slots ---
  Slot 0: RateLimiter (abyss-tide) [ACTIVE]
          Processed:          0 pkts | Dropped:        0 pkts
  Slot 1: Deep Packet Inspection (abyss-gaze) [ACTIVE]
          Processed:          0 pkts | Dropped:        0 pkts
===========================================================
```

#### JSON Output (`--json`):
```json
{
  "core_active": true,
  "blocked_ips_count": 0,
  "dpi_signatures_count": 4,
  "rate_limit_pps": 1000,
  "modules": [
    {
      "slot": 0,
      "name": "RateLimiter (abyss-tide)",
      "enabled": true,
      "packets_processed": 0,
      "packets_dropped": 0
    },
    {
      "slot": 1,
      "name": "Deep Packet Inspection (abyss-gaze)",
      "enabled": true,
      "packets_processed": 0,
      "packets_dropped": 0
    }
  ]
}
```

---

### 2.2 `stats`
Reads lock-free per-CPU telemetry counters from `PACKET_COUNTERS` and aggregates total ingress, passed, and categorized drop counts.

```bash
sudo abyssctl stats [OPTIONS]
```

| Flag | Short | Description |
| :--- | :--- | :--- |
| `--per-cpu` | `-p` | Display breakdown for each individual CPU core |
| `--watch` | `-w` | Stream live updates every second with throughput rates |

#### Example Output:
```text
===========================================================
             ABYSS FIREWALL METRICS             
===========================================================
Total Ingress Packets :            6
Total Processed Data : 776 B
Passed Packets : 3
Total Dropped Packets : 3
-----------------------------------------------------------
  - Dropped by IP Blocklist : 2
  - Dropped by Rate Limiter : 0
  - Dropped by DPI Inspection : 1
===========================================================
```

#### Per-CPU Breakdown (`--per-cpu`):
```text
--- Per-CPU Core Breakdown ---
  CPU  0: Passed:        0 | Dropped:      2 (RL:    0, DPI:    0, Block:    2)
  CPU  1: Passed:        0 | Dropped:      0 (RL:    0, DPI:    0, Block:    0)
  CPU  2: Passed:        0 | Dropped:      0 (RL:    0, DPI:    0, Block:    0)
  ...
```

---

### 2.3 `rules`
Dumps all active Deep Packet Inspection (DPI) attack signature patterns, matching offsets, and action verdicts loaded into `DPI_SIGNATURES`.

```bash
sudo abyssctl rules
```

#### Example Output:
```text
===========================================================
      DEEP PACKET INSPECTION (DPI) SIGNATURE RULES      
===========================================================
Active Signatures : 4
-----------------------------------------------------------
  INDEX ACTION OFFSET PATTERN
  0      DROP 0        ../..
  1      DROP 0        /etc/passwd
  2      DROP 0        UNION SELECT
  3      DROP 0        <script
===========================================================
```

---

### 2.4 `block <IP>`
Permanently blocks an IPv4 address at Ring 0 by inserting it into `BLOCKED_IPS`. All subsequent packets from this IP will be dropped instantly with `XDP_DROP` before entering downstream modules.

```bash
sudo abyssctl block 192.168.1.100
```

#### Example Output:
```text
[BLOCKED] IP 192.168.1.100 is now permanently blacklisted in Ring 0.
```

---

### 2.5 `unblock <IP>`
Removes an IPv4 address from `BLOCKED_IPS`, restoring immediate network ingress for that host.

```bash
sudo abyssctl unblock 192.168.1.100
```

#### Example Output:
```text
[UNBLOCKED] IP 192.168.1.100 has been removed from the Ring 0 blocklist.
```

---

### 2.6 `blocked`
Lists all currently blacklisted IP addresses recorded in the kernel.

```bash
sudo abyssctl blocked
```

#### Example Output:
```text
===========================================================
          RING 0 BLOCKED IP BLACKLIST          
===========================================================
Total Blocked IPs : 1
-----------------------------------------------------------
  - 192.168.1.100 [XDP_DROP]
===========================================================
```

---

### 2.7 `module <enable|disable> <rate-limiter|dpi>`
Hot-toggles security modules dynamically at runtime by modifying the `MODULE_STATUS` map in kernel space. **No daemon restart or interface detachment required.**

```bash
# Disable Rate Limiter
sudo abyssctl module disable rate-limiter

# Enable Rate Limiter
sudo abyssctl module enable rate-limiter

# Disable Deep Packet Inspection
sudo abyssctl module disable dpi

# Enable Deep Packet Inspection
sudo abyssctl module enable dpi
```

#### Example Output:
```text
[DISABLED] Security module RateLimiter (abyss-tide) (Slot 0) is now inactive.
[ENABLED] Security module RateLimiter (abyss-tide) (Slot 0) is now active.
```
