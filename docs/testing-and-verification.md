# Testing, Verification & Benchmarking Guide

This guide walks through testing and verifying the Abyss eBPF Pre-Firewall using unit test suites, contract tests, and an isolated Linux network namespace with virtual ethernet (`veth`) pairs.

---

## 1. Running Automated Workspace Tests

The workspace contains 73 comprehensive unit, contract, and parsing tests across kernel modules, common contracts, daemon, and CLI:

```bash
cargo test --workspace
```

### Test Breakdown
- `abyss-common`: Validates struct byte sizes, field offsets, `#![no_std]` IPv4 parser, and memory alignment (`#[repr(C)]`).
- `abyss-core`: Validates L2/L3 protocol decoding, truncated packet handling, and early dropout checks.
- `abyss-tide`: Validates fractional token bucket refills, burst limits, timestamp arithmetic, and zero jitter.
- `abyss-gaze`: Validates L4 TCP/UDP header parsing, directory traversal detection, SQL injection detection, and benign packet passthrough.
- `abyss-daemon`: Validates bytecode discovery, signature parsing, and CLI flag defaults.
- `abyss-cli`: Validates argument parsing, output formatting, JSON responses, and slot resolution.

---

## 2. End-to-End Testing with Virtual Ethernet (`veth`)

To test Ring 0 packet filtering without risking local host connectivity, Abyss provides helper scripts to create an isolated testbed:

### Step 1: Set Up the Isolated Namespace
```bash
sudo bash scripts/setup_veth.sh
```

This creates:
- Host interface: `veth-abyss` (`10.200.1.1/24`)
- Namespace: `abyss-ns` with peer interface `veth-peer` (`10.200.1.2/24`)

### Step 2: Start the Abyss Daemon
In **Terminal 1**:
```bash
sudo ./target/debug/abyss-daemon --iface veth-abyss --mode skb
```

Output should confirm all 3 modules loaded into the kernel:
```text
INFO abyss_daemon::loader: Successfully loaded eBPF object into Linux kernel (abyss-core)
INFO abyss_daemon::loader: Successfully loaded eBPF object into Linux kernel (abyss-tide)
INFO abyss_daemon::loader: Successfully loaded eBPF object into Linux kernel (abyss-gaze)
INFO abyss_daemon::attach: XDP Root Dispatcher attached and actively filtering Ring 0 ingress iface=veth-abyss mode=Skb
```

### Step 3: Verify Baseline Traffic
In **Terminal 2**:
```bash
# Ping from namespace to host (should succeed with 0% loss):
sudo ip netns exec abyss-ns ping -c 3 10.200.1.1
```

### Step 4: Test Ring 0 IP Blacklisting
```bash
# 1. Block the namespace IP:
sudo ./target/debug/abyssctl block 10.200.1.2

# 2. Verify it is listed in BLOCKED_IPS:
sudo ./target/debug/abyssctl blocked

# 3. Ping from namespace (should now suffer 100% loss):
sudo ip netns exec abyss-ns ping -c 2 -W 1 10.200.1.1

# 4. Check telemetry counters (packets_dropped_blocked should increment):
sudo ./target/debug/abyssctl stats

# 5. Unblock the IP:
sudo ./target/debug/abyssctl unblock 10.200.1.2

# 6. Verify traffic is immediately restored (0% loss):
sudo ip netns exec abyss-ns ping -c 2 10.200.1.1
```

### Step 5: Test Deep Packet Inspection (DPI)
```bash
# Send an attack payload containing directory traversal matching the default rule:
sudo ip netns exec abyss-ns bash -c 'echo -ne "GET /../../etc/passwd HTTP/1.1\r\n\r\n" | nc -u -w1 10.200.1.1 80'

# Verify DPI drop telemetry incremented:
sudo ./target/debug/abyssctl stats
# Look for: "- Dropped by DPI Inspection: 1"
```

### Step 6: Test Dynamic Module Bay Toggling
```bash
# Disable Rate Limiter on the fly:
sudo ./target/debug/abyssctl module disable rate-limiter
sudo ./target/debug/abyssctl status

# Re-enable Rate Limiter:
sudo ./target/debug/abyssctl module enable rate-limiter
```

### Step 7: Teardown Testbed
When finished testing:
```bash
sudo bash scripts/teardown_veth.sh
```

