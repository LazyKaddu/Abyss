# Abyss

> **A modular, ultra-high-performance eBPF/XDP pre-firewall and traffic dispatcher running directly in Linux Ring 0.**

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/technology-eBPF%20%2F%20XDP-blue.svg)](https://ebpf.io/)
[![Framework](https://img.shields.io/badge/framework-Aya-green.svg)](https://aya-rs.dev/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-lightgrey.svg)](LICENSE)

---

## Executive Summary

Traditional Linux firewalls like `iptables` and `nftables` rely on the kernel's network stack to allocate `sk_buff` memory buffers for every incoming packet before evaluating security rules. Under high-throughput conditions—such as volumetric DDoS attacks or application layer exploits—this memory allocation creates a severe CPU bottleneck, causing host exhaustion even when malicious traffic is blocked.

**Abyss** introduces a hardware-adjacent packet filtering architecture using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)** written in Rust. Operating inside the Network Interface Card (NIC) driver layer (Ring 0), it intercepts, analyzes, and drops unauthorized packets at line-rate speeds before the operating system allocates socket buffers, achieving near-zero CPU overhead.

---

## Core System Architecture

To avoid monolithic code bloat and satisfy the strict requirements of the Linux Kernel Verifier, Abyss implements a **Tail Call Dispatcher Pattern**:

```
                    +-------------------------------------------------------+
                    |                      USER-SPACE                       |
                    |                                                       |
                    |   +---------------------+   +---------------------+   |
                    |   |      abyssctl       |   |    abyss-daemon     |   |
                    |   |  (CLI Controller)   |   | (Async Orchestrator)|   |
                    |   +----------+----------+   +----------+----------+   |
                    |              |                         |              |
                    +--------------|-------------------------|--------------+
                                   |                         |
               bpffs Pinned Maps   |                         |  Aya eBPF Loader
               (/sys/fs/bpf/abyss) |                         |  & Map Relocation
                                   v                         v
+---------------------------------------------------------------------------+
|                           LINUX KERNEL (RING 0)                           |
|                                                                           |
|   +-------------------------------------------------------------------+   |
|   |                        SHARED eBPF MAPS                           |   |
|   |  MODULE_SLOTS | MODULE_STATUS | PACKET_COUNTERS | BLOCKED_IPS     |   |
|   |  RATE_LIMIT_CFG | RATE_LIMIT_TABLE | DPI_SIGNATURES               |   |
|   +-------------------------------------------------------------------+   |
|                                     ^                                     |
|                                     | reads/writes                        |
|                                                                           |
|   +-------------------------------------------------------------------+   |
|   |                       XDP INGRESS PIPELINE                        |   |
|   |                                                                   |   |
|   |  [ Incoming Packet ]                                              |   |
|   |          |                                                        |   |
|   |          v                                                        |   |
|   |  +-------------------------------------------------------------+  |   |
|   |  |                   abyss-core (Dispatcher)                   |  |   |
|   |  |  * Early Dropout: BLOCKED_IPS (Instant XDP_DROP)            |  |   |
|   |  |  * Module Bay Router: bpf_tail_call(ctx, MODULE_SLOTS, 0)   |  |   |
|   |  +------------------------------+------------------------------+  |   |
|   |                                 | (Tail Call)                     |   |
|   |                                 v                                 |   |
|   |  +-------------------------------------------------------------+  |   |
|   |  |                 abyss-tide (Rate Limiter - Slot 0)          |  |   |
|   |  |  * Microsecond Token Bucket via LRU Hash Map                |  |   |
|   |  |  * If allowed -> bpf_tail_call(ctx, MODULE_SLOTS, 1)        |  |   |
|   |  +------------------------------+------------------------------+  |   |
|   |                                 | (Tail Call)                     |   |
|   |                                 v                                 |   |
|   |  +-------------------------------------------------------------+  |   |
|   |  |                   abyss-gaze (DPI Engine - Slot 1)          |  |   |
|   |  |  * L4 parsing + branchless MASKS table pattern matching     |  |   |
|   |  |  * Drops exploit payloads (SQLi, XSS, Path Traversal)       |  |   |
|   |  +-------------------------------------------------------------+  |   |
|   +-------------------------------------------------------------------+   |
+---------------------------------------------------------------------------+
```

---

## Workspace Layout

```text
abyss/
├── Cargo.toml                       # Workspace root definition
├── docs/                            # Comprehensive System Documentation
│   ├── architecture.md              # System design & packet lifecycle
│   ├── ebpf-internals.md            # Verifier guide & branchless matching
│   ├── cli-reference.md             # abyssctl command-line manual
│   ├── daemon-configuration.md      # Daemon orchestration & systemd
│   ├── dpi-rules.md                 # DPI signature rules specification
│   └── testing-and-verification.md  # veth test harness & end-to-end runs
├── abyss-common/                    # Shared #![no_std] contracts & structs
│   └── README.md                    # Data layout & memory contract
├── abyss-daemon/                    # Async userspace daemon (Aya & Tokio)
│   └── README.md                    # Daemon orchestration guide
├── abyss-cli/                       # CLI management utility (abyssctl)
│   └── README.md                    # Controller documentation
├── kernel-modules/                  # Ring 0 eBPF payloads (bpfel-unknown-none)
│   ├── abyss-core/                  # The Root Dispatcher & Blocklist
│   │   └── README.md
│   ├── abyss-tide/                  # Slot 0: Token Bucket Rate Limiter
│   │   └── README.md
│   └── abyss-gaze/                  # Slot 1: Deep Packet Inspection Engine
│       └── README.md
└── scripts/                         # Testing & infrastructure scripts
    ├── setup_veth.sh                # Isolated namespace & veth pair setup
    └── teardown_veth.sh             # Test environment teardown
```

---

## Quickstart Guide

### 1. Prerequisites
- Modern Linux distribution (Fedora 38+, Ubuntu 22.04+, Debian 12+)
- Rust (stable toolchain) + Rust nightly (for compiling `#![no_std]` eBPF payloads)
- `bpfel-unknown-none` target and `rust-src`:
  ```bash
  rustup target add bpfel-unknown-none
  rustup component add rust-src
  ```

### 2. Compile Everything
```bash
# 1. Compile eBPF kernel modules
RUSTC_BOOTSTRAP=1 cargo build -Z build-std=core --target bpfel-unknown-none -p abyss-core -p abyss-tide -p abyss-gaze --release

# 2. Compile userspace daemon and CLI
cargo build --workspace
```

### 3. Run Automated Tests (73 tests)
```bash
cargo test --workspace
```

### 4. End-to-End Live Verification
```bash
# 1. Create an isolated testing namespace
sudo bash scripts/setup_veth.sh

# 2. Launch abyss-daemon on veth-abyss (Terminal 1)
sudo ./target/debug/abyss-daemon --iface veth-abyss --mode skb

# 3. Test abyssctl commands (Terminal 2)
sudo ./target/debug/abyssctl status
sudo ./target/debug/abyssctl stats

# 4. Block an IP and verify instant drop
sudo ./target/debug/abyssctl block 10.200.1.2
sudo ip netns exec abyss-ns ping -c 2 10.200.1.1  # 100% loss
sudo ./target/debug/abyssctl stats                 # Dropped by IP Blocklist: 2

# 5. Unblock IP
sudo ./target/debug/abyssctl unblock 10.200.1.2
sudo ip netns exec abyss-ns ping -c 2 10.200.1.1  # 0% loss (restored)

# 6. Test Deep Packet Inspection (DPI)
sudo ip netns exec abyss-ns bash -c 'echo -ne "GET /../../etc/passwd HTTP/1.1\r\n\r\n" | nc -u -w1 10.200.1.1 80'
sudo ./target/debug/abyssctl stats                 # Dropped by DPI Inspection: 1
```

---

## Comprehensive Documentation Index

- [Architecture & Ingress Pipeline](docs/architecture.md)
- [eBPF Internals & Verifier Engineering](docs/ebpf-internals.md)
- [`abyssctl` CLI Reference](docs/cli-reference.md)
- [`abyss-daemon` Configuration & Deployment](docs/daemon-configuration.md)
- [DPI Rules & Signature Syntax](docs/dpi-rules.md)
- [Testing, Verification & Benchmarking](docs/testing-and-verification.md)
