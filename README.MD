# Abyss

> *A modular, ultra-high-performance eBPF/XDP pre-firewall and traffic dispatcher running directly in Linux Ring 0.*

---

## Executive Summary

Traditional Linux firewalls like `iptables` and `nftables` rely on the kernel's network stack to allocate memory buffers for every incoming packet before applying security rules. Under high-throughput scenarios—such as DDoS attacks targeting cloud-native or AI infrastructure—this memory allocation creates a severe CPU bottleneck, causing the server to crash even if the traffic is eventually blocked.

**Abyss** introduces a dynamic, hardware-adjacent packet filtering architecture using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**. Written entirely in Rust, the system injects a modular "Adapter" directly into the Network Interface Card (NIC) driver (Ring 0). It intercepts, analyzes, and drops malicious packets at line-rate speeds before the Linux operating system even registers their existence, resulting in near-zero CPU overhead.

---

## Core System Architecture

To satisfy the strict requirements of the Linux Kernel Verifier and avoid monolithic code bloat, Abyss utilizes an **eBPF Tail Call Dispatcher Pattern**:

* **The Root Dispatcher (Triage Layer):** A lightweight XDP program attached to the NIC. It parses Ethernet and IP headers, classifies the protocol, and uses `bpf_tail_call()` to instantly jump execution to specific security modules stored in an eBPF `PROG_ARRAY` map.
* **The Module Bay (`PROG_ARRAY`):** A kernel-level routing table that holds file descriptors for independent packet-processing modules.
* **The User-Space Orchestrator (`abyss-daemon`):** A multi-threaded Rust daemon running in standard user-space. It dynamically compiles, loads, and hooks new XDP modules into the `PROG_ARRAY` at runtime, allowing the firewall logic to update instantly without detaching the Root Dispatcher or dropping active connections.
* **CLI Controller (`abyss-cli`):** A command-line utility (`abyssctl`) to inspect telemetry maps, check module statuses, and manage filtering rules on the fly.

---

## Pluggable Security Modules

The Adapter comes pre-loaded with two distinct packet processing modules:

1. **Stateful Rate Limiter (`abyss-tide`):**
* Uses an eBPF LRU (Least Recently Used) Hash Map to track source IP addresses and timestamps (`bpf_ktime_get_ns()`).
* Calculates request frequency at the microsecond level. If an IP exceeds the configured packet-per-second threshold, the module issues an `XDP_DROP` verdict, instantly mitigating SYN and ICMP floods.


2. **Deep Packet Inspection (DPI) Engine (`abyss-gaze`):**
* Executes strict, mathematically proven bounds-checking to parse past the TCP/UDP headers into the application payload.
* Scans the raw byte array for unauthorized signatures (e.g., malformed HTTP headers or SQL injection strings in plaintext) and drops non-compliant packets, acting as an ultra-low-latency Web Application Firewall (WAF) precursor.



---

## Technical Stack

* **Kernel Payload:** `#![no_std]` Rust, compiled to eBPF bytecode (`bpfel-unknown-none`).
* **User-Space Daemon & CLI:** Rust, utilizing the `Aya` framework for eBPF lifecycle management and `tokio` for asynchronous map polling.
* **Host Environment:** Native Linux deployment optimized for modern environments (such as Fedora KDE Plasma), utilizing `veth` pairs and Network Namespaces for safe, isolated testing.
* **Data Structures:** eBPF `PROG_ARRAY` (tail calls), LRU Hash Maps (state tracking), and `PerCpuArray` (lock-free telemetry counters).

---

## Repository Structure

```text
abyss/
├── Cargo.toml                  # Workspace root
├── abyss-common/               # Shared #![no_std] data structures and map keys
├── abyss-daemon/               # Background service managing eBPF loading and maps
├── abyss-cli/                  # Command-line controller (`abyssctl`)
└── kernel-modules/             # Ring 0 XDP payloads
    ├── abyss-core/             # The Root Dispatcher (Tail Call Router)
    ├── abyss-tide/             # Module: Rate Limiter (Token Bucket)
    └── abyss-gaze/             # Module: Deep Packet Inspection

```

---

## Projected Outcomes & Demo Implementation

The system demonstrates the architectural superiority of Ring 0 packet filtering through a split-screen stress test against a local virtualized network:

* **Baseline:** Standard `iptables` attempting to block a high-volume SYN flood, resulting in maximum CPU exhaustion.
* **Abyss Active:** The eBPF module engages, maintaining **1% CPU utilization** while dropping millions of packets per second silently into the void.