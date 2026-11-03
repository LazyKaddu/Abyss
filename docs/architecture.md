# Abyss Architecture & System Design

Abyss is a modular, high-performance eBPF/XDP pre-firewall and traffic dispatcher running directly in Linux Ring 0 (Network Interface Card driver space). It intercepts, inspects, and drops or routes packets at line-rate speeds before the Linux kernel network stack allocates an `sk_buff` socket buffer.

---

## 1. High-Level Architecture

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
|   |                                                                   |   |
|   |  - MODULE_SLOTS (ProgArray)       - RATE_LIMIT_CFG (Array)        |   |
|   |  - MODULE_STATUS (Array)          - RATE_LIMIT_TABLE (LruHashMap) |   |
|   |  - PACKET_COUNTERS (PerCpuArray)  - DPI_SIGNATURES (Array)        |   |
|   |  - BLOCKED_IPS (HashMap)                                          |   |
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
|   |  |  1. Parse Ethernet & IPv4/IPv6 headers                      |  |   |
|   |  |  2. Check BLOCKED_IPS map (Instant XDP_DROP if blacklisted) |  |   |
|   |  |  3. Check MODULE_STATUS for Slot 0                          |  |   |
|   |  |  4. bpf_tail_call(ctx, MODULE_SLOTS, 0)                     |  |   |
|   |  +------------------------------+------------------------------+  |   |
|   |                                 | (Tail Call)                     |   |
|   |                                 v                                 |   |
|   |  +-------------------------------------------------------------+  |   |
|   |  |                 abyss-tide (Rate Limiter - Slot 0)          |  |   |
|   |  |  1. Token bucket evaluation via RATE_LIMIT_TABLE (LRU)      |  |   |
|   |  |  2. If rate exceeded -> XDP_DROP                            |  |   |
|   |  |  3. If rate allowed & Slot 1 enabled -> tail_call(Slot 1)   |  |   |
|   |  |  4. Fallback -> XDP_PASS                                    |  |   |
|   |  +------------------------------+------------------------------+  |   |
|   |                                 | (Tail Call)                     |   |
|   |                                 v                                 |   |
|   |  +-------------------------------------------------------------+  |   |
|   |  |                   abyss-gaze (DPI Engine - Slot 1)          |  |   |
|   |  |  1. Parse L4 headers (TCP/UDP) & payload bounds             |  |   |
|   |  |  2. Branchless pattern scan against DPI_SIGNATURES          |  |   |
|   |  |  3. If attack detected -> XDP_DROP                          |  |   |
|   |  |  4. Clean packet -> XDP_PASS                                |  |   |
|   |  +-------------------------------------------------------------+  |   |
|   +-------------------------------------------------------------------+   |
+---------------------------------------------------------------------------+
```

---

## 2. Core Components

### 2.1 The Root Dispatcher (`abyss-core`)
- **Attachment Point**: Attached to the network interface via XDP in SKB or Native (driver) mode.
- **Responsibilities**:
  1. Fast L2/L3 packet parsing (Ethernet, VLAN, IPv4, IPv6).
  2. **Early Dropout Blocklist**: Checks `BLOCKED_IPS`. If the source IPv4 is blacklisted, it issues an immediate `XDP_DROP` without executing downstream filters.
  3. **Module Bay Routing**: Inspects `MODULE_STATUS` to check whether Slot 0 (`abyss-tide`) is active. If active, it invokes `bpf_tail_call(ctx, &MODULE_SLOTS, 0)`. If disabled, it checks Slot 1 (`abyss-gaze`) and jumps directly to Slot 1.
  4. Records global ingress and drop metrics in `PACKET_COUNTERS`.

### 2.2 The Stateful Rate Limiter (`abyss-tide` - Slot 0)
- **Algorithm**: High-precision microsecond-level Token Bucket using `bpf_ktime_get_ns()`.
- **State Tracking**: `RATE_LIMIT_TABLE` is an eBPF `LruHashMap<RateLimitKey, RateLimitValue, 65536>` keyed by source IPv4.
- **Fractional Token Refill**: Tokens refill dynamically based on elapsed wall-clock nanoseconds without requiring timer interrupts.
- **Chaining**: If the packet passes rate evaluation, `abyss-tide` queries `MODULE_STATUS` for Slot 1 and initiates a tail-call to `abyss-gaze`. If Slot 1 is disabled or the tail-call fails, it defaults to `XDP_PASS`.

### 2.3 Deep Packet Inspection (`abyss-gaze` - Slot 1)
- **Scope**: Parses L4 transport headers (TCP data offset, UDP header length) and inspects the application payload.
- **Scanning Engine**: Branchless difference accumulation using pre-computed mask tables (`MASKS: [[u8; 16]; 17]`), evaluated at key protocol token offsets (`0, 4, 5, 11, 13, 16`) within a 64-byte bounded payload window.
- **Rule Set**: Configurable via `DPI_SIGNATURES` map (defaults: directory traversal `../..`, `/etc/passwd`, SQL injection `UNION SELECT`, XSS `<script`).
- **Verdict**: Issues `XDP_DROP` upon match and updates `packets_dropped_dpi` telemetry; otherwise yields `XDP_PASS`.

### 2.4 User-Space Orchestrator (`abyss-daemon`)
- Written in async Rust using `Aya` and `tokio`.
- Loads compiled eBPF bytecode (`abyss-core`, `abyss-tide`, `abyss-gaze`) into the kernel.
- Links module file descriptors into `MODULE_SLOTS` (`PROG_ARRAY`).
- Pins eBPF maps to bpffs (`/sys/fs/bpf/abyss/`) for persistent CLI management.
- Runs an asynchronous telemetry loop collecting lock-free `PerCpuArray` statistics.

### 2.5 CLI Controller (`abyssctl`)
- Lightweight administration and monitoring tool built with `clap`.
- Interacts with live kernel maps via hybrid lookup (primary: pinned `/sys/fs/bpf/abyss/*`, fallback: active kernel map scanning).
- Provides live status, per-CPU telemetry streaming (`--watch`), IP blacklisting/unblacklisting, DPI rule inspection, and runtime module slot toggling without daemon restarts.

---

## 3. Shared Memory Contracts (`abyss-common`)

Because kernel-space and user-space run in completely isolated memory environments, all data structures exchanged through eBPF maps are defined in `abyss-common` under `#![no_std]` with explicit `#[repr(C)]` layouts:

| Struct | Size (Bytes) | Alignment | Purpose |
| :--- | :--- | :--- | :--- |
| `PacketCounters` | 48 | 8 | Ingress, pass, total drop, and per-reason drop counters |
| `ModuleStatus` | 4 | 2 | Bitfield / status flags for Slot 0 and Slot 1 runtime state |
| `RateLimitConfig` | 16 | 8 | Configured burst capacity and refill rate in nanoseconds |
| `RateLimitKey` | 4 | 4 | IPv4 address lookup key for rate limiter |
| `RateLimitValue` | 16 | 8 | Token count and last refill timestamp (`u64`) |
| `DpiSignature` | 40 | 8 | Pattern buffer (16 B), pattern length, payload offset, action |
| `PacketEvent` | 40 | 8 | Ring buffer event record for dropped or flagged packets |

---

## 4. eBPF Map Topology

| Map Name | Type | Key | Value | Max Entries | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `MODULE_SLOTS` | `ProgramArray` | `u32` (slot index) | `u32` (prog fd) | 8 | Tail-call routing table |
| `MODULE_STATUS` | `Array` | `u32` | `ModuleStatus` | 1 | Dynamic runtime enable/disable flags |
| `PACKET_COUNTERS` | `PerCpuArray` | `u32` | `PacketCounters` | 1 | Lock-free per-CPU telemetry metrics |
| `BLOCKED_IPS` | `HashMap` | `u32` (IPv4) | `u8` (action) | 65536 | Ring 0 early dropout IP blacklist |
| `RATE_LIMIT_CFG` | `Array` | `u32` | `RateLimitConfig` | 1 | Global rate limit parameters |
| `RATE_LIMIT_TABLE` | `LruHashMap` | `RateLimitKey` | `RateLimitValue` | 65536 | Per-IP token bucket tracking |
| `DPI_SIGNATURES` | `Array` | `u32` | `DpiSignature` | 16 | Loaded L7 attack signatures |

