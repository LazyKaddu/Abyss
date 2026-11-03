# `abyss-core` (The Root Dispatcher)

`abyss-core` is the primary XDP entry point for Abyss. Compiled directly to `#![no_std]` eBPF bytecode (`bpfel-unknown-none`), it is attached to the network interface card driver to perform early packet triage.

---

## Architecture & Responsibilities

1. **L2/L3 Packet Parsing**: Safely parses Ethernet frames (including 802.1Q VLAN tags) and IPv4/IPv6 headers.
2. **Early Dropout Blocklist**: Checks `BLOCKED_IPS`. If the source IPv4 is blacklisted, it issues an instant `XDP_DROP` verdict without consuming further CPU cycles.
3. **Module Bay Tail-Call Router**: Checks `MODULE_STATUS` to route allowed packets into downstream security modules in `MODULE_SLOTS`:
   - Slot 0: `abyss-tide` (Rate Limiter)
   - Slot 1: `abyss-gaze` (Deep Packet Inspection)
4. **Lock-Free Telemetry**: Updates per-CPU ingress and drop counters in `PACKET_COUNTERS`.

---

## Compiling Bytecode

```bash
RUSTC_BOOTSTRAP=1 cargo build -Z build-std=core --target bpfel-unknown-none -p abyss-core --release
```

Output binary: `target/bpfel-unknown-none/release/abyss-core`

---

## Documentation

- [System Architecture & Ingress Pipeline](../../docs/architecture.md)
- [eBPF Internals & Verifier Guide](../../docs/ebpf-internals.md)

