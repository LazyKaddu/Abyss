# `abyss-common`

`abyss-common` defines the shared data contract, memory layouts, and data structures exchanged between Linux Ring 0 eBPF kernel modules and user-space management applications (`abyss-daemon`, `abyssctl`).

---

## Key Features

- **`#![no_std]` Compatible**: Compiles for bare-metal targets (`bpfel-unknown-none`) and standard user-space platforms.
- **Explicit Memory Alignment**: All shared structs use `#[repr(C)]` with verified alignment and sizes across 32-bit and 64-bit boundaries.
- **Contract Tests**: Includes memory offset and roundtrip serialization tests in `tests/contract_tests.rs`.
- **Zero-Dependency IPv4 Parser**: Fast `#![no_std]` string-to-IPv4 conversion (`parse_ipv4_addr`) and octet unpacking (`u32_to_octets`).

---

## Main Structures

| Struct | Module | Description |
| :--- | :--- | :--- |
| `PacketCounters` | `telemetry` | Lock-free 48-byte packet and byte counters |
| `ModuleStatus` | `dispatcher` | Bitflags for Slot 0 and Slot 1 runtime enablement |
| `RateLimitConfig` | `rate_limit` | Token bucket capacity and refill parameters |
| `RateLimitKey` / `RateLimitValue` | `rate_limit` | Per-IP token bucket map state |
| `DpiSignature` | `dpi` | 40-byte L7 pattern signature definition |

---

## Documentation

For full system architecture and memory specifications, see [Abyss Architecture Guide](../docs/architecture.md).
