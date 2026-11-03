# `abyss-tide` (Stateful Token Bucket Rate Limiter)

`abyss-tide` occupies Slot 0 of the Abyss Ring 0 Module Bay. It provides microsecond-precision per-IP rate limiting directly in the NIC driver space to mitigate packet floods and denial-of-service attacks.

---

## Technical Highlights

- **Fractional Token Bucket**: Calculates token refills based on elapsed nanoseconds (`bpf_ktime_get_ns()`) without background timer threads or system calls.
- **LRU State Tracking**: Uses an eBPF `LruHashMap` (`RATE_LIMIT_TABLE`) with 65,536 entries to track active source IP addresses.
- **Arithmetic Safety**: Uses `wrapping_mul` to ensure that 64-bit multiplications compile directly to native BPF instructions without emitting 128-bit `__multi3` helper calls.
- **Tail-Call Chaining**: On valid packets, queries `MODULE_STATUS` to jump execution to Slot 1 (`abyss-gaze`).

---

## Compiling Bytecode

```bash
RUSTC_BOOTSTRAP=1 cargo build -Z build-std=core --target bpfel-unknown-none -p abyss-tide --release
```

Output binary: `target/bpfel-unknown-none/release/abyss-tide`

---

## Documentation

- [System Architecture](../../docs/architecture.md)
- [eBPF Internals & Verifier Guide](../../docs/ebpf-internals.md)
