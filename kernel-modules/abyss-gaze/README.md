# `abyss-gaze` (Ring 0 Deep Packet Inspection Engine)

`abyss-gaze` occupies Slot 1 of the Abyss Ring 0 Module Bay. It parses L4 transport headers (TCP/UDP) and performs high-speed pattern matching against application payloads to detect and drop exploit payloads at line rate.

---

## Technical Highlights

- **Branchless Mask Scanning (`MASKS`)**: Uses a zero-branch constant mask table (`MASKS: [[u8; 16]; 17]`) to eliminate loop branches, reducing verifier-simulated instructions from 1,000,000+ down to under 6,000.
- **Fixed Stack Snapshotting**: Copies packet payload into a bounded 64-byte stack chunk in a single linear pass with bitwise index masking (`& 63`), preventing unbounded variable stack read errors.
- **Protocol Fast-Path Offsets**: Evaluates candidate matches at standard HTTP and DNS token boundaries (`0, 4, 5, 11, 13, 16`).
- **Configurable Signatures**: Evaluates against `DPI_SIGNATURES` (defaults include path traversal `../..`, `/etc/passwd`, SQL injection `UNION SELECT`, and `<script`).

---

## Compiling Bytecode

```bash
RUSTC_BOOTSTRAP=1 cargo build -Z build-std=core --target bpfel-unknown-none -p abyss-gaze --release
```

Output binary: `target/bpfel-unknown-none/release/abyss-gaze`

---

## Documentation

- [DPI Rules & Signature Specification](../../docs/dpi-rules.md)
- [eBPF Internals & Verifier Guide](../../docs/ebpf-internals.md)
- [System Architecture](../../docs/architecture.md)
